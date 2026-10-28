//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_quack_attach_red.cpp
//
// Unit-level guard for the Phase 4 secret-lookup semantics:
//   - `CREATE SECRET ... (TYPE quack)` from a DuckDB CLI session that
//     never called `PRAGMA boilstream_bootstrap_session` must result in
//     `ATTACH 'quack:host' AS r (TYPE quack)` honouring the user's
//     secret (no auto-vend, no exception).
//   - When a boilstream session IS active, a user-supplied scope-matching
//     TYPE quack secret must take priority over the auto-vended one — the
//     server-vended JWT MUST NOT silently clobber the user's secret.
//
// These unit tests exercise actual lookup and connection-owned caches. Local
// secrets use StoreSecret with a real connection transaction. Authenticated
// cases seed publication and cached responses; no successful OPAQUE exchange,
// network service or full ATTACH is claimed by this executable.
//
// Build (from extension repo root):
//   make            # builds duckdb static libs + extension archive
//   cd test/cpp/build && cmake .. && cmake --build . --target quack_attach_red_test
//   ./quack_attach_red_test
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "boilstream_secret_storage.hpp"
#include "boilstream_connection_state.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/attach_statement.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"

using namespace duckdb;

class BoilstreamInputValidationTestAccess {
public:
	static std::chrono::system_clock::time_point ParseExpiresAt(RestApiSecretStorage &storage,
	                                                            const std::string &expires_at_str) {
		return storage.ParseExpiresAt(expires_at_str);
	}

	static bool IsManagedCatalogCredentialExpiredAt(RestApiSecretStorage &storage, const std::string &expires_at_str,
	                                                std::chrono::system_clock::time_point now) {
		return storage.IsManagedCatalogCredentialExpiredAt(expires_at_str, now);
	}
};

class BoilstreamSessionPublicationTestAccess {
public:
	static shared_ptr<BoilstreamConnectionState> Publish(RestApiSecretStorage &storage, ClientContext &context) {
		auto state = make_shared_ptr<BoilstreamConnectionState>();
		state->access_token = "synthetic-scope-test-token";
		state->session_key.assign(32, 7);
		state->token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(2);
		storage.PublishSession(context, state, nullptr, 0, false);
		return state;
	}

	// Seed the response cache, not a remote write. StoreSecret on an authenticated
	// owner intentionally requires the real server's write acknowledgement.
	static void Cache(RestApiSecretStorage &storage, BoilstreamConnectionState &state,
	                  unique_ptr<const BaseSecret> secret) {
		const auto bytes = storage.SerializeSecret(*secret).size();
		auto entry = BoilstreamSecretCache::Prepare(std::move(secret), BoilstreamSecretCache::Time::max(), bytes);
		state.secret_cache->Put(std::move(entry), state.secret_cache->Revision());
	}
};

struct QuackAttachFixture {
	duckdb::unique_ptr<DuckDB> db;
	duckdb::unique_ptr<RestApiSecretStorage> storage;

	QuackAttachFixture() {
		DBConfig config;
		config.options.maximum_threads = 2;
		config.options.async_threads = 2;
		db = duckdb::make_uniq<DuckDB>(nullptr, &config);
		// Empty endpoint URL == "no bootstrap_session yet". This is the
		// state every fresh duckdb process starts in.
		storage = duckdb::make_uniq<RestApiSecretStorage>(*db->instance, "");
	}
};

TEST_CASE_METHOD(QuackAttachFixture, "Managed credential expiry accepts RFC3339 UTC offsets",
                 "[quack][credentials][expiry]") {
	const auto expired = std::chrono::system_clock::time_point::min();
	const auto zulu = BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "2030-06-15T14:30:00Z");
	const auto utc_offset = BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "2030-06-15T14:30:00+00:00");
	const auto positive_offset =
	    BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "2030-06-15T16:30:00+02:00");
	const auto negative_offset =
	    BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "2030-06-15T09:30:00-05:00");
	const auto fractional =
	    BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "2030-06-15T14:30:00.123456Z");
	REQUIRE(zulu != expired);
	REQUIRE(utc_offset == zulu);
	REQUIRE(positive_offset == zulu);
	REQUIRE(negative_offset == zulu);
	REQUIRE(std::chrono::duration_cast<std::chrono::microseconds>(fractional - zulu).count() == 123456);
	REQUIRE_FALSE(BoilstreamInputValidationTestAccess::IsManagedCatalogCredentialExpiredAt(
	    *storage, "2030-06-15T14:30:00+00:00", zulu - std::chrono::seconds(15)));
	REQUIRE_FALSE(BoilstreamInputValidationTestAccess::IsManagedCatalogCredentialExpiredAt(
	    *storage, "2030-06-15T14:30:00+00:00", zulu - std::chrono::milliseconds(1)));
	REQUIRE(BoilstreamInputValidationTestAccess::IsManagedCatalogCredentialExpiredAt(
	    *storage, "2030-06-15T14:30:00+00:00", zulu));
	REQUIRE(BoilstreamInputValidationTestAccess::IsManagedCatalogCredentialExpiredAt(*storage, "not-rfc3339",
	                                                                                 zulu - std::chrono::seconds(15)));

	const vector<string> invalid_expirations {
	    "",
	    "2030-06-15T14:30:00",
	    "2030-06-15 14:30:00Z",
	    "2030-02-30T14:30:00Z",
	    "2030-06-15T14:30:00+00:00trailing",
	    "2030-06-15T14:30:00 UTC",
	    "2030-06-15T14:30:00+00",
	    "2030-06-15T14:30:00+0000",
	    "2030-06-15T14:30:00+00:00:00",
	    "2030-06-15T14:30:00+24:00",
	    "2030-06-15T14:30:00+00:60",
	    "2030-06-15T14:30:00.Z",
	    "2030-06-15T14:30:00z",
	};
	for (const auto &invalid : invalid_expirations) {
		REQUIRE(BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, invalid) == expired);
	}
}

TEST_CASE("Managed catalog credential envelope requires server trust and rejects client identity",
          "[quack][credentials][tls]") {
	const string valid = R"json({
        "token":"signed-capability",
        "expires_at":"2030-01-01T00:05:00Z",
        "endpoint":"pod.example.test:9494",
		"catalog_id":"9a927d1b-30f5-48da-91eb-af1492bf31c0",
		"storage_owner_tenant_id":42,
		"catalog_group":"9a927d1b_30f5_48da_91eb_af1492bf31c0",
        "server_ca_pem":"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"
      })json";
	ManagedCatalogCredentialEnvelope parsed;
	REQUIRE(ParseManagedCatalogCredentialEnvelope(valid, parsed));
	REQUIRE(parsed.token == "signed-capability");
	REQUIRE(parsed.endpoint == "pod.example.test:9494");
	REQUIRE(parsed.catalog_id == "9a927d1b-30f5-48da-91eb-af1492bf31c0");
	REQUIRE(parsed.storage_owner_tenant_id == 42);
	REQUIRE(parsed.server_ca_pem.find("BEGIN CERTIFICATE") != string::npos);
	auto replace_once = [](string input, const string &from, const string &to) {
		auto position = input.find(from);
		REQUIRE(position != string::npos);
		input.replace(position, from.size(), to);
		return input;
	};

	for (const auto &partial :
	     {string(R"json({"token":"t","expires_at":"2030-01-01T00:05:00Z","endpoint":"e"})json"),
	      replace_once(valid, "\"server_ca_pem\":\"-----BEGIN CERTIFICATE-----\\nca\\n-----END CERTIFICATE-----\\n\"",
	                   "\"server_ca_pem\":\"not-pem\""),
	      replace_once(valid, "\"server_ca_pem\":",
	                   "\"client_private_key_pem\":\"-----BEGIN PRIVATE KEY-----\",\"server_ca_pem\":"),
	      replace_once(valid, "\"server_ca_pem\":", "\"transport_identity\":{},\"server_ca_pem\":")}) {
		parsed.token = "must-be-cleared";
		REQUIRE_FALSE(ParseManagedCatalogCredentialEnvelope(partial, parsed));
		REQUIRE(parsed.token.empty());
	}
	for (const auto &invalid :
	     {replace_once(valid, "9a927d1b-30f5-48da-91eb-af1492bf31c0", "9A927D1B-30F5-48DA-91EB-AF1492BF31C0"),
	      replace_once(valid, "pod.example.test:9494", "https://pod.example.test:9494"),
	      replace_once(valid, "pod.example.test:9494", "pod.example.test:0"),
	      replace_once(valid, "pod.example.test:9494", "pod.example.test:65536"),
	      replace_once(valid, "pod.example.test:9494", "pod.example.test:9494' INJECT"),
	      replace_once(valid, "\"storage_owner_tenant_id\":42", "\"storage_owner_tenant_id\":0"),
	      replace_once(valid, "\"catalog_group\":\"9a927d1b_30f5_48da_91eb_af1492bf31c0\"",
	                   "\"catalog_group\":\"\"")}) {
		REQUIRE_FALSE(ParseManagedCatalogCredentialEnvelope(invalid, parsed));
		REQUIRE(parsed.catalog_id.empty());
		REQUIRE(parsed.storage_owner_tenant_id == 0);
	}
}

TEST_CASE("Managed catalog attach uses canonical scope and escapes only the presentation alias",
          "[quack][credentials][scope]") {
	ManagedCatalogCredentialEnvelope credential;
	credential.endpoint = "pod.example.test:9494";
	credential.catalog_id = "9a927d1b-30f5-48da-91eb-af1492bf31c0";
	credential.storage_owner_tenant_id = 42;
	credential.catalog_group = "9a927d1b_30f5_48da_91eb_af1492bf31c0";
	credential.token = "must-not-enter-sql";
	REQUIRE(ManagedCatalogSecretScope(credential.endpoint, credential.catalog_id) ==
	        "quack:pod.example.test:9494/catalog/9a927d1b-30f5-48da-91eb-af1492bf31c0");
	for (const auto &alias : {string("shared \"duckie\""), string("x\"; DROP TABLE valuable; --")}) {
		const auto attach_sql = BuildManagedCatalogAttachSql(credential, alias);
		auto parser = Parser::GetBuiltinParser();
		parser.ParseQuery(attach_sql);
		REQUIRE(parser.statements.size() == 1);
		auto &attach = *parser.statements[0]->Cast<AttachStatement>().info;
		REQUIRE(attach.name == alias);
		REQUIRE(attach.parsed_path);
		REQUIRE(attach.parsed_path->Cast<ConstantExpression>().GetLiteral().ToValue().GetValue<string>() ==
		        "quack:" + credential.endpoint);
		auto option = [&](const char *name) {
			return attach.options.at(name);
		};
		REQUIRE(option("secret").GetValue<string>() ==
		        "__quack__" + ManagedCatalogSecretScope(credential.endpoint, credential.catalog_id));
		REQUIRE(option("catalog_id").GetValue<string>() == credential.catalog_id);
		REQUIRE(option("tenant_id").GetValue<string>() == "42");
		REQUIRE(option("catalog_group").GetValue<string>() == credential.catalog_group);
		REQUIRE_FALSE(option("disable_ssl").GetValue<bool>());
		REQUIRE(option("http_version").GetValue<string>() == "1.1");
		REQUIRE(attach_sql.find(credential.token) == string::npos);
		REQUIRE(attach_sql.find("PRIVATE KEY") == string::npos);
	}
	REQUIRE_THROWS_AS(BuildManagedCatalogAttachSql(credential, ""), InvalidInputException);
}

TEST_CASE("Managed catalog credential vending stays inside the OPAQUE secrets boundary",
          "[quack][credentials][opaque]") {
	const string catalog_id = "9a927d1b-30f5-48da-91eb-af1492bf31c0";
	REQUIRE(ManagedCatalogCredentialUrl("https://host/secrets", catalog_id) ==
	        "https://host/secrets/quack/credentials?catalog_id=" + catalog_id);
	REQUIRE(ManagedCatalogCredentialUrl("https://host:8443/v1/secrets", catalog_id) ==
	        "https://host:8443/v1/secrets/quack/credentials?catalog_id=" + catalog_id);
	REQUIRE_THROWS_AS(ManagedCatalogCredentialUrl("https://host/auth", catalog_id), InvalidInputException);
	REQUIRE_THROWS_AS(ManagedCatalogCredentialUrl("https://host/secrets/trailing", catalog_id), InvalidInputException);
	REQUIRE_THROWS_AS(ManagedCatalogCredentialUrl("https://host/secrets", "not-a-uuid"), InvalidInputException);
	REQUIRE_THROWS_AS(ManagedCatalogCredentialUrl("https://host/secrets", "9A927D1B-30F5-48DA-91EB-AF1492BF31C0"),
	                  InvalidInputException);
}

TEST_CASE("Managed catalog credentials are isolated per authenticated connection",
          "[quack][credentials][multitenant]") {
	const string scope = "quack:pod.example.test:9494/catalog/9a927d1b-30f5-48da-91eb-af1492bf31c0";
	ManagedCatalogCredentialEnvelope owner;
	owner.token = "owner-token";
	ManagedCatalogCredentialEnvelope member = owner;
	member.token = "member-token";

	BoilstreamConnectionState owner_state;
	BoilstreamConnectionState member_state;
	owner_state.StoreManagedCatalogCredential(scope, owner);
	member_state.StoreManagedCatalogCredential(scope, member);

	ManagedCatalogCredentialEnvelope loaded;
	REQUIRE(owner_state.TryGetManagedCatalogCredential(scope, loaded));
	REQUIRE(loaded.token == "owner-token");
	REQUIRE(member_state.TryGetManagedCatalogCredential(scope, loaded));
	REQUIRE(loaded.token == "member-token");

	owner.token = "rotated-owner-token";
	owner_state.StoreManagedCatalogCredential(scope, owner);
	REQUIRE(member_state.TryGetManagedCatalogCredential(scope, loaded));
	REQUIRE(loaded.token == "member-token");

	owner_state.ClearSession();
	REQUIRE_FALSE(owner_state.TryGetManagedCatalogCredential(scope, loaded));
	REQUIRE(member_state.TryGetManagedCatalogCredential(scope, loaded));
	REQUIRE(loaded.token == "member-token");
}

TEST_CASE("Catalog-qualified managed credential wins over a broader user secret",
          "[quack][credentials][scope][multitenant]") {
	QuackAttachFixture fixture;
	auto &storage = *fixture.storage;
	Connection connection(*fixture.db);
	auto session = BoilstreamSessionPublicationTestAccess::Publish(storage, *connection.context);
	connection.BeginTransaction();

	const string endpoint_scope = "quack:non-routable.invalid:1";
	const string catalog_id = "9a927d1b-30f5-48da-91eb-af1492bf31c0";
	const string catalog_scope = ManagedCatalogSecretScope("non-routable.invalid:1", catalog_id);
	vector<string> broad_scope {endpoint_scope};
	auto broad = make_uniq<KeyValueSecret>(broad_scope, "quack", "config", "broad-user-secret");
	broad->secret_map["token"] = Value("broad-user-token");
	BoilstreamSessionPublicationTestAccess::Cache(storage, *session, std::move(broad));

	ManagedCatalogCredentialEnvelope managed;
	managed.token = "managed-catalog-token";
	managed.expires_at = "2030-01-01T00:05:00Z";
	managed.endpoint = "non-routable.invalid:1";
	managed.catalog_id = catalog_id;
	managed.storage_owner_tenant_id = 42;
	managed.catalog_group = "9a927d1b_30f5_48da_91eb_af1492bf31c0";
	managed.server_ca_pem = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n";
	session->StoreManagedCatalogCredential(catalog_scope, managed);
	{
		lock_guard<mutex> lock(session->expiration_lock);
		session->secret_expiration["__quack__" + catalog_scope] =
		    std::chrono::system_clock::now() + std::chrono::minutes(5);
	}

	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*connection.context);
	auto match = storage.LookupSecret(catalog_scope, "quack", &transaction);
	REQUIRE(match.HasMatch());
	REQUIRE(match.GetSecret().GetName() == "__quack__" + catalog_scope);
	auto &kv = dynamic_cast<const KeyValueSecret &>(match.GetSecret());
	REQUIRE(kv.secret_map.at("token").ToString() == "managed-catalog-token");
	REQUIRE(kv.secret_map.at("catalog_id").ToString() == catalog_id);
	REQUIRE(kv.secret_map.at("server_ca_pem").ToString().find("BEGIN CERTIFICATE") != string::npos);
	REQUIRE(kv.secret_map.find("client_certificate_pem") == kv.secret_map.end());
	REQUIRE(kv.secret_map.find("client_private_key_pem") == kv.secret_map.end());
	auto named = storage.GetSecretByName("__quack__" + catalog_scope, &transaction);
	REQUIRE(named);
	REQUIRE(dynamic_cast<const KeyValueSecret &>(*named->secret).secret_map.at("token").ToString() ==
	        "managed-catalog-token");
	// A second connection with the same catalog/secret name retains its own
	// capability. A connection without login cannot borrow either one.
	Connection member(*fixture.db), anonymous(*fixture.db);
	auto member_session = BoilstreamSessionPublicationTestAccess::Publish(storage, *member.context);
	managed.token = "member-catalog-token";
	member_session->StoreManagedCatalogCredential(catalog_scope, managed);
	{
		lock_guard<mutex> lock(member_session->expiration_lock);
		member_session->secret_expiration["__quack__" + catalog_scope] =
		    std::chrono::system_clock::now() + std::chrono::minutes(5);
	}
	member.BeginTransaction();
	anonymous.BeginTransaction();
	auto member_transaction = CatalogTransaction::GetSystemCatalogTransaction(*member.context);
	auto anonymous_transaction = CatalogTransaction::GetSystemCatalogTransaction(*anonymous.context);
	auto member_named = storage.GetSecretByName("__quack__" + catalog_scope, &member_transaction);
	REQUIRE(member_named);
	REQUIRE(dynamic_cast<const KeyValueSecret &>(*member_named->secret).secret_map.at("token").ToString() ==
	        "member-catalog-token");
	REQUIRE_FALSE(storage.GetSecretByName("__quack__" + catalog_scope, &anonymous_transaction));
	REQUIRE_FALSE(storage.GetSecretByName("__quack__quack:non-routable.invalid:1/catalog/not-a-uuid", &transaction));
	REQUIRE_FALSE(storage.GetSecretByName("__quack__quack:non-routable.invalid:1", &transaction));
	REQUIRE_FALSE(storage.GetSecretByName("__quack__" + catalog_scope, nullptr));
	member.Commit();
	anonymous.Commit();
	connection.Commit();
}

TEST_CASE("Catalog-qualified managed lookup never falls back to a broader user secret",
          "[quack][credentials][scope][fail-closed]") {
	QuackAttachFixture fixture;
	auto &storage = *fixture.storage;
	Connection connection(*fixture.db);
	connection.BeginTransaction();
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*connection.context);
	const string endpoint_scope = "quack:non-routable.invalid:1";
	const string catalog_scope =
	    ManagedCatalogSecretScope("non-routable.invalid:1", "9a927d1b-30f5-48da-91eb-af1492bf31c0");
	vector<string> broad_scope {endpoint_scope};
	auto broad = make_uniq<KeyValueSecret>(broad_scope, "quack", "config", "broad-user-secret");
	broad->secret_map["token"] = Value("must-not-be-selected");
	storage.StoreSecret(std::move(broad), OnCreateConflict::REPLACE_ON_CONFLICT, &transaction);

	// No authenticated session means managed vending cannot run. The exact
	// catalog scope must return no match instead of broadening to the endpoint
	// secret. Plain endpoint lookup remains the explicit manual interface.
	REQUIRE_FALSE(storage.LookupSecret(catalog_scope, "quack", &transaction).HasMatch());
	auto manual = storage.LookupSecret(endpoint_scope, "quack", &transaction);
	REQUIRE(manual.HasMatch());
	REQUIRE(manual.GetSecret().GetName() == "broad-user-secret");

	REQUIRE_FALSE(storage.LookupSecret(endpoint_scope + "/catalog/not-a-uuid", "quack", &transaction).HasMatch());
	connection.Commit();
}

//===----------------------------------------------------------------------===//
// Manual secrets remain usable without login, but only by their connection.
//===----------------------------------------------------------------------===//
TEST_CASE("LookupSecret returns user-supplied quack secret without bootstrap_session", "[quack][red][phase4]") {
	QuackAttachFixture f;
	auto &s = *f.storage;
	Connection connection(*f.db), fresh(*f.db);
	connection.BeginTransaction();
	fresh.BeginTransaction();
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*connection.context);
	auto fresh_transaction = CatalogTransaction::GetSystemCatalogTransaction(*fresh.context);

	// Build a KeyValueSecret of TYPE quack with scope matching the ATTACH path
	// the user would type. This mirrors what `CREATE SECRET ... (TYPE quack,
	// TOKEN '<jwt>', SCOPE 'quack:127.0.0.1:9494')` produces.
	const string user_path = "quack:127.0.0.1:9494";
	const string user_token = "user-supplied-token";
	vector<string> scope {user_path};
	auto secret = make_uniq<KeyValueSecret>(scope, "quack", "config", "__quack__user");
	secret->secret_map["token"] = Value(user_token);

	// The real StoreSecret API requires a connection even before login.
	REQUIRE_THROWS_WITH(s.StoreSecret(secret->Clone(), OnCreateConflict::REPLACE_ON_CONFLICT, nullptr),
	                    Catch::Matchers::Contains("A live connection is required"));
	s.StoreSecret(std::move(secret), OnCreateConflict::REPLACE_ON_CONFLICT, &transaction);
	auto match = s.LookupSecret(user_path, "quack", &transaction);
	REQUIRE(match.HasMatch());

	auto &returned = match.GetSecret();
	REQUIRE(returned.GetName() == "__quack__user");
	REQUIRE(returned.GetType() == "quack");
	REQUIRE(s.GetSecretByName("__quack__user", &transaction));
	REQUIRE_FALSE(s.GetSecretByName("__quack__user", &fresh_transaction));

	// The token field must round-trip — that's the entire contract: the
	// user supplied a token, ATTACH consumes it.
	auto &kv = dynamic_cast<const KeyValueSecret &>(returned);
	auto it = kv.secret_map.find("token");
	REQUIRE(it != kv.secret_map.end());
	REQUIRE(it->second.ToString() == user_token);
	REQUIRE_FALSE(s.LookupSecret(user_path, "quack", nullptr).HasMatch());
	REQUIRE_FALSE(s.LookupSecret(user_path, "quack", &fresh_transaction).HasMatch());
	// Foreign lookups must not consume or invalidate the owner's secret.
	REQUIRE(s.LookupSecret(user_path, "quack", &transaction).HasMatch());
	fresh.Commit();
	connection.Commit();
}

//===----------------------------------------------------------------------===//
// Companion: even WITH a conn_state present (bootstrap_session called),
// if a user-created TYPE quack secret already exists in the catalog with a
// matching scope, LookupSecret MUST prefer that over re-fetching from the
// boilstream server. Otherwise CREATE SECRET (TYPE quack) is pointless —
// the user's token is silently replaced on every ATTACH.
//===----------------------------------------------------------------------===//
TEST_CASE("LookupSecret prefers user-supplied quack secret over auto-vend", "[quack][red][phase4]") {
	QuackAttachFixture f;
	auto &s = *f.storage;

	// Seed actual connection publication; this is not an authentication test.
	Connection con(*f.db);
	auto session = BoilstreamSessionPublicationTestAccess::Publish(s, *con.context);

	// Production ATTACH always runs inside an active meta transaction (the
	// secret manager is invoked from query binding, not from raw API calls).
	// CatalogSetSecretStorage::LookupSecret eventually touches
	// `TransactionContext::ActiveTransaction()` so we must open one here.
	con.BeginTransaction();

	// Set up a path with a non-routable endpoint — so if the code DOES
	// take the auto-vend HTTP path, it will fail and we'd see an empty
	// SecretMatch. We want the GREEN path to return the user's secret
	// without touching HTTP at all.
	const string user_path = "quack:non-routable.invalid:1";
	const string user_token = "user-token-must-be-honoured";
	vector<string> scope {user_path};
	auto secret = make_uniq<KeyValueSecret>(scope, "quack", "config", "user-quack");
	secret->secret_map["token"] = Value(user_token);
	BoilstreamSessionPublicationTestAccess::Cache(s, *session, std::move(secret));

	// Use a CatalogTransaction wired to our connection so GetSession resolves.
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
	auto match = s.LookupSecret(user_path, "quack", &transaction);

	REQUIRE(match.HasMatch());
	REQUIRE(match.GetSecret().GetName() == "user-quack");

	auto &kv = dynamic_cast<const KeyValueSecret &>(match.GetSecret());
	auto it = kv.secret_map.find("token");
	REQUIRE(it != kv.secret_map.end());
	REQUIRE(it->second.ToString() == user_token);

	con.Commit();
}
