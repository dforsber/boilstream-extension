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
// This test stays in the unit lane:
//   - No live boilstream server.
//   - No bootstrap_session called.
//   - We instantiate RestApiSecretStorage directly and inject a
//     KeyValueSecret of TYPE quack, then assert LookupSecret returns it.
//
// Originally written as a RED TDD reproducer for the Phase 4 e2e blocker
// (ingestion-agent-cxum / ingestion-agent-8hnt); turned green by the
// StoreSecret-no-conn_state fix and the named auto-vend helper.
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
#include "duckdb/main/connection.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"

using namespace duckdb;

class BoilstreamInputValidationTestAccess {
public:
	static std::chrono::system_clock::time_point ParseExpiresAt(RestApiSecretStorage &storage,
	                                                            const std::string &expires_at_str) {
		return storage.ParseExpiresAt(expires_at_str);
	}

	static bool IsManagedCatalogCredentialExpiredAt(RestApiSecretStorage &storage,
	                                                const std::string &expires_at_str,
	                                                std::chrono::system_clock::time_point now) {
		return storage.IsManagedCatalogCredentialExpiredAt(expires_at_str, now);
	}
};

struct QuackAttachFixture {
	duckdb::unique_ptr<DuckDB> db;
	duckdb::unique_ptr<RestApiSecretStorage> storage;

	QuackAttachFixture() {
		db = duckdb::make_uniq<DuckDB>(nullptr);
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
	REQUIRE(BoilstreamInputValidationTestAccess::IsManagedCatalogCredentialExpiredAt(
	    *storage, "not-rfc3339", zulu - std::chrono::seconds(15)));

	const vector<string> invalid_expirations {
	    "",                                  "2030-06-15T14:30:00",         "2030-06-15 14:30:00Z",
	    "2030-02-30T14:30:00Z",             "2030-06-15T14:30:00+00:00trailing",
	    "2030-06-15T14:30:00 UTC",          "2030-06-15T14:30:00+00",      "2030-06-15T14:30:00+0000",
	    "2030-06-15T14:30:00+00:00:00",     "2030-06-15T14:30:00+24:00",  "2030-06-15T14:30:00+00:60",
	    "2030-06-15T14:30:00.Z",            "2030-06-15T14:30:00z",
	};
	for (const auto &invalid : invalid_expirations) {
		REQUIRE(BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, invalid) == expired);
	}
}

TEST_CASE("Managed catalog credential envelope requires the complete mTLS bundle", "[quack][credentials][mtls]") {
	const string valid = R"json({
        "token":"signed-capability",
        "expires_at":"2030-01-01T00:05:00Z",
        "endpoint":"pod.example.test:9494",
		"catalog_id":"9a927d1b-30f5-48da-91eb-af1492bf31c0",
		"storage_owner_tenant_id":42,
		"catalog_group":"9a927d1b_30f5_48da_91eb_af1492bf31c0",
        "transport_identity":{
          "client_certificate_pem":"-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----\n",
          "client_private_key_pem":"-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
          "server_ca_pem":"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"
        }
      })json";
	ManagedCatalogCredentialEnvelope parsed;
	REQUIRE(ParseManagedCatalogCredentialEnvelope(valid, parsed));
	REQUIRE(parsed.token == "signed-capability");
	REQUIRE(parsed.endpoint == "pod.example.test:9494");
	REQUIRE(parsed.catalog_id == "9a927d1b-30f5-48da-91eb-af1492bf31c0");
	REQUIRE(parsed.storage_owner_tenant_id == 42);
	REQUIRE(parsed.client_private_key_pem.find("BEGIN PRIVATE KEY") != string::npos);

	for (
	    const auto &partial :
	    {string(R"json({"token":"t","expires_at":"2030-01-01T00:05:00Z","endpoint":"e"})json"),
	     string(
	         R"json({"token":"t","expires_at":"2030-01-01T00:05:00Z","endpoint":"e","transport_identity":{"client_certificate_pem":"-----BEGIN CERTIFICATE-----","client_private_key_pem":"-----BEGIN PRIVATE KEY-----"}})json"),
	     string(
	         R"json({"token":"t","expires_at":"2030-01-01T00:05:00Z","endpoint":"e","transport_identity":{"client_certificate_pem":"not-pem","client_private_key_pem":"-----BEGIN PRIVATE KEY-----","server_ca_pem":"-----BEGIN CERTIFICATE-----"}})json")}) {
		parsed.token = "must-be-cleared";
		REQUIRE_FALSE(ParseManagedCatalogCredentialEnvelope(partial, parsed));
		REQUIRE(parsed.token.empty());
		REQUIRE(parsed.client_private_key_pem.empty());
	}

	auto replace_once = [](string input, const string &from, const string &to) {
		auto position = input.find(from);
		REQUIRE(position != string::npos);
		input.replace(position, from.size(), to);
		return input;
	};
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
	credential.client_private_key_pem = "must-not-enter-sql-private-key";
	REQUIRE(ManagedCatalogSecretScope(credential.endpoint, credential.catalog_id) ==
	        "quack:pod.example.test:9494/catalog/9a927d1b-30f5-48da-91eb-af1492bf31c0");
	const auto attach_sql = BuildManagedCatalogAttachSql(credential, "shared \"duckie\"");
	REQUIRE(attach_sql == "ATTACH 'quack:pod.example.test:9494' AS \"shared \"\"duckie\"\"\" (TYPE quack, "
	                      "CATALOG_ID '9a927d1b-30f5-48da-91eb-af1492bf31c0', TENANT_ID '42', "
	                      "CATALOG_GROUP '9a927d1b_30f5_48da_91eb_af1492bf31c0', DISABLE_SSL false)");
	REQUIRE(attach_sql.find(credential.token) == string::npos);
	REQUIRE(attach_sql.find(credential.client_private_key_pem) == string::npos);
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
	REQUIRE_THROWS_AS(ManagedCatalogCredentialUrl("https://host/secrets/trailing", catalog_id),
	                  InvalidInputException);
	REQUIRE_THROWS_AS(ManagedCatalogCredentialUrl("https://host/secrets", "not-a-uuid"),
	                  InvalidInputException);
	REQUIRE_THROWS_AS(ManagedCatalogCredentialUrl("https://host/secrets", "9A927D1B-30F5-48DA-91EB-AF1492BF31C0"),
	                  InvalidInputException);
}

TEST_CASE("Managed catalog credentials are isolated per authenticated connection",
          "[quack][credentials][multitenant]") {
	const string scope = "quack:pod.example.test:9494/catalog/9a927d1b-30f5-48da-91eb-af1492bf31c0";
	ManagedCatalogCredentialEnvelope owner;
	owner.token = "owner-token";
	owner.client_private_key_pem = "owner-key";
	ManagedCatalogCredentialEnvelope member = owner;
	member.token = "member-token";
	member.client_private_key_pem = "member-key";

	BoilstreamConnectionState owner_state;
	BoilstreamConnectionState member_state;
	owner_state.StoreManagedCatalogCredential(scope, owner);
	member_state.StoreManagedCatalogCredential(scope, member);

	ManagedCatalogCredentialEnvelope loaded;
	REQUIRE(owner_state.TryGetManagedCatalogCredential(scope, loaded));
	REQUIRE(loaded.token == "owner-token");
	REQUIRE(loaded.client_private_key_pem == "owner-key");
	REQUIRE(member_state.TryGetManagedCatalogCredential(scope, loaded));
	REQUIRE(loaded.token == "member-token");
	REQUIRE(loaded.client_private_key_pem == "member-key");

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
	auto &session = storage.GetOrCreateSession("managed-session");
	Connection connection(*fixture.db);
	storage.SetActiveSessionKeyForConnection(connection.context->GetConnectionId(), "managed-session");
	connection.BeginTransaction();

	const string endpoint_scope = "quack:non-routable.invalid:1";
	const string catalog_id = "9a927d1b-30f5-48da-91eb-af1492bf31c0";
	const string catalog_scope = ManagedCatalogSecretScope("non-routable.invalid:1", catalog_id);
	vector<string> broad_scope {endpoint_scope};
	auto broad = make_uniq<KeyValueSecret>(broad_scope, "quack", "config", "broad-user-secret");
	broad->secret_map["token"] = Value("broad-user-token");
	storage.StoreSecret(std::move(broad), OnCreateConflict::REPLACE_ON_CONFLICT, nullptr);

	ManagedCatalogCredentialEnvelope managed;
	managed.token = "managed-catalog-token";
	managed.expires_at = "2030-01-01T00:05:00Z";
	managed.endpoint = "non-routable.invalid:1";
	managed.catalog_id = catalog_id;
	managed.storage_owner_tenant_id = 42;
	managed.catalog_group = "9a927d1b_30f5_48da_91eb_af1492bf31c0";
	managed.client_certificate_pem = "-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----\n";
	managed.client_private_key_pem = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n";
	managed.server_ca_pem = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n";
	session.StoreManagedCatalogCredential(catalog_scope, managed);
	{
		lock_guard<mutex> lock(session.expiration_lock);
		session.secret_expiration["__quack__" + catalog_scope] =
		    std::chrono::system_clock::now() + std::chrono::minutes(5);
	}

	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*connection.context);
	auto match = storage.LookupSecret(catalog_scope, "quack", &transaction);
	REQUIRE(match.HasMatch());
	REQUIRE(match.GetSecret().GetName() == "__quack__" + catalog_scope);
	auto &kv = dynamic_cast<const KeyValueSecret &>(match.GetSecret());
	REQUIRE(kv.secret_map.at("token").ToString() == "managed-catalog-token");
	REQUIRE(kv.secret_map.at("catalog_id").ToString() == catalog_id);
}

TEST_CASE("Catalog-qualified managed lookup never falls back to a broader user secret",
          "[quack][credentials][scope][fail-closed]") {
	QuackAttachFixture fixture;
	auto &storage = *fixture.storage;
	const string endpoint_scope = "quack:non-routable.invalid:1";
	const string catalog_scope =
	    ManagedCatalogSecretScope("non-routable.invalid:1", "9a927d1b-30f5-48da-91eb-af1492bf31c0");
	vector<string> broad_scope {endpoint_scope};
	auto broad = make_uniq<KeyValueSecret>(broad_scope, "quack", "config", "broad-user-secret");
	broad->secret_map["token"] = Value("must-not-be-selected");
	storage.StoreSecret(std::move(broad), OnCreateConflict::REPLACE_ON_CONFLICT, nullptr);

	// No authenticated session means managed vending cannot run. The exact
	// catalog scope must return no match instead of broadening to the endpoint
	// secret. Plain endpoint lookup remains the explicit manual interface.
	REQUIRE_FALSE(storage.LookupSecret(catalog_scope, "quack", nullptr).HasMatch());
	auto manual = storage.LookupSecret(endpoint_scope, "quack", nullptr);
	REQUIRE(manual.HasMatch());
	REQUIRE(manual.GetSecret().GetName() == "broad-user-secret");

	REQUIRE_FALSE(storage.LookupSecret(endpoint_scope + "/catalog/not-a-uuid", "quack", nullptr).HasMatch());
}

//===----------------------------------------------------------------------===//
// RED: a user-created TYPE quack secret MUST be returned by LookupSecret
// when there is no active boilstream session. The auto-vend path requires
// a live conn_state; absent one, LookupQuackSecret must fall through to the
// local CatalogSet path and return the user's secret unchanged.
//===----------------------------------------------------------------------===//
// Green as of the StoreSecret-no-conn_state fix + named auto-vend helper
// (closes ingestion-agent-8hnt). The `[red]` tag stays for cross-reference
// with the Phase 4 incident reports; the test now asserts the expected
// behaviour rather than reproducing the bug.
TEST_CASE("LookupSecret returns user-supplied quack secret without bootstrap_session", "[quack][red][phase4]") {
	QuackAttachFixture f;
	auto &s = *f.storage;

	// Build a KeyValueSecret of TYPE quack with scope matching the ATTACH path
	// the user would type. This mirrors what `CREATE SECRET ... (TYPE quack,
	// TOKEN '<jwt>', SCOPE 'quack:127.0.0.1:9494')` produces.
	const string user_path = "quack:127.0.0.1:9494";
	const string user_token = "user-supplied-token";
	vector<string> scope {user_path};
	auto secret = make_uniq<KeyValueSecret>(scope, "quack", "config", "smk");
	secret->secret_map["token"] = Value(user_token);

	// Install through the public StoreSecret API — same path `CREATE SECRET`
	// hits via the secret manager. With no conn_state, StoreSecret stores
	// locally only (no REST persist), matching DuckDB's TEMPORARY semantics.
	s.StoreSecret(std::move(secret), OnCreateConflict::REPLACE_ON_CONFLICT, nullptr /* no transaction */);

	// ─── LookupSecret with no conn_state, type=quack ──────────────────
	auto match = s.LookupSecret(user_path, "quack", nullptr);

	// RED: this currently fails because LookupQuackSecret at line ~3797
	// returns SecretMatch() empty when conn_state is null, then the
	// fallthrough generic /match HTTP call at line ~3157 throws (no
	// connection state) — so we never re-consult the local catalog where
	// the user secret lives.
	REQUIRE(match.HasMatch());

	auto &returned = match.GetSecret();
	REQUIRE(returned.GetName() == "smk");
	REQUIRE(returned.GetType() == "quack");

	// The token field must round-trip — that's the entire contract: the
	// user supplied a token, ATTACH consumes it.
	auto &kv = dynamic_cast<const KeyValueSecret &>(returned);
	auto it = kv.secret_map.find("token");
	REQUIRE(it != kv.secret_map.end());
	REQUIRE(it->second.ToString() == user_token);
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

	// Establish a conn_state so the LookupQuackSecret branch runs in full.
	auto &session = s.GetOrCreateSession("test-session");
	Connection con(*f.db);
	s.SetActiveSessionKeyForConnection(con.context->GetConnectionId(), "test-session");

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
	s.StoreSecret(std::move(secret), OnCreateConflict::REPLACE_ON_CONFLICT, nullptr);

	// Use a CatalogTransaction wired to our connection so GetSession resolves.
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
	auto match = s.LookupSecret(user_path, "quack", &transaction);

	REQUIRE(match.HasMatch());
	REQUIRE(match.GetSecret().GetName() == "user-quack");

	auto &kv = dynamic_cast<const KeyValueSecret &>(match.GetSecret());
	auto it = kv.secret_map.find("token");
	REQUIRE(it != kv.secret_map.end());
	REQUIRE(it->second.ToString() == user_token);

	// Silence unused warning under -DNDEBUG.
	(void)session;
}
