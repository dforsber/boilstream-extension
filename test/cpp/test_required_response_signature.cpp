// Signature fixtures come from independent Python hashlib/hmac code.
#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "boilstream_secret_storage.hpp"
#include "yyjson.hpp"
#include "duckdb/main/tenant/active_tenant_registry.hpp"
#include "duckdb/main/tenant/tenant_context.hpp"
#include <iostream>
#include <sstream>
using namespace duckdb;
using namespace duckdb_yyjson;
static void Require(bool ok) {
	if (!ok)
		throw std::runtime_error("assertion");
}
class BoilstreamSessionPublicationTestAccess {
public:
	static void Publish(RestApiSecretStorage &s, ClientContext &ctx,
	                    const shared_ptr<BoilstreamConnectionState> &state) {
		auto old = s.GetSessionForConnection(ctx.GetConnectionId());
		s.PublishSession(ctx, state, old, old ? old->authentication_generation.load() : 0, true);
	}
	static void Verify(RestApiSecretStorage &s, const string &body, uint16_t status,
	                   const case_insensitive_map_t<string> &headers, const vector<uint8_t> &key) {
		s.VerifyResponseSignature(body, status, headers, key);
	}
	static vector<uint8_t> RequestKey(RestApiSecretStorage &s, BoilstreamConnectionState &state) {
		vector<uint8_t> key;
		s.BuildAuthenticatedHeaders("GET", "https://synthetic.invalid/secrets", "", state, &key);
		return key;
	}
	static void Delete(RestApiSecretStorage &s, const string &url, BoilstreamConnectionState &state) {
		s.HttpDelete(url, state);
	}
};
struct Config : DBConfig {
	Config() {
		options.load_extensions = false;
		options.maximum_threads = 2;
	}
};
static void Seed(BoilstreamConnectionState &s, bool finish = false) {
	s.session_key.assign(64, 7);
	s.access_token = string(64, 'a');
	s.region = "synthetic-region";
	s.refresh_token.assign(32, 8);
	s.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
	s.is_exchanging = finish;
}
int main(int argc, char **argv) {
	if (argc != 2)
		return 2;
	Config cfg;
	DuckDB db(nullptr, &cfg);
	Connection c(db);
	SecretManager::Get(*db.instance).SetEnablePersistentSecrets(false);
	Require(ExtensionHelper::LoadExtension(db, "httpfs") == ExtensionLoadResult::LOADED_EXTENSION);
	Require(!c.Query("SET httpfs_client_implementation='curl'")->HasError());
	auto owned_storage = make_uniq<RestApiSecretStorage>(*db.instance, "");
	auto &storage = *owned_storage;
	SecretManager::Get(*db.instance).LoadSecretStorage(std::move(owned_storage));
	int failures = 0;
	auto test = [&](const string &name, auto fn) {
		try {
			fn();
			std::cout << "CASE " << name << " PASS" << std::endl;
		} catch (...) {
			++failures;
			std::cout << "CASE " << name << " FAIL" << std::endl;
		}
	};
	const string input((std::istreambuf_iterator<char>(std::cin)), {});
	auto doc = std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)>(yyjson_read(input.data(), input.size(), 0),
	                                                                   yyjson_doc_free);
	Require(bool(doc));
	auto root = yyjson_doc_get_root(doc.get());
	Require(yyjson_is_arr(root));
	size_t i, n;
	yyjson_val *entry;
	yyjson_arr_foreach(root, i, n, entry) {
		auto str = [&](const char *key) {
			auto v = yyjson_obj_get(entry, key);
			Require(yyjson_is_str(v));
			return string(yyjson_get_str(v), yyjson_get_len(v));
		};
		test(str("name"), [&] {
			case_insensitive_map_t<string> headers;
			auto object = yyjson_obj_get(entry, "headers");
			size_t j, count;
			yyjson_val *k, *v;
			yyjson_obj_foreach(object, j, count, k, v) {
				headers[string(yyjson_get_str(k), yyjson_get_len(k))] = string(yyjson_get_str(v), yyjson_get_len(v));
			}
			bool rejected = false;
			auto key = vector<uint8_t>(64, yyjson_get_bool(yyjson_obj_get(entry, "wrong_key")) ? 9 : 7);
			try {
				BoilstreamSessionPublicationTestAccess::Verify(
				    storage, str("body"), yyjson_get_uint(yyjson_obj_get(entry, "status")), headers, key);
			} catch (const IOException &) {
				rejected = true;
			}
			Require(rejected == yyjson_get_bool(yyjson_obj_get(entry, "reject")));
		});
	}
	for (const auto &method : vector<string> {"GET", "POST", "DELETE", "FINALIZE"})
		for (const auto &mode :
		     vector<string> {"valid", "missing", "malformed", "wrong-key", "tampered", "stale", "bad-date"}) {
			test("http_" + method + "_" + mode, [&] {
				BoilstreamConnectionState state;
				Seed(state, method == "FINALIZE");
				BoilstreamConnectionState other;
				Seed(other);
				other.session_key.assign(64, 9);
				const auto generation = state.authentication_generation.load();
				bool rejected = false;
				string body;
				const auto url = string(argv[1]) + "/" + method + "/" + mode;
				try {
					if (method == "GET")
						body = storage.HttpGetWithState(url, state);
					else if (method == "DELETE")
						BoilstreamSessionPublicationTestAccess::Delete(storage, url, state);
					else
						body = storage.HttpPostWithState(url, "{}", state);
				} catch (const IOException &) {
					rejected = true;
				}
				Require(rejected == (mode != "valid"));
				if (mode == "valid") {
					Require(!state.session_key.empty());
					if (method != "DELETE")
						Require(body == "synthetic-result");
				} else {
					Require(state.session_key.empty() && state.access_token.empty() && state.refresh_token.empty());
					Require(state.authentication_generation.load() > generation);
					Require(state.secret_cache->IsClosed());
				}
				Require(other.session_key == vector<uint8_t>(64, 9) && !other.access_token.empty() &&
				        other.authentication_generation.load() == 0);
			});
		}
	test("forged_reply_retires_only_its_published_tenant", [&] {
		Connection a(db), b(db);
		TenantContext tenant_a, tenant_b;
		tenant_a.SetTenantId("42");
		tenant_b.SetTenantId("43");
		auto state_a = make_shared_ptr<BoilstreamConnectionState>();
		Seed(*state_a);
		auto state_b = make_shared_ptr<BoilstreamConnectionState>();
		Seed(*state_b);
		state_b->session_key.assign(64, 9);
		{
			ActiveTenantRegistry::Guard guard(*db.instance, &tenant_a);
			BoilstreamSessionPublicationTestAccess::Publish(storage, *a.context, state_a);
		}
		{
			ActiveTenantRegistry::Guard guard(*db.instance, &tenant_b);
			BoilstreamSessionPublicationTestAccess::Publish(storage, *b.context, state_b);
		}
		Require(state_a->authenticated_tenant == "42" && state_b->authenticated_tenant == "43");
		bool rejected = false;
		{
			ActiveTenantRegistry::Guard guard(*db.instance, &tenant_a);
			try {
				storage.HttpGetWithState(string(argv[1]) + "/GET/wrong-key", *state_a);
			} catch (const IOException &) {
				rejected = true;
			}
		}
		Require(rejected && state_a->session_key.empty() && state_a->secret_cache->IsClosed());
		Require(storage.GetSessionForConnection(b.context->GetConnectionId()) == state_b);
		Require(!state_b->secret_cache->IsClosed() && state_b->refresh_token == vector<uint8_t>(32, 8));
		{
			ActiveTenantRegistry::Guard guard(*db.instance, &tenant_b);
			Require(storage.HttpGetWithState(string(argv[1]) + "/GET/wrong-key", *state_b) == "synthetic-result");
		}
	});
	test("retired_request_failure_preserves_replacement_session", [&] {
		Connection a(db);
		auto old = make_shared_ptr<BoilstreamConnectionState>();
		Seed(*old);
		BoilstreamSessionPublicationTestAccess::Publish(storage, *a.context, old);
		auto replacement = make_shared_ptr<BoilstreamConnectionState>();
		Seed(*replacement);
		replacement->session_key.assign(64, 9);
		BoilstreamSessionPublicationTestAccess::Publish(storage, *a.context, replacement);
		// Keep the real old owner alive, as an in-flight request does across replacement.
		bool rejected = false;
		try {
			storage.HttpGetWithState(string(argv[1]) + "/GET/missing", *old);
		} catch (const IOException &) {
			rejected = true;
		}
		Require(rejected && old->session_key.empty());
		Require(storage.GetSessionForConnection(a.context->GetConnectionId()) == replacement);
		Require(replacement->session_key == vector<uint8_t>(64, 9) && !replacement->secret_cache->IsClosed());
		Require(storage.HttpGetWithState(string(argv[1]) + "/GET/wrong-key", *replacement) == "synthetic-result");
	});
	test("request_verification_key_survives_logout", [&] {
		BoilstreamConnectionState state;
		Seed(state);
		auto key = BoilstreamSessionPublicationTestAccess::RequestKey(storage, state);
		Require(key == vector<uint8_t>(64, 7));
		state.ClearSession();
		Require(state.session_key.empty());
		Require(key == vector<uint8_t>(64, 7));
	});
	test("get_without_session_does_not_send_request", [&] {
		BoilstreamConnectionState empty;
		bool rejected = false;
		try {
			storage.HttpGetWithState(string(argv[1]) + "/GET/valid", empty);
		} catch (const IOException &) {
			rejected = true;
		}
		Require(rejected);
	});
	test("pre_key_login_start_accepts_unsigned_reply", [&] {
		BoilstreamConnectionState pending;
		pending.is_exchanging = true;
		Require(storage.HttpPostWithState(string(argv[1]) + "/START/missing", "{}", pending) == "synthetic-result");
	});
	return failures ? 1 : 0;
}
