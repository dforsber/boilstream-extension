#include "client_test_context.hpp"
// Synthetic marker checks; never print captured native diagnostics or exceptions.
#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "boilstream_secret_storage.hpp"
#include "boilstream_diagnostics.hpp"
#include "boilstream_extension.hpp"
#include "opaque_wrapper.hpp"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <atomic>
#include <thread>
using namespace duckdb;
#ifdef BOILSTREAM_TRACK_STATE_FREE
static std::atomic<int> login_frees {0}, registration_frees {0};
extern "C" void __real_opaque_free_login_state(LoginState *);
extern "C" void __real_opaque_free_registration_state(RegistrationState *);
extern "C" void __wrap_opaque_free_login_state(LoginState *p) {
	++login_frees;
	__real_opaque_free_login_state(p);
}
extern "C" void __wrap_opaque_free_registration_state(RegistrationState *p) {
	++registration_frees;
	__real_opaque_free_registration_state(p);
}
#endif

static const string MARKER = "private_diagnostic_marker_A7";
static const string TOKEN_PREFIX = "deadbeef1234abcd";
static void Require(bool ok) {
	if (!ok)
		throw std::runtime_error("assertion");
}
struct Captured {
	string logs;
	string error;
	bool failed = false;
};
template <class F>
static Captured Capture(F fn) {
	std::ostringstream sink;
	auto old = std::cerr.rdbuf(sink.rdbuf());
	Captured result;
	try {
		fn();
	} catch (const std::exception &e) {
		result.failed = true;
		result.error = e.what();
	} catch (...) {
		result.failed = true;
		result.error = "unknown exception";
	}
	std::cerr.rdbuf(old);
	result.logs = sink.str();
	return result;
}
static void Private(const Captured &result) {
	for (auto &marker : {MARKER, TOKEN_PREFIX})
		Require(result.logs.find(marker) == string::npos && result.error.find(marker) == string::npos);
}
class BoilstreamSessionPublicationTestAccess {
public:
	static unique_ptr<BaseSecret> Decode(RestApiSecretStorage &s, SecretManager &manager, const string &json) {
		return s.DeserializeSecret(json, manager);
	}
	static string Encode(RestApiSecretStorage &s, const BaseSecret &secret) {
		return s.SerializeSecret(secret);
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
static const string AUTHORITY = "https://diagnostic.invalid";
class DiagnosticHTTP : public HTTPUtil {
public:
	int status = 200;
	bool fail = false;
	size_t requests = 0;
	unique_ptr<HTTPParams> InitializeParameters(DatabaseInstance &, const string &) override {
		return make_uniq<HTTPParams>(*this);
	}
	unique_ptr<HTTPResponse> SendRequest(BaseRequest &request, unique_ptr<HTTPClient> &) override {
		Require(request.url == AUTHORITY + "/auth/api/protocol/v2/handshake");
		++requests;
		if (fail)
			throw IOException(unordered_map<string, string> {{"status_code", "403"}, {"response_body", MARKER}}, "%s",
			                  MARKER);
		auto response = make_uniq<HTTPResponse>(static_cast<HTTPStatusCode>(status));
		response->headers.Insert("Set-Cookie", "session=" + MARKER);
		response->headers.Insert("X-Boilstream-Response-Signature", TOKEN_PREFIX);
		request.Cast<PostRequestInfo>().buffer_out = MARKER;
		return response;
	}
};
static void Channel(BoilstreamConnectionState &state) {
	std::array<uint8_t, 32> key {};
	key[0] = 9;
	state.protocol = make_shared_ptr<BoilstreamProtocol>(AUTHORITY, key);
	state.access_token = TOKEN_PREFIX;
	state.session_key.assign(32, 9);
	state.is_exchanging = true;
}
int main() {
	Config config;
	DuckDB db(nullptr, &config);
	Connection connection(db);
	SecretManager::Get(*db.instance).SetEnablePersistentSecrets(false);
	LoadTestHttpfs(connection);
	auto set = connection.Query("SET httpfs_client_implementation='curl'");
	Require(set && !set->HasError());
	db.LoadStaticExtension<BoilstreamExtension>();
	auto http = make_shared_ptr<DiagnosticHTTP>();
	DBConfig::GetConfig(*db.instance).SetHTTPUtil(http);
	Require(!connection.Query("PRAGMA boilstream_server_key('" + AUTHORITY + "', '09" + string(62, '0') + "')")
	             ->HasError());
	RestApiSecretStorage storage(*db.instance, "");
	int failures = 0;
	auto test = [&](const char *name, auto fn) {
		try {
			fn();
			std::cout << "CASE " << name << " PASS" << std::endl;
		} catch (...) {
			++failures;
			std::cout << "CASE " << name << " FAIL" << std::endl;
		}
	};
	test("structured_http_error_preserves_only_status", [&] {
		auto r = Capture([&] {
			unordered_map<string, string> info {
			    {"status_code", "403"}, {"response_body", MARKER}, {"header_set-cookie", MARKER}, {"reason", MARKER}};
			IOException original(info, "%s", MARKER);
			try {
				BoilstreamRethrowSafe("Authentication request failed", original);
			} catch (const std::exception &e) {
				ErrorData safe(e);
				Require(safe.ExtraInfo().size() == 1);
				Require(safe.ExtraInfo().at("status_code") == "403");
				throw;
			}
		});
		Require(r.failed && r.error.find("403") != string::npos);
		Private(r);
	});
	test("malicious_status_metadata_is_dropped", [&] {
		for (const auto &value :
		     vector<string> {"099", "600", "-40", "403 ", "403" + MARKER, string("403\0secret", 10), "4x3", ""}) {
			bool checked = false;
			auto r = Capture([&] {
				IOException original(unordered_map<string, string> {{"status_code", value}, {"response_body", MARKER}},
				                     "%s", MARKER);
				try {
					BoilstreamRethrowSafe("Authentication request failed", original);
				} catch (const std::exception &e) {
					Require(ErrorData(e).ExtraInfo().empty());
					checked = true;
					throw;
				}
			});
			Require(r.failed && checked);
			Private(r);
		}
	});
	test("non_http_exception_is_not_forwarded", [&] {
		auto r = Capture([&] { BoilstreamRethrowSafe("Authentication request failed", std::runtime_error(MARKER)); });
		Require(r.failed && r.error.find("Authentication request failed") != string::npos);
		Private(r);
	});

	for (int status : {200, 400, 403, 429, 501}) {
		http->status = status;
		for (const auto &entry : vector<string> {"boilstream_login", "boilstream_register_user"}) {
			test((entry + "_unverified_" + std::to_string(status) + "_private").c_str(), [&] {
				auto before = http->requests;
				bool rejected = false;
				auto r = Capture([&] {
					auto sql = "PRAGMA " + entry + "('" + AUTHORITY + "/" + MARKER + "@example.com','" + MARKER + "'" +
					           (entry == "boilstream_login" ? ",'123456')" : ")");
					auto result = connection.Query(sql);
					Require(result && result->HasError());
					rejected = true;
					throw std::runtime_error(result->GetError());
				});
				Require(rejected && r.failed && http->requests == before + 1);
				Require(r.error.find("Application protocol exchange failed") != string::npos ||
				        r.error.find("Failed to fetch CSRF token") != string::npos);
				Private(r);
			});
		}
	}
	test("sql_json_error_drops_untrusted_status_and_payload", [&] {
		Require(!connection.Query("SET errors_as_json=true")->HasError());
		http->fail = true;
		auto before = http->requests;
		auto result = connection.Query("PRAGMA boilstream_login('" + AUTHORITY + "/" + MARKER + "@example.com','" +
		                               MARKER + "','123456')");
		http->fail = false;
		Require(!connection.Query("SET errors_as_json=false")->HasError());
		Require(result && result->HasError() && http->requests == before + 1);
		Captured captured;
		captured.error = result->GetError();
		Private(captured);
		Require(captured.error.find("exception_type") != string::npos);
		Require(captured.error.find("error_location") == string::npos);
		Require(captured.error.find("status_code") == string::npos);
	});
	for (const auto &method : vector<string> {"GET", "POST", "DELETE"}) {
		test((method + "_failure_releases_recursion_guard").c_str(), [&] {
			http->fail = true;
			auto before = http->requests;
			for (int attempt = 0; attempt < 2; ++attempt) {
				BoilstreamConnectionState pending;
				Channel(pending);
				auto r = Capture([&] {
					if (method == "GET")
						storage.HttpGetWithState(AUTHORITY + "/secrets/" + MARKER, pending);
					else if (method == "DELETE")
						BoilstreamSessionPublicationTestAccess::Delete(storage, AUTHORITY + "/secrets/" + MARKER,
						                                               pending);
					else
						storage.HttpPostWithState(AUTHORITY + "/auth/email/login", MARKER, pending);
				});
				Require(r.failed && r.error.find("Application protocol exchange failed") != string::npos);
				Require(pending.access_token.empty() && pending.session_key.empty());
				Private(r);
			}
			Require(http->requests == before + 2);
			http->fail = false;
		});
	}

	test("concurrent_errors_keep_their_own_status", [&] {
		std::atomic<bool> correct {true};
		auto r = Capture([&] {
			vector<std::thread> workers;
			for (int i = 0; i < 8; ++i)
				workers.emplace_back([&, i] {
					const auto status = std::to_string(400 + i);
					for (int j = 0; j < 100; ++j) {
						IOException original(
						    unordered_map<string, string> {{"status_code", status}, {"response_body", MARKER}}, "%s",
						    MARKER);
						try {
							BoilstreamRethrowSafe("Authentication request failed", original);
						} catch (const std::exception &e) {
							ErrorData error(e);
							if (error.ExtraInfo().size() != 1 || error.ExtraInfo().at("status_code") != status ||
							    string(e.what()).find(MARKER) != string::npos)
								correct = false;
						}
					}
				});
			for (auto &worker : workers)
				worker.join();
		});
		Require(!r.failed && correct);
		Private(r);
	});
	test("secret_base64_errors_do_not_echo_secret", [&] {
		auto r = Capture([&] {
			BoilstreamSessionPublicationTestAccess::Decode(storage, SecretManager::Get(*db.instance),
			                                               "{\"data\":\"" + MARKER + "\"}");
		});
		Require(r.failed);
		Private(r);
	});
	test("valid_secret_roundtrip_keeps_payload_private", [&] {
		KeyValueSecret secret(vector<string> {"s3://synthetic/"}, "s3", "config", "synthetic-secret");
		secret.secret_map["key_id"] = Value(MARKER);
		bool correct = false;
		auto r = Capture([&] {
			auto decoded = BoilstreamSessionPublicationTestAccess::Decode(
			    storage, SecretManager::Get(*db.instance),
			    BoilstreamSessionPublicationTestAccess::Encode(storage, secret));
			correct = decoded && decoded->GetName() == secret.GetName() && decoded->GetType() == "s3" &&
			          static_cast<KeyValueSecret &>(*decoded).TryGetValue("key_id").ToString() == MARKER;
		});
		Require(!r.failed && correct);
		Private(r);
	});
	test("opaque_login_invalid_base64_keeps_payload_private", [&] {
		auto state = OpaqueClientWrapper::LoginStart(MARKER);
		auto r = Capture([&] { OpaqueClientWrapper::LoginFinish(state.state, MARKER); });
		Require(r.failed);
		Private(r);
	});
	test("opaque_registration_invalid_base64_keeps_payload_private", [&] {
		auto state = OpaqueClientWrapper::RegistrationStart(MARKER);
		auto r = Capture([&] { OpaqueClientWrapper::RegistrationFinish(state.state, MARKER); });
		Require(r.failed);
		Private(r);
	});

#ifdef BOILSTREAM_TRACK_STATE_FREE
	test("opaque_state_cleanup_before_and_after_ffi", [&] {
		// Count real frees; the wrappers always forward to the actual Rust library.
		// Before FFI, C++ owns cleanup. After FFI, Rust consumes the state itself.
		for (const auto &input : vector<string> {MARKER, string(65537, 'A'), "", "AAAA"}) {
			auto login = OpaqueClientWrapper::LoginStart(MARKER);
			const int before_login = login_frees;
			auto r = Capture([&] { OpaqueClientWrapper::LoginFinish(login.state, input); });
			Require(r.failed);
			Private(r);
			const int expected = (input == MARKER || input.size() > 65536) ? 1 : 0;
			Require(login_frees - before_login == expected);
			auto registration = OpaqueClientWrapper::RegistrationStart(MARKER);
			const int before_registration = registration_frees;
			r = Capture([&] { OpaqueClientWrapper::RegistrationFinish(registration.state, input); });
			Require(r.failed);
			Private(r);
			Require(registration_frees - before_registration == expected);
		}
	});
#endif

	return failures ? 1 : 0;
}
