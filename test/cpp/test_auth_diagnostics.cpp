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
	static uint16_t Cipher(RestApiSecretStorage &s, const string &value) {
		return s.ParseCipherSuite({{"x-boilstream-cipher", value}});
	}
	static void Verify(RestApiSecretStorage &s) {
		s.VerifyResponseSignature(
		    "synthetic-body", 200,
		    {{"x-boilstream-response-signature", MARKER}, {"x-boilstream-date", MARKER}, {"set-cookie", MARKER}},
		    vector<uint8_t>(32, 7));
	}
	static bool Sign(RestApiSecretStorage &s) {
		auto result =
		    s.SignRequest("POST", "https://example.invalid/" + MARKER, "synthetic-body", 1700000000, 1,
		                  vector<uint8_t>(32, 7), TOKEN_PREFIX + TOKEN_PREFIX + TOKEN_PREFIX + TOKEN_PREFIX, MARKER);
		return !result.signature.empty() && !result.date_time.empty();
	}
};
struct Config : DBConfig {
	Config() {
		options.load_extensions = false;
		options.maximum_threads = 2;
	}
};
int main(int argc, char **argv) {
	if (argc != 2)
		return 2;
	Config config;
	DuckDB db(nullptr, &config);
	Connection connection(db);
	SecretManager::Get(*db.instance).SetEnablePersistentSecrets(false);
	Require(ExtensionHelper::LoadExtension(db, "httpfs") == ExtensionLoadResult::LOADED_EXTENSION);
	auto set = connection.Query("SET httpfs_client_implementation='curl'");
	Require(set && !set->HasError());
	db.LoadStaticExtension<BoilstreamExtension>();
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
	test("supported_cipher_control", [&] {
		Require(BoilstreamSessionPublicationTestAccess::Cipher(storage, "0x0001") == 1);
		Require(BoilstreamSessionPublicationTestAccess::Cipher(storage, "0x0002") == 2);
	});
	test("malformed_cipher_diagnostic_does_not_echo_header", [&] {
		auto r = Capture([&] { BoilstreamSessionPublicationTestAccess::Cipher(storage, MARKER); });
		Require(r.failed);
		Private(r);
	});
	test("cipher_parser_rejects_trailing_text", [&] {
		auto r = Capture([&] { BoilstreamSessionPublicationTestAccess::Cipher(storage, "0x0001" + MARKER); });
		Require(r.failed);
		Private(r);
	});
	test("cipher_parser_rejects_truncated_high_bits", [&] {
		auto r = Capture([&] { BoilstreamSessionPublicationTestAccess::Cipher(storage, "0x10001"); });
		Require(r.failed);
		Private(r);
	});
	test("response_verification_does_not_log_headers", [&] {
		auto r = Capture([&] { BoilstreamSessionPublicationTestAccess::Verify(storage); });
		Require(r.failed);
		Private(r);
	});
	test("request_signing_keeps_credentials_and_url_private", [&] {
		bool signed_request = false;
		auto r = Capture([&] { signed_request = BoilstreamSessionPublicationTestAccess::Sign(storage); });
		Require(signed_request && !r.failed);
		Private(r);
	});
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
	test("cipher_boundary_matrix", [&] {
		for (const auto &v :
		     vector<string> {"", "0x", "0x1", "0X0001", "0x0000", "0x0003", "0xffff", "0x000g", "0x 001", "0x+001",
		                     string("0x00\0"
		                            "1",
		                            6)}) {
			auto r = Capture([&] { BoilstreamSessionPublicationTestAccess::Cipher(storage, v); });
			Require(r.failed);
			Private(r);
		}
	});
	test("successful_http_body_is_returned_but_not_logged", [&] {
		BoilstreamConnectionState pending;
		pending.is_exchanging = true;
		string body;
		auto r =
		    Capture([&] { body = storage.HttpPostWithState(string(argv[1]) + "/200/" + MARKER, MARKER, pending); });
		Require(!r.failed && body.find(MARKER) != string::npos);
		Private(r);
	});
	for (const auto &scenario :
	     vector<string> {"csrf-invalid", "csrf-missing", "csrf-http", "login-http", "login-cookie",
	                     "login-malformed-cookie", "mfa-invalid", "mfa-rejected", "bootstrap-invalid"}) {
		test(("sql_login_" + scenario + "_private").c_str(), [&] {
			bool rejected = false;
			auto r = Capture([&] {
				auto result = connection.Query("PRAGMA boilstream_login('" + string(argv[1]) + "/" + scenario + "/" +
				                               MARKER + "@example.com','" + MARKER + "','123456')");
				Require(result && result->HasError());
				rejected = true;
				throw std::runtime_error(result->GetError());
			});
			Require(r.failed && rejected);
			Private(r);
			const std::map<string, string> expected {
			    {"csrf-invalid", "Failed to parse CSRF response"},
			    {"csrf-missing", "CSRF response missing csrf_token"},
			    {"csrf-http", "HTTP 403"},
			    {"login-http", "HTTP 403"},
			    {"login-cookie", "No session cookie returned"},
			    {"login-malformed-cookie", "Set-Cookie header missing session cookie"},
			    {"mfa-invalid", "Failed to parse MFA response"},
			    {"mfa-rejected", "MFA authentication failed"},
			    {"bootstrap-invalid", "Failed to parse bootstrap token response"}};
			Require(r.error.find(expected.at(scenario)) != string::npos);
		});
	}
	for (auto status : {400, 429, 501}) {
		const auto name = "http_post_" + std::to_string(status) + "_keeps_body_private";
		test(name.c_str(), [&] {
			BoilstreamConnectionState pending;
			pending.is_exchanging = true;
			auto r = Capture([&] {
				storage.HttpPostWithState(string(argv[1]) + "/" + std::to_string(status) + "/" + MARKER, MARKER,
				                          pending);
			});
			Require(r.failed && r.error.find(std::to_string(status)) != string::npos);
			Private(r);
		});
	}

	test("http_get_error_clears_recursion_guard", [&] {
		BoilstreamConnectionState pending;
		pending.is_exchanging = true;
		string body;
		auto r = Capture([&] { body = storage.HttpGetWithState(string(argv[1]) + "/403/" + MARKER, pending); });
		Require(!r.failed && body.empty());
		Private(r);
		r = Capture([&] { body = storage.HttpGetWithState(string(argv[1]) + "/200/" + MARKER, pending); });
		Require(!r.failed && body.find(MARKER) != string::npos);
		Private(r);
	});
	test("http_delete_error_keeps_status_and_clears_recursion_guard", [&] {
		BoilstreamConnectionState pending;
		pending.session_key.assign(32, 9);
		pending.region = MARKER;
		pending.access_token = TOKEN_PREFIX + TOKEN_PREFIX + TOKEN_PREFIX + TOKEN_PREFIX;
		pending.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
		for (int attempt = 0; attempt < 2; ++attempt) {
			auto r = Capture([&] {
				BoilstreamSessionPublicationTestAccess::Delete(storage, string(argv[1]) + "/403/" + MARKER, pending);
			});
			Require(r.failed && r.error.find("403") != string::npos);
			Private(r);
		}
	});

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
	for (const auto &scenario : vector<string> {"csrf-invalid", "csrf-http", "signup-rejected"}) {
		test(("sql_registration_" + scenario + "_private").c_str(), [&] {
			bool rejected = false;
			auto r = Capture([&] {
				auto result = connection.Query("PRAGMA boilstream_register_user('" + string(argv[1]) + "/register-" +
				                               scenario + "/" + MARKER + "@example.com','" + MARKER + "')");
				Require(result && result->HasError());
				rejected = true;
				throw std::runtime_error(result->GetError());
			});
			Require(rejected && r.failed);
			Private(r);
			const std::map<string, string> expected {{"csrf-invalid", "Failed to parse CSRF response"},
			                                         {"csrf-http", "HTTP 403"},
			                                         {"signup-rejected", "Signup failed"}};
			Require(r.error.find(expected.at(scenario)) != string::npos);
		});
	}

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
