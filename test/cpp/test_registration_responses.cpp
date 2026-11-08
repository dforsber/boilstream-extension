// Production authenticated-body parsers and result publication, without a fake
// successful wire peer. Actual native/browser auth runs against the private server.
#include "../../src/boilstream_extension.cpp"
#include "duckdb/main/config.hpp"
#include <iostream>
using namespace duckdb;
static void Require(bool value) {
	if (!value)
		throw std::runtime_error("assertion");
}
template <class F>
static void Reject(F action) {
	bool rejected = false;
	try {
		action();
	} catch (const Exception &error) {
		Require(string(error.what()).find("private_marker_A7") == string::npos);
		rejected = true;
	}
	Require(rejected);
}
struct Config : DBConfig {
	Config() {
		options.load_extensions = false;
		options.maximum_threads = 2;
	}
};
int main() {
	int failed = 0;
	auto test = [&](const char *name, auto action) {
		try {
			action();
			std::cout << "CASE " << name << " PASS\n";
		} catch (...) {
			++failed;
			std::cout << "CASE " << name << " FAIL\n";
		}
	};
	test("success_requires_object_true_and_unambiguous_field", [] {
		BoilstreamAuthResponse("{\"success\":true}").RequireSuccess();
		for (const string value :
		     {"", "private_marker_A7", "[]", "null", "true", "{}", "{\"success\":false}", "{\"success\":1}",
		      "{\"success\":\"true\"}", "{\"success\":true,\"success\":false}"}) {
			Reject([&] { BoilstreamAuthResponse(value).RequireSuccess(); });
		}
	});
	test("csrf_totp_and_bootstrap_fields_reject_wrong_type_control_bytes_and_duplicates", [] {
		for (const string field : {"csrf_token", "secret", "bootstrap_token"}) {
			const auto prefix = "{\"" + field + "\":";
			Require(BoilstreamAuthResponse(prefix + "\"valid-value\"}").Text(field.c_str()) == "valid-value");
			for (const string value : {"null", "false", "1", "[]", "{}", "\"\"", "\"private_marker_A7\\u0000tail\"",
			                           "\"private_marker_A7\\n\""}) {
				Reject([&] { BoilstreamAuthResponse(prefix + value + "}").Text(field.c_str()); });
			}
			Reject([&] { BoilstreamAuthResponse(prefix + "\"a\",\"" + field + "\":\"b\"}").Text(field.c_str()); });
			Reject([&] { BoilstreamAuthResponse("{}").Text(field.c_str()); });
			Require(BoilstreamAuthResponse(prefix + "\"" + string(4096, 'a') + "\"}").Text(field.c_str()).size() ==
			        4096);
			Reject([&] { BoilstreamAuthResponse(prefix + "\"" + string(4097, 'a') + "\"}").Text(field.c_str()); });
		}
	});
	test("success_rejects_conflicting_and_duplicate_error_fields", [] {
		BoilstreamAuthResponse(R"({"success":true,"error":null})").RequireSuccess();
		for (const string error : {"false", "0", "[]", "{}", "\"\"", "\"private_marker_A7\""}) {
			Reject([&] { BoilstreamAuthResponse("{\"success\":true,\"error\":" + error + "}").RequireSuccess(); });
		}
		Reject([] { BoilstreamAuthResponse(R"({"success":true,"error":null,"error":null})").RequireSuccess(); });
	});
	test("opaque_start_and_region_require_bounded_unambiguous_text", [] {
		for (const string field : {"credential_response", "state_id", "region"}) {
			const size_t limit = field == "credential_response" ? 64 * 1024 : 4096;
			const auto prefix = "{\"" + field + "\":";
			for (const string value : {"null", "false", "1", "[]", "{}", "\"\"", "\"private_marker_A7\\u0000tail\"",
			                           "\"private_marker_A7\\n\""}) {
				Reject([&] { BoilstreamAuthResponse(prefix + value + "}").Text(field.c_str(), limit); });
			}
			Reject(
			    [&] { BoilstreamAuthResponse(prefix + "\"a\",\"" + field + "\":\"b\"}").Text(field.c_str(), limit); });
			Reject([&] { BoilstreamAuthResponse("{}").Text(field.c_str(), limit); });
			Require(
			    BoilstreamAuthResponse(prefix + "\"" + string(limit, 'a') + "\"}").Text(field.c_str(), limit).size() ==
			    limit);
			Reject([&] {
				BoilstreamAuthResponse(prefix + "\"" + string(limit + 1, 'a') + "\"}").Text(field.c_str(), limit);
			});
		}
	});
	test("opaque_access_token_requires_exact_lowercase_hex", [] {
		const auto token = string(64, 'a');
		Require(BoilstreamAuthResponse("{\"access_token\":\"" + token + "\"}").OpaqueAccessToken() == token);
		Reject([] { BoilstreamAuthResponse("{}").OpaqueAccessToken(); });
		for (const string value : {"null", "true", "64", "[]", "{}", "\"\"", "\"private_marker_A7\\u0000\""}) {
			Reject([&] { BoilstreamAuthResponse("{\"access_token\":" + value + "}").OpaqueAccessToken(); });
		}
		for (const string value : {string(63, 'a'), string(65, 'a'), string(64, 'A'), string(63, 'a') + "g"}) {
			Reject([&] { BoilstreamAuthResponse("{\"access_token\":\"" + value + "\"}").OpaqueAccessToken(); });
		}
		Reject([&] {
			BoilstreamAuthResponse("{\"access_token\":\"" + token + "\",\"access_token\":\"" + token + "\"}")
			    .OpaqueAccessToken();
		});
	});
	test("opaque_expiry_requires_future_representable_unix_seconds", [] {
		using namespace std::chrono;
		const auto now = system_clock::time_point(seconds(2000000000));
		const auto max_seconds = duration_cast<seconds>(system_clock::duration::max()).count();
		auto expiry = [&](const string &value) {
			return BoilstreamAuthResponse("{\"expires_at\":" + value + "}").SessionExpiry(now);
		};
		Require(expiry("2000000001") == now + seconds(1));
		// Do not truncate Unix seconds at the signed 32-bit boundary in 2038.
		Require(expiry("2200000000") == system_clock::time_point(seconds(2200000000LL)));
		Require(expiry(std::to_string(max_seconds)) == system_clock::time_point(seconds(max_seconds)));
		Reject([&] { expiry(std::to_string(max_seconds + 1)); });
		for (const string value :
		     {"null", "true", "[]", "{}", "\"\"", "\"2200000000\"", "\"private_marker_A7\"", "-1", "0", "1999999999",
		      "2000000000", "2200000000.0", "18446744073709551615", "18446744073709551616", "9223372036854775807"}) {
			Reject([&] { expiry(value); });
		}
		Reject([&] { BoilstreamAuthResponse("{}").SessionExpiry(now); });
		Reject(
		    [&] { BoilstreamAuthResponse(R"({"expires_at":2200000000,"expires_at":2300000000})").SessionExpiry(now); });
	});
	test("session_cookie_has_exact_name_and_bounded_cookie_octets", [] {
		Require(BoilstreamSessionCookie("session=abc-DEF_123; HttpOnly; Path=/auth; Secure") == "abc-DEF_123");
		Require(BoilstreamSessionCookie("session=abc") == "abc");
		for (const string cookie : {"", "session=", "xsession=private_marker_A7", "other=session=private_marker_A7",
		                            "other=value; session=private_marker_A7", "session=private_marker_A7\n",
		                            "session=a b", "session=a,b", "session=\"a\"", "session=a\\b"}) {
			Reject([&] { BoilstreamSessionCookie(cookie); });
		}
		Reject([] { BoilstreamSessionCookie(string("session=private_marker_A7\0", 26)); });
		Require(BoilstreamSessionCookie("session=" + string(4096, 'a')).size() == 4096);
		Reject([] { BoilstreamSessionCookie("session=" + string(4097, 'a')); });
	});
	Config config;
	DuckDB db(nullptr, &config);
	Require(ExtensionHelper::LoadExtension(db, "core_functions") == ExtensionLoadResult::LOADED_EXTENSION);
	db.LoadStaticExtension<BoilstreamExtension>();
	Connection owner(db), sibling(db);
	auto storage = GetStorageFromContext(*owner.context);
	Require(storage);
	auto begin = [&](Connection &connection) {
		BoilstreamProtocol::Configure(*connection.context, "https://responses.invalid",
		                              "0900000000000000000000000000000000000000000000000000000000000000");
		auto operation =
		    storage->BeginRegistration(*connection.context, "https://responses.invalid", "fixture@example.test");
		if (operation.totp_uri.empty())
			storage->StoreRegistrationState(*connection.context, operation.generation, "synthetic-cookie",
			                                "otpauth://totp/fixture?secret=ABCD");
		return operation;
	};
	test("invalid_recovery_response_preserves_pending_owner_and_allows_retry", [&] {
		for (const string codes : vector<string> {"{}", "null", "[1]", "[\"\"]", "[\"private_marker_A7\\u0000\"]",
		                                          "[\"private_marker_A7\\n\"]", "[\"private_marker_A7\\u007f\"]",
		                                          "[\"" + string(8193, 'a') + "\"]"}) {
			auto enrollment = begin(owner);
			storage->EndRegistrationOperation(*owner.context, enrollment.generation);
			auto operation = storage->BeginMfaVerification(*owner.context);
			Reject([&] {
				CompleteMfaRegistration(*owner.context, *storage, operation.generation,
				                        "{\"success\":true,\"backup_codes\":" + codes + "}");
			});
			storage->EndRegistrationOperation(*owner.context, operation.generation);
			auto retry = storage->BeginMfaVerification(*owner.context);
			Require(retry.session_token == "synthetic-cookie");
			storage->EndRegistrationOperation(*owner.context, retry.generation);
		}
	});
	test("recovery_count_and_value_boundaries", [] {
		string codes = "[";
		for (size_t i = 0; i < 128; ++i)
			codes += (i ? ",\"a\"" : "\"a\"");
		Require(
		    BoilstreamAuthResponse("{\"success\":true,\"backup_codes\":" + codes + "]}").RecoveryCodes()->rows.size() ==
		    128);
		Reject([&] {
			BoilstreamAuthResponse("{\"success\":true,\"backup_codes\":" + codes + ",\"a\"]}").RecoveryCodes();
		});
		Require(BoilstreamAuthResponse("{\"success\":true,\"backup_codes\":[\"" + string(8192, 'a') + "\"]}")
		            .RecoveryCodes()
		            ->rows[0]
		            .value.size() == 8192);
		Reject([] {
			BoilstreamAuthResponse("{\"success\":true,\"backup_codes\":[],\"backup_codes\":[]}").RecoveryCodes();
		});
	});
	test("recovery_sql_is_data_one_use_and_connection_owned", [&] {
		auto enrollment = begin(owner);
		storage->EndRegistrationOperation(*owner.context, enrollment.generation);
		auto operation = storage->BeginMfaVerification(*owner.context);
		RegistrationOperationGuard guard(*storage, *owner.context, operation.generation);
		auto other = begin(sibling);
		const auto sql =
		    CompleteMfaRegistration(*owner.context, *storage, operation.generation,
		                            "{\"success\":true,\"backup_codes\":[\"'); SELECT 'private_marker_A7\"]}");
		Require(sql.find("private_marker_A7") == string::npos);
		Require(sibling.Query(sql)->HasError());
		auto result = owner.Query(sql);
		Require(result && !result->HasError() && result->RowCount() == 1);
		Require(result->Collection().GetValue(0, 0).ToString() == "'); SELECT 'private_marker_A7");
		Require(owner.Query(sql)->HasError());
		Reject([&] { storage->BeginMfaVerification(*owner.context); });
		storage->EndRegistrationOperation(*sibling.context, other.generation);
		auto remaining = storage->BeginMfaVerification(*sibling.context);
		Require(remaining.session_token == "synthetic-cookie");
		storage->EndRegistrationOperation(*sibling.context, remaining.generation);
	});
	test("empty_or_absent_recovery_list_completes_registration", [&] {
		for (const string response : {"{\"success\":true,\"backup_codes\":[]}", "{\"success\":true}"}) {
			auto enrollment = begin(owner);
			storage->EndRegistrationOperation(*owner.context, enrollment.generation);
			auto operation = storage->BeginMfaVerification(*owner.context);
			RegistrationOperationGuard guard(*storage, *owner.context, operation.generation);
			auto result =
			    owner.Query(CompleteMfaRegistration(*owner.context, *storage, operation.generation, response));
			Require(result && !result->HasError() && result->RowCount() == 1);
			Reject([&] { storage->BeginMfaVerification(*owner.context); });
		}
	});
	test("enrollment_without_optional_renderer_returns_owned_manual_setup", [&] {
		auto operation = begin(owner);
		const string uri = "otpauth://totp/fixture?secret=ABCD";
		auto sql = RegistrationQrResult(*owner.context, *storage, operation.generation, uri);
		Require(sql.find("ABCD") == string::npos && sql.find("INSTALL") == string::npos);
		storage->EndRegistrationOperation(*owner.context, operation.generation);
		auto result = owner.Query(sql);
		Require(result && !result->HasError() && result->RowCount() == 3);
		Require(result->Collection().GetValue(0, 0).ToString() == "ABCD");
		Require(result->Collection().GetValue(0, 2).ToString() == uri);
	});
	return failed ? 1 : 0;
}
