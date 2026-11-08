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
