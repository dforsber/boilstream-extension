#include "boilstream_query_privacy.hpp"
#include "boilstream_diagnostics.hpp"
#include <iostream>
using namespace duckdb;
int main() {
	struct Case {
		const char *name;
		string query;
		bool private_error;
	};
	vector<Case> cases = {
	    {"login", "PRAGMA boilstream_login('secret',)", true},
	    {"registration", "PRAGMA boilstream_register_user('secret',)", true},
	    {"verification", "PRAGMA boilstream_verify_mfa('secret',)", true},
	    {"bootstrap", "PRAGMA boilstream_bootstrap_session('secret',)", true},
	    {"mixed_case", "pRaGmA BoIlStReAm_LoGiN('secret',)", true},
	    {"quoted_name", "PRAGMA \"boilstream_login\"('secret',)", true},
	    {"header_comments", "PRAGMA /* nested /* x */ y */ boilstream_login('secret',)", true},
	    {"leading_comment", "-- comment\n PRAGMA boilstream_login('secret',)", true},
	    {"later_statement", "SELECT 1; PRAGMA boilstream_login('secret',)", true},
	    {"earlier_statement", "PRAGMA boilstream_login('secret',); SELECT )", true},
	    {"after_safe_pragma", "PRAGMA version; PRAGMA boilstream_login('secret',)", true},
	    {"unterminated_argument", "PRAGMA boilstream_login('secret", true},
	    {"lexical_failure_before_auth", "SELECT E'\\x'; PRAGMA boilstream_login('secret',)", true},
	    {"unterminated_comment", "SELECT 1; /* PRAGMA boilstream_login('secret',)", true},
	    {"unterminated_dollar_string", "SELECT $q$ PRAGMA boilstream_login('secret',)", true},
	    {"nul_hides_tail", string("SELECT 1") + string(1, '\0') + "PRAGMA boilstream_login('secret',)", true},
	    {"unicode_identifier", "PRAGMA U&\"boilstream_log\\0069n\"('secret',)", true},
	    {"custom_unicode_escape", "PRAGMA U&\"boilstream_log!0069n\" UESCAPE '!'('secret',)", true},
	    {"escaped_argument", "PRAGMA boilstream_login(E'secret\\n',)", true},
	    {"dollar_argument", "PRAGMA boilstream_login($q$secret$q$,)", true},
	    {"ordinary_syntax_error", "SELECT ordinary_missing_name,)", false},
	    {"ordinary_binder_error", "SELECT ordinary_missing_name", false},
	    {"ordinary_pragma", "PRAGMA ordinary_missing_pragma('value',)", false},
	    {"ordinary_quoted_pragma", "PRAGMA \"ordinary_missing_pragma\"('value',)", false},
	    {"comment_is_not_statement", "/* PRAGMA boilstream_login('value') */ SELECT missing", false},
	    {"line_comment_is_not_statement", "SELECT missing -- PRAGMA boilstream_login('value')", false},
	    {"string_is_not_statement", "SELECT 'PRAGMA boilstream_login(value)'::INTEGER", false},
	    {"dollar_string_is_not_statement", "SELECT $q$PRAGMA boilstream_login(value)$q$::INTEGER", false},
	    {"quoted_column_is_not_statement", "SELECT \"PRAGMA boilstream_login\"", false},
	    {"similar_name_is_not_auth", "PRAGMA boilstream_login_other('value',)", false},
	    {"huge_input_has_bounded_diagnostic_work", string(1024 * 1024 + 1, 'x'), true},
	    {"huge_pragma_header_is_private", "PRAGMA " + string(4097, 'x'), true}};
	cases.push_back({"runtime_result", "SELECT value::INTEGER FROM boilstream_auth_result(1::UBIGINT)", true});
	cases.push_back({"quoted_runtime_result", "SELECT * FROM \"boilstream_auth_result\"(1)", true});
	cases.push_back({"mixed_case_runtime_result", "SELECT * FROM BoIlStReAm_AuTh_ReSuLt(1)", true});
	cases.push_back({"qualified_runtime_result", "SELECT * FROM main.boilstream_auth_result(1)", true});
	cases.push_back({"runtime_result_comment", "SELECT * FROM boilstream_auth_result /* header */ (1)", true});
	cases.push_back({"similar_runtime_function", "SELECT * FROM boilstream_auth_result_other(1)", false});
	cases.push_back({"runtime_name_in_literal", "SELECT 'boilstream_auth_result(1)'::INTEGER", false});
	cases.push_back({"runtime_name_in_comment", "SELECT missing /* boilstream_auth_result(1) */", false});
	cases.push_back({"runtime_name_as_column", "SELECT \"boilstream_auth_result\"", false});
	string many_headers;
	for (int i = 0; i < 64; ++i)
		many_headers += "PRAGMA version;";
	cases.push_back({"header_work_exact_boundary", many_headers + "SELECT missing", false});
	cases.push_back({"header_work_is_bounded", many_headers + "PRAGMA version; SELECT missing", true});

	string many_candidates = "SELECT ";
	for (int i = 0; i < 64; ++i)
		many_candidates += "boilstream_auth_result_other(1),";
	cases.push_back({"result_header_work_exact_boundary", many_candidates + "missing", false});
	cases.push_back({"result_header_work_is_bounded", many_candidates + "boilstream_auth_result_other(1)", true});

	cases.push_back({"unicode_runtime_result", R"SQL(SELECT * FROM U&"boilstream_auth_res\0075lt"(1))SQL", true});
	cases.push_back({"custom_unicode_runtime_result",
	                 R"SQL(SELECT * FROM U&"boilstream_auth_res!0075lt" UESCAPE '!'(1))SQL", true});
	cases.push_back(
	    {"unsupported_unicode_function_is_private", R"SQL(SELECT * FROM U&"ordinary_f\0075nction"(1))SQL", true});

	int failed = 0;
	for (const auto &test : cases) {
		bool actual;
		try {
			actual = BoilstreamPrivateQueryError(test.query);
		} catch (...) {
			actual = true;
		} // Exact fail-closed contract of the core callback boundary.
		const bool ok = actual == test.private_error;
		failed += !ok;
		std::cout << "CASE " << test.name << (ok ? " PASS" : " FAIL") << std::endl;
	}

	auto check = [&](const char *name, bool ok) {
		failed += !ok;
		std::cout << "CASE " << name << (ok ? " PASS" : " FAIL") << std::endl;
	};
	check("public_literal",
	      BoilstreamPrivateErrorMessage(ErrorData(ExceptionType::IO, "Failed to parse CSRF response")) ==
	          "Failed to parse CSRF response");
	check("public_literal_suffix_rejected",
	      BoilstreamPrivateErrorMessage(ErrorData(ExceptionType::IO, "Failed to parse CSRF response SECRET")).empty());
	check("wrong_category_rejected",
	      BoilstreamPrivateErrorMessage(ErrorData(ExceptionType::PARSER, "Failed to parse CSRF response")).empty());
	check("unknown_message_rejected", BoilstreamPrivateErrorMessage(ErrorData(ExceptionType::IO, "SECRET")).empty());
	for (const auto &status : vector<string> {"100", "403", "599"}) {
		IOException original(unordered_map<string, string> {{"status_code", status}, {"response_body", "SECRET"}},
		                     "SECRET");
		auto safe = BoilstreamPrivateErrorMessage(ErrorData(original));
		check(("status_" + status).c_str(), safe == "Authentication request failed: HTTP " + status);
		check(("status_roundtrip_" + status).c_str(),
		      BoilstreamPrivateErrorMessage(ErrorData(ExceptionType::IO, safe)) == safe);
	}
	unsigned index = 0;
	for (const auto &status :
	     vector<string> {"", "099", "600", "403 ", "4x3", "-40", string("403\0SECRET", 10), string(1024 * 1024, '4')}) {
		IOException original(unordered_map<string, string> {{"status_code", status}, {"response_body", "SECRET"}},
		                     "SECRET");
		check(("invalid_status_" + std::to_string(index++)).c_str(),
		      BoilstreamPrivateErrorMessage(ErrorData(original)).empty());
	}
	check("canonical_status_suffix_rejected",
	      BoilstreamPrivateErrorMessage(ErrorData(ExceptionType::IO, "Authentication request failed: HTTP 403 SECRET"))
	          .empty());
	for (const auto &message :
	     vector<string> {"Failed to parse CSRF response", "Authentication request failed: HTTP 403"}) {
		ErrorData json(ExceptionType::IO, message);
		json.ConvertErrorToJSON();
		check(("json_roundtrip_" + std::to_string(message.size())).c_str(),
		      BoilstreamPrivateErrorMessage(json) == message);
	}
	check("malformed_json_rejected", BoilstreamPrivateErrorMessage(ErrorData(ExceptionType::IO, "{SECRET")).empty());
	check("oversized_json_rejected",
	      BoilstreamPrivateErrorMessage(ErrorData(ExceptionType::IO, "{" + string(1024, 'x'))).empty());
	ErrorData private_json(ExceptionType::IO, "SECRET");
	private_json.ConvertErrorToJSON();
	check("json_private_message_rejected", BoilstreamPrivateErrorMessage(private_json).empty());
	return failed ? 1 : 0;
}
