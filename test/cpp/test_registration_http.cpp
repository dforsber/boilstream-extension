// Execute actual handler result SQL with a local QR encoder, excluding only
// optional textplot installation. HTTPFS and registration FFI are real.
#include "../../src/boilstream_extension.cpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include <iostream>
#include <thread>
#include <atomic>
using namespace duckdb;
static void Require(bool ok) {
	if (!ok)
		throw std::runtime_error("assertion");
}
template <class F>
static void Reject(F fn) {
	bool caught = false;
	try {
		fn();
	} catch (const IOException &) {
		caught = true;
	} catch (const InvalidInputException &) {
		caught = true;
	}
	Require(caught);
}
struct Config : DBConfig {
	Config() {
		options.load_extensions = false;
		options.maximum_threads = 2;
	}
};
static void QrPassthrough(DataChunk &args, ExpressionState &, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [](string_t input) { return input; });
}
static string Render(Connection &connection, const string &sql, bool qr) {
	Require(sql.find("JBSWY3DPEHPK3PXP") == string::npos && sql.find("backup-b") == string::npos);
	const auto start = qr ? sql.find("SELECT unnest(") : 0;
	Require(start != string::npos);
	auto result = connection.Query(sql.substr(start));
	Require(result && !result->HasError());
	if (!qr) {
		Require(result->RowCount() == 1);
		return result->Collection().GetValue(0, 0).ToString();
	}
	Require(result->RowCount() == 3 && result->Collection().GetValue(0, 0).ToString() == "JBSW Y3DP EHPK 3PXP");
	Require(result->Collection().GetValue(0, 1).ToString() == "PRAGMA boilstream_verify_mfa('123456');");
	return result->ToString();
}
static string Register(Connection &connection, const string &base, const string &email) {
	FunctionParameters p;
	p.values = {Value(base + "/" + email), Value("synthetic-password-123")};
	return Render(connection, RegisterUser(*connection.context, p), true);
}
static string Verify(Connection &connection, const string &code) {
	FunctionParameters p;
	p.values = {Value(code)};
	return Render(connection, VerifyMfa(*connection.context, p), false);
}
static string Token(Connection &connection) {
	auto *s = GetStorageFromContext(*connection.context);
	auto state = s->BeginMfaVerification(*connection.context);
	s->EndRegistrationOperation(*connection.context, state.generation);
	return state.session_token;
}
int main(int argc, char **argv) {
	if (argc != 2)
		return 2;
	Config cfg;
	DuckDB db(nullptr, &cfg);
	Connection a(db), b(db);
	SecretManager::Get(*db.instance).SetEnablePersistentSecrets(false);
	Require(ExtensionHelper::LoadExtension(db, "httpfs") == ExtensionLoadResult::LOADED_EXTENSION);
	Require(ExtensionHelper::LoadExtension(db, "core_functions") == ExtensionLoadResult::LOADED_EXTENSION);
	db.LoadStaticExtension<BoilstreamExtension>();
	CreateScalarFunctionInfo tp_qr(
	    ScalarFunction("tp_qr", {LogicalType::VARCHAR}, LogicalType::VARCHAR, QrPassthrough));
	a.context->RunFunctionInTransaction(
	    [&]() { Catalog::GetSystemCatalog(*a.context).CreateFunction(*a.context, tp_qr); });
	for (auto *c : {&a, &b}) {
		auto r = c->Query("SET httpfs_client_implementation='curl'");
		Require(r && !r->HasError());
	}
	const string base = argv[1];
	int failed = 0;
	auto test = [&](const char *name, auto fn) {
		try {
			fn();
			std::cout << "CASE " << name << " PASS" << std::endl;
		} catch (...) {
			++failed;
			std::cout << "CASE " << name << " FAIL" << std::endl;
		}
	};
	string qr_a, qr_b;
	test("real_handlers_parallel_registration_owns_each_cookie", [&] {
		std::atomic<bool> ok {true};
		std::thread x([&] {
			try {
				qr_a = Register(a, base, "a@example.com");
			} catch (...) {
				ok = false;
			}
		}),
		    y([&] {
			    try {
				    qr_b = Register(b, base, "b@example.com");
			    } catch (...) {
				    ok = false;
			    }
		    });
		x.join();
		y.join();
		Require(ok && !qr_a.empty() && !qr_b.empty() && qr_a != qr_b);
		Require(Token(a) == "synthetic-a" && Token(b) == "synthetic-b");
	});
	test("same_account_reuses_only_its_cached_qr", [&] {
		Require(Register(a, base, "a@example.com") == qr_a);
		Require(Token(b) == "synthetic-b");
	});
	test("new_account_on_same_server_starts_new_enrollment", [&] {
		Require(Register(a, base, "c@example.com") != qr_a);
		Require(Token(a) == "synthetic-c" && Token(b) == "synthetic-b");
	});
	test("failed_mfa_releases_operation_for_retry", [&] {
		Reject([&] { Verify(b, "000000"); });
		Require(Token(b) == "synthetic-b" && Token(a) == "synthetic-c");
	});
	test("successful_mfa_consumes_only_its_own_cookie", [&] {
		Require(Verify(b, "123456") == "backup-b");
		Reject([&] { Token(b); });
		Require(Token(a) == "synthetic-c");
	});
	test("registration_failure_clears_busy_state_and_old_identity", [&] {
		Reject([&] { Register(a, base, "failure@example.com"); });
		Reject([&] { Token(a); });
		Require(!Register(a, base, "failure@example.com").empty());
		Require(Token(a) == "synthetic-failure");
	});
	for (const auto &entry : vector<std::pair<string, string>> {{"111111", "object_instead_of_code_list"},
	                                                            {"222222", "non_string_code"},
	                                                            {"333333", "empty_code"},
	                                                            {"444444", "embedded_nul_code"},
	                                                            {"555555", "oversized_code"},
	                                                            {"666666", "excessive_code_count"},
	                                                            {"777777", "empty_list_success"},
	                                                            {"888888", "control_byte_code"},
	                                                            {"999999", "sql_looking_code_is_data"}}) {
		test(("recovery_" + entry.second).c_str(), [&] {
			Connection c(db);
			auto storage = GetStorageFromContext(*c.context);
			auto operation = storage->BeginRegistration(*c.context, base, "validation@example.com");
			storage->StoreRegistrationState(*c.context, operation.generation, "synthetic-validation",
			                                "otpauth://totp/synthetic?secret=ABCD");
			storage->EndRegistrationOperation(*c.context, operation.generation);
			if (entry.first == "777777")
				Require(Verify(c, entry.first) == "MFA enrollment complete - no backup codes provided");
			else if (entry.first == "999999")
				Require(Verify(c, entry.first) == "'); SELECT 'synthetic");
			else
				Reject([&] { Verify(c, entry.first); });
		});
	}

	return failed ? 1 : 0;
}
