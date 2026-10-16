// Invoke the actual PRAGMA handlers; do not execute the returned optional
// textplot installation/QR SQL. HTTPFS and registration FFI are real.
#include "../../src/boilstream_extension.cpp"
#include "duckdb/main/config.hpp"
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
	}
	Require(caught);
}
struct Config : DBConfig {
	Config() {
		options.load_extensions = false;
		options.maximum_threads = 2;
	}
};
static string Register(Connection &connection, const string &base, const string &email) {
	FunctionParameters p;
	p.values = {Value(base + "/" + email), Value("synthetic-password-123")};
	return RegisterUser(*connection.context, p);
}
static string Verify(Connection &connection, const string &code) {
	FunctionParameters p;
	p.values = {Value(code)};
	return VerifyMfa(*connection.context, p);
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
	db.LoadStaticExtension<BoilstreamExtension>();
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
		const auto sql = Verify(b, "123456");
		Require(sql.find("backup-b") != string::npos && sql.find("backup-c") == string::npos);
		Reject([&] { Token(b); });
		Require(Token(a) == "synthetic-c");
	});
	test("registration_failure_clears_busy_state_and_old_identity", [&] {
		Reject([&] { Register(a, base, "failure@example.com"); });
		Reject([&] { Token(a); });
		Require(!Register(a, base, "failure@example.com").empty());
		Require(Token(a) == "synthetic-failure");
	});
	return failed ? 1 : 0;
}
