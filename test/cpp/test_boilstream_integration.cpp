//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_boilstream_integration.cpp
//
// Integration tests for Boilstream Extension
// Tests full end-to-end flows against a real boilstream server
//
// Prerequisites:
// - Boilstream server running at https://localhost:4332
// - Valid bootstrap token available
//
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include <iostream>
#include "duckdb/main/database.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/config.hpp"

using namespace duckdb;
using namespace std;

//===----------------------------------------------------------------------===//
// Test Configuration
//===----------------------------------------------------------------------===//

// Bootstrap tokens are short-lived (5 min) and single-use
// Get a fresh token from your boilstream server before running tests
//
// Usage:
//   1. Get fresh bootstrap token from your boilstream server
//   2. Set environment variable with full endpoint (same format as PRAGMA):
//      export BOILSTREAM_TEST_ENDPOINT="https://localhost:4332/secrets:your_bootstrap_token_here"
//   3. Run tests: ./boilstream_integration_test
//
// REQUIRED: Tests will fail if BOILSTREAM_TEST_ENDPOINT is not set

static string GetTestEndpoint() {
	const char* env_endpoint = std::getenv("BOILSTREAM_TEST_ENDPOINT");
	if (!env_endpoint || strlen(env_endpoint) == 0) {
		throw std::runtime_error(
			"BOILSTREAM_TEST_ENDPOINT environment variable not set. "
			"Set it to your boilstream endpoint with fresh bootstrap token: "
			"export BOILSTREAM_TEST_ENDPOINT='https://localhost:4332/secrets:your_token_here'"
		);
	}
	return string(env_endpoint);
}

// Get boilstream extension path from environment or default
static string GetBoilstreamExtensionPath() {
	const char* env_path = std::getenv("BOILSTREAM_EXTENSION_PATH");
	if (env_path && strlen(env_path) > 0) {
		return string(env_path);
	}

	// Default: assume we're in test/cpp/build and extension is in ../../../build/release/extension/boilstream/
	return "../../../build/release/extension/boilstream/boilstream.duckdb_extension";
}

// Helper: Check if extensions load
static bool CanLoadExtension() {
	try {
		DBConfig config;
		config.options.allow_unsigned_extensions = true;
		DuckDB db(nullptr, &config);
		Connection con(db);

		// Try to load httpfs first
		auto httpfs_result = con.Query("LOAD httpfs;");
		if (httpfs_result->HasError()) {
			return false;
		}

		// Try to load boilstream extension from local build
		string extension_path = GetBoilstreamExtensionPath();
		string load_sql = "LOAD '" + extension_path + "';";
		auto result = con.Query(load_sql);
		if (result->HasError()) {
			return false;
		}
		return true;
	} catch (...) {
		return false;
	}
}

//===----------------------------------------------------------------------===//
// Test: Basic Extension Loading
//===----------------------------------------------------------------------===//
TEST_CASE("Extension Loading", "[boilstream][integration]") {
	DBConfig config;
	config.options.allow_unsigned_extensions = true;
	DuckDB db(nullptr, &config);
	Connection con(db);

	SECTION("Load httpfs and boilstream extensions successfully") {
		auto httpfs_result = con.Query("LOAD httpfs;");
		REQUIRE_FALSE(httpfs_result->HasError());

		string extension_path = GetBoilstreamExtensionPath();
		string load_sql = "LOAD '" + extension_path + "';";
		auto result = con.Query(load_sql);
		REQUIRE_FALSE(result->HasError());
	}

	SECTION("Extensions appear in loaded extensions") {
		con.Query("LOAD httpfs;");

		string extension_path = GetBoilstreamExtensionPath();
		string load_sql = "LOAD '" + extension_path + "';";
		con.Query(load_sql);

		auto result = con.Query("SELECT * FROM duckdb_extensions() WHERE extension_name IN ('httpfs', 'boilstream');");
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->RowCount() == 2);
	}
}

//===----------------------------------------------------------------------===//
// Global Test State
// Bootstrap token is single-use, so we exchange it ONCE and share the session
//===----------------------------------------------------------------------===//
static duckdb::unique_ptr<DuckDB> g_test_db = nullptr;

// Initialize database and exchange bootstrap token
static void InitializeTestDatabase() {
	if (g_test_db) {
		return; // Already initialized
	}

	string endpoint = GetTestEndpoint(); // Throws if not set
	string extension_path = GetBoilstreamExtensionPath();

	cout << "DEBUG: Using endpoint: " << endpoint << endl;
	cout << "DEBUG: Loading boilstream extension from: " << extension_path << endl;

	// Create database with unsigned extensions allowed (for local development/testing)
	DBConfig config;
	config.options.allow_unsigned_extensions = true;
	g_test_db = duckdb::make_uniq<DuckDB>(nullptr, &config);
	Connection con(*g_test_db);

	// Load httpfs first (required for HTTP operations) - can use built-in
	auto httpfs_result = con.Query("LOAD httpfs;");
	if (httpfs_result->HasError()) {
		throw std::runtime_error("Failed to load httpfs extension: " + httpfs_result->GetError());
	}
	cout << "DEBUG: httpfs loaded successfully" << endl;

	// Load boilstream extension from LOCAL build (not community extension)
	string load_sql = "LOAD '" + extension_path + "';";
	auto load_result = con.Query(load_sql);
	if (load_result->HasError()) {
		throw std::runtime_error("Failed to load boilstream extension from " + extension_path +
		                         ": " + load_result->GetError() +
		                         "\nMake sure the extension is built first: GEN=ninja make");
	}
	cout << "DEBUG: boilstream loaded successfully from local build" << endl;

	// Exchange bootstrap token
	string pragma_sql = "PRAGMA duckdb_secrets_boilstream_endpoint('" + endpoint + "');";
	cout << "DEBUG: Executing PRAGMA: " << pragma_sql << endl;

	auto result = con.Query(pragma_sql);

	if (result->HasError()) {
		throw std::runtime_error("Bootstrap token exchange failed: " + result->GetError() +
		                         "\nMake sure BOILSTREAM_TEST_ENDPOINT has a valid fresh bootstrap token");
	}

	cout << "DEBUG: Token exchange successful!" << endl;
}

//===----------------------------------------------------------------------===//
// Test: Bootstrap Token Exchange (One-Time Setup)
//===----------------------------------------------------------------------===//
TEST_CASE("Bootstrap Token Exchange", "[boilstream][integration][setup]") {
	// This test MUST run first - it consumes the single-use bootstrap token
	InitializeTestDatabase();

	// Verify database is initialized
	Connection con(*g_test_db);
	auto result = con.Query("SELECT 1");
	REQUIRE_FALSE(result->HasError());
}

//===----------------------------------------------------------------------===//
// Test: Bootstrap Token Single-Use Verification
//===----------------------------------------------------------------------===//
TEST_CASE("Bootstrap Token Single-Use", "[boilstream][integration]") {
	// This test verifies that the bootstrap token CANNOT be reused
	// It must run AFTER the successful token exchange above

	string endpoint = GetTestEndpoint(); // Get the same endpoint used above

	SECTION("Bootstrap token cannot be reused after successful exchange") {
		// Create a NEW database instance and try to use the SAME bootstrap token
		DBConfig config;
		config.options.allow_unsigned_extensions = true;
		DuckDB db(nullptr, &config);
		Connection con(db);
		con.Query("LOAD httpfs;");

		// Load local build
		string extension_path = GetBoilstreamExtensionPath();
		string load_sql = "LOAD '" + extension_path + "';";
		con.Query(load_sql);

		// Attempt to exchange the same bootstrap token that was already used
		string pragma_sql = "PRAGMA duckdb_secrets_boilstream_endpoint('" + endpoint + "');";
		auto result = con.Query(pragma_sql);

		// Should FAIL because bootstrap token is single-use
		REQUIRE(result->HasError());
		string error = result->GetError();

		// Error should indicate token exchange failed (token already used or expired)
		REQUIRE((error.find("Token exchange failed") != string::npos ||
		         error.find("expired") != string::npos ||
		         error.find("used") != string::npos ||
		         error.find("invalid") != string::npos));

		cout << "DEBUG: Reuse attempt correctly failed with: " << error << endl;
	}
}

//===----------------------------------------------------------------------===//
// Test: URL Validation (Client-Side Validation)
//===----------------------------------------------------------------------===//
TEST_CASE("Client-Side URL Validation", "[boilstream][integration][validation]") {
	// These tests verify client-side validation without making server calls

	SECTION("Empty bootstrap token rejected (client-side)") {
		DBConfig config;
		config.options.allow_unsigned_extensions = true;
		DuckDB db(nullptr, &config);
		Connection con(db);
		con.Query("LOAD httpfs;");

		string extension_path = GetBoilstreamExtensionPath();
		string load_sql = "LOAD '" + extension_path + "';";
		con.Query(load_sql);

		// Empty token should be rejected before making any HTTP request
		string pragma_sql = "PRAGMA duckdb_secrets_boilstream_endpoint('https://example.com/secrets:');";
		auto result = con.Query(pragma_sql);

		REQUIRE(result->HasError());
		string error = result->GetError();
		cout << "DEBUG: Error message for empty token: " << error << endl;
		REQUIRE((error.find("token") != string::npos || error.find("empty") != string::npos));
	}

	SECTION("Malformed URL rejected (client-side)") {
		DBConfig config;
		config.options.allow_unsigned_extensions = true;
		DuckDB db(nullptr, &config);
		Connection con(db);
		con.Query("LOAD httpfs;");

		string extension_path = GetBoilstreamExtensionPath();
		string load_sql = "LOAD '" + extension_path + "';";
		con.Query(load_sql);

		// Malformed URL should be rejected before making any HTTP request
		auto result = con.Query("PRAGMA duckdb_secrets_boilstream_endpoint('not_a_url:token');");
		REQUIRE(result->HasError());
	}

	SECTION("Missing path rejected (client-side)") {
		DBConfig config;
		config.options.allow_unsigned_extensions = true;
		DuckDB db(nullptr, &config);
		Connection con(db);
		con.Query("LOAD httpfs;");

		string extension_path = GetBoilstreamExtensionPath();
		string load_sql = "LOAD '" + extension_path + "';";
		con.Query(load_sql);

		// URL without path should be rejected
		auto result = con.Query("PRAGMA duckdb_secrets_boilstream_endpoint('https://example.com:token');");
		REQUIRE(result->HasError());
		string error = result->GetError();
		REQUIRE(error.find("path") != string::npos);
	}
}

//===----------------------------------------------------------------------===//
// Test: Secret CRUD Operations
//===----------------------------------------------------------------------===//
TEST_CASE("Secret CRUD Operations", "[boilstream][integration]") {
	// Use shared database instance (bootstrap token already exchanged)
	InitializeTestDatabase();
	Connection con(*g_test_db);

	SECTION("Create secret") {
		auto result = con.Query(
			"CREATE SECRET test_secret_crud_create ("
			"    TYPE S3,"
			"    KEY_ID 'test_access_key',"
			"    SECRET 'test_secret_key',"
			"    REGION 'us-east-1'"
			");"
		);

		if (result->HasError()) {
			WARN("Create secret failed: " << result->GetError());
		}
		REQUIRE_FALSE(result->HasError());
	}

	SECTION("List secrets includes created secret") {
		// Create a secret first
		auto create_result = con.Query(
			"CREATE SECRET test_secret_crud_list ("
			"    TYPE S3,"
			"    KEY_ID 'list_test_key',"
			"    SECRET 'list_test_secret'"
			");"
		);
		if (create_result->HasError()) {
			cout << "DEBUG: Create secret failed: " << create_result->GetError() << endl;
		}
		REQUIRE_FALSE(create_result->HasError());

		auto result = con.Query("FROM duckdb_secrets() WHERE name = 'test_secret_crud_list';");
		if (result->HasError()) {
			cout << "DEBUG: List secrets failed: " << result->GetError() << endl;
		}
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->RowCount() > 0);
	}

	SECTION("Delete secret") {
		// Create a secret first
		con.Query(
			"CREATE SECRET test_secret_crud_delete ("
			"    TYPE S3,"
			"    KEY_ID 'delete_test_key',"
			"    SECRET 'delete_test_secret'"
			");"
		);

		// Delete it
		auto result = con.Query("DROP SECRET test_secret_crud_delete;");
		REQUIRE_FALSE(result->HasError());

		// Verify it's gone
		auto check = con.Query("FROM duckdb_secrets() WHERE name = 'test_secret_crud_delete';");
		REQUIRE(check->RowCount() == 0);
	}

	SECTION("Update secret (drop and recreate)") {
		// Create initial secret
		con.Query(
			"CREATE SECRET test_secret_crud_update ("
			"    TYPE S3,"
			"    KEY_ID 'old_key',"
			"    SECRET 'old_secret'"
			");"
		);

		// Drop and recreate with new values
		con.Query("DROP SECRET test_secret_crud_update;");
		auto result = con.Query(
			"CREATE SECRET test_secret_crud_update ("
			"    TYPE S3,"
			"    KEY_ID 'new_key',"
			"    SECRET 'new_secret'"
			");"
		);

		REQUIRE_FALSE(result->HasError());
	}
}

//===----------------------------------------------------------------------===//
// Test: Token Rotation
//===----------------------------------------------------------------------===//
TEST_CASE("Token Rotation", "[boilstream][integration]") {
	// Use shared database instance (bootstrap token already exchanged)
	InitializeTestDatabase();
	Connection con(*g_test_db);

	SECTION("Operations work after token rotation") {
		// Create a secret (forces token usage)
		con.Query(
			"CREATE SECRET test_rotation_before ("
			"    TYPE S3,"
			"    KEY_ID 'before_rotation',"
			"    SECRET 'before_secret'"
			");"
		);

		// TODO: Trigger rotation (currently automatic when <30min remain)
		// For now, just verify operations still work

		// Create another secret (should work with same or rotated token)
		auto result = con.Query(
			"CREATE SECRET test_rotation_after ("
			"    TYPE S3,"
			"    KEY_ID 'after_rotation',"
			"    SECRET 'after_secret'"
			");"
		);

		REQUIRE_FALSE(result->HasError());
	}
}

//===----------------------------------------------------------------------===//
// Test: Error Handling
//===----------------------------------------------------------------------===//
TEST_CASE("Error Handling", "[boilstream][integration]") {
	// Use shared database instance (bootstrap token already exchanged)
	InitializeTestDatabase();
	Connection con(*g_test_db);

	SECTION("Delete non-existent secret returns clear error") {
		auto result = con.Query("DROP SECRET nonexistent_secret_12345;");
		// Should fail with clear error (not just "HTTP error")
		REQUIRE(result->HasError());
		string error = result->GetError();
		// Error should mention secret name or "not found"
		REQUIRE((error.find("nonexistent") != string::npos ||
		         error.find("not found") != string::npos ||
		         error.find("404") != string::npos));
	}

	SECTION("Invalid secret type rejected") {
		auto result = con.Query(
			"CREATE SECRET test_invalid_type ("
			"    TYPE INVALID_TYPE,"
			"    KEY_ID 'test'"
			");"
		);
		REQUIRE(result->HasError());
	}

	SECTION("Duplicate secret name rejected") {
		// Create first secret
		con.Query(
			"CREATE SECRET test_duplicate ("
			"    TYPE S3,"
			"    KEY_ID 'first'"
			");"
		);

		// Try to create duplicate
		auto result = con.Query(
			"CREATE SECRET test_duplicate ("
			"    TYPE S3,"
			"    KEY_ID 'second'"
			");"
		);

		REQUIRE(result->HasError());
		string error = result->GetError();
		REQUIRE((error.find("exists") != string::npos ||
		         error.find("duplicate") != string::npos));
	}
}

//===----------------------------------------------------------------------===//
// Test: Concurrent Operations
//===----------------------------------------------------------------------===//
TEST_CASE("Concurrent Operations", "[boilstream][integration]") {
	// Use shared database instance (bootstrap token already exchanged)
	InitializeTestDatabase();

	SECTION("Multiple connections can use secrets concurrently") {
		// Create multiple connections to the shared database
		Connection con1(*g_test_db);
		Connection con2(*g_test_db);

		// Both connections should be able to create secrets
		auto result1 = con1.Query(
			"CREATE SECRET test_concurrent_1 ("
			"    TYPE S3,"
			"    KEY_ID 'concurrent_1'"
			");"
		);
		auto result2 = con2.Query(
			"CREATE SECRET test_concurrent_2 ("
			"    TYPE S3,"
			"    KEY_ID 'concurrent_2'"
			");"
		);

		REQUIRE_FALSE(result1->HasError());
		REQUIRE_FALSE(result2->HasError());
	}
}

//===----------------------------------------------------------------------===//
// Test: HTTPS Enforcement
//===----------------------------------------------------------------------===//
TEST_CASE("HTTPS Enforcement", "[boilstream][integration]") {
	DBConfig config;
	config.options.allow_unsigned_extensions = true;
	DuckDB db(nullptr, &config);
	Connection con(db);
	con.Query("LOAD httpfs;");

	string extension_path = GetBoilstreamExtensionPath();
	string load_sql = "LOAD '" + extension_path + "';";
	con.Query(load_sql);

	SECTION("HTTP not allowed for non-localhost (must be HTTPS)") {
		auto result = con.Query("PRAGMA duckdb_secrets_boilstream_endpoint('http://example.com/secrets:token');");
		REQUIRE(result->HasError());
		string error = result->GetError();
		REQUIRE(error.find("HTTPS") != string::npos);
	}

	SECTION("Missing token in URL rejected") {
		auto result = con.Query("PRAGMA duckdb_secrets_boilstream_endpoint('https://example.com/secrets');");
		REQUIRE(result->HasError());
		string error = result->GetError();
		// Should mention token or colon
		REQUIRE((error.find("token") != string::npos || error.find(":") != string::npos));
	}
}
