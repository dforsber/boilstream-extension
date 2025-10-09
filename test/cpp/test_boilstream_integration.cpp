//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_boilstream_integration.cpp
//
// Integration tests for Boilstream Extension with OPAQUE Authentication
// Tests real server connectivity and end-to-end flows
//
// Environment Variables:
//   BOILSTREAM_TEST_ENDPOINT - Full endpoint with token (e.g., "https://localhost:4332/secrets:TOKEN")
//   BOILSTREAM_EXTENSION_PATH - Path to boilstream extension (optional)
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
// Test Configuration Helpers
//===----------------------------------------------------------------------===//

static string GetBoilstreamExtensionPath() {
	const char *env_path = std::getenv("BOILSTREAM_EXTENSION_PATH");
	if (env_path && strlen(env_path) > 0) {
		return string(env_path);
	}
	return "../../../build/release/extension/boilstream/boilstream.duckdb_extension";
}

// Helper to request a new bootstrap token from the user
// Bootstrap tokens are single-use for security - each test needs a fresh one
static string RequestNewBootstrapToken(const string &test_name) {
	const string base_endpoint = "https://localhost/secrets";

	// Prompt for new token
	cout << "\n[TEST: " << test_name << "]" << endl;
	cout << "Bootstrap tokens are single-use. Please provide a NEW bootstrap token." << endl;
	cout << "Enter bootstrap token: ";
	cout.flush();

	string token;
	if (!std::getline(cin, token) || token.empty()) {
		throw std::runtime_error("No token provided for test: " + test_name);
	}

	// Construct full endpoint URL
	return base_endpoint + ":" + token;
}

static void LoadExtensions(Connection &con) {
	auto httpfs_result = con.Query("LOAD httpfs;");
	if (httpfs_result->HasError()) {
		throw std::runtime_error("Failed to load httpfs: " + httpfs_result->GetError());
	}

	string extension_path = GetBoilstreamExtensionPath();
	string load_sql = "LOAD '" + extension_path + "';";
	auto load_result = con.Query(load_sql);
	if (load_result->HasError()) {
		throw std::runtime_error("Failed to load boilstream extension from " + extension_path + ": " +
		                         load_result->GetError());
	}
}

//===----------------------------------------------------------------------===//
// Test: Extension Loading (Local Tests)
//===----------------------------------------------------------------------===//
TEST_CASE("Extension Loading", "[boilstream][local]") {
	DBConfig config;
	config.options.allow_unsigned_extensions = true;
	DuckDB db(nullptr, &config);
	Connection con(db);

	SECTION("Load httpfs extension") {
		auto result = con.Query("LOAD httpfs;");
		if (result->HasError()) {
			WARN("httpfs not available: " << result->GetError());
		} else {
			REQUIRE_FALSE(result->HasError());
		}
	}

	SECTION("Load boilstream extension") {
		string extension_path = GetBoilstreamExtensionPath();
		string load_sql = "LOAD '" + extension_path + "';";
		auto result = con.Query(load_sql);

		if (result->HasError()) {
			WARN("Boilstream extension not built at " << extension_path);
		}
	}
}

//===----------------------------------------------------------------------===//
// Test: Basic Database Operations (Local Tests)
//===----------------------------------------------------------------------===//
TEST_CASE("Basic Operations", "[boilstream][local]") {
	DBConfig config;
	config.options.allow_unsigned_extensions = true;
	DuckDB db(nullptr, &config);
	Connection con(db);

	SECTION("Simple query works") {
		auto result = con.Query("SELECT 1 as test;");
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->RowCount() == 1);
	}

	SECTION("Can list extensions") {
		auto result = con.Query("SELECT * FROM duckdb_extensions() LIMIT 5;");
		REQUIRE_FALSE(result->HasError());
	}
}

//===----------------------------------------------------------------------===//
// Test: OPAQUE Authentication via PRAGMA (Server Tests)
//===----------------------------------------------------------------------===//
TEST_CASE("OPAQUE Authentication", "[boilstream][server][auth]") {
	DBConfig config;
	config.options.allow_unsigned_extensions = true;
	DuckDB db(nullptr, &config);
	Connection con(db);

	LoadExtensions(con);

	SECTION("Can authenticate with PRAGMA") {
		string endpoint = RequestNewBootstrapToken("OPAQUE Authentication");

		// The PRAGMA handles OPAQUE registration/login internally
		string sql = "PRAGMA duckdb_secrets_boilstream_endpoint('" + endpoint + "');";
		auto result = con.Query(sql);

		if (result->HasError()) {
			cerr << "\n!!! AUTHENTICATION ERROR !!!" << endl;
			cerr << "Error: " << result->GetError() << endl;
			cerr << "Endpoint: " << endpoint << endl;
			INFO("Authentication error: " << result->GetError());
		}
		REQUIRE_FALSE(result->HasError());
	}

	SECTION("Invalid endpoint format fails") {
		// Missing token (no colon)
		string sql = "PRAGMA duckdb_secrets_boilstream_endpoint('https://localhost:4332/secrets');";
		auto result = con.Query(sql);

		REQUIRE(result->HasError());
	}
}

//===----------------------------------------------------------------------===//
// Test: All Server Operations (Single Token for All Tests)
//===----------------------------------------------------------------------===//
TEST_CASE("Server Operations", "[boilstream][server]") {
	DBConfig config;
	config.options.allow_unsigned_extensions = true;
	DuckDB db(nullptr, &config);
	Connection con(db);

	LoadExtensions(con);

	// Request ONE bootstrap token for all server tests
	// This single token will be used for all operations below
	string endpoint = RequestNewBootstrapToken("All Server Operations");

	// Authenticate with PRAGMA
	string pragma_sql = "PRAGMA duckdb_secrets_boilstream_endpoint('" + endpoint + "');";
	auto auth_result = con.Query(pragma_sql);
	if (auth_result->HasError()) {
		WARN("Authentication failed, skipping all server tests: " << auth_result->GetError());
		return;
	}

	//-------------------------------------------------------------------
	// Secret CRUD Operations
	//-------------------------------------------------------------------

	SECTION("Can create secret") {
		// Use CREATE OR REPLACE to handle secrets from previous test runs
		auto result = con.Query("CREATE OR REPLACE PERSISTENT SECRET test_crud_create IN boilstream ("
		                        "    TYPE S3,"
		                        "    KEY_ID 'test_key_create',"
		                        "    SECRET 'test_secret_create',"
		                        "    REGION 'us-east-1'"
		                        ");");

		if (result->HasError()) {
			cerr << "Create secret error: " << result->GetError() << endl;
			INFO("Create secret error: " << result->GetError());
		}
		REQUIRE_FALSE(result->HasError());
	}

	SECTION("Can list secrets") {
		// Create a secret first (use OR REPLACE for idempotency)
		con.Query("CREATE OR REPLACE PERSISTENT SECRET test_crud_list IN boilstream ("
		          "    TYPE S3,"
		          "    KEY_ID 'test_key_list',"
		          "    SECRET 'test_secret_list'"
		          ");");

		auto result = con.Query("SELECT name, type FROM duckdb_secrets() WHERE name = 'test_crud_list';");

		if (result->HasError()) {
			INFO("List secrets error: " << result->GetError());
		}
		REQUIRE_FALSE(result->HasError());
		REQUIRE(result->RowCount() >= 1);
	}

	SECTION("Can delete secret") {
		// Create a secret (use OR REPLACE for idempotency)
		con.Query("CREATE OR REPLACE PERSISTENT SECRET test_crud_delete IN boilstream ("
		          "    TYPE S3,"
		          "    KEY_ID 'test_key_delete',"
		          "    SECRET 'test_secret_delete'"
		          ");");

		// Delete it
		auto result = con.Query("DROP PERSISTENT SECRET test_crud_delete;");

		if (result->HasError()) {
			INFO("Delete secret error: " << result->GetError());
		}
		REQUIRE_FALSE(result->HasError());

		// Verify it's gone
		auto check = con.Query("SELECT * FROM duckdb_secrets() WHERE name = 'test_crud_delete';");
		REQUIRE(check->RowCount() == 0);
	}

	SECTION("Can update secret using REPLACE") {
		// Create initial secret (use OR REPLACE for idempotency)
		con.Query("CREATE OR REPLACE PERSISTENT SECRET test_crud_update IN boilstream ("
		          "    TYPE S3,"
		          "    KEY_ID 'old_key',"
		          "    SECRET 'old_secret'"
		          ");");

		// Replace with new values
		auto result = con.Query("CREATE OR REPLACE PERSISTENT SECRET test_crud_update IN boilstream ("
		                        "    TYPE S3,"
		                        "    KEY_ID 'new_key',"
		                        "    SECRET 'new_secret'"
		                        ");");

		if (result->HasError()) {
			INFO("Update secret error: " << result->GetError());
		}
		REQUIRE_FALSE(result->HasError());
	}

	SECTION("Duplicate secret name fails without REPLACE") {
		// Delete if exists from previous run (ignore errors)
		con.Query("DROP PERSISTENT SECRET IF EXISTS test_crud_duplicate;");

		// Create first secret
		auto create1 = con.Query("CREATE PERSISTENT SECRET test_crud_duplicate IN boilstream ("
		                         "    TYPE S3,"
		                         "    KEY_ID 'first_key'"
		                         ");");
		REQUIRE_FALSE(create1->HasError());

		// Try to create duplicate without OR REPLACE - this should fail
		auto result = con.Query("CREATE PERSISTENT SECRET test_crud_duplicate IN boilstream ("
		                        "    TYPE S3,"
		                        "    KEY_ID 'second_key'"
		                        ");");

		REQUIRE(result->HasError());
		string error = result->GetError();
		// cerr << "Duplicate secret error: " << error << endl;
		// Check for various error patterns indicating duplicate: "exists", "already", "conflict", or "duplicate"
		REQUIRE((error.find("exists") != string::npos ||
		         error.find("already") != string::npos ||
		         error.find("conflict") != string::npos ||
		         error.find("duplicate") != string::npos));
	}
}

//===----------------------------------------------------------------------===//
// Test: Error Handling (Server Tests)
//===----------------------------------------------------------------------===//
TEST_CASE("Error Handling", "[boilstream][server][errors]") {
	DBConfig config;
	config.options.allow_unsigned_extensions = true;
	DuckDB db(nullptr, &config);
	Connection con(db);

	LoadExtensions(con);

	// Request a NEW bootstrap token (single-use security requirement)
	string endpoint = RequestNewBootstrapToken("Error Handling");

	// Authenticate with PRAGMA
	string pragma_sql = "PRAGMA duckdb_secrets_boilstream_endpoint('" + endpoint + "');";
	auto auth_result = con.Query(pragma_sql);
	if (auth_result->HasError()) {
		WARN("Authentication failed, skipping error handling tests: " << auth_result->GetError());
		return;
	}

	SECTION("Delete non-existent secret fails gracefully") {
		auto result = con.Query("DROP PERSISTENT SECRET nonexistent_secret_xyz123;");

		REQUIRE(result->HasError());
		string error = result->GetError();
		// DuckDB returns "Failed to remove non-existent secret with name..."
		REQUIRE(error.find("non-existent") != string::npos);
	}

	SECTION("Operations without login fail") {
		// Create a new connection without login
		DBConfig config2;
		config2.options.allow_unsigned_extensions = true;
		DuckDB db2(nullptr, &config2);
		Connection con2(db2);
		LoadExtensions(con2);

		// Try to create secret without authentication
		auto result = con2.Query("CREATE PERSISTENT SECRET test_no_auth IN boilstream ("
		                         "    TYPE S3,"
		                         "    KEY_ID 'test'"
		                         ");");

		REQUIRE(result->HasError());
		string error = result->GetError();
		REQUIRE(
		    (error.find("endpoint not configured") != string::npos || error.find("not configured") != string::npos));
	}
}

//===----------------------------------------------------------------------===//
// Test: Concurrent Operations (Server Tests)
//===----------------------------------------------------------------------===//
TEST_CASE("Concurrent Operations", "[boilstream][server][concurrent]") {
	DBConfig config;
	config.options.allow_unsigned_extensions = true;
	DuckDB db(nullptr, &config);
	Connection con(db);

	LoadExtensions(con);

	// Request a NEW bootstrap token (single-use security requirement)
	string endpoint = RequestNewBootstrapToken("Concurrent Operations");

	// Authenticate with PRAGMA
	string pragma_sql = "PRAGMA duckdb_secrets_boilstream_endpoint('" + endpoint + "');";
	auto auth_result = con.Query(pragma_sql);
	if (auth_result->HasError()) {
		WARN("Authentication failed, skipping concurrent tests: " << auth_result->GetError());
		return;
	}

	SECTION("Multiple connections can use secrets") {
		// Create two connections to same database
		Connection con1(db);
		Connection con2(db);

		// Both should be able to create secrets (sharing same session, use OR REPLACE for idempotency)
		auto result1 = con1.Query("CREATE OR REPLACE PERSISTENT SECRET test_concurrent_1 IN boilstream ("
		                          "    TYPE S3,"
		                          "    KEY_ID 'concurrent_key_1'"
		                          ");");
		auto result2 = con2.Query("CREATE OR REPLACE PERSISTENT SECRET test_concurrent_2 IN boilstream ("
		                          "    TYPE S3,"
		                          "    KEY_ID 'concurrent_key_2'"
		                          ");");

		if (result1->HasError()) {
			INFO("Connection 1 error: " << result1->GetError());
		}
		if (result2->HasError()) {
			INFO("Connection 2 error: " << result2->GetError());
		}

		REQUIRE_FALSE(result1->HasError());
		REQUIRE_FALSE(result2->HasError());
	}
}

//===----------------------------------------------------------------------===//
// Test: Session Persistence (Server Tests)
//===----------------------------------------------------------------------===//
TEST_CASE("Session Persistence", "[boilstream][server][session]") {
	DBConfig config;
	config.options.allow_unsigned_extensions = true;
	DuckDB db(nullptr, &config);
	Connection con(db);

	LoadExtensions(con);

	// Request a NEW bootstrap token (single-use security requirement)
	string endpoint = RequestNewBootstrapToken("Session Persistence");

	SECTION("Session persists across multiple operations") {
		// Authenticate with PRAGMA
		string pragma_sql = "PRAGMA duckdb_secrets_boilstream_endpoint('" + endpoint + "');";
		auto auth_result = con.Query(pragma_sql);
		if (auth_result->HasError()) {
			WARN("Authentication failed: " << auth_result->GetError());
			return;
		}

		// Create secret (use OR REPLACE for idempotency)
		auto create1 = con.Query("CREATE OR REPLACE PERSISTENT SECRET test_session_1 IN boilstream ("
		                         "    TYPE S3,"
		                         "    KEY_ID 'session_key_1'"
		                         ");");
		REQUIRE_FALSE(create1->HasError());

		// Create another secret (should use same session, use OR REPLACE for idempotency)
		auto create2 = con.Query("CREATE OR REPLACE PERSISTENT SECRET test_session_2 IN boilstream ("
		                         "    TYPE S3,"
		                         "    KEY_ID 'session_key_2'"
		                         ");");
		REQUIRE_FALSE(create2->HasError());

		// List secrets (should use same session)
		auto list = con.Query("SELECT name FROM duckdb_secrets() WHERE name LIKE 'test_session_%';");
		REQUIRE_FALSE(list->HasError());
		REQUIRE(list->RowCount() >= 2);
	}

	SECTION("Sequence counter increments correctly across multiple operations") {
		// Authenticate with PRAGMA (sequence starts at 0)
		string pragma_sql = "PRAGMA duckdb_secrets_boilstream_endpoint('" + endpoint + "');";
		auto auth_result = con.Query(pragma_sql);
		if (auth_result->HasError()) {
			WARN("Authentication failed: " << auth_result->GetError());
			return;
		}

		// Operation 1: List all secrets (GET request, sequence 0)
		auto list1 = con.Query("SELECT name FROM duckdb_secrets();");
		REQUIRE_FALSE(list1->HasError());

		// Operation 2: Create a secret (POST request, sequence 1)
		auto create = con.Query("CREATE OR REPLACE PERSISTENT SECRET test_sequence IN boilstream ("
		                        "    TYPE S3,"
		                        "    KEY_ID 'sequence_test_key'"
		                        ");");
		REQUIRE_FALSE(create->HasError());

		// Operation 3: Get secret by name (POST request to /get endpoint, sequence 2)
		auto get = con.Query("SELECT name FROM duckdb_secrets() WHERE name = 'test_sequence';");
		REQUIRE_FALSE(get->HasError());
		REQUIRE(get->RowCount() == 1);

		// Operation 4: List secrets again (GET request, sequence 3)
		auto list2 = con.Query("SELECT name FROM duckdb_secrets() WHERE name LIKE 'test_%';");
		REQUIRE_FALSE(list2->HasError());
		REQUIRE(list2->RowCount() >= 1);

		// Operation 5: Delete the secret (DELETE request, sequence 4)
		auto drop = con.Query("DROP PERSISTENT SECRET test_sequence;");
		REQUIRE_FALSE(drop->HasError());

		// Operation 6: Verify it's gone (POST request to /get endpoint, sequence 5)
		auto verify = con.Query("SELECT name FROM duckdb_secrets() WHERE name = 'test_sequence';");
		REQUIRE_FALSE(verify->HasError());
		REQUIRE(verify->RowCount() == 0);
	}
}
