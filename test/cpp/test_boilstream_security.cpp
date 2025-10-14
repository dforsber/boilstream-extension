//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_boilstream_security.cpp
//
// Unit tests for Boilstream Extension Security Features
//
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "boilstream_secret_storage.hpp"
#include "mbedtls_wrapper.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/common/types/blob.hpp"

#include <thread>
#include <chrono>

using namespace duckdb;
using namespace std;

//===----------------------------------------------------------------------===//
// Helper: Create Test Storage Instance
//===----------------------------------------------------------------------===//
static duckdb::unique_ptr<RestApiSecretStorage> CreateTestStorage() {
	auto db = duckdb::make_uniq<DuckDB>(nullptr);
	return duckdb::make_uniq<RestApiSecretStorage>(*db->instance, "https://localhost/secrets");
}

//===----------------------------------------------------------------------===//
// Test: Token Format Validation
//===----------------------------------------------------------------------===//
TEST_CASE("Token Format Validation", "[boilstream][security]") {
	auto storage = CreateTestStorage();

	SECTION("Valid tokens pass validation") {
		// Minimum length (32 chars)
		string valid_min = "abcdefghijklmnopqrstuvwxyz012345";
		REQUIRE_NOTHROW(storage->ValidateTokenFormat(valid_min, "Test"));

		// Maximum length (512 chars)
		string valid_max(512, 'a');
		REQUIRE_NOTHROW(storage->ValidateTokenFormat(valid_max, "Test"));

		// Mixed alphanumeric with hyphens and underscores
		string valid_mixed = "aB1-_cD2-_eF3-_gH4-_iJ5-_kL6-_mN7";
		REQUIRE_NOTHROW(storage->ValidateTokenFormat(valid_mixed, "Test"));
	}

	SECTION("Empty token fails validation") {
		REQUIRE_THROWS_AS(storage->ValidateTokenFormat("", "Test"), IOException);
	}

	SECTION("Token too short fails validation") {
		string too_short = "abc123"; // < 32 chars
		REQUIRE_THROWS_AS(storage->ValidateTokenFormat(too_short, "Test"), IOException);
	}

	SECTION("Token too long fails validation") {
		string too_long(513, 'a'); // > 512 chars
		REQUIRE_THROWS_AS(storage->ValidateTokenFormat(too_long, "Test"), IOException);
	}

	SECTION("Invalid characters fail validation") {
		// Space
		REQUIRE_THROWS_AS(storage->ValidateTokenFormat("abcd efgh ijkl mnop qrst uvwx yz01", "Test"), IOException);

		// Special chars
		REQUIRE_THROWS_AS(storage->ValidateTokenFormat("abcd@efgh#ijkl$mnop%qrst^uvwx&yz01", "Test"), IOException);

		// Newline
		REQUIRE_THROWS_AS(storage->ValidateTokenFormat("abcdefghijklmnopqrstuvwxyz\n012345", "Test"), IOException);
	}
}

//===----------------------------------------------------------------------===//
// Test: Session Token State Management
//===----------------------------------------------------------------------===//
TEST_CASE("Session Token State Management", "[boilstream][security]") {
	auto storage = CreateTestStorage();

	SECTION("IsSessionTokenValid returns false when token is empty") {
		REQUIRE(storage->IsSessionTokenValid() == false);
	}

	SECTION("ClearSession wipes all session state") {
		storage->ClearSession();

		// After clear, session should be invalid
		REQUIRE(storage->IsSessionTokenValid() == false);
	}
}

//===----------------------------------------------------------------------===//
// Test: Connection User Mapping
//===----------------------------------------------------------------------===//
TEST_CASE("Connection User Mapping", "[boilstream][security]") {
	auto storage = CreateTestStorage();

	SECTION("SetUserContextForConnection and retrieval") {
		idx_t conn_id = 42;
		string user_id = "test-user-123";

		storage->SetUserContextForConnection(conn_id, user_id);
		REQUIRE(storage->GetUserContextForConnection(conn_id) == user_id);
	}

	SECTION("GetUserContextForConnection returns anonymous for unknown connection") {
		idx_t unknown_conn_id = 999;
		REQUIRE(storage->GetUserContextForConnection(unknown_conn_id) == "anonymous");
	}

	SECTION("ClearConnectionMapping removes mapping") {
		idx_t conn_id = 42;
		string user_id = "test-user-123";

		storage->SetUserContextForConnection(conn_id, user_id);
		storage->ClearConnectionMapping(conn_id);
		REQUIRE(storage->GetUserContextForConnection(conn_id) == "anonymous");
	}

	SECTION("Multiple connections can have different users") {
		storage->SetUserContextForConnection(1, "user-1");
		storage->SetUserContextForConnection(2, "user-2");
		storage->SetUserContextForConnection(3, "user-3");

		REQUIRE(storage->GetUserContextForConnection(1) == "user-1");
		REQUIRE(storage->GetUserContextForConnection(2) == "user-2");
		REQUIRE(storage->GetUserContextForConnection(3) == "user-3");
	}
}

//===----------------------------------------------------------------------===//
// Test: Bootstrap Token Hash Management
//===----------------------------------------------------------------------===//
TEST_CASE("Bootstrap Token Hash Management", "[boilstream][security]") {
	auto storage = CreateTestStorage();

	SECTION("GetBootstrapTokenHash returns empty initially") {
		REQUIRE(storage->GetBootstrapTokenHash().empty());
	}

	SECTION("SetBootstrapTokenHash and retrieval") {
		string hash = "test-hash-value-32chars-long!";
		storage->SetBootstrapTokenHash(hash);
		REQUIRE(storage->GetBootstrapTokenHash() == hash);
	}

	SECTION("ClearSession clears bootstrap token hash") {
		storage->SetBootstrapTokenHash("test-hash");
		storage->ClearSession();
		REQUIRE(storage->GetBootstrapTokenHash().empty());
	}
}

//===----------------------------------------------------------------------===//
// Test: Thread Safety (Race Condition Detection)
//===----------------------------------------------------------------------===//
TEST_CASE("Thread Safety for Token Operations", "[boilstream][security][.]") {
	// Note: [.] tag means this test is hidden by default (run with --run-all)

	SECTION("Concurrent ClearSession calls") {
		auto storage = CreateTestStorage();
		const int num_threads = 10;

		std::vector<std::thread> threads;
		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&storage]() {
				for (int i = 0; i < 100; i++) {
					storage->ClearSession();
				}
			});
		}

		for (auto &thread : threads) {
			thread.join();
		}

		// Should not crash, and session should be cleared
		REQUIRE(storage->IsSessionTokenValid() == false);
	}

	SECTION("Concurrent user context mapping") {
		auto storage = CreateTestStorage();
		const int num_threads = 5;
		const int ops_per_thread = 100;

		std::vector<std::thread> threads;
		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&storage, t, ops_per_thread]() {
				for (int i = 0; i < ops_per_thread; i++) {
					idx_t conn_id = t * 1000 + i;
					string user_id = "user-" + std::to_string(t) + "-" + std::to_string(i);
					storage->SetUserContextForConnection(conn_id, user_id);

					// Verify immediately
					string retrieved = storage->GetUserContextForConnection(conn_id);
					REQUIRE(retrieved == user_id);

					// Clear mapping
					storage->ClearConnectionMapping(conn_id);
				}
			});
		}

		for (auto &thread : threads) {
			thread.join();
		}

		// All mappings should be cleared (return to anonymous)
		for (int t = 0; t < num_threads; t++) {
			for (int i = 0; i < ops_per_thread; i++) {
				idx_t conn_id = t * 1000 + i;
				REQUIRE(storage->GetUserContextForConnection(conn_id) == "anonymous");
			}
		}
	}
}

//===----------------------------------------------------------------------===//
// Test: Error Handling
//===----------------------------------------------------------------------===//
TEST_CASE("Error Handling for Token Validation", "[boilstream][security]") {
	auto storage = CreateTestStorage();

	SECTION("Validation provides descriptive error messages") {
		try {
			storage->ValidateTokenFormat("", "Token exchange");
			REQUIRE(false); // Should not reach here
		} catch (const IOException &e) {
			string error_msg = e.what();
			REQUIRE(error_msg.find("Token exchange") != string::npos);
			REQUIRE(error_msg.find("Empty") != string::npos);
		}

		try {
			storage->ValidateTokenFormat("short", "Token rotation");
			REQUIRE(false);
		} catch (const IOException &e) {
			string error_msg = e.what();
			REQUIRE(error_msg.find("Token rotation") != string::npos);
			REQUIRE(error_msg.find("length") != string::npos);
		}

		try {
			storage->ValidateTokenFormat("invalid!@#$%^&*()characters123456", "Test context");
			REQUIRE(false);
		} catch (const IOException &e) {
			string error_msg = e.what();
			REQUIRE(error_msg.find("Test context") != string::npos);
			REQUIRE(error_msg.find("invalid characters") != string::npos);
		}
	}
}
