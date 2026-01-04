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
#include "boilstream_connection_state.hpp"
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
// Test Fixture - Keeps Database alive for Storage
//===----------------------------------------------------------------------===//
struct TestFixture {
	duckdb::unique_ptr<DuckDB> db;
	duckdb::unique_ptr<RestApiSecretStorage> storage;

	TestFixture() {
		db = duckdb::make_uniq<DuckDB>(nullptr);
		storage = duckdb::make_uniq<RestApiSecretStorage>(*db->instance, "https://localhost/secrets");
	}
};

//===----------------------------------------------------------------------===//
// Test: Token Format Validation
//===----------------------------------------------------------------------===//
TEST_CASE("Token Format Validation", "[boilstream][security]") {
	TestFixture fixture;

	SECTION("Valid tokens pass validation") {
		// Minimum length (32 chars)
		string valid_min = "abcdefghijklmnopqrstuvwxyz012345";
		REQUIRE_NOTHROW(fixture.storage->ValidateTokenFormat(valid_min, "Test"));

		// Maximum length (512 chars)
		string valid_max(512, 'a');
		REQUIRE_NOTHROW(fixture.storage->ValidateTokenFormat(valid_max, "Test"));

		// Mixed alphanumeric with hyphens and underscores
		string valid_mixed = "aB1-_cD2-_eF3-_gH4-_iJ5-_kL6-_mN7";
		REQUIRE_NOTHROW(fixture.storage->ValidateTokenFormat(valid_mixed, "Test"));
	}

	SECTION("Empty token fails validation") {
		REQUIRE_THROWS_AS(fixture.storage->ValidateTokenFormat("", "Test"), IOException);
	}

	SECTION("Token too short fails validation") {
		string too_short = "abc123"; // < 32 chars
		REQUIRE_THROWS_AS(fixture.storage->ValidateTokenFormat(too_short, "Test"), IOException);
	}

	SECTION("Token too long fails validation") {
		string too_long(513, 'a'); // > 512 chars
		REQUIRE_THROWS_AS(fixture.storage->ValidateTokenFormat(too_long, "Test"), IOException);
	}

	SECTION("Invalid characters fail validation") {
		// Space
		REQUIRE_THROWS_AS(fixture.storage->ValidateTokenFormat("abcd efgh ijkl mnop qrst uvwx yz01", "Test"),
		                  IOException);

		// Special chars
		REQUIRE_THROWS_AS(fixture.storage->ValidateTokenFormat("abcd@efgh#ijkl$mnop%qrst^uvwx&yz01", "Test"),
		                  IOException);

		// Newline
		REQUIRE_THROWS_AS(fixture.storage->ValidateTokenFormat("abcdefghijklmnopqrstuvwxyz\n012345", "Test"),
		                  IOException);
	}
}

//===----------------------------------------------------------------------===//
// Test: Session Token State Management (using BoilstreamConnectionState)
//===----------------------------------------------------------------------===//
TEST_CASE("Session Token State Management", "[boilstream][security]") {
	// Test directly on BoilstreamConnectionState since session management moved there
	BoilstreamConnectionState conn_state;

	SECTION("IsSessionTokenValid returns false when token is empty") {
		REQUIRE(conn_state.IsSessionTokenValid() == false);
	}

	SECTION("ClearSession wipes all session state") {
		// Set some state first
		conn_state.access_token = "test_token";
		conn_state.session_key = {1, 2, 3, 4};
		conn_state.bootstrap_token_hash = "test_hash";

		conn_state.ClearSession();

		// After clear, session should be invalid
		REQUIRE(conn_state.IsSessionTokenValid() == false);
		REQUIRE(conn_state.access_token.empty());
		REQUIRE(conn_state.session_key.empty());
		REQUIRE(conn_state.bootstrap_token_hash.empty());
	}

	SECTION("Session token validity considers expiration") {
		// Set valid token and key
		conn_state.access_token = "valid_token";
		conn_state.session_key = {1, 2, 3, 4, 5, 6, 7, 8};

		// Set expiration to future (more than 30min buffer)
		conn_state.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);

		REQUIRE(conn_state.IsSessionTokenValid() == true);

		// Set expiration to past
		conn_state.token_expires_at = std::chrono::system_clock::now() - std::chrono::hours(1);
		REQUIRE(conn_state.IsSessionTokenValid() == false);
	}
}

//===----------------------------------------------------------------------===//
// Test: Connection User Mapping
//===----------------------------------------------------------------------===//
TEST_CASE("Connection User Mapping", "[boilstream][security]") {
	TestFixture fixture;

	SECTION("SetUserContextForConnection and retrieval") {
		idx_t conn_id = 42;
		string user_id = "test-user-123";

		fixture.storage->SetUserContextForConnection(conn_id, user_id);
		REQUIRE(fixture.storage->GetUserContextForConnection(conn_id) == user_id);
	}

	SECTION("GetUserContextForConnection returns anonymous for unknown connection") {
		idx_t unknown_conn_id = 999;
		REQUIRE(fixture.storage->GetUserContextForConnection(unknown_conn_id) == "anonymous");
	}

	SECTION("ClearConnectionMapping removes mapping") {
		idx_t conn_id = 42;
		string user_id = "test-user-123";

		fixture.storage->SetUserContextForConnection(conn_id, user_id);
		fixture.storage->ClearConnectionMapping(conn_id);
		REQUIRE(fixture.storage->GetUserContextForConnection(conn_id) == "anonymous");
	}

	SECTION("Multiple connections can have different users") {
		fixture.storage->SetUserContextForConnection(1, "user-1");
		fixture.storage->SetUserContextForConnection(2, "user-2");
		fixture.storage->SetUserContextForConnection(3, "user-3");

		REQUIRE(fixture.storage->GetUserContextForConnection(1) == "user-1");
		REQUIRE(fixture.storage->GetUserContextForConnection(2) == "user-2");
		REQUIRE(fixture.storage->GetUserContextForConnection(3) == "user-3");
	}
}

//===----------------------------------------------------------------------===//
// Test: Bootstrap Token Hash Management (using BoilstreamConnectionState)
//===----------------------------------------------------------------------===//
TEST_CASE("Bootstrap Token Hash Management", "[boilstream][security]") {
	BoilstreamConnectionState conn_state;

	SECTION("GetBootstrapTokenHash returns empty initially") {
		REQUIRE(conn_state.GetBootstrapTokenHash().empty());
	}

	SECTION("SetBootstrapTokenHash and retrieval") {
		string hash = "test-hash-value-32chars-long!";
		conn_state.SetBootstrapTokenHash(hash);
		REQUIRE(conn_state.GetBootstrapTokenHash() == hash);
	}

	SECTION("ClearSession clears bootstrap token hash") {
		conn_state.SetBootstrapTokenHash("test-hash");
		conn_state.ClearSession();
		REQUIRE(conn_state.GetBootstrapTokenHash().empty());
	}
}

//===----------------------------------------------------------------------===//
// Test: Session Management via RestApiSecretStorage
//===----------------------------------------------------------------------===//
TEST_CASE("Session Management via Storage", "[boilstream][security]") {
	TestFixture fixture;

	SECTION("GetOrCreateSession creates new session") {
		auto &session = fixture.storage->GetOrCreateSession("test_key_1");
		REQUIRE(session.access_token.empty());
		REQUIRE(session.IsSessionTokenValid() == false);
	}

	SECTION("GetOrCreateSession returns same session for same key") {
		auto &session1 = fixture.storage->GetOrCreateSession("test_key_2");
		session1.access_token = "modified";

		auto &session2 = fixture.storage->GetOrCreateSession("test_key_2");
		REQUIRE(session2.access_token == "modified");
	}

	SECTION("Different keys create different sessions") {
		auto &session1 = fixture.storage->GetOrCreateSession("key_a");
		auto &session2 = fixture.storage->GetOrCreateSession("key_b");

		session1.access_token = "token_a";
		session2.access_token = "token_b";

		REQUIRE(fixture.storage->GetOrCreateSession("key_a").access_token == "token_a");
		REQUIRE(fixture.storage->GetOrCreateSession("key_b").access_token == "token_b");
	}

	SECTION("HasSession returns correct status") {
		REQUIRE(fixture.storage->HasSession("nonexistent") == false);

		fixture.storage->GetOrCreateSession("exists");
		REQUIRE(fixture.storage->HasSession("exists") == true);
	}

	SECTION("GetSessionByKey returns nullptr for nonexistent") {
		REQUIRE(fixture.storage->GetSessionByKey("nope") == nullptr);
	}

	SECTION("GetSessionByKey returns session pointer") {
		fixture.storage->GetOrCreateSession("ptr_test");
		auto *ptr = fixture.storage->GetSessionByKey("ptr_test");
		REQUIRE(ptr != nullptr);
	}

	SECTION("SetActiveSessionKey and GetSession work together") {
		fixture.storage->GetOrCreateSession("active_test");
		fixture.storage->SetActiveSessionKey("active_test");

		auto *session = fixture.storage->GetSession(nullptr);
		REQUIRE(session != nullptr);
	}
}

//===----------------------------------------------------------------------===//
// Test: Thread Safety (Race Condition Detection)
//===----------------------------------------------------------------------===//
TEST_CASE("Thread Safety for Token Operations", "[boilstream][security][.]") {
	// Note: [.] tag means this test is hidden by default (run with --run-all)

	SECTION("Concurrent ClearSession calls on connection state") {
		BoilstreamConnectionState conn_state;
		const int num_threads = 10;

		std::vector<std::thread> threads;
		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&conn_state]() {
				for (int i = 0; i < 100; i++) {
					conn_state.ClearSession();
				}
			});
		}

		for (auto &thread : threads) {
			thread.join();
		}

		// Should not crash, and session should be cleared
		REQUIRE(conn_state.IsSessionTokenValid() == false);
	}

	SECTION("Concurrent user context mapping") {
		TestFixture fixture;
		const int num_threads = 5;
		const int ops_per_thread = 100;

		std::vector<std::thread> threads;
		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&fixture, t, ops_per_thread]() {
				for (int i = 0; i < ops_per_thread; i++) {
					idx_t conn_id = t * 1000 + i;
					string user_id = "user-" + std::to_string(t) + "-" + std::to_string(i);
					fixture.storage->SetUserContextForConnection(conn_id, user_id);

					// Verify immediately
					string retrieved = fixture.storage->GetUserContextForConnection(conn_id);
					REQUIRE(retrieved == user_id);

					// Clear mapping
					fixture.storage->ClearConnectionMapping(conn_id);
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
				REQUIRE(fixture.storage->GetUserContextForConnection(conn_id) == "anonymous");
			}
		}
	}

	SECTION("Concurrent session creation") {
		TestFixture fixture;
		const int num_threads = 10;

		std::vector<std::thread> threads;
		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&fixture, t]() {
				for (int i = 0; i < 50; i++) {
					string key = "session_" + std::to_string(t) + "_" + std::to_string(i);
					auto &session = fixture.storage->GetOrCreateSession(key);
					session.access_token = "token_" + key;
				}
			});
		}

		for (auto &thread : threads) {
			thread.join();
		}

		// Verify all sessions exist
		for (int t = 0; t < num_threads; t++) {
			for (int i = 0; i < 50; i++) {
				string key = "session_" + std::to_string(t) + "_" + std::to_string(i);
				REQUIRE(fixture.storage->HasSession(key));
			}
		}
	}
}

//===----------------------------------------------------------------------===//
// Test: Error Handling
//===----------------------------------------------------------------------===//
TEST_CASE("Error Handling for Token Validation", "[boilstream][security]") {
	TestFixture fixture;

	SECTION("Validation provides descriptive error messages") {
		try {
			fixture.storage->ValidateTokenFormat("", "Token exchange");
			REQUIRE(false); // Should not reach here
		} catch (const IOException &e) {
			string error_msg = e.what();
			REQUIRE(error_msg.find("Token exchange") != string::npos);
			REQUIRE(error_msg.find("Empty") != string::npos);
		}

		try {
			fixture.storage->ValidateTokenFormat("short", "Token rotation");
			REQUIRE(false);
		} catch (const IOException &e) {
			string error_msg = e.what();
			REQUIRE(error_msg.find("Token rotation") != string::npos);
			REQUIRE(error_msg.find("length") != string::npos);
		}

		try {
			fixture.storage->ValidateTokenFormat("invalid!@#$%^&*()characters123456", "Test context");
			REQUIRE(false);
		} catch (const IOException &e) {
			string error_msg = e.what();
			REQUIRE(error_msg.find("Test context") != string::npos);
			REQUIRE(error_msg.find("invalid characters") != string::npos);
		}
	}
}
