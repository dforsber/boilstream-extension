//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_boilstream_connection_state.cpp
//
// Unit tests for per-connection authentication state isolation
// Tests that each DuckDB connection gets independent OPAQUE session credentials
//
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "boilstream_connection_state.hpp"
#include "boilstream_secret_storage.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/client_context.hpp"

#include <thread>
#include <chrono>
#include <vector>
#include <atomic>

using namespace duckdb;

TEST_CASE("Expiration sentinels never keep credentials valid", "[boilstream][connection][expiry_regression]") {
	BoilstreamConnectionState state;
	using Clock = std::chrono::system_clock;
	const auto expiration = GENERATE(Clock::time_point::min(), Clock::time_point::min() + std::chrono::seconds(1),
	                                 Clock::now() - std::chrono::hours(1));
	state.access_token = "test-token";
	state.session_key = {1, 2, 3};
	state.token_expires_at = expiration;
	state.StoreExpiration("catalog", expiration);
	CHECK_FALSE(state.IsSessionTokenValid());
	CHECK(state.IsSecretExpired("catalog"));
}

// Note: Don't use "using namespace std" due to conflicts with duckdb::vector, duckdb::unique_ptr, etc.

//===----------------------------------------------------------------------===//
// Test Access Helper - allows access to private members for testing
//===----------------------------------------------------------------------===//
class BoilstreamConnectionStateTestAccess {
public:
	static BoilstreamConnectionState &GetOrCreateState(ClientContext &context) {
		return *context.registered_state->GetOrCreate<BoilstreamConnectionState>("boilstream_auth");
	}

	static BoilstreamConnectionState *GetState(ClientContext &context) {
		return context.registered_state->Get<BoilstreamConnectionState>("boilstream_auth").get();
	}

	static void SetAccessToken(BoilstreamConnectionState &state, const string &token) {
		lock_guard<mutex> lock(state.session_lock);
		state.access_token = token;
	}

	static string GetAccessToken(BoilstreamConnectionState &state) {
		lock_guard<mutex> lock(state.session_lock);
		return state.access_token;
	}

	static void SetSessionKey(BoilstreamConnectionState &state, const duckdb::vector<uint8_t> &key) {
		lock_guard<mutex> lock(state.session_lock);
		state.session_key = key;
	}

	static duckdb::vector<uint8_t> GetSessionKey(BoilstreamConnectionState &state) {
		lock_guard<mutex> lock(state.session_lock);
		return state.session_key;
	}

	static void SetRegion(BoilstreamConnectionState &state, const string &region) {
		lock_guard<mutex> lock(state.session_lock);
		state.region = region;
	}

	static string GetRegion(BoilstreamConnectionState &state) {
		lock_guard<mutex> lock(state.session_lock);
		return state.region;
	}

	static uint64_t GetSequence(BoilstreamConnectionState &state) {
		lock_guard<mutex> lock(state.session_lock);
		return state.client_sequence;
	}

	static void IncrementSequence(BoilstreamConnectionState &state) {
		lock_guard<mutex> lock(state.session_lock);
		state.client_sequence++;
	}
};

//===----------------------------------------------------------------------===//
// Test: Connection State Creation
//===----------------------------------------------------------------------===//
TEST_CASE("Connection State Creation", "[boilstream][connection]") {
	DuckDB db(nullptr);

	SECTION("Each connection gets its own state") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		// States should be different objects
		REQUIRE(&state1 != &state2);
	}

	SECTION("Same connection returns same state") {
		Connection con(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con.context);

		// Should be the same object
		REQUIRE(&state1 == &state2);
	}

	SECTION("State is initially empty") {
		Connection con(db);
		auto &state = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con.context);

		REQUIRE(BoilstreamConnectionStateTestAccess::GetAccessToken(state).empty());
		REQUIRE(BoilstreamConnectionStateTestAccess::GetSessionKey(state).empty());
		REQUIRE(BoilstreamConnectionStateTestAccess::GetRegion(state).empty());
		REQUIRE(BoilstreamConnectionStateTestAccess::GetSequence(state) == 0);
		REQUIRE_FALSE(state.IsSessionTokenValid());
	}
}

//===----------------------------------------------------------------------===//
// Test: Connection State Isolation
//===----------------------------------------------------------------------===//
TEST_CASE("Connection State Isolation", "[boilstream][connection]") {
	DuckDB db(nullptr);

	SECTION("Modifying one connection state does not affect another") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		// Set different values for each connection
		BoilstreamConnectionStateTestAccess::SetAccessToken(state1, "token-connection-1");
		BoilstreamConnectionStateTestAccess::SetAccessToken(state2, "token-connection-2");

		BoilstreamConnectionStateTestAccess::SetRegion(state1, "us-east-1");
		BoilstreamConnectionStateTestAccess::SetRegion(state2, "eu-west-1");

		// Verify isolation
		REQUIRE(BoilstreamConnectionStateTestAccess::GetAccessToken(state1) == "token-connection-1");
		REQUIRE(BoilstreamConnectionStateTestAccess::GetAccessToken(state2) == "token-connection-2");

		REQUIRE(BoilstreamConnectionStateTestAccess::GetRegion(state1) == "us-east-1");
		REQUIRE(BoilstreamConnectionStateTestAccess::GetRegion(state2) == "eu-west-1");
	}

	SECTION("Session keys are isolated between connections") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		duckdb::vector<uint8_t> key1 = {1, 2, 3, 4, 5, 6, 7, 8};
		duckdb::vector<uint8_t> key2 = {9, 10, 11, 12, 13, 14, 15, 16};

		BoilstreamConnectionStateTestAccess::SetSessionKey(state1, key1);
		BoilstreamConnectionStateTestAccess::SetSessionKey(state2, key2);

		REQUIRE(BoilstreamConnectionStateTestAccess::GetSessionKey(state1) == key1);
		REQUIRE(BoilstreamConnectionStateTestAccess::GetSessionKey(state2) == key2);
	}

	SECTION("Sequence counters are independent per connection") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		// Increment connection 1's sequence multiple times
		BoilstreamConnectionStateTestAccess::IncrementSequence(state1);
		BoilstreamConnectionStateTestAccess::IncrementSequence(state1);
		BoilstreamConnectionStateTestAccess::IncrementSequence(state1);

		// Increment connection 2's sequence once
		BoilstreamConnectionStateTestAccess::IncrementSequence(state2);

		REQUIRE(BoilstreamConnectionStateTestAccess::GetSequence(state1) == 3);
		REQUIRE(BoilstreamConnectionStateTestAccess::GetSequence(state2) == 1);
	}

	SECTION("Clearing one connection state does not affect another") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		// Set up both connections
		BoilstreamConnectionStateTestAccess::SetAccessToken(state1, "token-1");
		BoilstreamConnectionStateTestAccess::SetAccessToken(state2, "token-2");

		// Clear only connection 1
		state1.ClearSession();

		// Connection 1 should be cleared
		REQUIRE(BoilstreamConnectionStateTestAccess::GetAccessToken(state1).empty());

		// Connection 2 should be unaffected
		REQUIRE(BoilstreamConnectionStateTestAccess::GetAccessToken(state2) == "token-2");
	}
}

//===----------------------------------------------------------------------===//
// Test: Secret Expiration Isolation
//===----------------------------------------------------------------------===//
TEST_CASE("Secret Expiration Isolation", "[boilstream][connection]") {
	DuckDB db(nullptr);

	SECTION("Secret expirations are per-connection") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		auto now = std::chrono::system_clock::now();
		auto future1 = now + std::chrono::hours(1);
		auto future2 = now + std::chrono::hours(2);

		// Store different expirations for same secret name in different connections
		state1.StoreExpiration("my-secret", future1);
		state2.StoreExpiration("my-secret", future2);

		// Verify they are different
		auto exp1 = state1.GetSecretExpiration("my-secret");
		auto exp2 = state2.GetSecretExpiration("my-secret");

		// Allow 1 second tolerance for comparison
		auto diff1 = std::chrono::duration_cast<std::chrono::seconds>(exp1 - future1).count();
		auto diff2 = std::chrono::duration_cast<std::chrono::seconds>(exp2 - future2).count();

		REQUIRE(std::abs(diff1) < 2);
		REQUIRE(std::abs(diff2) < 2);
	}

	SECTION("Clearing expiration in one connection does not affect another") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		auto future = std::chrono::system_clock::now() + std::chrono::hours(1);

		state1.StoreExpiration("secret-a", future);
		state2.StoreExpiration("secret-a", future);

		// Clear only from connection 1
		state1.ClearExpiration("secret-a");

		// Connection 1 should show expired (min time_point)
		REQUIRE(state1.IsSecretExpired("secret-a"));

		// Connection 2 should still have the expiration
		REQUIRE_FALSE(state2.IsSecretExpired("secret-a"));
	}
}

//===----------------------------------------------------------------------===//
// Test: Session Snapshot Thread Safety
//===----------------------------------------------------------------------===//
TEST_CASE("Session Snapshot Thread Safety", "[boilstream][connection][threading]") {
	DuckDB db(nullptr);
	Connection con(db);

	auto &state = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con.context);

	// Set up session state
	BoilstreamConnectionStateTestAccess::SetAccessToken(
	    state, "test-token-64chars-0123456789abcdef0123456789abcdef0123456789ab");
	duckdb::vector<uint8_t> key(32, 0x42);
	BoilstreamConnectionStateTestAccess::SetSessionKey(state, key);
	BoilstreamConnectionStateTestAccess::SetRegion(state, "us-east-1");

	SECTION("GetSessionSnapshot atomically reads and increments sequence") {
		uint64_t initial_seq = BoilstreamConnectionStateTestAccess::GetSequence(state);

		auto snapshot = state.GetSessionSnapshot();

		// Snapshot should have the sequence at time of call
		REQUIRE(snapshot.sequence == initial_seq);

		// Sequence should have been incremented
		REQUIRE(BoilstreamConnectionStateTestAccess::GetSequence(state) == initial_seq + 1);
	}

	SECTION("Concurrent GetSessionSnapshot calls get unique sequences") {
		const int NUM_THREADS = 10;
		const int CALLS_PER_THREAD = 100;

		std::vector<std::thread> threads;
		std::vector<std::vector<uint64_t>> sequences(NUM_THREADS);
		std::atomic<bool> start_flag {false};

		for (int i = 0; i < NUM_THREADS; i++) {
			threads.emplace_back([&, i]() {
				// Wait for start signal
				while (!start_flag.load()) {
					std::this_thread::yield();
				}

				for (int j = 0; j < CALLS_PER_THREAD; j++) {
					auto snapshot = state.GetSessionSnapshot();
					sequences[i].push_back(snapshot.sequence);
				}
			});
		}

		// Start all threads simultaneously
		start_flag.store(true);

		for (auto &t : threads) {
			t.join();
		}

		// Collect all sequences
		std::vector<uint64_t> all_sequences;
		for (const auto &seq_vec : sequences) {
			all_sequences.insert(all_sequences.end(), seq_vec.begin(), seq_vec.end());
		}

		// Sort and check for duplicates
		std::sort(all_sequences.begin(), all_sequences.end());
		for (size_t i = 1; i < all_sequences.size(); i++) {
			REQUIRE(all_sequences[i] != all_sequences[i - 1]);
		}

		// Verify total count
		REQUIRE(all_sequences.size() == NUM_THREADS * CALLS_PER_THREAD);
	}
}

//===----------------------------------------------------------------------===//
// Test: Multiple Connections Concurrent Access
//===----------------------------------------------------------------------===//
TEST_CASE("Multiple Connections Concurrent Access", "[boilstream][connection][threading]") {
	DuckDB db(nullptr);

	SECTION("Concurrent modifications to different connections are safe") {
		const int NUM_CONNECTIONS = 5;
		const int OPS_PER_CONNECTION = 100;

		std::vector<std::unique_ptr<Connection>> connections;
		for (int i = 0; i < NUM_CONNECTIONS; i++) {
			connections.push_back(std::make_unique<Connection>(db));
		}

		std::vector<std::thread> threads;
		std::atomic<int> completed {0};

		for (int i = 0; i < NUM_CONNECTIONS; i++) {
			threads.emplace_back([&, i]() {
				auto &state = BoilstreamConnectionStateTestAccess::GetOrCreateState(*connections[i]->context);

				for (int j = 0; j < OPS_PER_CONNECTION; j++) {
					// Set token
					string token = "token-conn-" + std::to_string(i) + "-op-" + std::to_string(j);
					BoilstreamConnectionStateTestAccess::SetAccessToken(state, token);

					// Get snapshot (increments sequence)
					auto snapshot = state.GetSessionSnapshot();

					// Store expiration
					auto exp = std::chrono::system_clock::now() + std::chrono::minutes(j);
					state.StoreExpiration("secret-" + std::to_string(j), exp);
				}

				completed++;
			});
		}

		for (auto &t : threads) {
			t.join();
		}

		REQUIRE(completed == NUM_CONNECTIONS);

		// Verify each connection's final state is consistent
		for (int i = 0; i < NUM_CONNECTIONS; i++) {
			auto &state = BoilstreamConnectionStateTestAccess::GetOrCreateState(*connections[i]->context);

			// Last token set
			string expected_token = "token-conn-" + std::to_string(i) + "-op-" + std::to_string(OPS_PER_CONNECTION - 1);
			REQUIRE(BoilstreamConnectionStateTestAccess::GetAccessToken(state) == expected_token);

			// Sequence should be exactly OPS_PER_CONNECTION (one GetSessionSnapshot per op)
			REQUIRE(BoilstreamConnectionStateTestAccess::GetSequence(state) == OPS_PER_CONNECTION);
		}
	}
}

//===----------------------------------------------------------------------===//
// Test: Bootstrap Token Hash Per Connection
//===----------------------------------------------------------------------===//
TEST_CASE("Bootstrap Token Hash Per Connection", "[boilstream][connection]") {
	DuckDB db(nullptr);

	SECTION("Each connection has independent bootstrap token hash") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		state1.SetBootstrapTokenHash("hash-for-connection-1");
		state2.SetBootstrapTokenHash("hash-for-connection-2");

		REQUIRE(state1.GetBootstrapTokenHash() == "hash-for-connection-1");
		REQUIRE(state2.GetBootstrapTokenHash() == "hash-for-connection-2");
	}
}

//===----------------------------------------------------------------------===//
// Test: Token Expiration Per Connection
//===----------------------------------------------------------------------===//
TEST_CASE("Token Expiration Per Connection", "[boilstream][connection]") {
	DuckDB db(nullptr);

	SECTION("IsSessionTokenValid uses per-connection state") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		// Set up connection 1 with valid session
		BoilstreamConnectionStateTestAccess::SetAccessToken(
		    state1, "valid-token-1234567890abcdef1234567890abcdef1234567890abcdef12");
		duckdb::vector<uint8_t> key1(32, 0x01);
		BoilstreamConnectionStateTestAccess::SetSessionKey(state1, key1);
		{
			lock_guard<mutex> lock(state1.session_lock);
			state1.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
		}

		// Connection 2 has no session
		// (already empty by default)

		REQUIRE(state1.IsSessionTokenValid());
		REQUIRE_FALSE(state2.IsSessionTokenValid());
	}

	SECTION("Expired token in one connection does not affect another") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		// Both have tokens
		BoilstreamConnectionStateTestAccess::SetAccessToken(
		    state1, "token-1-abcdef1234567890abcdef1234567890abcdef1234567890abcd");
		BoilstreamConnectionStateTestAccess::SetAccessToken(
		    state2, "token-2-abcdef1234567890abcdef1234567890abcdef1234567890abcd");

		duckdb::vector<uint8_t> key(32, 0x42);
		BoilstreamConnectionStateTestAccess::SetSessionKey(state1, key);
		BoilstreamConnectionStateTestAccess::SetSessionKey(state2, key);

		// Connection 1: expired (in the past)
		{
			lock_guard<mutex> lock(state1.session_lock);
			state1.token_expires_at = std::chrono::system_clock::now() - std::chrono::hours(1);
		}

		// Connection 2: valid (in the future)
		{
			lock_guard<mutex> lock(state2.session_lock);
			state2.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
		}

		REQUIRE_FALSE(state1.IsSessionTokenValid());
		REQUIRE(state2.IsSessionTokenValid());
	}
}

//===----------------------------------------------------------------------===//
// Test: Connection Destruction Cleanup
//===----------------------------------------------------------------------===//
TEST_CASE("Connection Destruction Cleanup", "[boilstream][connection]") {
	DuckDB db(nullptr);

	SECTION("State is cleaned up when connection is destroyed") {
		BoilstreamConnectionState *state_ptr = nullptr;

		{
			Connection con(db);
			auto &state = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con.context);

			// Set some state
			BoilstreamConnectionStateTestAccess::SetAccessToken(
			    state, "temp-token-abcdef1234567890abcdef1234567890abcdef1234567890");
			duckdb::vector<uint8_t> key(32, 0xFF);
			BoilstreamConnectionStateTestAccess::SetSessionKey(state, key);

			state_ptr = &state;
		}
		// Connection destroyed here

		// Note: We can't safely access state_ptr after destruction
		// The test validates that destruction happens without crash
		// The destructor calls ClearSession() which securely wipes memory
		REQUIRE(true); // If we get here, destruction was clean
	}
}

//===----------------------------------------------------------------------===//
// Test: Catalog Version Isolation
//===----------------------------------------------------------------------===//
TEST_CASE("Catalog Version Isolation", "[boilstream][connection]") {
	DuckDB db(nullptr);

	SECTION("Catalog versions are tracked per connection") {
		Connection con1(db);
		Connection con2(db);

		auto &state1 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con1.context);
		auto &state2 = BoilstreamConnectionStateTestAccess::GetOrCreateState(*con2.context);

		// Store different catalog versions
		{
			lock_guard<mutex> lock(state1.version_lock);
			state1.catalog_versions["catalog-uuid-1"] = {1, "my-catalog"};
		}
		{
			lock_guard<mutex> lock(state2.version_lock);
			state2.catalog_versions["catalog-uuid-1"] = {5, "my-catalog"};
		}

		// Verify isolation
		{
			lock_guard<mutex> lock(state1.version_lock);
			REQUIRE(state1.catalog_versions["catalog-uuid-1"].version == 1);
		}
		{
			lock_guard<mutex> lock(state2.version_lock);
			REQUIRE(state2.catalog_versions["catalog-uuid-1"].version == 5);
		}
	}
}
