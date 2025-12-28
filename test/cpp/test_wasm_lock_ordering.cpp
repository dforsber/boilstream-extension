//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_wasm_lock_ordering.cpp
//
// Tests to verify that the session state lock pattern does not deadlock.
// After simplification, WASM uses a single global state with one lock,
// eliminating deadlock risk. This test verifies concurrent access is safe.
//
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <thread>
#include <mutex>
#include <chrono>
#include <atomic>
#include <vector>
#include <future>
#include <string>

using namespace std::chrono_literals;

//===----------------------------------------------------------------------===//
// Mock structure that mirrors BoilstreamConnectionState
//===----------------------------------------------------------------------===//
struct MockConnectionState {
	std::mutex session_lock;
	std::string session_key;
	std::string access_token;
	std::string refresh_token;
	std::string region;
	uint64_t client_sequence = 0;

	// Simulates GetSessionSnapshot - atomically reads and increments sequence
	uint64_t GetSessionSnapshot() {
		std::lock_guard<std::mutex> lock(session_lock);
		return client_sequence++;
	}

	void SetSession(const std::string &key, const std::string &token) {
		std::lock_guard<std::mutex> lock(session_lock);
		session_key = key;
		access_token = token;
	}

	bool HasSession() {
		std::lock_guard<std::mutex> lock(session_lock);
		return !session_key.empty();
	}

	void ClearSession() {
		std::lock_guard<std::mutex> lock(session_lock);
		session_key.clear();
		access_token.clear();
		client_sequence = 0;
	}
};

//===----------------------------------------------------------------------===//
// Test: Single Lock Pattern (WASM-style global state)
//===----------------------------------------------------------------------===//
TEST_CASE("Single lock pattern is deadlock-free", "[wasm][locking][threading]") {
	// This simulates WASM behavior: single global state, single lock
	MockConnectionState global_state;

	SECTION("Concurrent access to global state completes without deadlock") {
		const int NUM_THREADS = 8;
		const int OPS_PER_THREAD = 1000;
		std::atomic<bool> start_flag {false};
		std::atomic<int> completed {0};

		std::vector<std::future<void>> futures;

		for (int t = 0; t < NUM_THREADS; t++) {
			futures.push_back(std::async(std::launch::async, [&, t]() {
				while (!start_flag.load())
					std::this_thread::yield();

				for (int i = 0; i < OPS_PER_THREAD; i++) {
					switch (i % 4) {
					case 0:
						global_state.GetSessionSnapshot();
						break;
					case 1:
						global_state.SetSession("key-" + std::to_string(t), "token-" + std::to_string(i));
						break;
					case 2:
						(void)global_state.HasSession();
						break;
					case 3:
						if (t % 2 == 0) {
							global_state.ClearSession();
						}
						break;
					}
				}
				completed++;
			}));
		}

		start_flag.store(true);

		// Wait with timeout
		bool all_completed = true;
		for (auto &f : futures) {
			if (f.wait_for(10s) != std::future_status::ready) {
				all_completed = false;
				break;
			}
		}

		REQUIRE(all_completed);
		REQUIRE(completed == NUM_THREADS);
	}

	SECTION("Sequence numbers are unique under contention") {
		const int NUM_THREADS = 10;
		const int CALLS_PER_THREAD = 500;

		std::vector<std::future<std::vector<uint64_t>>> futures;
		std::atomic<bool> start_flag {false};

		for (int t = 0; t < NUM_THREADS; t++) {
			futures.push_back(std::async(std::launch::async, [&]() {
				std::vector<uint64_t> sequences;
				sequences.reserve(CALLS_PER_THREAD);

				while (!start_flag.load())
					std::this_thread::yield();

				for (int i = 0; i < CALLS_PER_THREAD; i++) {
					sequences.push_back(global_state.GetSessionSnapshot());
				}
				return sequences;
			}));
		}

		start_flag.store(true);

		// Collect all sequences
		std::vector<uint64_t> all_sequences;
		for (auto &f : futures) {
			REQUIRE(f.wait_for(10s) == std::future_status::ready);
			auto seqs = f.get();
			all_sequences.insert(all_sequences.end(), seqs.begin(), seqs.end());
		}

		// Sort and check for duplicates
		std::sort(all_sequences.begin(), all_sequences.end());
		for (size_t i = 1; i < all_sequences.size(); i++) {
			REQUIRE(all_sequences[i] != all_sequences[i - 1]);
		}

		REQUIRE(all_sequences.size() == NUM_THREADS * CALLS_PER_THREAD);
	}
}

//===----------------------------------------------------------------------===//
// Test: Stress Test Single Lock Pattern
//===----------------------------------------------------------------------===//
TEST_CASE("Stress test single lock pattern", "[wasm][locking][threading][stress]") {
	MockConnectionState global_state;

	SECTION("High contention completes without issues") {
		const int NUM_THREADS = 16;
		const int OPS_PER_THREAD = 2000;

		std::atomic<bool> start_flag {false};
		std::atomic<int> completed {0};
		std::atomic<uint64_t> total_ops {0};

		// Pre-initialize session
		global_state.SetSession("stress-test-key", "stress-test-token");

		std::vector<std::future<void>> futures;

		for (int t = 0; t < NUM_THREADS; t++) {
			futures.push_back(std::async(std::launch::async, [&, t]() {
				while (!start_flag.load())
					std::this_thread::yield();

				for (int i = 0; i < OPS_PER_THREAD; i++) {
					// Mix of operations
					if (i % 5 == 0) {
						global_state.ClearSession();
						global_state.SetSession("key-" + std::to_string(t), "token");
					} else if (i % 5 == 1) {
						global_state.GetSessionSnapshot();
					} else if (i % 5 == 2) {
						(void)global_state.HasSession();
					} else {
						// Just read sequence
						std::lock_guard<std::mutex> lock(global_state.session_lock);
						volatile auto seq = global_state.client_sequence;
						(void)seq;
					}
					total_ops++;
				}
				completed++;
			}));
		}

		start_flag.store(true);

		// Wait with generous timeout
		bool all_completed = true;
		for (auto &f : futures) {
			if (f.wait_for(30s) != std::future_status::ready) {
				all_completed = false;
				break;
			}
		}

		REQUIRE(all_completed);
		REQUIRE(completed == NUM_THREADS);
		REQUIRE(total_ops == NUM_THREADS * OPS_PER_THREAD);
	}
}

//===----------------------------------------------------------------------===//
// Test: Per-Connection State (Non-WASM style)
//===----------------------------------------------------------------------===//
TEST_CASE("Per-connection state isolation", "[native][locking][threading]") {
	// This simulates non-WASM behavior: each connection has its own state
	const int NUM_CONNECTIONS = 4;
	std::vector<MockConnectionState> connection_states(NUM_CONNECTIONS);

	SECTION("Independent connections don't interfere") {
		const int OPS_PER_CONNECTION = 500;
		std::atomic<bool> start_flag {false};
		std::atomic<int> completed {0};

		std::vector<std::future<void>> futures;

		for (int c = 0; c < NUM_CONNECTIONS; c++) {
			futures.push_back(std::async(std::launch::async, [&, c]() {
				while (!start_flag.load())
					std::this_thread::yield();

				auto &state = connection_states[c];
				state.SetSession("conn-" + std::to_string(c), "token-" + std::to_string(c));

				for (int i = 0; i < OPS_PER_CONNECTION; i++) {
					state.GetSessionSnapshot();
				}
				completed++;
			}));
		}

		start_flag.store(true);

		for (auto &f : futures) {
			REQUIRE(f.wait_for(10s) == std::future_status::ready);
		}

		REQUIRE(completed == NUM_CONNECTIONS);

		// Each connection should have its own sequence
		for (int c = 0; c < NUM_CONNECTIONS; c++) {
			std::lock_guard<std::mutex> lock(connection_states[c].session_lock);
			REQUIRE(connection_states[c].client_sequence == OPS_PER_CONNECTION);
			REQUIRE(connection_states[c].session_key == "conn-" + std::to_string(c));
		}
	}
}
