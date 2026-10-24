// Native concurrency tests of the production session class. The historical
// filename/target is retained; this does not qualify browser/WASM execution.
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "boilstream_connection_state.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <future>
#include <numeric>
#include <thread>
#include <vector>

using duckdb::BoilstreamConnectionState;

// Publish consistent fixture credentials under the actual state's lock.
static void SetCredentials(BoilstreamConnectionState &state, uint8_t identity) {
	duckdb::lock_guard<duckdb::mutex> lock(state.session_lock);
	state.access_token = "token-" + std::to_string(identity);
	state.session_key.assign(32, identity);
	state.region = "region-" + std::to_string(identity);
}

static bool Matches(const BoilstreamConnectionState::SessionSnapshot &snapshot, uint8_t identity) {
	return snapshot.has_session_key && snapshot.session_key.size() == 32 &&
	       std::all_of(snapshot.session_key.begin(), snapshot.session_key.end(),
	                   [identity](uint8_t byte) { return byte == identity; }) &&
	       snapshot.access_token == "token-" + std::to_string(identity) &&
	       snapshot.region == "region-" + std::to_string(identity);
}

static void Rendezvous(std::atomic<int> &ready, std::atomic<bool> &go) {
	ready.fetch_add(1);
	while (!go.load())
		std::this_thread::yield();
}

static void Start(std::atomic<int> &ready, std::atomic<bool> &go, int threads) {
	while (ready.load() != threads)
		std::this_thread::yield();
	go.store(true);
}

TEST_CASE("Production session snapshots have exact sequences under contention", "[session][locking][threading]") {
	BoilstreamConnectionState state;
	SetCredentials(state, 1);
	constexpr int THREADS = 10, CALLS = 500;
	std::atomic<int> ready {0};
	std::atomic<bool> go {false};
	std::atomic<int> mismatches {0};
	std::vector<std::future<std::vector<uint64_t>>> workers;
	for (int thread = 0; thread < THREADS; ++thread) {
		workers.push_back(std::async(std::launch::async, [&] {
			Rendezvous(ready, go);
			std::vector<uint64_t> sequences;
			for (int call = 0; call < CALLS; ++call) {
				auto snapshot = state.GetSessionSnapshot();
				if (!Matches(snapshot, 1))
					mismatches.fetch_add(1);
				sequences.push_back(snapshot.sequence);
			}
			return sequences;
		}));
	}
	Start(ready, go, THREADS);
	std::vector<uint64_t> sequences;
	for (auto &worker : workers) {
		auto values = worker.get();
		sequences.insert(sequences.end(), values.begin(), values.end());
	}
	std::sort(sequences.begin(), sequences.end());
	std::vector<uint64_t> expected(THREADS * CALLS);
	std::iota(expected.begin(), expected.end(), uint64_t(0));
	REQUIRE(mismatches.load() == 0);
	REQUIRE(sequences.size() == expected.size());
	REQUIRE(std::equal(sequences.begin(), sequences.end(), expected.begin()));
	REQUIRE(state.GetSessionSnapshot().sequence == THREADS * CALLS);
}

TEST_CASE("Production snapshots stay coherent during credential changes and logout", "[session][locking][stress]") {
	BoilstreamConnectionState state;
	SetCredentials(state, 1);
	constexpr int THREADS = 16, OPERATIONS = 2000;
	std::atomic<int> ready {0}, completed {0}, snapshots {0}, mismatches {0};
	std::atomic<bool> go {false};
	std::vector<std::future<void>> workers;
	for (int thread = 0; thread < THREADS; ++thread) {
		workers.push_back(std::async(std::launch::async, [&, thread] {
			Rendezvous(ready, go);
			for (int operation = 0; operation < OPERATIONS; ++operation) {
				if (operation % 5 == 0) {
					state.ClearSession();
					SetCredentials(state, uint8_t(thread + 1));
				} else {
					auto snapshot = state.GetSessionSnapshot();
					bool valid = !snapshot.has_session_key && snapshot.session_key.empty() &&
					             snapshot.access_token.empty() && snapshot.region.empty();
					for (int identity = 1; identity <= THREADS && !valid; ++identity)
						valid = Matches(snapshot, uint8_t(identity));
					if (!valid)
						mismatches.fetch_add(1);
					snapshots.fetch_add(1);
				}
				completed.fetch_add(1);
			}
		}));
	}
	Start(ready, go, THREADS);
	for (auto &worker : workers)
		worker.get();
	REQUIRE(completed.load() == THREADS * OPERATIONS);
	REQUIRE(snapshots.load() == THREADS * OPERATIONS * 4 / 5);
	REQUIRE(state.authentication_generation.load() == THREADS * OPERATIONS / 5);
	REQUIRE(mismatches.load() == 0);
	state.ClearSession();
	auto cleared = state.GetSessionSnapshot();
	REQUIRE_FALSE(cleared.has_session_key);
	REQUIRE(cleared.session_key.empty());
	REQUIRE(cleared.access_token.empty());
	REQUIRE(cleared.region.empty());
}

TEST_CASE("Production session counters and logout remain owner-local", "[session][locking][isolation]") {
	constexpr int CONNECTIONS = 4, CALLS = 500;
	std::array<BoilstreamConnectionState, CONNECTIONS> states;
	std::atomic<int> ready {0}, mismatches {0};
	std::atomic<bool> go {false};
	std::vector<std::future<void>> workers;
	for (int connection = 0; connection < CONNECTIONS; ++connection) {
		SetCredentials(states[connection], uint8_t(connection + 1));
		workers.push_back(std::async(std::launch::async, [&, connection] {
			Rendezvous(ready, go);
			for (int call = 0; call < CALLS; ++call) {
				auto snapshot = states[connection].GetSessionSnapshot();
				if (!Matches(snapshot, uint8_t(connection + 1)) || snapshot.sequence != uint64_t(call))
					mismatches.fetch_add(1);
			}
		}));
	}
	Start(ready, go, CONNECTIONS);
	for (auto &worker : workers)
		worker.get();
	REQUIRE(mismatches.load() == 0);
	states[0].ClearSession();
	REQUIRE_FALSE(states[0].GetSessionSnapshot().has_session_key);
	REQUIRE(states[0].authentication_generation.load() == 1);
	for (int connection = 1; connection < CONNECTIONS; ++connection) {
		auto snapshot = states[connection].GetSessionSnapshot();
		REQUIRE(Matches(snapshot, uint8_t(connection + 1)));
		REQUIRE(snapshot.sequence == CALLS);
		REQUIRE(states[connection].authentication_generation.load() == 0);
	}
}
