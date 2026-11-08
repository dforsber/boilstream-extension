// Native concurrency checks of the active session lifecycle. Protocol sequencing
// belongs to BoilstreamProtocol/Rust ClientSession, not a second credential counter.
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "boilstream_connection_state.hpp"
#include <array>
#include <atomic>
#include <future>
#include <thread>
#include <vector>

using namespace duckdb;

static void Seed(BoilstreamConnectionState &state, uint8_t identity) {
	// Setup is private and completes before any worker can read the state.
	state.access_token = "token-" + std::to_string(identity);
	state.session_key.assign(64, identity);
	state.refresh_token.assign(32, identity);
	state.bootstrap_token_hash = "hash-" + std::to_string(identity);
	state.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(2);
	std::array<uint8_t, 32> pin {};
	pin[0] = 9;
	state.protocol = make_shared_ptr<BoilstreamProtocol>("https://lifecycle.invalid", pin);
	state.StoreExpiration("owned", state.token_expires_at);
	ManagedCatalogCredentialEnvelope credential;
	credential.token = "catalog-token-" + std::to_string(identity);
	state.StoreManagedCatalogCredential("owned", credential);
}

static void Rendezvous(std::atomic<int> &ready, std::atomic<bool> &go) {
	ready.fetch_add(1);
	while (!go.load()) {
		std::this_thread::yield();
	}
}

static void Start(std::atomic<int> &ready, std::atomic<bool> &go, int count) {
	while (ready.load() != count) {
		std::this_thread::yield();
	}
	go.store(true);
}

TEST_CASE("Concurrent logout invalidates every generation and clears authority", "[session][locking]") {
	BoilstreamConnectionState state;
	Seed(state, 1);
	REQUIRE(state.IsSessionTokenValid());
	constexpr int WRITERS = 4, READERS = 4, CALLS = 500;
	std::atomic<int> ready {0}, failures {0};
	std::atomic<bool> go {false}, retired {false};
	std::vector<std::future<void>> workers;
	for (int worker = 0; worker < WRITERS + READERS; ++worker) {
		workers.push_back(std::async(std::launch::async, [&, worker] {
			Rendezvous(ready, go);
			for (int call = 0; call < CALLS; ++call) {
				if (worker < WRITERS) {
					state.ClearSession();
					retired.store(true);
				} else {
					// Once any logout completes, no later read may recover authority.
					const bool must_be_retired = retired.load();
					const bool valid = state.IsSessionTokenValid();
					const auto hash = state.GetBootstrapTokenHash();
					if (must_be_retired && (valid || !hash.empty())) {
						failures.fetch_add(1);
					}
				}
			}
		}));
	}
	Start(ready, go, WRITERS + READERS);
	for (auto &worker : workers) {
		worker.get();
	}
	REQUIRE(failures.load() == 0);
	REQUIRE(state.authentication_generation.load() == WRITERS * CALLS);
	REQUIRE_FALSE(state.IsSessionTokenValid());
	REQUIRE(state.access_token.empty());
	REQUIRE(state.session_key.empty());
	REQUIRE(state.refresh_token.empty());
	REQUIRE(state.GetBootstrapTokenHash().empty());
	REQUIRE(state.GetSecretExpiration("owned") == std::chrono::system_clock::time_point::min());
	REQUIRE(state.secret_cache->IsClosed());
	ManagedCatalogCredentialEnvelope credential;
	REQUIRE_FALSE(state.TryGetManagedCatalogCredential("owned", credential));
}

TEST_CASE("Concurrent logout is owner-local", "[session][isolation]") {
	constexpr int OWNERS = 4, CALLS = 500;
	std::array<BoilstreamConnectionState, OWNERS> states;
	std::atomic<int> ready {0}, failures {0};
	std::atomic<bool> go {false};
	std::vector<std::future<void>> workers;
	for (int owner = 0; owner < OWNERS; ++owner) {
		Seed(states[owner], static_cast<uint8_t>(owner + 1));
		workers.push_back(std::async(std::launch::async, [&, owner] {
			Rendezvous(ready, go);
			for (int call = 0; call < CALLS; ++call) {
				if (owner == 0) {
					states[owner].ClearSession();
				} else if (!states[owner].IsSessionTokenValid() ||
				           states[owner].GetBootstrapTokenHash() != "hash-" + std::to_string(owner + 1)) {
					failures.fetch_add(1);
				}
			}
		}));
	}
	Start(ready, go, OWNERS);
	for (auto &worker : workers) {
		worker.get();
	}
	REQUIRE(failures.load() == 0);
	REQUIRE(states[0].authentication_generation.load() == CALLS);
	REQUIRE_FALSE(states[0].IsSessionTokenValid());
	for (int owner = 1; owner < OWNERS; ++owner) {
		REQUIRE(states[owner].authentication_generation.load() == 0);
		REQUIRE(states[owner].IsSessionTokenValid());
		REQUIRE_FALSE(states[owner].secret_cache->IsClosed());
		ManagedCatalogCredentialEnvelope credential;
		REQUIRE(states[owner].TryGetManagedCatalogCredential("owned", credential));
		REQUIRE(credential.token == "catalog-token-" + std::to_string(owner + 1));
	}
}

TEST_CASE("Retained cache handles cannot publish or retrieve after logout", "[session][cache]") {
	BoilstreamConnectionState state;
	Seed(state, 1);
	auto cache = state.secret_cache;
	const auto revision = cache->Revision();
	auto secret =
	    make_uniq<KeyValueSecret>(vector<string> {"test://owned/"}, Identifier("owned"), "config", Identifier("owned"));
	secret->secret_map["key"] = Value("fixture-credential");
	auto entry = BoilstreamSecretCache::Prepare(std::move(secret), state.token_expires_at, 128);
	cache->Put(entry, revision);
	REQUIRE(cache->Get("owned"));
	state.ClearSession();
	REQUIRE_FALSE(cache->Get("owned"));
	REQUIRE_FALSE(cache->Get("owned", true));
	REQUIRE(cache->Snapshot(true).empty());
	REQUIRE_THROWS_AS(cache->Put(entry, revision), IOException);
	REQUIRE_THROWS_AS(cache->Put(entry, cache->Revision()), IOException);
	REQUIRE_THROWS_AS(cache->ValidatePut(entry, cache->Revision()), IOException);
}
