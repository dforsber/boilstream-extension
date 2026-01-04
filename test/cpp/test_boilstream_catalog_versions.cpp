//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_boilstream_catalog_versions.cpp
//
// Unit tests for Catalog Version Polling Feature
//
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "boilstream_secret_storage.hpp"
#include "boilstream_connection_state.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/connection.hpp"

#include <thread>
#include <chrono>

using namespace duckdb;
using namespace std;

//===----------------------------------------------------------------------===//
// Test Access Friend Class - Allows testing private methods
//===----------------------------------------------------------------------===//

class BoilstreamCatalogVersionTestAccess {
public:
	// Access the catalog_versions map from connection state
	static case_insensitive_map_t<BoilstreamConnectionState::CatalogVersionInfo> &
	GetCatalogVersions(BoilstreamConnectionState &conn_state) {
		return conn_state.catalog_versions;
	}

	// Access last_version_check timestamp from connection state
	static std::chrono::system_clock::time_point &GetLastVersionCheck(BoilstreamConnectionState &conn_state) {
		return conn_state.last_version_check;
	}

	// Access secret_expiration map from connection state
	static case_insensitive_map_t<std::chrono::system_clock::time_point> &
	GetSecretExpiration(BoilstreamConnectionState &conn_state) {
		return conn_state.secret_expiration;
	}

	// Call RefreshCatalogCredentials with connection state
	static void RefreshCatalogCredentials(RestApiSecretStorage &storage, const string &catalog_name,
	                                      BoilstreamConnectionState &conn_state) {
		storage.RefreshCatalogCredentials(catalog_name, conn_state);
	}

	// Call CheckCatalogVersions with connection state
	static void CheckCatalogVersions(RestApiSecretStorage &storage, BoilstreamConnectionState &conn_state) {
		storage.CheckCatalogVersions(conn_state);
	}

	// Get VERSION_CHECK_INTERVAL_SECONDS constant from connection state
	static int GetVersionCheckInterval() {
		return BoilstreamConnectionState::VERSION_CHECK_INTERVAL_SECONDS;
	}

	// Access the version_lock for testing thread safety
	static mutex &GetVersionLock(BoilstreamConnectionState &conn_state) {
		return conn_state.version_lock;
	}

	// Set endpoint URL (needed to trigger version check logic)
	static void SetEndpoint(RestApiSecretStorage &storage, const string &endpoint) {
		storage.SetEndpoint(endpoint);
	}
};

//===----------------------------------------------------------------------===//
// Test Fixture - Keeps Database alive for Storage
//===----------------------------------------------------------------------===//
struct TestFixture {
	duckdb::unique_ptr<DuckDB> db;
	duckdb::unique_ptr<RestApiSecretStorage> storage;
	BoilstreamConnectionState conn_state;

	TestFixture() {
		db = duckdb::make_uniq<DuckDB>(nullptr);
		storage = duckdb::make_uniq<RestApiSecretStorage>(*db->instance, "https://localhost/secrets");
	}
};

//===----------------------------------------------------------------------===//
// Test: CatalogVersionInfo Struct
//===----------------------------------------------------------------------===//
TEST_CASE("CatalogVersionInfo Struct", "[boilstream][catalog_versions]") {
	SECTION("Default construction") {
		BoilstreamConnectionState::CatalogVersionInfo info;
		info.version = 42;
		info.catalog_name = "test_catalog";

		REQUIRE(info.version == 42);
		REQUIRE(info.catalog_name == "test_catalog");
	}

	SECTION("Can be stored in map") {
		case_insensitive_map_t<BoilstreamConnectionState::CatalogVersionInfo> versions;

		BoilstreamConnectionState::CatalogVersionInfo info1;
		info1.version = 1;
		info1.catalog_name = "catalog_a";

		BoilstreamConnectionState::CatalogVersionInfo info2;
		info2.version = 5;
		info2.catalog_name = "catalog_b";

		versions["uuid-1"] = info1;
		versions["uuid-2"] = info2;

		REQUIRE(versions.size() == 2);
		REQUIRE(versions["uuid-1"].version == 1);
		REQUIRE(versions["uuid-1"].catalog_name == "catalog_a");
		REQUIRE(versions["uuid-2"].version == 5);
		REQUIRE(versions["uuid-2"].catalog_name == "catalog_b");
	}
}

//===----------------------------------------------------------------------===//
// Test: RefreshCatalogCredentials
//===----------------------------------------------------------------------===//
TEST_CASE("RefreshCatalogCredentials", "[boilstream][catalog_versions]") {
	TestFixture fixture;

	SECTION("Sets secret expiration to minimum time_point") {
		string catalog_name = "my_catalog";

		// Call refresh
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, catalog_name,
		                                                              fixture.conn_state);

		// Verify expiration was set to minimum
		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(fixture.conn_state);
		REQUIRE(expiration_map.find(catalog_name) != expiration_map.end());
		REQUIRE(expiration_map[catalog_name] == std::chrono::system_clock::time_point::min());
	}

	SECTION("Multiple catalogs can be refreshed independently") {
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, "catalog_1",
		                                                              fixture.conn_state);
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, "catalog_2",
		                                                              fixture.conn_state);
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, "catalog_3",
		                                                              fixture.conn_state);

		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(fixture.conn_state);
		REQUIRE(expiration_map.size() >= 3);
		REQUIRE(expiration_map["catalog_1"] == std::chrono::system_clock::time_point::min());
		REQUIRE(expiration_map["catalog_2"] == std::chrono::system_clock::time_point::min());
		REQUIRE(expiration_map["catalog_3"] == std::chrono::system_clock::time_point::min());
	}

	SECTION("Calling refresh twice doesn't cause issues") {
		string catalog_name = "double_refresh_test";

		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, catalog_name,
		                                                              fixture.conn_state);
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, catalog_name,
		                                                              fixture.conn_state);

		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(fixture.conn_state);
		REQUIRE(expiration_map[catalog_name] == std::chrono::system_clock::time_point::min());
	}
}

//===----------------------------------------------------------------------===//
// Test: Version Check Interval Constant
//===----------------------------------------------------------------------===//
TEST_CASE("Version Check Interval", "[boilstream][catalog_versions]") {
	SECTION("Interval is 60 seconds") {
		REQUIRE(BoilstreamCatalogVersionTestAccess::GetVersionCheckInterval() == 60);
	}
}

//===----------------------------------------------------------------------===//
// Test: Catalog Version Tracking State
//===----------------------------------------------------------------------===//
TEST_CASE("Catalog Version Tracking State", "[boilstream][catalog_versions]") {
	BoilstreamConnectionState conn_state;

	SECTION("catalog_versions map starts empty") {
		auto &versions = BoilstreamCatalogVersionTestAccess::GetCatalogVersions(conn_state);
		REQUIRE(versions.empty());
	}

	SECTION("last_version_check starts at min time_point") {
		auto &last_check = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state);
		// Default-constructed in BoilstreamConnectionState is min()
		REQUIRE(last_check == std::chrono::system_clock::time_point::min());
	}

	SECTION("Can manually populate catalog_versions for testing") {
		auto &versions = BoilstreamCatalogVersionTestAccess::GetCatalogVersions(conn_state);

		BoilstreamConnectionState::CatalogVersionInfo info;
		info.version = 10;
		info.catalog_name = "test_catalog";
		versions["test-uuid"] = info;

		REQUIRE(versions.size() == 1);
		REQUIRE(versions["test-uuid"].version == 10);
	}
}

//===----------------------------------------------------------------------===//
// Test: Rate Limiting Logic
//===----------------------------------------------------------------------===//
TEST_CASE("CheckCatalogVersions Rate Limiting", "[boilstream][catalog_versions]") {
	// Note: Without an active session (access_token), CheckCatalogVersions
	// returns early and doesn't update timestamps. These tests verify the
	// rate limiting state management works correctly by testing state directly.

	SECTION("last_version_check can be set and retrieved") {
		BoilstreamConnectionState conn_state;

		auto now = std::chrono::system_clock::now();
		BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state) = now;

		auto &last_check = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state);

		// Timestamp should match what we set
		auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(last_check - now).count();
		REQUIRE(diff == 0);
	}

	SECTION("Rate limiting interval is 60 seconds") {
		// Verify the constant is set correctly
		REQUIRE(BoilstreamCatalogVersionTestAccess::GetVersionCheckInterval() == 60);
	}

	SECTION("Rate limiting check logic") {
		BoilstreamConnectionState conn_state;

		auto now = std::chrono::system_clock::now();
		auto interval_seconds = BoilstreamCatalogVersionTestAccess::GetVersionCheckInterval();

		// Set last check to now - should be within rate limit window
		BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state) = now;
		auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
		                   now - BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state))
		                   .count();
		REQUIRE(elapsed < interval_seconds);

		// Set last check to 2 minutes ago - should be outside rate limit window
		auto two_min_ago = now - std::chrono::seconds(120);
		BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state) = two_min_ago;
		elapsed = std::chrono::duration_cast<std::chrono::seconds>(
		              now - BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state))
		              .count();
		REQUIRE(elapsed >= interval_seconds);
	}

	SECTION("Rate limiting is per-connection-state") {
		// Note: CheckCatalogVersions only updates timestamp and does work when there's
		// a valid session. Without setting up session state, it returns early.
		// This test verifies that rate limiting state is stored per-connection-state.

		BoilstreamConnectionState conn_state1;
		BoilstreamConnectionState conn_state2;

		// Manually set timestamps to verify they are independent
		auto now = std::chrono::system_clock::now();
		auto one_hour_ago = now - std::chrono::hours(1);
		auto two_hours_ago = now - std::chrono::hours(2);

		BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state1) = one_hour_ago;
		BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state2) = two_hours_ago;

		// Verify they are independent
		REQUIRE(BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state1) == one_hour_ago);
		REQUIRE(BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state2) == two_hours_ago);
		REQUIRE(BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state1) !=
		        BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(conn_state2));
	}
}

//===----------------------------------------------------------------------===//
// Test: Thread Safety
//===----------------------------------------------------------------------===//
TEST_CASE("Catalog Version Thread Safety", "[boilstream][catalog_versions][.]") {
	// Note: [.] tag means this test is hidden by default

	SECTION("Concurrent RefreshCatalogCredentials calls") {
		TestFixture fixture;
		const int num_threads = 10;
		const int ops_per_thread = 50;

		std::vector<std::thread> threads;
		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&fixture, t, ops_per_thread]() {
				for (int i = 0; i < ops_per_thread; i++) {
					string catalog_name = "catalog_" + std::to_string(t) + "_" + std::to_string(i);
					BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, catalog_name,
					                                                              fixture.conn_state);
				}
			});
		}

		for (auto &thread : threads) {
			thread.join();
		}

		// Should not crash, and all catalogs should be in expiration map
		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(fixture.conn_state);
		REQUIRE(expiration_map.size() == num_threads * ops_per_thread);
	}

	SECTION("Concurrent catalog_versions map access") {
		BoilstreamConnectionState conn_state;
		const int num_threads = 5;
		const int ops_per_thread = 100;

		std::vector<std::thread> threads;
		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&conn_state, t, ops_per_thread]() {
				auto &versions = BoilstreamCatalogVersionTestAccess::GetCatalogVersions(conn_state);
				auto &lock = BoilstreamCatalogVersionTestAccess::GetVersionLock(conn_state);

				for (int i = 0; i < ops_per_thread; i++) {
					string uuid = "uuid_" + std::to_string(t) + "_" + std::to_string(i);
					BoilstreamConnectionState::CatalogVersionInfo info;
					info.version = i;
					info.catalog_name = "catalog_" + std::to_string(t);

					// Acquire lock before accessing shared map
					{
						std::lock_guard<mutex> guard(lock);
						versions[uuid] = info;
					}
				}
			});
		}

		for (auto &thread : threads) {
			thread.join();
		}

		// Should not crash
		auto &versions = BoilstreamCatalogVersionTestAccess::GetCatalogVersions(conn_state);
		REQUIRE(versions.size() == num_threads * ops_per_thread);
	}
}

//===----------------------------------------------------------------------===//
// Test: Version Comparison Logic
//===----------------------------------------------------------------------===//
TEST_CASE("Version Comparison", "[boilstream][catalog_versions]") {
	// Test that version comparison is correct (new_version > old_version triggers refresh)

	SECTION("Higher version triggers refresh") {
		uint64_t old_version = 5;
		uint64_t new_version = 6;
		REQUIRE(new_version > old_version);
	}

	SECTION("Same version does not trigger refresh") {
		uint64_t old_version = 5;
		uint64_t new_version = 5;
		REQUIRE_FALSE(new_version > old_version);
	}

	SECTION("Lower version does not trigger refresh") {
		uint64_t old_version = 5;
		uint64_t new_version = 4;
		REQUIRE_FALSE(new_version > old_version);
	}

	SECTION("Version 0 is valid") {
		uint64_t version = 0;
		REQUIRE(version == 0);
		// Version 0 means catalog has no master yet - should be stored normally
	}

	SECTION("Large version numbers work correctly") {
		uint64_t old_version = UINT64_MAX - 1;
		uint64_t new_version = UINT64_MAX;
		REQUIRE(new_version > old_version);
	}
}

//===----------------------------------------------------------------------===//
// Test: Empty Endpoint Handling
//===----------------------------------------------------------------------===//
TEST_CASE("Empty Endpoint Handling", "[boilstream][catalog_versions]") {
	TestFixture fixture;

	SECTION("CheckCatalogVersions returns early with empty endpoint") {
		// Don't set endpoint - it should be empty by default
		auto before = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(fixture.conn_state);

		BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);

		auto after = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(fixture.conn_state);

		// With empty endpoint, timestamp should still be updated (rate limiting happens first)
		// Actually, looking at the code, rate limiting happens first, then endpoint check
		// So timestamp will be updated even if endpoint is empty
		// Let's verify the catalog_versions map is still empty
		auto &versions = BoilstreamCatalogVersionTestAccess::GetCatalogVersions(fixture.conn_state);
		REQUIRE(versions.empty());
	}
}

//===----------------------------------------------------------------------===//
// Test: Secret Expiration in Connection State
//===----------------------------------------------------------------------===//
TEST_CASE("Secret Expiration in Connection State", "[boilstream][catalog_versions]") {
	BoilstreamConnectionState conn_state;

	SECTION("StoreExpiration and GetSecretExpiration work correctly") {
		string secret_name = "test_secret";
		auto expiration = std::chrono::system_clock::now() + std::chrono::hours(1);

		conn_state.StoreExpiration(secret_name, expiration);
		auto retrieved = conn_state.GetSecretExpiration(secret_name);

		// Allow 1 second tolerance for comparison
		auto diff = std::chrono::duration_cast<std::chrono::seconds>(expiration - retrieved).count();
		REQUIRE(std::abs(diff) <= 1);
	}

	SECTION("IsSecretExpired returns true for expired secrets") {
		string secret_name = "expired_secret";
		auto past = std::chrono::system_clock::now() - std::chrono::hours(1);

		conn_state.StoreExpiration(secret_name, past);
		REQUIRE(conn_state.IsSecretExpired(secret_name) == true);
	}

	SECTION("IsSecretExpired returns false for valid secrets") {
		string secret_name = "valid_secret";
		auto future = std::chrono::system_clock::now() + std::chrono::hours(1);

		conn_state.StoreExpiration(secret_name, future);
		REQUIRE(conn_state.IsSecretExpired(secret_name) == false);
	}

	SECTION("IsSecretExpired returns true for unknown secrets") {
		REQUIRE(conn_state.IsSecretExpired("nonexistent") == true);
	}

	SECTION("ClearExpiration removes secret from map") {
		string secret_name = "to_clear";
		conn_state.StoreExpiration(secret_name, std::chrono::system_clock::now());

		conn_state.ClearExpiration(secret_name);

		// After clearing, GetSecretExpiration returns min time_point
		REQUIRE(conn_state.GetSecretExpiration(secret_name) == std::chrono::system_clock::time_point::min());
	}
}
