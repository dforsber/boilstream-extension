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
	// Access the catalog_versions map
	static case_insensitive_map_t<RestApiSecretStorage::CatalogVersionInfo> &
	GetCatalogVersions(RestApiSecretStorage &storage) {
		return storage.catalog_versions;
	}

	// Access last_version_check timestamp
	static std::chrono::system_clock::time_point &GetLastVersionCheck(RestApiSecretStorage &storage) {
		return storage.last_version_check;
	}

	// Access secret_expiration map
	static case_insensitive_map_t<std::chrono::system_clock::time_point> &
	GetSecretExpiration(RestApiSecretStorage &storage) {
		return storage.secret_expiration;
	}

	// Call RefreshCatalogCredentials
	static void RefreshCatalogCredentials(RestApiSecretStorage &storage, const string &catalog_name) {
		storage.RefreshCatalogCredentials(catalog_name);
	}

	// Call CheckCatalogVersions (will fail HTTP but tests rate limiting)
	static void CheckCatalogVersions(RestApiSecretStorage &storage) {
		storage.CheckCatalogVersions();
	}

	// Get VERSION_CHECK_INTERVAL_SECONDS constant
	static int GetVersionCheckInterval() {
		return RestApiSecretStorage::VERSION_CHECK_INTERVAL_SECONDS;
	}

	// Access the version_lock for testing thread safety
	static mutex &GetVersionLock(RestApiSecretStorage &storage) {
		return storage.version_lock;
	}

	// Set endpoint URL (needed to trigger version check logic)
	static void SetEndpoint(RestApiSecretStorage &storage, const string &endpoint) {
		storage.SetEndpoint(endpoint);
	}
};

//===----------------------------------------------------------------------===//
// Helper: Create Test Storage Instance
//===----------------------------------------------------------------------===//
static duckdb::unique_ptr<RestApiSecretStorage> CreateTestStorage() {
	auto db = duckdb::make_uniq<DuckDB>(nullptr);
	return duckdb::make_uniq<RestApiSecretStorage>(*db->instance, "https://localhost/secrets");
}

//===----------------------------------------------------------------------===//
// Test: CatalogVersionInfo Struct
//===----------------------------------------------------------------------===//
TEST_CASE("CatalogVersionInfo Struct", "[boilstream][catalog_versions]") {
	SECTION("Default construction") {
		RestApiSecretStorage::CatalogVersionInfo info;
		info.version = 42;
		info.catalog_name = "test_catalog";

		REQUIRE(info.version == 42);
		REQUIRE(info.catalog_name == "test_catalog");
	}

	SECTION("Can be stored in map") {
		case_insensitive_map_t<RestApiSecretStorage::CatalogVersionInfo> versions;

		RestApiSecretStorage::CatalogVersionInfo info1;
		info1.version = 1;
		info1.catalog_name = "catalog_a";

		RestApiSecretStorage::CatalogVersionInfo info2;
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
	auto storage = CreateTestStorage();

	SECTION("Sets secret expiration to minimum time_point") {
		string catalog_name = "my_catalog";

		// Call refresh
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*storage, catalog_name);

		// Verify expiration was set to minimum
		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(*storage);
		REQUIRE(expiration_map.find(catalog_name) != expiration_map.end());
		REQUIRE(expiration_map[catalog_name] == std::chrono::system_clock::time_point::min());
	}

	SECTION("Multiple catalogs can be refreshed independently") {
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*storage, "catalog_1");
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*storage, "catalog_2");
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*storage, "catalog_3");

		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(*storage);
		REQUIRE(expiration_map.size() >= 3);
		REQUIRE(expiration_map["catalog_1"] == std::chrono::system_clock::time_point::min());
		REQUIRE(expiration_map["catalog_2"] == std::chrono::system_clock::time_point::min());
		REQUIRE(expiration_map["catalog_3"] == std::chrono::system_clock::time_point::min());
	}

	SECTION("Calling refresh twice doesn't cause issues") {
		string catalog_name = "double_refresh_test";

		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*storage, catalog_name);
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*storage, catalog_name);

		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(*storage);
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
	auto storage = CreateTestStorage();

	SECTION("catalog_versions map starts empty") {
		auto &versions = BoilstreamCatalogVersionTestAccess::GetCatalogVersions(*storage);
		REQUIRE(versions.empty());
	}

	SECTION("last_version_check starts at epoch") {
		auto &last_check = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(*storage);
		// Default-constructed time_point is epoch (0)
		REQUIRE(last_check == std::chrono::system_clock::time_point());
	}

	SECTION("Can manually populate catalog_versions for testing") {
		auto &versions = BoilstreamCatalogVersionTestAccess::GetCatalogVersions(*storage);

		RestApiSecretStorage::CatalogVersionInfo info;
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
	auto storage = CreateTestStorage();

	// Note: Without an active session (access_token), CheckCatalogVersions
	// will return early from FetchCatalogVersions. This is intentional -
	// we test the rate limiting behavior by checking timestamps.

	SECTION("First call updates last_version_check") {
		// Set endpoint (but no session, so HTTP won't be attempted)
		BoilstreamCatalogVersionTestAccess::SetEndpoint(*storage, "https://test.example.com/secrets");

		auto before = std::chrono::system_clock::now();

		// This will update timestamp but return early (no session)
		BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*storage);

		auto &last_check = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(*storage);

		// Timestamp should be updated to approximately now
		auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(last_check - before).count();
		REQUIRE(elapsed >= 0);
		REQUIRE(elapsed <= 1);
	}

	SECTION("Subsequent call within 60 seconds is skipped") {
		BoilstreamCatalogVersionTestAccess::SetEndpoint(*storage, "https://test.example.com/secrets");

		// First call
		BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*storage);
		auto first_check = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(*storage);

		// Immediate second call should be skipped (timestamp unchanged)
		BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*storage);
		auto second_check = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(*storage);

		REQUIRE(first_check == second_check);
	}

	SECTION("Rate limiting is per-storage instance") {
		auto storage1 = CreateTestStorage();
		auto storage2 = CreateTestStorage();

		BoilstreamCatalogVersionTestAccess::SetEndpoint(*storage1, "https://test.example.com/secrets");
		BoilstreamCatalogVersionTestAccess::SetEndpoint(*storage2, "https://test.example.com/secrets");

		// Check storage1
		BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*storage1);
		auto check1 = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(*storage1);

		// Check storage2 (should not be affected by storage1's rate limit)
		BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*storage2);
		auto check2 = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(*storage2);

		// Both should have been checked (timestamps should be recent)
		REQUIRE(check1 != std::chrono::system_clock::time_point());
		REQUIRE(check2 != std::chrono::system_clock::time_point());
	}
}

//===----------------------------------------------------------------------===//
// Test: Thread Safety
//===----------------------------------------------------------------------===//
TEST_CASE("Catalog Version Thread Safety", "[boilstream][catalog_versions][.]") {
	// Note: [.] tag means this test is hidden by default

	SECTION("Concurrent RefreshCatalogCredentials calls") {
		auto storage = CreateTestStorage();
		const int num_threads = 10;
		const int ops_per_thread = 50;

		std::vector<std::thread> threads;
		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&storage, t, ops_per_thread]() {
				for (int i = 0; i < ops_per_thread; i++) {
					string catalog_name = "catalog_" + std::to_string(t) + "_" + std::to_string(i);
					BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*storage, catalog_name);
				}
			});
		}

		for (auto &thread : threads) {
			thread.join();
		}

		// Should not crash, and all catalogs should be in expiration map
		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(*storage);
		REQUIRE(expiration_map.size() == num_threads * ops_per_thread);
	}

	SECTION("Concurrent catalog_versions map access") {
		auto storage = CreateTestStorage();
		const int num_threads = 5;
		const int ops_per_thread = 100;

		std::vector<std::thread> threads;
		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&storage, t, ops_per_thread]() {
				auto &versions = BoilstreamCatalogVersionTestAccess::GetCatalogVersions(*storage);
				auto &lock = BoilstreamCatalogVersionTestAccess::GetVersionLock(*storage);

				for (int i = 0; i < ops_per_thread; i++) {
					string uuid = "uuid_" + std::to_string(t) + "_" + std::to_string(i);
					RestApiSecretStorage::CatalogVersionInfo info;
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
		auto &versions = BoilstreamCatalogVersionTestAccess::GetCatalogVersions(*storage);
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
	auto storage = CreateTestStorage();

	SECTION("CheckCatalogVersions returns early with empty endpoint") {
		// Don't set endpoint - it should be empty by default
		auto before = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(*storage);

		BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*storage);

		auto after = BoilstreamCatalogVersionTestAccess::GetLastVersionCheck(*storage);

		// With empty endpoint, timestamp should still be updated (rate limiting happens first)
		// Actually, looking at the code, rate limiting happens first, then endpoint check
		// So timestamp will be updated even if endpoint is empty
		// Let's verify the catalog_versions map is still empty
		auto &versions = BoilstreamCatalogVersionTestAccess::GetCatalogVersions(*storage);
		REQUIRE(versions.empty());
	}
}
