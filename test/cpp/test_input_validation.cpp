//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_input_validation.cpp
//
// Comprehensive Input Validation Tests for Boilstream Extension
//
// Tests that the extension properly handles malicious, malformed, and empty
// inputs without crashing (segfaults) or using dangerous default values.
//
// CRITICAL: These tests exercise PRODUCTION code paths, not mock implementations.
//
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "boilstream_secret_storage.hpp"
#include "boilstream_connection_state.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/http_util.hpp"
#include "opaque_client.h"

#include <string>
#include <vector>
#include <cstring>
#include <thread>
#include <atomic>

using namespace duckdb;

//===----------------------------------------------------------------------===//
// Test Access Friend Class - Access private methods for testing
//===----------------------------------------------------------------------===//
class BoilstreamInputValidationTestAccess {
public:
	static bool IsExpired(RestApiSecretStorage &storage, const string &name, BoilstreamConnectionState &state) {
		return storage.IsExpired(name, state);
	}

	static void CheckCatalogVersions(RestApiSecretStorage &storage, BoilstreamConnectionState &state) {
		storage.CheckCatalogVersions(state);
	}

	static unique_ptr<BaseSecret> DeserializeSecret(RestApiSecretStorage &storage, const std::string &json_data,
	                                                SecretManager &manager) {
		return storage.DeserializeSecret(json_data, manager);
	}

	static std::chrono::system_clock::time_point ParseExpiresAt(RestApiSecretStorage &storage,
	                                                            const std::string &expires_at_str) {
		return storage.ParseExpiresAt(expires_at_str);
	}
};

//===----------------------------------------------------------------------===//
// Test Fixture - Provides clean test environment
//===----------------------------------------------------------------------===//
struct InputValidationTestFixture {
	duckdb::unique_ptr<DuckDB> db;
	duckdb::unique_ptr<RestApiSecretStorage> storage;
	vector<uint8_t> valid_session_key;
	std::string valid_access_token;

	InputValidationTestFixture() {
		db = duckdb::make_uniq<DuckDB>(nullptr);
		storage = duckdb::make_uniq<RestApiSecretStorage>(*db->instance, "https://test.example.com/secrets");

		// Create a valid 64-byte session key for tests that need one
		valid_session_key.resize(64);
		for (size_t i = 0; i < 64; i++) {
			valid_session_key[i] = static_cast<uint8_t>(i + 0x10);
		}

		// Create a valid 64-character access token
		valid_access_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	}
};

TEST_CASE_METHOD(InputValidationTestFixture, "Storage expiration sentinels require refresh",
                 "[input_validation][expiry_regression]") {
	BoilstreamConnectionState state;
	using Clock = std::chrono::system_clock;
	const auto expiration = GENERATE(Clock::time_point::min(), Clock::time_point::min() + std::chrono::seconds(1));
	state.StoreExpiration("catalog", expiration);
	CHECK(BoilstreamInputValidationTestAccess::IsExpired(*storage, "catalog", state));
}

TEST_CASE_METHOD(InputValidationTestFixture, "Initial catalog version check is not rate limited",
                 "[input_validation][expiry_regression]") {
	BoilstreamConnectionState state;
	const auto before = std::chrono::system_clock::now();
	// With no session the fetch fails locally, but the initial poll must still be attempted.
	BoilstreamInputValidationTestAccess::CheckCatalogVersions(*storage, state);
	CHECK(state.last_version_check >= before);
	const auto last_check = state.last_version_check;
	BoilstreamInputValidationTestAccess::CheckCatalogVersions(*storage, state);
	CHECK(state.last_version_check == last_check);
}

TEST_CASE_METHOD(InputValidationTestFixture, "Managed catalog forced expiration rejects cached token",
                 "[input_validation][expiry_regression]") {
	Connection connection(*db);
	connection.BeginTransaction();
	storage->SetEndpoint("");
	auto &state = storage->GetOrCreateSession("expiry-test");
	storage->SetActiveSessionKeyForConnection(connection.context->GetConnectionId(), "expiry-test");
	const string catalog_id = "9a927d1b-30f5-48da-91eb-af1492bf31c0";
	const auto scope = ManagedCatalogSecretScope("pod.example.test:9494", catalog_id);
	ManagedCatalogCredentialEnvelope credential;
	credential.token = "expired-token";
	credential.catalog_id = catalog_id;
	state.StoreManagedCatalogCredential(scope, credential);
	state.StoreExpiration("__quack__" + scope, std::chrono::system_clock::time_point::min());
	// No endpoint: re-vending fails locally and must not resurrect the cached token.
	storage->SetEndpoint("");
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*connection.context);
	CHECK_FALSE(storage->LookupSecret(scope, "quack", &transaction).HasMatch());
}

TEST_CASE_METHOD(InputValidationTestFixture, "DeserializeSecret rejects malformed JSON",
                 "[input_validation][deserialize][json]") {
	Connection conn(*db);
	auto &secret_manager = db->instance->GetSecretManager();

	SECTION("Empty string returns nullptr") {
		auto result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, "", secret_manager);
		REQUIRE(result == nullptr);
	}

	SECTION("Invalid JSON returns nullptr") {
		auto result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, "not json", secret_manager);
		REQUIRE(result == nullptr);
	}

	SECTION("Empty JSON object returns nullptr") {
		auto result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, "{}", secret_manager);
		REQUIRE(result == nullptr);
	}

	SECTION("JSON with null data field returns nullptr") {
		auto result =
		    BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, R"({"data": null})", secret_manager);
		REQUIRE(result == nullptr);
	}

	SECTION("JSON with empty data field returns nullptr") {
		auto result =
		    BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, R"({"data": ""})", secret_manager);
		REQUIRE(result == nullptr);
	}

	SECTION("JSON with non-string data field returns nullptr") {
		auto result =
		    BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, R"({"data": 12345})", secret_manager);
		REQUIRE(result == nullptr);
	}

	SECTION("JSON with invalid base64 in data field throws or returns nullptr") {
		// Invalid base64 should not crash - throwing is acceptable
		bool threw = false;
		unique_ptr<BaseSecret> result;
		try {
			result = BoilstreamInputValidationTestAccess::DeserializeSecret(
			    *storage, R"({"data": "not-valid-base64!!!"})", secret_manager);
		} catch (const std::exception &) {
			threw = true;
		}
		// Either returns nullptr or throws - both are acceptable, crashing is not
		REQUIRE((threw || result == nullptr));
	}
}

TEST_CASE_METHOD(InputValidationTestFixture, "ParseExpiresAt handles malformed timestamps",
                 "[input_validation][timestamp]") {
	auto min_time = std::chrono::system_clock::time_point::min();

	SECTION("Empty string returns time_point::min (expired)") {
		auto result = BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "");
		REQUIRE(result == min_time);
	}

	SECTION("Invalid format returns time_point::min (expired)") {
		auto result = BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "not-a-timestamp");
		REQUIRE(result == min_time);
	}

	SECTION("Missing Z suffix returns time_point::min (expired)") {
		auto result = BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "2025-01-01T12:00:00");
		REQUIRE(result == min_time);
	}

	SECTION("Wrong separator returns time_point::min (expired)") {
		auto result = BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "2025-01-01 12:00:00Z");
		REQUIRE(result == min_time);
	}

	SECTION("Partial timestamp returns time_point::min (expired)") {
		auto result = BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "2025-01-01");
		REQUIRE(result == min_time);
	}

	SECTION("Valid ISO8601 timestamp parses correctly") {
		auto result = BoilstreamInputValidationTestAccess::ParseExpiresAt(*storage, "2030-06-15T14:30:00Z");
		REQUIRE(result != min_time);
		REQUIRE(result > std::chrono::system_clock::now()); // Future date
	}
}

TEST_CASE("BoilstreamConnectionState handles empty values safely", "[input_validation][connection_state]") {
	BoilstreamConnectionState state;

	SECTION("Initial state has empty values") {
		REQUIRE(state.access_token.empty());
		REQUIRE(state.session_key.empty());
		REQUIRE(state.refresh_token.empty());
		REQUIRE(state.region.empty());
	}

	SECTION("IsSessionTokenValid returns false for empty state") {
		REQUIRE_FALSE(state.IsSessionTokenValid());
	}

	SECTION("ClearSession is safe to call on empty state") {
		REQUIRE_NOTHROW(state.ClearSession());
		REQUIRE_FALSE(state.IsSessionTokenValid());
	}

	SECTION("Multiple ClearSession calls are safe") {
		state.ClearSession();
		state.ClearSession();
		state.ClearSession();
		REQUIRE_FALSE(state.IsSessionTokenValid());
	}
}

TEST_CASE("BoilstreamConnectionState session management", "[input_validation][connection_state][session]") {
	BoilstreamConnectionState state;

	SECTION("Setting empty access_token results in invalid session") {
		{
			std::lock_guard<std::mutex> lock(state.session_lock);
			state.access_token = "";
			state.session_key = {0x01, 0x02, 0x03};
			state.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
		}
		REQUIRE_FALSE(state.IsSessionTokenValid());
	}

	SECTION("Setting empty session_key results in invalid session") {
		{
			std::lock_guard<std::mutex> lock(state.session_lock);
			state.access_token = "valid_token";
			state.session_key.clear();
			state.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
		}
		REQUIRE_FALSE(state.IsSessionTokenValid());
	}

	SECTION("Both access_token and session_key required for valid session") {
		{
			std::lock_guard<std::mutex> lock(state.session_lock);
			state.access_token = "valid_token";
			state.session_key = {0x01, 0x02, 0x03};
			state.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
		}
		REQUIRE(state.IsSessionTokenValid());
	}

	SECTION("Expired token results in invalid session") {
		{
			std::lock_guard<std::mutex> lock(state.session_lock);
			state.access_token = "valid_token";
			state.session_key = {0x01, 0x02, 0x03};
			// Set expiration to 1 hour ago
			state.token_expires_at = std::chrono::system_clock::now() - std::chrono::hours(1);
		}
		REQUIRE_FALSE(state.IsSessionTokenValid());
	}
}

TEST_CASE_METHOD(InputValidationTestFixture, "Extension handles malicious JSON payloads",
                 "[input_validation][security][malicious]") {
	Connection conn(*db);
	auto &secret_manager = db->instance->GetSecretManager();

	SECTION("Deeply nested JSON does not cause stack overflow") {
		// Create deeply nested JSON
		std::string nested_json = "{";
		for (int i = 0; i < 100; i++) {
			nested_json += "\"a\":{";
		}
		nested_json += "\"data\":\"\"";
		for (int i = 0; i < 100; i++) {
			nested_json += "}";
		}
		nested_json += "}";

		// Should not crash
		auto result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, nested_json, secret_manager);
		REQUIRE(result == nullptr);
	}

	SECTION("Very long string values do not cause issues") {
		std::string long_value(1000000, 'a'); // 1MB string
		std::string json = R"({"data": ")" + long_value + R"("})";

		// The base64 decodes to invalid serialized secret bytes. A successful
		// object, or silently swallowing the decoding error, must fail this test.
		REQUIRE_THROWS_AS(BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, json, secret_manager),
		                  IOException);
	}

	SECTION("Unicode and special characters are handled") {
		std::string json = R"({"data": "🔐\u0000\x00\r\n\t"})";
		auto result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, json, secret_manager);
		REQUIRE(result == nullptr);
	}

	SECTION("Control characters in JSON strings are handled") {
		std::string json = "{\"data\": \"\x01\x02\x03\x04\x05\"}";
		auto result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, json, secret_manager);
		REQUIRE(result == nullptr);
	}
}

TEST_CASE_METHOD(InputValidationTestFixture, "Extension handles SQL injection attempts in values",
                 "[input_validation][security][injection]") {
	Connection conn(*db);
	auto &secret_manager = db->instance->GetSecretManager();

	SECTION("SQL injection in JSON data field") {
		std::string json = R"({"data": "'; DROP TABLE secrets; --"})";
		// Should return nullptr or throw (invalid base64), not execute SQL
		bool threw = false;
		unique_ptr<BaseSecret> result;
		try {
			result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, json, secret_manager);
		} catch (const std::exception &) {
			threw = true;
		}
		REQUIRE((threw || result == nullptr));
	}

	SECTION("Path traversal in JSON data field") {
		std::string json = R"({"data": "../../../etc/passwd"})";
		// Should return nullptr or throw (invalid base64)
		bool threw = false;
		unique_ptr<BaseSecret> result;
		try {
			result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, json, secret_manager);
		} catch (const std::exception &) {
			threw = true;
		}
		REQUIRE((threw || result == nullptr));
	}
}

TEST_CASE_METHOD(InputValidationTestFixture, "DeserializeSecret rejects oversized JSON",
                 "[input_validation][security][size_limits]") {
	auto &secret_manager = db->instance->GetSecretManager();
	const std::string oversized_json = "{\"data\":\"" + std::string(11 * 1024 * 1024, ' ') + "\"}";
	REQUIRE_THROWS_AS(BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, oversized_json, secret_manager),
	                  IOException);
}

TEST_CASE("BoilstreamConnectionState concurrent access is safe", "[input_validation][threading]") {
	BoilstreamConnectionState state;
	std::atomic<bool> start_flag {false};
	std::atomic<int> completed {0};
	const int NUM_THREADS = 8;
	const int OPS_PER_THREAD = 1000;

	std::vector<std::thread> threads;

	for (int t = 0; t < NUM_THREADS; t++) {
		threads.emplace_back([&, t]() {
			while (!start_flag.load()) {
				std::this_thread::yield();
			}

			for (int i = 0; i < OPS_PER_THREAD; i++) {
				switch (i % 5) {
				case 0:
					state.GetBootstrapTokenHash();
					break;
				case 1:
					state.IsSessionTokenValid();
					break;
				case 2:
					state.GetBootstrapTokenHash();
					break;
				case 3:
					state.ClearSession();
					break;
				case 4: {
					std::lock_guard<std::mutex> lock(state.session_lock);
					state.access_token = "token-" + std::to_string(t);
					state.session_key = {static_cast<uint8_t>(t), 0x02, 0x03};
					break;
				}
				}
			}
			completed++;
		});
	}

	start_flag.store(true);

	for (auto &t : threads) {
		t.join();
	}

	REQUIRE(completed == NUM_THREADS);
}
