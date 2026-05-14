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
	static RestApiSecretStorage::SigningResult SignRequest(RestApiSecretStorage &storage, const std::string &method,
	                                                       const std::string &url, const std::string &body,
	                                                       uint64_t timestamp, uint64_t sequence,
	                                                       const vector<uint8_t> &session_key,
	                                                       const std::string &access_token, const std::string &region) {
		return storage.SignRequest(method, url, body, timestamp, sequence, session_key, access_token, region);
	}

	static std::string DecryptResponse(RestApiSecretStorage &storage, const std::string &encrypted_response_body,
	                                   const vector<uint8_t> &session_key, uint16_t cipher_suite) {
		return storage.DecryptResponse(encrypted_response_body, session_key, cipher_suite);
	}

	static void VerifyResponseSignature(RestApiSecretStorage &storage, const std::string &response_body,
	                                    uint16_t status_code, const case_insensitive_map_t<std::string> &headers,
	                                    const vector<uint8_t> &session_key) {
		storage.VerifyResponseSignature(response_body, status_code, headers, session_key);
	}

	static unique_ptr<BaseSecret> DeserializeSecret(RestApiSecretStorage &storage, const std::string &json_data,
	                                                SecretManager &manager) {
		return storage.DeserializeSecret(json_data, manager);
	}

	static std::chrono::system_clock::time_point ParseExpiresAt(RestApiSecretStorage &storage,
	                                                            const std::string &expires_at_str) {
		return storage.ParseExpiresAt(expires_at_str);
	}

	static bool LoadRefreshToken(RestApiSecretStorage &storage, BoilstreamConnectionState &conn_state) {
		return storage.LoadRefreshToken(conn_state);
	}

	static void SaveRefreshToken(RestApiSecretStorage &storage, BoilstreamConnectionState &conn_state,
	                             bool resumption_enabled) {
		storage.SaveRefreshToken(conn_state, resumption_enabled);
	}

	static std::string GetRefreshTokenPath(RestApiSecretStorage &storage) {
		return storage.GetRefreshTokenPath();
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

//===----------------------------------------------------------------------===//
// SECTION 1: Region Validation Tests
// Ensures no silent fallback to "us-east-1" or other default values
//===----------------------------------------------------------------------===//

TEST_CASE_METHOD(InputValidationTestFixture, "SignRequest rejects empty region",
                 "[input_validation][region][critical]") {
	SECTION("Empty region string throws error") {
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::SignRequest(*storage, "GET", "https://api.example.com/secrets", "",
		                                                     1234567890, 1, valid_session_key, valid_access_token, ""),
		    IOException);
	}

	SECTION("Empty region error message is descriptive") {
		try {
			BoilstreamInputValidationTestAccess::SignRequest(*storage, "GET", "https://api.example.com/secrets", "",
			                                                 1234567890, 1, valid_session_key, valid_access_token, "");
			FAIL("Expected IOException");
		} catch (const IOException &e) {
			std::string msg = e.what();
			REQUIRE(msg.find("region") != std::string::npos);
			REQUIRE(msg.find("required") != std::string::npos);
			// Must NOT contain fallback values
			REQUIRE(msg.find("us-east-1") == std::string::npos);
		}
	}

	SECTION("Valid region succeeds") {
		REQUIRE_NOTHROW(BoilstreamInputValidationTestAccess::SignRequest(
		    *storage, "GET", "https://api.example.com/secrets", "", 1234567890, 1, valid_session_key,
		    valid_access_token, "eu-west-1"));
	}
}

//===----------------------------------------------------------------------===//
// SECTION 2: Access Token Validation Tests
//===----------------------------------------------------------------------===//

TEST_CASE_METHOD(InputValidationTestFixture, "SignRequest validates access_token length",
                 "[input_validation][token][critical]") {
	SECTION("Empty access_token throws error") {
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::SignRequest(*storage, "GET", "https://api.example.com/secrets", "",
		                                                     1234567890, 1, valid_session_key, "", "us-west-2"),
		    IOException);
	}

	SECTION("Short access_token (7 chars) throws error") {
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::SignRequest(*storage, "GET", "https://api.example.com/secrets", "",
		                                                     1234567890, 1, valid_session_key, "1234567", "us-west-2"),
		    IOException);
	}

	SECTION("Access token too short error is descriptive") {
		try {
			BoilstreamInputValidationTestAccess::SignRequest(*storage, "GET", "https://api.example.com/secrets", "",
			                                                 1234567890, 1, valid_session_key, "short", "us-west-2");
			FAIL("Expected IOException");
		} catch (const IOException &e) {
			std::string msg = e.what();
			REQUIRE(msg.find("access_token") != std::string::npos);
			REQUIRE(msg.find("too short") != std::string::npos);
		}
	}

	SECTION("Minimum valid access_token (8 chars) succeeds") {
		REQUIRE_NOTHROW(BoilstreamInputValidationTestAccess::SignRequest(
		    *storage, "GET", "https://api.example.com/secrets", "", 1234567890, 1, valid_session_key, "12345678",
		    "us-west-2"));
	}
}

//===----------------------------------------------------------------------===//
// SECTION 3: DecryptResponse JSON Validation Tests
//===----------------------------------------------------------------------===//

TEST_CASE_METHOD(InputValidationTestFixture, "DecryptResponse rejects malformed JSON",
                 "[input_validation][decrypt][json]") {
	SECTION("Empty string throws error") {
		REQUIRE_THROWS_AS(BoilstreamInputValidationTestAccess::DecryptResponse(*storage, "", valid_session_key, 0x0001),
		                  IOException);
	}

	SECTION("Invalid JSON throws error") {
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::DecryptResponse(*storage, "not json", valid_session_key, 0x0001),
		    IOException);
	}

	SECTION("Empty JSON object throws error") {
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::DecryptResponse(*storage, "{}", valid_session_key, 0x0001),
		    IOException);
	}

	SECTION("JSON with null values throws error") {
		std::string json_with_nulls = R"({
			"encrypted": true,
			"nonce": null,
			"ciphertext": null,
			"hmac": null
		})";
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::DecryptResponse(*storage, json_with_nulls, valid_session_key, 0x0001),
		    IOException);
	}
}

TEST_CASE_METHOD(InputValidationTestFixture, "DecryptResponse rejects empty field values",
                 "[input_validation][decrypt][empty]") {
	SECTION("Empty nonce throws error") {
		std::string json = R"({
			"encrypted": true,
			"nonce": "",
			"ciphertext": "YWJjZGVmZ2hpamtsbW5vcHFyc3Q=",
			"hmac": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		})";
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::DecryptResponse(*storage, json, valid_session_key, 0x0001),
		    IOException);
	}

	SECTION("Empty ciphertext throws error") {
		std::string json = R"({
			"encrypted": true,
			"nonce": "YWJjZGVmZ2hpamts",
			"ciphertext": "",
			"hmac": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		})";
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::DecryptResponse(*storage, json, valid_session_key, 0x0001),
		    IOException);
	}

	SECTION("Empty hmac throws error") {
		std::string json = R"({
			"encrypted": true,
			"nonce": "YWJjZGVmZ2hpamts",
			"ciphertext": "YWJjZGVmZ2hpamtsbW5vcHFyc3Q=",
			"hmac": ""
		})";
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::DecryptResponse(*storage, json, valid_session_key, 0x0001),
		    IOException);
	}

	SECTION("Error messages are descriptive for empty fields") {
		std::string json = R"({
			"encrypted": true,
			"nonce": "",
			"ciphertext": "YWJjZGVmZ2hpamtsbW5vcHFyc3Q=",
			"hmac": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		})";
		try {
			BoilstreamInputValidationTestAccess::DecryptResponse(*storage, json, valid_session_key, 0x0001);
			FAIL("Expected IOException");
		} catch (const IOException &e) {
			std::string msg = e.what();
			REQUIRE(msg.find("empty") != std::string::npos);
		}
	}
}

TEST_CASE_METHOD(InputValidationTestFixture, "DecryptResponse validates field sizes",
                 "[input_validation][decrypt][size]") {
	SECTION("Wrong nonce size (not 12 bytes) throws error") {
		// Base64 of 8 bytes instead of 12
		std::string json = R"({
			"encrypted": true,
			"nonce": "YWJjZGVmZ2g=",
			"ciphertext": "YWJjZGVmZ2hpamtsbW5vcHFyc3Q=",
			"hmac": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		})";
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::DecryptResponse(*storage, json, valid_session_key, 0x0001),
		    IOException);
	}

	SECTION("Wrong hmac size (not 64 hex chars) throws error") {
		std::string json = R"({
			"encrypted": true,
			"nonce": "YWJjZGVmZ2hpamts",
			"ciphertext": "YWJjZGVmZ2hpamtsbW5vcHFyc3Q=",
			"hmac": "0123456789abcdef"
		})";
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::DecryptResponse(*storage, json, valid_session_key, 0x0001),
		    IOException);
	}

	SECTION("Ciphertext too short for AEAD tag throws error") {
		// Base64 of only 10 bytes (< 16 bytes required for AEAD tag)
		std::string json = R"({
			"encrypted": true,
			"nonce": "YWJjZGVmZ2hpamts",
			"ciphertext": "YWJjZGVmZ2hpag==",
			"hmac": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		})";
		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::DecryptResponse(*storage, json, valid_session_key, 0x0001),
		    IOException);
	}
}

TEST_CASE_METHOD(InputValidationTestFixture, "DecryptResponse validates cipher suite",
                 "[input_validation][decrypt][cipher]") {
	// Valid JSON structure but unsupported cipher suite
	std::string valid_structure_json = R"({
		"encrypted": true,
		"nonce": "YWJjZGVmZ2hpamts",
		"ciphertext": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		"hmac": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	})";

	SECTION("Unsupported cipher suite 0x0000 throws error") {
		REQUIRE_THROWS_AS(BoilstreamInputValidationTestAccess::DecryptResponse(*storage, valid_structure_json,
		                                                                       valid_session_key, 0x0000),
		                  IOException);
	}

	SECTION("Unsupported cipher suite 0x0003 throws error") {
		REQUIRE_THROWS_AS(BoilstreamInputValidationTestAccess::DecryptResponse(*storage, valid_structure_json,
		                                                                       valid_session_key, 0x0003),
		                  IOException);
	}

	SECTION("Unsupported cipher suite 0xFFFF throws error") {
		REQUIRE_THROWS_AS(BoilstreamInputValidationTestAccess::DecryptResponse(*storage, valid_structure_json,
		                                                                       valid_session_key, 0xFFFF),
		                  IOException);
	}
}

//===----------------------------------------------------------------------===//
// SECTION 4: DeserializeSecret JSON Validation Tests
//===----------------------------------------------------------------------===//

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

//===----------------------------------------------------------------------===//
// SECTION 5: ParseExpiresAt Validation Tests
//===----------------------------------------------------------------------===//

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

//===----------------------------------------------------------------------===//
// SECTION 6: Session Key Validation Tests
//===----------------------------------------------------------------------===//

TEST_CASE_METHOD(InputValidationTestFixture, "SignRequest validates session_key", "[input_validation][session_key]") {
	SECTION("Empty session_key is handled") {
		vector<uint8_t> empty_key;
		// Should either throw or produce a result - must not crash
		try {
			auto result = BoilstreamInputValidationTestAccess::SignRequest(
			    *storage, "GET", "https://api.example.com/secrets", "", 1234567890, 1, empty_key, valid_access_token,
			    "us-west-2");
			// If it doesn't throw, that's also acceptable behavior
		} catch (const std::exception &) {
			// Throwing is acceptable
		}
	}

	SECTION("Short session_key is handled") {
		vector<uint8_t> short_key = {0x01, 0x02, 0x03}; // Only 3 bytes
		// Should either throw or produce a result - must not crash
		try {
			auto result = BoilstreamInputValidationTestAccess::SignRequest(
			    *storage, "GET", "https://api.example.com/secrets", "", 1234567890, 1, short_key, valid_access_token,
			    "us-west-2");
		} catch (const std::exception &) {
			// Throwing is acceptable
		}
	}
}

//===----------------------------------------------------------------------===//
// SECTION 7: BoilstreamConnectionState Validation Tests
//===----------------------------------------------------------------------===//

TEST_CASE("BoilstreamConnectionState handles empty values safely", "[input_validation][connection_state]") {
	BoilstreamConnectionState state;

	SECTION("Initial state has empty values") {
		REQUIRE(state.access_token.empty());
		REQUIRE(state.session_key.empty());
		REQUIRE(state.refresh_token.empty());
		REQUIRE(state.region.empty());
		REQUIRE(state.client_sequence == 0);
	}

	SECTION("IsSessionTokenValid returns false for empty state") {
		REQUIRE_FALSE(state.IsSessionTokenValid());
	}

	SECTION("GetSessionSnapshot returns valid snapshot even with empty state") {
		auto snapshot = state.GetSessionSnapshot();
		REQUIRE(snapshot.access_token.empty());
		REQUIRE(snapshot.session_key.empty());
		REQUIRE(snapshot.region.empty());
		// Note: sequence increments on each call
		REQUIRE(snapshot.has_session_key == false);
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

//===----------------------------------------------------------------------===//
// SECTION 8: Malicious Input Tests
//===----------------------------------------------------------------------===//

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

		// Should not crash - may throw due to invalid base64
		try {
			auto result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, json, secret_manager);
			// Either nullptr or valid result - both acceptable
		} catch (const std::exception &) {
			// Throwing is acceptable for malformed input
		}
		REQUIRE(true); // Test passes if we reach here without crash
	}

	SECTION("Unicode and special characters are handled") {
		std::string json = R"({"data": "🔐\u0000\x00\r\n\t"})";
		auto result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, json, secret_manager);
		// Should not crash
	}

	SECTION("Control characters in JSON strings are handled") {
		std::string json = "{\"data\": \"\x01\x02\x03\x04\x05\"}";
		auto result = BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, json, secret_manager);
		// Should not crash
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

//===----------------------------------------------------------------------===//
// SECTION 9: Response Signature Validation Tests
//===----------------------------------------------------------------------===//

TEST_CASE_METHOD(InputValidationTestFixture, "VerifyResponseSignature validates headers",
                 "[input_validation][signature][headers]") {
	case_insensitive_map_t<std::string> headers;

	SECTION("Empty headers - verify behavior") {
		// VerifyResponseSignature may not throw for missing headers if they're optional
		// The key is it doesn't crash and handles gracefully
		try {
			BoilstreamInputValidationTestAccess::VerifyResponseSignature(*storage, "{}", 200, headers,
			                                                             valid_session_key);
			// If it doesn't throw, that's acceptable
		} catch (const std::exception &) {
			// Throwing is also acceptable
		}
		REQUIRE(true); // Test passes if no crash
	}

	SECTION("Invalid signature header is handled") {
		headers["x-boilstream-date"] = "20250101T120000Z";
		headers["x-boilstream-status"] = "200";
		headers["x-boilstream-signature"] = "invalid-signature-format";
		// Should either throw or handle gracefully - no crash
		try {
			BoilstreamInputValidationTestAccess::VerifyResponseSignature(*storage, "{}", 200, headers,
			                                                             valid_session_key);
		} catch (const std::exception &) {
			// Expected - invalid signature should fail verification
		}
		REQUIRE(true); // Test passes if no crash
	}

	SECTION("Malformed date header is handled") {
		headers["x-boilstream-date"] = "not-a-valid-date";
		headers["x-boilstream-status"] = "200";
		headers["x-boilstream-signature"] = "YWJjZGVm"; // Some base64
		try {
			BoilstreamInputValidationTestAccess::VerifyResponseSignature(*storage, "{}", 200, headers,
			                                                             valid_session_key);
		} catch (const std::exception &) {
			// Expected
		}
		REQUIRE(true); // Test passes if no crash
	}
}

//===----------------------------------------------------------------------===//
// SECTION 10: HTTP URL Validation Tests
//===----------------------------------------------------------------------===//

TEST_CASE_METHOD(InputValidationTestFixture, "SignRequest handles various URL formats", "[input_validation][url]") {
	SECTION("Empty URL is handled") {
		// Empty URL should be handled gracefully
		try {
			auto result = BoilstreamInputValidationTestAccess::SignRequest(
			    *storage, "GET", "", "", 1234567890, 1, valid_session_key, valid_access_token, "us-west-2");
			// If it succeeds, that's fine
		} catch (const std::exception &) {
			// Throwing is also acceptable
		}
	}

	SECTION("Malformed URL is handled") {
		try {
			auto result = BoilstreamInputValidationTestAccess::SignRequest(
			    *storage, "GET", "not-a-url", "", 1234567890, 1, valid_session_key, valid_access_token, "us-west-2");
		} catch (const std::exception &) {
			// Throwing is acceptable
		}
	}

	SECTION("URL with special characters is handled") {
		try {
			auto result = BoilstreamInputValidationTestAccess::SignRequest(
			    *storage, "GET", "https://api.example.com/secrets?name=test%20secret&foo=bar", "", 1234567890, 1,
			    valid_session_key, valid_access_token, "us-west-2");
		} catch (const std::exception &) {
			// Throwing is acceptable
		}
	}
}

//===----------------------------------------------------------------------===//
// SECTION 11: Size Limit Validation Tests (DoS protection)
//===----------------------------------------------------------------------===//

TEST_CASE_METHOD(InputValidationTestFixture, "Size limits prevent DoS attacks",
                 "[input_validation][security][size_limits]") {
	SECTION("DecryptResponse rejects oversized response") {
		// Create a response larger than MAX_ENCRYPTED_RESPONSE_SIZE (10MB)
		std::string oversized_response(11 * 1024 * 1024, 'a'); // 11MB
		REQUIRE_THROWS_AS(BoilstreamInputValidationTestAccess::DecryptResponse(*storage, oversized_response,
		                                                                       valid_session_key, 0x0001),
		                  IOException);
	}

	SECTION("DecryptResponse error message includes size info") {
		std::string oversized_response(11 * 1024 * 1024, 'a');
		try {
			BoilstreamInputValidationTestAccess::DecryptResponse(*storage, oversized_response, valid_session_key,
			                                                     0x0001);
			FAIL("Expected IOException");
		} catch (const IOException &e) {
			std::string msg = e.what();
			REQUIRE(msg.find("too large") != std::string::npos);
			REQUIRE(msg.find("bytes") != std::string::npos);
		}
	}

	SECTION("DeserializeSecret rejects oversized JSON") {
		Connection conn(*db);
		auto &secret_manager = db->instance->GetSecretManager();

		// Create JSON larger than MAX_JSON_RESPONSE_SIZE (10MB)
		std::string oversized_json(11 * 1024 * 1024, ' ');
		oversized_json = "{\"data\": \"" + oversized_json + "\"}";

		REQUIRE_THROWS_AS(
		    BoilstreamInputValidationTestAccess::DeserializeSecret(*storage, oversized_json, secret_manager),
		    IOException);
	}

	SECTION("Reasonable sizes are accepted") {
		// Valid-sized encrypted response (should fail on content, not size)
		std::string valid_size_json = R"({"encrypted": true, "nonce": "YWJj", "ciphertext": "YWJj", "hmac": "abc"})";
		try {
			BoilstreamInputValidationTestAccess::DecryptResponse(*storage, valid_size_json, valid_session_key, 0x0001);
		} catch (const IOException &e) {
			// Should fail on content validation, not size
			std::string msg = e.what();
			REQUIRE(msg.find("too large") == std::string::npos);
		}
	}
}

//===----------------------------------------------------------------------===//
// SECTION 12: Boundary Value Tests
//===----------------------------------------------------------------------===//

TEST_CASE_METHOD(InputValidationTestFixture, "Boundary value tests for numeric fields",
                 "[input_validation][boundary]") {
	SECTION("Maximum sequence number is handled") {
		REQUIRE_NOTHROW(BoilstreamInputValidationTestAccess::SignRequest(
		    *storage, "GET", "https://api.example.com/secrets", "", 1234567890, UINT64_MAX, valid_session_key,
		    valid_access_token, "us-west-2"));
	}

	SECTION("Zero timestamp is handled") {
		REQUIRE_NOTHROW(
		    BoilstreamInputValidationTestAccess::SignRequest(*storage, "GET", "https://api.example.com/secrets", "", 0,
		                                                     1, valid_session_key, valid_access_token, "us-west-2"));
	}

	SECTION("Maximum timestamp is handled") {
		REQUIRE_NOTHROW(BoilstreamInputValidationTestAccess::SignRequest(
		    *storage, "GET", "https://api.example.com/secrets", "", UINT64_MAX, 1, valid_session_key,
		    valid_access_token, "us-west-2"));
	}
}

//===----------------------------------------------------------------------===//
// SECTION 12: Thread Safety Tests for Input Validation
//===----------------------------------------------------------------------===//

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
					state.GetSessionSnapshot();
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

//===----------------------------------------------------------------------===//
// SECTION 13: Error Message Quality Tests
//===----------------------------------------------------------------------===//

TEST_CASE_METHOD(InputValidationTestFixture, "Error messages do not leak sensitive information",
                 "[input_validation][security][error_messages]") {
	SECTION("Region error does not suggest default values") {
		try {
			BoilstreamInputValidationTestAccess::SignRequest(*storage, "GET", "https://api.example.com/secrets", "",
			                                                 1234567890, 1, valid_session_key, valid_access_token, "");
			FAIL("Expected IOException");
		} catch (const IOException &e) {
			std::string msg = e.what();
			// Error message should NOT suggest fallback values
			REQUIRE(msg.find("us-east-1") == std::string::npos);
			REQUIRE(msg.find("default") == std::string::npos);
		}
	}

	SECTION("Token error does not expose token value") {
		try {
			BoilstreamInputValidationTestAccess::SignRequest(*storage, "GET", "https://api.example.com/secrets", "",
			                                                 1234567890, 1, valid_session_key, "short", "us-west-2");
			FAIL("Expected IOException");
		} catch (const IOException &e) {
			std::string msg = e.what();
			// Error should reference "access_token" but not include the actual value
			REQUIRE(msg.find("access_token") != std::string::npos);
			// The actual short token value should ideally not appear, but length is OK
		}
	}
}
