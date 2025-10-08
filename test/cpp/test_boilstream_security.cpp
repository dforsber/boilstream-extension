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

#include <set>
#include <unordered_set>
#include <thread>
#include <chrono>
#include <algorithm>

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
// Test: Code Verifier Generation (Rejection Sampling)
//===----------------------------------------------------------------------===//
TEST_CASE("PKCE Code Verifier Generation", "[boilstream][security]") {
	auto storage = CreateTestStorage();

	SECTION("Verifier has correct length") {
		auto verifier = storage->GenerateCodeVerifier();
		REQUIRE(verifier.length() == 64);
	}

	SECTION("Verifier contains only valid base64url characters") {
		auto verifier = storage->GenerateCodeVerifier();
		const string valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

		for (char c : verifier) {
			REQUIRE(valid_chars.find(c) != string::npos);
		}
	}

	SECTION("Multiple verifiers are unique") {
		std::set<string> verifiers;
		const int num_samples = 1000;

		for (int i = 0; i < num_samples; i++) {
			verifiers.insert(storage->GenerateCodeVerifier());
		}

		// With 64 chars from 64-char alphabet, collision probability is negligible
		// We should have close to 1000 unique values
		REQUIRE(verifiers.size() >= num_samples - 5); // Allow tiny margin for statistical variance
	}

	SECTION("Verifier has high entropy (chi-square test approximation)") {
		// Generate many verifiers and check character distribution
		const int num_verifiers = 100;
		const int verifier_length = 64;
		const int alphabet_size = 64;
		std::unordered_map<char, int> char_counts;

		for (int i = 0; i < num_verifiers; i++) {
			auto verifier = storage->GenerateCodeVerifier();
			for (char c : verifier) {
				char_counts[c]++;
			}
		}

		// Expected count per character (if uniform)
		double expected = (num_verifiers * verifier_length) / (double)alphabet_size;

		// Chi-square test: sum of (observed - expected)^2 / expected
		// For uniform distribution, should be relatively small
		double chi_square = 0.0;
		for (const auto &pair : char_counts) {
			double diff = pair.second - expected;
			chi_square += (diff * diff) / expected;
		}

		// With 64 categories and reasonable randomness, chi-square should be < 100
		// This is a loose test, but catches catastrophic bias
		REQUIRE(chi_square < 150.0);
	}
}

//===----------------------------------------------------------------------===//
// Test: Code Challenge Computation
//===----------------------------------------------------------------------===//
TEST_CASE("PKCE Code Challenge Computation", "[boilstream][security]") {
	auto storage = CreateTestStorage();

	SECTION("Challenge is base64url encoded SHA256") {
		auto verifier = storage->GenerateCodeVerifier();
		auto challenge = storage->ComputeCodeChallenge(verifier);

		// Base64url of SHA256 (32 bytes) = 43 characters (no padding)
		REQUIRE(challenge.length() == 43);
	}

	SECTION("Challenge contains only base64url characters") {
		auto verifier = storage->GenerateCodeVerifier();
		auto challenge = storage->ComputeCodeChallenge(verifier);
		const string valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

		for (char c : challenge) {
			REQUIRE(valid_chars.find(c) != string::npos);
		}
	}

	SECTION("Same verifier produces same challenge") {
		auto verifier = "test_verifier_123456789_abcdefghijklmnopqrstuvwxyz_ABCDEFGH";
		auto challenge1 = storage->ComputeCodeChallenge(verifier);
		auto challenge2 = storage->ComputeCodeChallenge(verifier);

		REQUIRE(challenge1 == challenge2);
	}

	SECTION("Different verifiers produce different challenges") {
		auto verifier1 = storage->GenerateCodeVerifier();
		auto verifier2 = storage->GenerateCodeVerifier();
		auto challenge1 = storage->ComputeCodeChallenge(verifier1);
		auto challenge2 = storage->ComputeCodeChallenge(verifier2);

		REQUIRE(challenge1 != challenge2);
	}

	SECTION("Known verifier produces expected challenge (test vector)") {
		// RFC 7636 test vector (using S256 method)
		string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
		auto challenge = storage->ComputeCodeChallenge(verifier);

		// Expected: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM (from RFC 7636)
		string expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

		REQUIRE(challenge == expected);
	}
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

	SECTION("ShouldRotateToken returns false when token is empty") {
		REQUIRE(storage->ShouldRotateToken() == false);
	}

	SECTION("ClearSession wipes all session state") {
		storage->ClearSession();

		// After clear, session should be invalid
		REQUIRE(storage->IsSessionTokenValid() == false);
		REQUIRE(storage->ShouldRotateToken() == false);
	}
}

//===----------------------------------------------------------------------===//
// Test: Thread Safety (Race Condition Detection)
//===----------------------------------------------------------------------===//
TEST_CASE("Thread Safety for Token Operations", "[boilstream][security][.]") {
	// Note: [.] tag means this test is hidden by default (run with --run-all)
	// These tests may be flaky depending on timing

	SECTION("Concurrent code verifier generation") {
		auto storage = CreateTestStorage();
		const int num_threads = 10;
		const int verifiers_per_thread = 100;

		std::vector<std::thread> threads;
		std::vector<std::set<string>> thread_results(num_threads);

		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&storage, &thread_results, t, verifiers_per_thread]() {
				for (int i = 0; i < verifiers_per_thread; i++) {
					thread_results[t].insert(storage->GenerateCodeVerifier());
				}
			});
		}

		for (auto &thread : threads) {
			thread.join();
		}

		// Collect all verifiers
		std::set<string> all_verifiers;
		for (const auto &results : thread_results) {
			all_verifiers.insert(results.begin(), results.end());
		}

		// Should have unique verifiers (near 1000)
		REQUIRE(all_verifiers.size() >= (num_threads * verifiers_per_thread - 10));
	}

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
}

//===----------------------------------------------------------------------===//
// Test: Security Properties
//===----------------------------------------------------------------------===//
TEST_CASE("Security Properties", "[boilstream][security]") {
	auto storage = CreateTestStorage();

	SECTION("Code verifiers are unpredictable") {
		// Generate many verifiers and check they don't follow a pattern
		std::vector<string> verifiers;
		for (int i = 0; i < 100; i++) {
			verifiers.push_back(storage->GenerateCodeVerifier());
		}

		// Check no two consecutive verifiers are identical
		for (size_t i = 1; i < verifiers.size(); i++) {
			REQUIRE(verifiers[i] != verifiers[i - 1]);
		}

		// Check Hamming distance between consecutive verifiers is substantial
		// (they should differ in many positions)
		int total_hamming = 0;
		for (size_t i = 1; i < verifiers.size(); i++) {
			int hamming = 0;
			for (size_t j = 0; j < 64; j++) {
				if (verifiers[i][j] != verifiers[i - 1][j]) {
					hamming++;
				}
			}
			total_hamming += hamming;
		}

		double avg_hamming = total_hamming / (double)(verifiers.size() - 1);
		// Average Hamming distance should be close to 63 for truly random strings
		// (each position has 63/64 chance of being different)
		REQUIRE(avg_hamming > 55.0); // At least 55 positions differ on average
		REQUIRE(avg_hamming < 64.0); // But not all positions (mathematically impossible)
	}

	SECTION("Code challenges are one-way (cannot recover verifier)") {
		auto verifier = storage->GenerateCodeVerifier();
		auto challenge = storage->ComputeCodeChallenge(verifier);

		// The challenge should not contain the verifier as a substring
		REQUIRE(challenge.find(verifier) == string::npos);

		// The challenge should have different length (43 vs 64)
		REQUIRE(challenge.length() != verifier.length());
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
