//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_aws_signing.cpp
//
// Unit tests for AWS SigV4-style Request Signing
//
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "opaque_client.h"
#include <string>
#include <cstring>
#include <array>
#include <algorithm>

using namespace std;

//===----------------------------------------------------------------------===//
// Helper: Free OpaqueBuffer RAII wrapper
//===----------------------------------------------------------------------===//
struct BufferGuard {
	OpaqueBuffer buffer;

	BufferGuard(OpaqueBuffer b) : buffer(b) {
	}
	~BufferGuard() {
		if (buffer.data) {
			opaque_free_buffer(buffer);
		}
	}

	string to_string() const {
		return string(reinterpret_cast<const char *>(buffer.data), buffer.len);
	}
};

//===----------------------------------------------------------------------===//
// Test: aws_build_canonical_request
//===----------------------------------------------------------------------===//
TEST_CASE("AWS Build Canonical Request - Empty Payload", "[aws][signing]") {
	const char *method = "GET";
	const char *uri = "/secrets";
	const char *query = "";
	const char *headers = "x-boilstream-date:20251009T120000Z\n";
	const char *signed_headers = "x-boilstream-date";

	auto result = aws_build_canonical_request(method, strlen(method), uri, strlen(uri), query, strlen(query), headers,
	                                          strlen(headers), signed_headers, strlen(signed_headers), nullptr, 0);

	REQUIRE(result.error == OPAQUE_SUCCESS);
	REQUIRE(result.buffer.data != nullptr);

	BufferGuard guard(result.buffer);
	string canonical_request = guard.to_string();

	SECTION("Contains HTTP method") {
		REQUIRE(canonical_request.find("GET") != string::npos);
	}

	SECTION("Contains URI path") {
		REQUIRE(canonical_request.find("/secrets") != string::npos);
	}

	SECTION("Contains canonical headers") {
		REQUIRE(canonical_request.find("x-boilstream-date:20251009T120000Z") != string::npos);
	}

	SECTION("Contains empty payload hash") {
		// SHA-256 of empty string
		REQUIRE(canonical_request.find("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") !=
		        string::npos);
	}
}

TEST_CASE("AWS Build Canonical Request - With Payload", "[aws][signing]") {
	const char *method = "POST";
	const char *uri = "/secrets/my-secret";
	const char *query = "";
	const char *headers = "x-boilstream-date:20251009T120000Z\nx-boilstream-sequence:42\n";
	const char *signed_headers = "x-boilstream-date;x-boilstream-sequence";
	const char *payload = "{\"test\":\"data\"}";

	auto result = aws_build_canonical_request(method, strlen(method), uri, strlen(uri), query, strlen(query), headers,
	                                          strlen(headers), signed_headers, strlen(signed_headers),
	                                          reinterpret_cast<const uint8_t *>(payload), strlen(payload));

	REQUIRE(result.error == OPAQUE_SUCCESS);
	REQUIRE(result.buffer.data != nullptr);

	BufferGuard guard(result.buffer);
	string canonical_request = guard.to_string();

	SECTION("Contains POST method") {
		REQUIRE(canonical_request.find("POST") != string::npos);
	}

	SECTION("Contains URI path") {
		REQUIRE(canonical_request.find("/secrets/my-secret") != string::npos);
	}

	SECTION("Contains both headers") {
		REQUIRE(canonical_request.find("x-boilstream-date:20251009T120000Z") != string::npos);
		REQUIRE(canonical_request.find("x-boilstream-sequence:42") != string::npos);
	}

	SECTION("Contains signed headers list") {
		REQUIRE(canonical_request.find("x-boilstream-date;x-boilstream-sequence") != string::npos);
	}

	SECTION("Payload is hashed (not empty hash)") {
		// Should NOT contain empty hash
		REQUIRE(canonical_request.find("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") ==
		        string::npos);
	}
}

TEST_CASE("AWS Build Canonical Request - With Query Parameters", "[aws][signing]") {
	const char *method = "GET";
	const char *uri = "/secrets";
	const char *query = "filter=active&limit=10";
	const char *headers = "x-boilstream-date:20251009T120000Z\n";
	const char *signed_headers = "x-boilstream-date";

	auto result = aws_build_canonical_request(method, strlen(method), uri, strlen(uri), query, strlen(query), headers,
	                                          strlen(headers), signed_headers, strlen(signed_headers), nullptr, 0);

	REQUIRE(result.error == OPAQUE_SUCCESS);

	BufferGuard guard(result.buffer);
	string canonical_request = guard.to_string();

	SECTION("Contains query parameters") {
		REQUIRE(canonical_request.find("filter=active&limit=10") != string::npos);
	}
}

TEST_CASE("AWS Build Canonical Request - Null Pointer Handling", "[aws][signing]") {
	auto result = aws_build_canonical_request(nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0);

	REQUIRE(result.error == OPAQUE_INVALID_INPUT);
	REQUIRE(result.buffer.data == nullptr);
}

//===----------------------------------------------------------------------===//
// Test: aws_derive_signing_key
//===----------------------------------------------------------------------===//
TEST_CASE("AWS Derive Signing Key - Basic Derivation", "[aws][signing]") {
	const uint8_t base_key[] = "test_base_signing_key_32bytes!!";
	const char *date = "20251009";
	const char *region = "us-east-1";
	const char *service = "secrets";

	auto result = aws_derive_signing_key(base_key, sizeof(base_key) - 1, date, strlen(date), region, strlen(region),
	                                     service, strlen(service));

	REQUIRE(result.error == OPAQUE_SUCCESS);
	REQUIRE(result.buffer.data != nullptr);
	REQUIRE(result.buffer.len == 32); // HMAC-SHA256 produces 32 bytes

	opaque_free_buffer(result.buffer);
}

TEST_CASE("AWS Derive Signing Key - Deterministic", "[aws][signing]") {
	const uint8_t base_key[] = "test_base_signing_key_32bytes!!";
	const char *date = "20251009";
	const char *region = "us-east-1";
	const char *service = "secrets";

	auto result1 = aws_derive_signing_key(base_key, sizeof(base_key) - 1, date, strlen(date), region, strlen(region),
	                                      service, strlen(service));

	auto result2 = aws_derive_signing_key(base_key, sizeof(base_key) - 1, date, strlen(date), region, strlen(region),
	                                      service, strlen(service));

	REQUIRE(result1.error == OPAQUE_SUCCESS);
	REQUIRE(result2.error == OPAQUE_SUCCESS);
	REQUIRE(result1.buffer.len == result2.buffer.len);

	SECTION("Same inputs produce identical keys") {
		bool keys_match = memcmp(result1.buffer.data, result2.buffer.data, result1.buffer.len) == 0;
		REQUIRE(keys_match);
	}

	opaque_free_buffer(result1.buffer);
	opaque_free_buffer(result2.buffer);
}

TEST_CASE("AWS Derive Signing Key - Date Scoping", "[aws][signing]") {
	const uint8_t base_key[] = "test_base_signing_key_32bytes!!";
	const char *date1 = "20251009";
	const char *date2 = "20251010";
	const char *region = "us-east-1";
	const char *service = "secrets";

	auto result1 = aws_derive_signing_key(base_key, sizeof(base_key) - 1, date1, strlen(date1), region, strlen(region),
	                                      service, strlen(service));

	auto result2 = aws_derive_signing_key(base_key, sizeof(base_key) - 1, date2, strlen(date2), region, strlen(region),
	                                      service, strlen(service));

	REQUIRE(result1.error == OPAQUE_SUCCESS);
	REQUIRE(result2.error == OPAQUE_SUCCESS);

	SECTION("Different dates produce different keys") {
		bool keys_differ = memcmp(result1.buffer.data, result2.buffer.data, result1.buffer.len) != 0;
		REQUIRE(keys_differ);
	}

	opaque_free_buffer(result1.buffer);
	opaque_free_buffer(result2.buffer);
}

TEST_CASE("AWS Derive Signing Key - Region Scoping", "[aws][signing]") {
	const uint8_t base_key[] = "test_base_signing_key_32bytes!!";
	const char *date = "20251009";
	const char *region1 = "us-east-1";
	const char *region2 = "eu-west-1";
	const char *service = "secrets";

	auto result1 = aws_derive_signing_key(base_key, sizeof(base_key) - 1, date, strlen(date), region1, strlen(region1),
	                                      service, strlen(service));

	auto result2 = aws_derive_signing_key(base_key, sizeof(base_key) - 1, date, strlen(date), region2, strlen(region2),
	                                      service, strlen(service));

	REQUIRE(result1.error == OPAQUE_SUCCESS);
	REQUIRE(result2.error == OPAQUE_SUCCESS);

	SECTION("Different regions produce different keys") {
		bool keys_differ = memcmp(result1.buffer.data, result2.buffer.data, result1.buffer.len) != 0;
		REQUIRE(keys_differ);
	}

	opaque_free_buffer(result1.buffer);
	opaque_free_buffer(result2.buffer);
}

//===----------------------------------------------------------------------===//
// Test: aws_sign_canonical_request
//===----------------------------------------------------------------------===//
TEST_CASE("AWS Sign Canonical Request - Basic Signing", "[aws][signing]") {
	const uint8_t signing_key[] = "test_signing_key_32_bytes_long!";
	const char *canonical_request = "POST\n/"
	                                "secrets\n\nx-boilstream-date:20251009T120000Z\n\nx-boilstream-"
	                                "date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	auto result =
	    aws_sign_canonical_request(signing_key, sizeof(signing_key) - 1, canonical_request, strlen(canonical_request));

	REQUIRE(result.error == OPAQUE_SUCCESS);
	REQUIRE(result.buffer.data != nullptr);

	BufferGuard guard(result.buffer);
	string signature = guard.to_string();

	SECTION("Signature is base64-encoded") {
		REQUIRE(signature.length() == 44); // base64 of 32 bytes = 44 chars
	}

	SECTION("Signature contains only base64 characters") {
		const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
		for (char c : signature) {
			REQUIRE(base64_chars.find(c) != string::npos);
		}
	}
}

TEST_CASE("AWS Sign Canonical Request - Deterministic", "[aws][signing]") {
	const uint8_t signing_key[] = "test_signing_key_32_bytes_long!";
	const char *canonical_request = "GET\n/"
	                                "secrets\n\nx-boilstream-date:20251009T120000Z\n\nx-boilstream-"
	                                "date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	auto result1 =
	    aws_sign_canonical_request(signing_key, sizeof(signing_key) - 1, canonical_request, strlen(canonical_request));

	auto result2 =
	    aws_sign_canonical_request(signing_key, sizeof(signing_key) - 1, canonical_request, strlen(canonical_request));

	REQUIRE(result1.error == OPAQUE_SUCCESS);
	REQUIRE(result2.error == OPAQUE_SUCCESS);
	REQUIRE(result1.buffer.len == result2.buffer.len);

	SECTION("Same inputs produce identical signatures") {
		bool signatures_match = memcmp(result1.buffer.data, result2.buffer.data, result1.buffer.len) == 0;
		REQUIRE(signatures_match);
	}

	opaque_free_buffer(result1.buffer);
	opaque_free_buffer(result2.buffer);
}

TEST_CASE("AWS Sign Canonical Request - Different Requests", "[aws][signing]") {
	const uint8_t signing_key[] = "test_signing_key_32_bytes_long!";
	const char *request1 = "GET\n/"
	                       "secrets\n\nx-boilstream-date:20251009T120000Z\n\nx-boilstream-"
	                       "date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
	const char *request2 = "POST\n/"
	                       "secrets\n\nx-boilstream-date:20251009T120000Z\n\nx-boilstream-"
	                       "date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	auto result1 = aws_sign_canonical_request(signing_key, sizeof(signing_key) - 1, request1, strlen(request1));

	auto result2 = aws_sign_canonical_request(signing_key, sizeof(signing_key) - 1, request2, strlen(request2));

	REQUIRE(result1.error == OPAQUE_SUCCESS);
	REQUIRE(result2.error == OPAQUE_SUCCESS);

	SECTION("Different requests produce different signatures") {
		bool signatures_differ = memcmp(result1.buffer.data, result2.buffer.data, result1.buffer.len) != 0;
		REQUIRE(signatures_differ);
	}

	opaque_free_buffer(result1.buffer);
	opaque_free_buffer(result2.buffer);
}

//===----------------------------------------------------------------------===//
// Test: End-to-End Signing Flow
//===----------------------------------------------------------------------===//
TEST_CASE("AWS Full Signing Flow", "[aws][signing][integration]") {
	// Simulate complete signing workflow
	const uint8_t base_key[] = "test_base_signing_key_32bytes!!";
	const char *date = "20251009";
	const char *region = "us-east-1";
	const char *service = "secrets";

	// Step 1: Derive signing key
	auto key_result = aws_derive_signing_key(base_key, sizeof(base_key) - 1, date, strlen(date), region, strlen(region),
	                                         service, strlen(service));
	REQUIRE(key_result.error == OPAQUE_SUCCESS);

	// Step 2: Build canonical request
	const char *method = "POST";
	const char *uri = "/secrets/my-secret";
	const char *query = "";
	const char *headers = "x-boilstream-date:20251009T120000Z\n";
	const char *signed_headers = "x-boilstream-date";
	const char *payload = "{\"name\":\"test\"}";

	auto canonical_result = aws_build_canonical_request(
	    method, strlen(method), uri, strlen(uri), query, strlen(query), headers, strlen(headers), signed_headers,
	    strlen(signed_headers), reinterpret_cast<const uint8_t *>(payload), strlen(payload));
	REQUIRE(canonical_result.error == OPAQUE_SUCCESS);

	// Step 3: Sign the canonical request
	auto sig_result = aws_sign_canonical_request(key_result.buffer.data, key_result.buffer.len,
	                                             reinterpret_cast<const char *>(canonical_result.buffer.data),
	                                             canonical_result.buffer.len);
	REQUIRE(sig_result.error == OPAQUE_SUCCESS);

	BufferGuard sig_guard(sig_result.buffer);
	string signature = sig_guard.to_string();

	SECTION("Final signature is valid base64") {
		REQUIRE(signature.length() == 44);
		REQUIRE(signature.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") ==
		        string::npos);
	}

	// Cleanup
	opaque_free_buffer(key_result.buffer);
	opaque_free_buffer(canonical_result.buffer);
}

//===----------------------------------------------------------------------===//
// Test: Memory Safety
//===----------------------------------------------------------------------===//
TEST_CASE("AWS Signing Memory Safety", "[aws][signing][memory]") {
	SECTION("Multiple buffer allocations and frees") {
		const uint8_t base_key[] = "test_base_signing_key_32bytes!!";
		const char *date = "20251009";
		const char *region = "us-east-1";
		const char *service = "secrets";

		// Allocate and free 100 times
		for (int i = 0; i < 100; i++) {
			auto result = aws_derive_signing_key(base_key, sizeof(base_key) - 1, date, strlen(date), region,
			                                     strlen(region), service, strlen(service));
			REQUIRE(result.error == OPAQUE_SUCCESS);
			opaque_free_buffer(result.buffer);
		}
	}

	SECTION("Buffer can be safely copied before freeing") {
		const uint8_t signing_key[] = "test_signing_key_32_bytes_long!";
		const char *canonical_request = "GET\n/"
		                                "secrets\n\nx-boilstream-date:20251009T120000Z\n\nx-boilstream-"
		                                "date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

		auto result = aws_sign_canonical_request(signing_key, sizeof(signing_key) - 1, canonical_request,
		                                         strlen(canonical_request));

		REQUIRE(result.error == OPAQUE_SUCCESS);

		// Copy data before freeing
		string signature_copy(reinterpret_cast<const char *>(result.buffer.data), result.buffer.len);

		opaque_free_buffer(result.buffer);

		// Verify copy is still valid
		REQUIRE(signature_copy.length() == 44);
	}
}

TEST_CASE("Canonical signing rejects malformed UTF-8 in every text field", "[aws][signing][boundary]") {
	for (size_t field = 0; field < 5; ++field) {
		DYNAMIC_SECTION("field " << field) {
			std::array<std::string, 5> fields = {"POST", "/secrets", "q=a", "x-test:yes\n", "x-test"};
			fields[field].push_back(char(0xff));
			auto result = aws_build_canonical_request(fields[0].data(), fields[0].size(), fields[1].data(), fields[1].size(),
			    fields[2].data(), fields[2].size(), fields[3].data(), fields[3].size(), fields[4].data(), fields[4].size(), nullptr, 0);
			BufferGuard guard(result.buffer);
			REQUIRE(result.error == OPAQUE_INVALID_INPUT);
			REQUIRE(result.buffer.data == nullptr);
			REQUIRE(result.buffer.len == 0);
		}
	}
}

TEST_CASE("Signing key derivation rejects malformed UTF-8 scopes", "[aws][signing][boundary]") {
	const uint8_t key[] = {1, 2, 3};
	for (size_t field = 0; field < 3; ++field) {
		DYNAMIC_SECTION("scope " << field) {
			std::array<std::string, 3> fields = {"20251009", "eu-west-1", "secrets"};
			fields[field].push_back(char(0xff));
			auto result = aws_derive_signing_key(key, sizeof(key), fields[0].data(), fields[0].size(),
			    fields[1].data(), fields[1].size(), fields[2].data(), fields[2].size());
			BufferGuard guard(result.buffer);
			REQUIRE(result.error == OPAQUE_INVALID_INPUT);
			REQUIRE(result.buffer.data == nullptr);
			REQUIRE(result.buffer.len == 0);
		}
	}
}

TEST_CASE("Canonical signing rejects a missing nonempty payload", "[aws][signing][boundary]") {
	auto result = aws_build_canonical_request("GET", 3, "/", 1, "", 0, "", 0, "", 0, nullptr, 1);
	BufferGuard guard(result.buffer);
	REQUIRE(result.error == OPAQUE_INVALID_INPUT);
	REQUIRE(result.buffer.data == nullptr);
	REQUIRE(result.buffer.len == 0);
}

TEST_CASE("Signing matches independent binary-payload known answers", "[aws][signing][vectors]") {
	// Reference vectors: Python hashlib/hmac SHA-256, without this Rust library.
	const std::array<uint8_t, 32> base_key = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
	const std::array<uint8_t, 32> expected_key = {24, 47, 93, 210, 182, 242, 120, 177, 125, 185, 72, 76, 155, 58, 87, 11, 39, 23, 193, 30, 154, 221, 193, 188, 71, 18, 135, 142, 194, 156, 93, 186};
	const uint8_t payload[] = {0, 255, 65};
	const std::string headers = "x-boilstream-date:20251009T120000Z\n";
	const std::string names = "x-boilstream-date";
	const std::string expected_canonical = "POST\n/secrets\nq=a%20b\nx-boilstream-date:20251009T120000Z\n\nx-boilstream-date\na90a10503fbfc95789ff38a1bb5039cb71869ab9c0eb1cb51c4a9099f2933c6b";
	auto key = aws_derive_signing_key(base_key.data(), base_key.size(), "20251009", 8, "eu-west-1", 9, "secrets", 7);
	BufferGuard key_guard(key.buffer);
	REQUIRE(key.error == OPAQUE_SUCCESS);
	REQUIRE(key.buffer.data != nullptr);
	REQUIRE(key.buffer.len == expected_key.size());
	REQUIRE(std::equal(expected_key.begin(), expected_key.end(), key.buffer.data));
	auto canonical = aws_build_canonical_request("POST", 4, "/secrets", 8, "q=a%20b", 7,
	    headers.data(), headers.size(), names.data(), names.size(), payload, sizeof(payload));
	BufferGuard canonical_guard(canonical.buffer);
	REQUIRE(canonical.error == OPAQUE_SUCCESS);
	REQUIRE(canonical.buffer.data != nullptr);
	REQUIRE(canonical.buffer.len == expected_canonical.size());
	REQUIRE(canonical_guard.to_string() == expected_canonical);
	auto signature = aws_sign_canonical_request(key.buffer.data, key.buffer.len,
	    reinterpret_cast<const char *>(canonical.buffer.data), canonical.buffer.len);
	BufferGuard signature_guard(signature.buffer);
	REQUIRE(signature.error == OPAQUE_SUCCESS);
	REQUIRE(signature.buffer.data != nullptr);
	REQUIRE(signature.buffer.len == 44);
	REQUIRE(signature_guard.to_string() == "3ezGTaBS03EXVLK+JQqmaqWh0PjVrcDx3SMJ0Mu2Dlk=");
}
