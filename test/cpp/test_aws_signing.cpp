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
