//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_boilstream_encryption.cpp
//
// Test suite for Boilstream response encryption/decryption
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "boilstream_secret_storage.hpp"
#include "duckdb.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/blob.hpp"
#include "mbedtls_wrapper.hpp"

using namespace duckdb;

// Friend class to access private methods for testing
class BoilstreamEncryptionTestAccess {
public:
	static std::string DecryptResponse(const std::string &encrypted_response_body,
	                                   const std::vector<uint8_t> &session_key, uint16_t cipher_suite) {
		DuckDB duckdb_instance;
		Connection conn(duckdb_instance);
		auto &db = *conn.context->db;
		RestApiSecretStorage storage(db, "https://test.example.com");

		// Convert to duckdb vector
		vector<uint8_t> duckdb_session_key(session_key.begin(), session_key.end());

		return storage.DecryptResponse(encrypted_response_body, duckdb_session_key, cipher_suite);
	}

	static std::vector<uint8_t> DeriveEncryptionKey(const std::vector<uint8_t> &session_key) {
		DuckDB duckdb_instance;
		Connection conn(duckdb_instance);
		auto &db = *conn.context->db;
		RestApiSecretStorage storage(db, "https://test.example.com");

		vector<uint8_t> duckdb_session_key(session_key.begin(), session_key.end());
		auto key = storage.DeriveEncryptionKey(duckdb_session_key);
		return std::vector<uint8_t>(key.begin(), key.end());
	}

	static std::vector<uint8_t> DeriveIntegrityKey(const std::vector<uint8_t> &session_key) {
		DuckDB duckdb_instance;
		Connection conn(duckdb_instance);
		auto &db = *conn.context->db;
		RestApiSecretStorage storage(db, "https://test.example.com");

		vector<uint8_t> duckdb_session_key(session_key.begin(), session_key.end());
		auto key = storage.DeriveIntegrityKey(duckdb_session_key);
		return std::vector<uint8_t>(key.begin(), key.end());
	}
};

// Test fixture with common test data
struct EncryptionTestFixture {
	std::vector<uint8_t> test_session_key;
	std::vector<uint8_t> encryption_key;
	std::vector<uint8_t> integrity_key;
	std::string plaintext_json;

	EncryptionTestFixture() {
		// Test session key (32 bytes)
		test_session_key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		                    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
		                    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

		// Derive keys
		encryption_key = BoilstreamEncryptionTestAccess::DeriveEncryptionKey(test_session_key);
		integrity_key = BoilstreamEncryptionTestAccess::DeriveIntegrityKey(test_session_key);

		// Test plaintext
		plaintext_json =
		    R"({"secret_name":"test_secret","secret_type":"s3","provider":"aws","scope":["s3://bucket/*"]})";
	}

	// Helper: Encrypt plaintext using AES-256-GCM AEAD
	std::string EncryptAes256Gcm(const std::vector<uint8_t> &nonce, const std::string &plaintext) {
		duckdb_mbedtls::MbedTlsWrapper::AESStateMBEDTLS aes_encrypt(duckdb::EncryptionTypes::CipherType::GCM,
		                                                            32 // 256-bit key
		);

		aes_encrypt.InitializeEncryption(nonce.data(), nonce.size(), encryption_key.data(), encryption_key.size(),
		                                 nullptr, 0 // no AAD
		);

		std::vector<uint8_t> ciphertext(plaintext.size());
		aes_encrypt.Process(reinterpret_cast<duckdb::const_data_ptr_t>(plaintext.data()), plaintext.size(),
		                    ciphertext.data(), ciphertext.size());

		std::vector<uint8_t> aead_tag(16);
		aes_encrypt.Finalize(ciphertext.data(), 0, aead_tag.data(), aead_tag.size());

		// Build ciphertext_with_tag (ciphertext || tag)
		std::vector<uint8_t> ciphertext_with_tag_vec;
		ciphertext_with_tag_vec.insert(ciphertext_with_tag_vec.end(), ciphertext.begin(), ciphertext.end());
		ciphertext_with_tag_vec.insert(ciphertext_with_tag_vec.end(), aead_tag.begin(), aead_tag.end());

		return std::string(reinterpret_cast<char *>(ciphertext_with_tag_vec.data()), ciphertext_with_tag_vec.size());
	}
};

TEST_CASE("Response Encryption/Decryption - AES-256-GCM", "[encryption][aes]") {
	EncryptionTestFixture fixture;

	SECTION("Encrypt and decrypt plaintext successfully") {
		// 1. Generate nonce (12 bytes)
		std::vector<uint8_t> nonce = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab};

		// 2. Encrypt plaintext using AES-256-GCM AEAD
		std::string ciphertext_with_tag = fixture.EncryptAes256Gcm(nonce, fixture.plaintext_json);
		REQUIRE(ciphertext_with_tag.size() >= 16); // At least 16 bytes for AEAD tag

		// 3. Compute HMAC over (nonce || ciphertext_with_tag)
		std::vector<uint8_t> hmac_input;
		hmac_input.insert(hmac_input.end(), nonce.begin(), nonce.end());
		hmac_input.insert(hmac_input.end(), ciphertext_with_tag.begin(), ciphertext_with_tag.end());

		char hmac[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
		duckdb_mbedtls::MbedTlsWrapper::Hmac256(
		    reinterpret_cast<const char *>(fixture.integrity_key.data()), fixture.integrity_key.size(),
		    reinterpret_cast<const char *>(hmac_input.data()), hmac_input.size(), hmac);

		// 4. Encode fields for JSON
		std::string nonce_b64 = Blob::ToBase64(string_t(reinterpret_cast<const char *>(nonce.data()), nonce.size()));
		std::string ciphertext_b64 = Blob::ToBase64(string_t(ciphertext_with_tag.c_str(), ciphertext_with_tag.size()));

		// Hex encode HMAC (lowercase)
		std::string hmac_hex;
		const char *hex_chars = "0123456789abcdef";
		for (size_t i = 0; i < 32; i++) {
			unsigned char byte = static_cast<unsigned char>(hmac[i]);
			hmac_hex += hex_chars[(byte >> 4) & 0xF];
			hmac_hex += hex_chars[byte & 0xF];
		}

		// 5. Build encrypted response JSON
		std::string encrypted_response = R"({
			"encrypted": true,
			"nonce": ")" + nonce_b64 + R"(",
			"ciphertext": ")" + ciphertext_b64 +
		                                 R"(",
			"hmac": ")" + hmac_hex + R"("
		})";

		// 6. Decrypt response
		std::string decrypted_plaintext =
		    BoilstreamEncryptionTestAccess::DecryptResponse(encrypted_response, fixture.test_session_key,
		                                                    0x0001 // AES-256-GCM
		    );

		// 7. Verify decrypted plaintext matches original
		REQUIRE(decrypted_plaintext == fixture.plaintext_json);
	}

	SECTION("Reject response with invalid HMAC (tampering detection)") {
		// Create valid encrypted response
		std::vector<uint8_t> nonce = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab};

		std::string ciphertext_with_tag = fixture.EncryptAes256Gcm(nonce, fixture.plaintext_json);

		std::vector<uint8_t> hmac_input;
		hmac_input.insert(hmac_input.end(), nonce.begin(), nonce.end());
		hmac_input.insert(hmac_input.end(), ciphertext_with_tag.begin(), ciphertext_with_tag.end());

		char hmac[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
		duckdb_mbedtls::MbedTlsWrapper::Hmac256(
		    reinterpret_cast<const char *>(fixture.integrity_key.data()), fixture.integrity_key.size(),
		    reinterpret_cast<const char *>(hmac_input.data()), hmac_input.size(), hmac);

		// Tamper with HMAC by flipping one bit
		hmac[0] ^= 0x01;

		std::string nonce_b64 = Blob::ToBase64(string_t(reinterpret_cast<const char *>(nonce.data()), nonce.size()));
		std::string ciphertext_b64 = Blob::ToBase64(string_t(ciphertext_with_tag.c_str(), ciphertext_with_tag.size()));

		std::string hmac_hex;
		const char *hex_chars = "0123456789abcdef";
		for (size_t i = 0; i < 32; i++) {
			unsigned char byte = static_cast<unsigned char>(hmac[i]);
			hmac_hex += hex_chars[(byte >> 4) & 0xF];
			hmac_hex += hex_chars[byte & 0xF];
		}

		std::string encrypted_response = R"({
			"encrypted": true,
			"nonce": ")" + nonce_b64 + R"(",
			"ciphertext": ")" + ciphertext_b64 +
		                                 R"(",
			"hmac": ")" + hmac_hex + R"("
		})";

		// Should throw because HMAC verification fails
		REQUIRE_THROWS_WITH(
		    BoilstreamEncryptionTestAccess::DecryptResponse(encrypted_response, fixture.test_session_key, 0x0001),
		    Catch::Contains("tampering detected"));
	}

	SECTION("Reject response with tampered ciphertext") {
		std::vector<uint8_t> nonce = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab};

		std::string ciphertext_with_tag = fixture.EncryptAes256Gcm(nonce, fixture.plaintext_json);

		// Tamper with ciphertext
		ciphertext_with_tag[0] ^= 0x01;

		// Compute HMAC over tampered ciphertext (attacker's perspective)
		std::vector<uint8_t> hmac_input;
		hmac_input.insert(hmac_input.end(), nonce.begin(), nonce.end());
		hmac_input.insert(hmac_input.end(), ciphertext_with_tag.begin(), ciphertext_with_tag.end());

		char hmac[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
		duckdb_mbedtls::MbedTlsWrapper::Hmac256(
		    reinterpret_cast<const char *>(fixture.integrity_key.data()), fixture.integrity_key.size(),
		    reinterpret_cast<const char *>(hmac_input.data()), hmac_input.size(), hmac);

		std::string nonce_b64 = Blob::ToBase64(string_t(reinterpret_cast<const char *>(nonce.data()), nonce.size()));
		std::string ciphertext_b64 = Blob::ToBase64(string_t(ciphertext_with_tag.c_str(), ciphertext_with_tag.size()));

		std::string hmac_hex;
		const char *hex_chars = "0123456789abcdef";
		for (size_t i = 0; i < 32; i++) {
			unsigned char byte = static_cast<unsigned char>(hmac[i]);
			hmac_hex += hex_chars[(byte >> 4) & 0xF];
			hmac_hex += hex_chars[byte & 0xF];
		}

		std::string encrypted_response = R"({
			"encrypted": true,
			"nonce": ")" + nonce_b64 + R"(",
			"ciphertext": ")" + ciphertext_b64 +
		                                 R"(",
			"hmac": ")" + hmac_hex + R"("
		})";

		// HMAC will pass, but AES-GCM AEAD tag verification will fail during decryption
		REQUIRE_THROWS(
		    BoilstreamEncryptionTestAccess::DecryptResponse(encrypted_response, fixture.test_session_key, 0x0001));
	}

	SECTION("Reject response with invalid nonce size") {
		std::string encrypted_response = R"({
			"encrypted": true,
			"nonce": "aGVsbG8=",
			"ciphertext": "dGVzdA==",
			"hmac": "0000000000000000000000000000000000000000000000000000000000000000"
		})";

		REQUIRE_THROWS_WITH(
		    BoilstreamEncryptionTestAccess::DecryptResponse(encrypted_response, fixture.test_session_key, 0x0001),
		    Catch::Contains("Invalid nonce size"));
	}

	SECTION("Reject response with missing encrypted field") {
		std::string encrypted_response = R"({
			"nonce": "oKGio6SlpqeoqaqrAA==",
			"ciphertext": "dGVzdA==",
			"hmac": "0000000000000000000000000000000000000000000000000000000000000000"
		})";

		REQUIRE_THROWS_WITH(
		    BoilstreamEncryptionTestAccess::DecryptResponse(encrypted_response, fixture.test_session_key, 0x0001),
		    Catch::Contains("not encrypted"));
	}

	SECTION("Reject response with encrypted=false") {
		std::string encrypted_response = R"({
			"encrypted": false,
			"nonce": "oKGio6SlpqeoqaqrAA==",
			"ciphertext": "dGVzdA==",
			"hmac": "0000000000000000000000000000000000000000000000000000000000000000"
		})";

		REQUIRE_THROWS_WITH(
		    BoilstreamEncryptionTestAccess::DecryptResponse(encrypted_response, fixture.test_session_key, 0x0001),
		    Catch::Contains("not encrypted"));
	}

	SECTION("Reject response with invalid HMAC length") {
		// Use valid 12-byte nonce and ciphertext so validation reaches HMAC length check
		std::vector<uint8_t> nonce = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab};
		std::string nonce_b64 = Blob::ToBase64(string_t(reinterpret_cast<const char *>(nonce.data()), nonce.size()));

		// Create valid ciphertext with AEAD tag (at least 16 bytes)
		std::vector<uint8_t> ciphertext_with_tag(20, 0x00); // 20 bytes of zeros
		std::string ciphertext_b64 = Blob::ToBase64(
		    string_t(reinterpret_cast<const char *>(ciphertext_with_tag.data()), ciphertext_with_tag.size()));

		std::string encrypted_response = R"({
			"encrypted": true,
			"nonce": ")" + nonce_b64 + R"(",
			"ciphertext": ")" + ciphertext_b64 +
		                                 R"(",
			"hmac": "00000000"
		})";

		REQUIRE_THROWS_WITH(
		    BoilstreamEncryptionTestAccess::DecryptResponse(encrypted_response, fixture.test_session_key, 0x0001),
		    Catch::Contains("Invalid HMAC size"));
	}

	SECTION("Reject unsupported cipher suite") {
		// Use valid 12-byte nonce, ciphertext, and HMAC so validation reaches cipher suite check
		std::vector<uint8_t> nonce = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab};
		std::string nonce_b64 = Blob::ToBase64(string_t(reinterpret_cast<const char *>(nonce.data()), nonce.size()));

		// Create valid ciphertext with AEAD tag (at least 16 bytes)
		std::vector<uint8_t> ciphertext_with_tag(20, 0x00); // 20 bytes of zeros
		std::string ciphertext_b64 = Blob::ToBase64(
		    string_t(reinterpret_cast<const char *>(ciphertext_with_tag.data()), ciphertext_with_tag.size()));

		std::string encrypted_response = R"({
			"encrypted": true,
			"nonce": ")" + nonce_b64 + R"(",
			"ciphertext": ")" + ciphertext_b64 +
		                                 R"(",
			"hmac": "0000000000000000000000000000000000000000000000000000000000000000"
		})";

		REQUIRE_THROWS_WITH(
		    BoilstreamEncryptionTestAccess::DecryptResponse(encrypted_response, fixture.test_session_key, 0x9999),
		    Catch::Contains("Unsupported cipher suite"));
	}
}

TEST_CASE("Response Encryption - HMAC Computation Order", "[encryption][hmac]") {
	EncryptionTestFixture fixture;

	SECTION("HMAC computed over nonce || ciphertext_with_tag (correct order)") {
		std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
		std::vector<uint8_t> ciphertext_with_tag = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

		// Correct order: nonce || ciphertext_with_tag
		std::vector<uint8_t> hmac_input;
		hmac_input.insert(hmac_input.end(), nonce.begin(), nonce.end());
		hmac_input.insert(hmac_input.end(), ciphertext_with_tag.begin(), ciphertext_with_tag.end());

		REQUIRE(hmac_input.size() == 20); // 12 + 8
		REQUIRE(hmac_input[0] == 0x01);   // First byte from nonce
		REQUIRE(hmac_input[11] == 0x0c);  // Last byte from nonce
		REQUIRE(hmac_input[12] == 0x10);  // First byte from ciphertext
		REQUIRE(hmac_input[19] == 0x17);  // Last byte from ciphertext
	}
}
