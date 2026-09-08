//===----------------------------------------------------------------------===//
//                         Boilstream Extension
//
// test_boilstream_registration.cpp
//
// Tests for email/password registration FFI functions
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "../../src/include/opaque_client_ffi.hpp"
#include <cstring>
#include <string>

//===----------------------------------------------------------------------===//
// Email Validation Tests
//===----------------------------------------------------------------------===//

TEST_CASE("registration_validate_email - valid emails", "[registration][ffi]") {
	REQUIRE(registration_validate_email("user@example.com") == 0);
	REQUIRE(registration_validate_email("alice@company.org") == 0);
	REQUIRE(registration_validate_email("test.user@sub.domain.com") == 0);
	REQUIRE(registration_validate_email("user+tag@example.com") == 0);
	REQUIRE(registration_validate_email("123@456.com") == 0);
}

TEST_CASE("registration_validate_email - invalid emails", "[registration][ffi]") {
	REQUIRE(registration_validate_email("") == -1);
	REQUIRE(registration_validate_email("notanemail") == -1);
	REQUIRE(registration_validate_email("@example.com") == -1);
	REQUIRE(registration_validate_email("user@") == -1);
	REQUIRE(registration_validate_email("user") == -1);
	REQUIRE(registration_validate_email("@") == -1);
	REQUIRE(registration_validate_email("..") == -1);
}

TEST_CASE("registration_validate_email - null input", "[registration][ffi]") {
	REQUIRE(registration_validate_email(nullptr) == -1);
}

//===----------------------------------------------------------------------===//
// Password Validation Tests
//===----------------------------------------------------------------------===//

TEST_CASE("registration_validate_password - valid passwords", "[registration][ffi]") {
	const char *password1 = "SecurePass123!";
	REQUIRE(registration_validate_password(reinterpret_cast<const uint8_t *>(password1), strlen(password1)) == 0);

	const char *password2 = "ThisIsA12CharPass";
	REQUIRE(registration_validate_password(reinterpret_cast<const uint8_t *>(password2), strlen(password2)) == 0);

	const char *password3 = "VeryLongPasswordThatIsDefinitelySecure";
	REQUIRE(registration_validate_password(reinterpret_cast<const uint8_t *>(password3), strlen(password3)) == 0);

	// Exactly 12 characters
	const char *password4 = "12chars_pass";
	REQUIRE(registration_validate_password(reinterpret_cast<const uint8_t *>(password4), strlen(password4)) == 0);
}

TEST_CASE("registration_validate_password - weak passwords", "[registration][ffi]") {
	const char *password1 = "";
	REQUIRE(registration_validate_password(reinterpret_cast<const uint8_t *>(password1), strlen(password1)) == -1);

	const char *password2 = "short";
	REQUIRE(registration_validate_password(reinterpret_cast<const uint8_t *>(password2), strlen(password2)) == -1);

	const char *password3 = "11chars_bad";
	REQUIRE(registration_validate_password(reinterpret_cast<const uint8_t *>(password3), strlen(password3)) == -1);

	// 11 characters (too short)
	const char *password4 = "11charspas";
	REQUIRE(registration_validate_password(reinterpret_cast<const uint8_t *>(password4), 11) == -1);
}

TEST_CASE("registration_validate_password - null input", "[registration][ffi]") {
	REQUIRE(registration_validate_password(nullptr, 0) == -1);
	REQUIRE(registration_validate_password(nullptr, 12) == -1);
}

//===----------------------------------------------------------------------===//
// TOTP URI Building Tests
//===----------------------------------------------------------------------===//

TEST_CASE("registration_build_totp_uri - default issuer", "[registration][ffi]") {
	const char *email = "alice@example.com";
	const char *secret = "JBSWY3DPEHPK3PXP";
	char uri_buffer[512];

	long result = registration_build_totp_uri(email, secret, nullptr, uri_buffer, sizeof(uri_buffer));

	REQUIRE(result > 0);
	REQUIRE(result < 512);

	std::string uri(uri_buffer, result);
	REQUIRE(uri.find("otpauth://totp/BoilStream:alice%40example.com") == 0);
	REQUIRE(uri.find("secret=JBSWY3DPEHPK3PXP") != std::string::npos);
	REQUIRE(uri.find("issuer=BoilStream") != std::string::npos);
	REQUIRE(uri.find("algorithm=SHA512") != std::string::npos);
	REQUIRE(uri.find("digits=6") != std::string::npos);
	REQUIRE(uri.find("period=30") != std::string::npos);
}

TEST_CASE("registration_build_totp_uri - custom issuer", "[registration][ffi]") {
	const char *email = "bob@company.com";
	const char *secret = "SECRET123";
	const char *issuer = "MyCompany";
	char uri_buffer[512];

	long result = registration_build_totp_uri(email, secret, issuer, uri_buffer, sizeof(uri_buffer));

	REQUIRE(result > 0);

	std::string uri(uri_buffer, result);
	REQUIRE(uri.find("otpauth://totp/MyCompany:bob%40company.com") == 0);
	REQUIRE(uri.find("secret=SECRET123") != std::string::npos);
	REQUIRE(uri.find("issuer=MyCompany") != std::string::npos);
}

TEST_CASE("registration_build_totp_uri - buffer too small", "[registration][ffi]") {
	const char *email = "user@example.com";
	const char *secret = "SECRET";
	char small_buffer[10]; // Too small

	long result = registration_build_totp_uri(email, secret, nullptr, small_buffer, sizeof(small_buffer));

	REQUIRE(result == -1); // Should fail with buffer too small
}

TEST_CASE("registration_build_totp_uri - null inputs", "[registration][ffi]") {
	const char *email = "user@example.com";
	const char *secret = "SECRET";
	char uri_buffer[512];

	// Null email
	REQUIRE(registration_build_totp_uri(nullptr, secret, nullptr, uri_buffer, sizeof(uri_buffer)) == -1);

	// Null secret
	REQUIRE(registration_build_totp_uri(email, nullptr, nullptr, uri_buffer, sizeof(uri_buffer)) == -1);

	// Null buffer
	REQUIRE(registration_build_totp_uri(email, secret, nullptr, nullptr, sizeof(uri_buffer)) == -1);

	// All null
	REQUIRE(registration_build_totp_uri(nullptr, nullptr, nullptr, nullptr, 0) == -1);
}

TEST_CASE("registration_build_totp_uri - special characters in email", "[registration][ffi]") {
	const char *email = "user+tag@example.com";
	const char *secret = "SECRET";
	char uri_buffer[512];

	long result = registration_build_totp_uri(email, secret, nullptr, uri_buffer, sizeof(uri_buffer));

	REQUIRE(result > 0);

	std::string uri(uri_buffer, result);
	REQUIRE(uri.find("user%2Btag%40example.com") != std::string::npos);
}

TEST_CASE("registration_build_totp_uri - verify null termination", "[registration][ffi]") {
	const char *email = "test@example.com";
	const char *secret = "SECRET";
	char uri_buffer[512];
	memset(uri_buffer, 'X', sizeof(uri_buffer)); // Fill with junk

	long result = registration_build_totp_uri(email, secret, nullptr, uri_buffer, sizeof(uri_buffer));

	REQUIRE(result > 0);
	// Verify null termination
	REQUIRE(uri_buffer[result] == '\0');
}

//===----------------------------------------------------------------------===//
// Integration Tests
//===----------------------------------------------------------------------===//

TEST_CASE("registration flow validation", "[registration][integration]") {
	// Test complete validation flow
	const char *email = "newuser@example.com";
	const char *password = "SecurePassword123!";

	// Step 1: Validate email
	REQUIRE(registration_validate_email(email) == 0);

	// Step 2: Validate password
	REQUIRE(registration_validate_password(reinterpret_cast<const uint8_t *>(password), strlen(password)) == 0);

	// Step 3: Build TOTP URI
	const char *secret = "JBSWY3DPEHPK3PXP";
	char uri_buffer[512];
	long uri_len = registration_build_totp_uri(email, secret, nullptr, uri_buffer, sizeof(uri_buffer));

	REQUIRE(uri_len > 0);
	REQUIRE(uri_buffer[uri_len] == '\0');

	std::string uri(uri_buffer, uri_len);
	REQUIRE(uri.find("otpauth://totp/") == 0);
	REQUIRE(uri.find("newuser%40example.com") != std::string::npos);
	REQUIRE(uri.find(secret) != std::string::npos);
}

TEST_CASE("registration validation catches errors early", "[registration][integration]") {
	// Test that invalid email is caught before password validation
	const char *invalid_email = "notanemail";
	const char *valid_password = "SecurePassword123!";

	REQUIRE(registration_validate_email(invalid_email) == -1);

	// Test that weak password is caught before TOTP generation
	const char *valid_email = "user@example.com";
	const char *weak_password = "short";

	REQUIRE(registration_validate_email(valid_email) == 0);
	REQUIRE(registration_validate_password(reinterpret_cast<const uint8_t *>(weak_password), strlen(weak_password)) ==
	        -1);
}
