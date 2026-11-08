// Tests the production Rust C ABI, not a parallel implementation of the protocol.
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "opaque_client.h"
#include <array>
#include <string>

static std::string Hex(const std::array<uint8_t, 32> &bytes) {
	const char *digits = "0123456789abcdef";
	std::string result;
	for (auto byte : bytes) {
		result += digits[byte >> 4];
		result += digits[byte & 15];
	}
	return result;
}

TEST_CASE("Production SHA-256 known-answer vectors", "[crypto][sha256]") {
	std::array<uint8_t, 32> digest {};
	const std::string empty;
	opaque_client_sha256(reinterpret_cast<const uint8_t *>(empty.data()), empty.size(), digest.data());
	REQUIRE(Hex(digest) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	const std::string abc = "abc";
	opaque_client_sha256(reinterpret_cast<const uint8_t *>(abc.data()), abc.size(), digest.data());
	REQUIRE(Hex(digest) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("Production OPAQUE refresh credential matches the independent vector", "[crypto][refresh-token]") {
	std::array<uint8_t, 64> key {};
	for (size_t i = 0; i < key.size(); ++i) {
		key[i] = static_cast<uint8_t>(i);
	}
	std::array<uint8_t, 32> refresh {}, identity {};
	REQUIRE(opaque_client_derive_refresh_token(key.data(), key.size(), refresh.data()) == 0);
	// HKDF-Expand(key, "session-resumption-v1", 32), independently checked with
	// Python's standard-library HMAC and retained from the protocol test vector.
	REQUIRE(Hex(refresh) == "870246bc83f0728dac2c1d486834a7eefe1565c6252469c895374fc733828942");
	opaque_client_sha256(refresh.data(), refresh.size(), identity.data());
	REQUIRE(Hex(identity) == "4cf42b1fbdc10b41302f03978931de2ae6d4581c8531c6b740aa3a5c0043bd33");
	const auto original = refresh;
	key[0] ^= 1;
	REQUIRE(opaque_client_derive_refresh_token(key.data(), key.size(), refresh.data()) == 0);
	REQUIRE(refresh != original);
}

TEST_CASE("Refresh derivation rejects invalid inputs without writing output", "[crypto][ffi]") {
	std::array<uint8_t, 64> key {};
	std::array<uint8_t, 32> output;
	output.fill(0xa5);
	const auto sentinel = output;
	REQUIRE(opaque_client_derive_refresh_token(nullptr, key.size(), output.data()) != 0);
	REQUIRE(output == sentinel);
	REQUIRE(opaque_client_derive_refresh_token(key.data(), 0, output.data()) != 0);
	REQUIRE(output == sentinel);
	REQUIRE(opaque_client_derive_refresh_token(key.data(), key.size(), nullptr) != 0);
}
