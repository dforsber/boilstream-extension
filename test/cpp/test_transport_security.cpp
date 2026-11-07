#include "boilstream_security.hpp"
#include <algorithm>
#include <iostream>
#include <vector>

static void Require(bool condition) {
	if (!condition)
		throw std::runtime_error("security regression assertion failed");
}
int main() {
	for (const auto &url : {"https://example.com", "https://api.example.com:443/path?q=x", "http://localhost:8080/a",
	                        "http://LOCALHOST/a", "http://127.0.0.1", "http://[::1]:8080/a"}) {
		boilstream::ValidateEndpoint(url);
	}
	for (const auto &url :
	     {"http://localhost:80@evil.test/a", "https://localhost@evil.test", "http://127.0.0.1:80@evil.test",
	      "http://localhost.evil.test", "http://127.1", "http://2130706433", "http://[::1]@evil.test",
	      "http://[::1]:80@evil.test", "http://%6cocalhost", "http://localhost\\@evil.test", "http://localhost:0",
	      "http://localhost:65536", "http://localhost:", "http://localhost:abc", "https://", "http:///x",
	      "https://host/#fragment", "http://localhost\n.evil.test"}) {
		bool rejected = false;
		try {
			boilstream::ValidateEndpoint(url);
		} catch (const std::invalid_argument &) {
			rejected = true;
		}
		Require(rejected);
	}
	std::string body(boilstream::MAX_HTTP_RESPONSE_BYTES - 1, 'x');
	boilstream::AppendResponse(body, "x", 1);
	bool rejected = false;
	try {
		boilstream::AppendResponse(body, "y", 1);
	} catch (const std::runtime_error &) {
		rejected = true;
	}
	Require(rejected && body.size() == boilstream::MAX_HTTP_RESPONSE_BYTES && body.back() == 'x');
	body.clear();
	rejected = false;
	try {
		boilstream::AppendResponse(body, "x", static_cast<size_t>(-1));
	} catch (const std::runtime_error &) {
		rejected = true;
	}
	Require(rejected && body.empty()); // No overflow, read or allocation for impossible lengths.
	std::string secret = "sensitive";
	std::vector<unsigned char> key(64, 7);
	try {
		boilstream::WipeOnExit wipe_secret(secret);
		boilstream::WipeOnExit wipe_key(key);
		throw std::runtime_error("simulate exceptional exit");
	} catch (const std::runtime_error &) {
	}
	Require(std::all_of(secret.begin(), secret.end(), [](char c) { return c == 0; }));
	Require(std::all_of(key.begin(), key.end(), [](unsigned char c) { return c == 0; }));
	std::cout << "Transport URL, bounded append and exceptional secret erasure checks passed\n";
}
