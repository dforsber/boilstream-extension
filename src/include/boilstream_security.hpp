#pragma once

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

namespace boilstream {

inline void WipeMemory(void *pointer, size_t size) noexcept {
	volatile unsigned char *bytes = static_cast<volatile unsigned char *>(pointer);
	while (size--) {
		*bytes++ = 0;
	}
}

struct WipeCStringDeleter {
	void operator()(char *value) const noexcept {
		if (value) {
			WipeMemory(value, std::strlen(value));
			std::free(value);
		}
	}
};

// Deliberately accept an unambiguous subset of HTTP URLs. In particular, the
// authority is never decoded and userinfo is never accepted by this client.
inline void ValidateEndpoint(const std::string &url) {
	const bool secure = url.compare(0, 8, "https://") == 0;
	const size_t begin = secure ? 8 : 7;
	if (!secure && url.compare(0, 7, "http://") != 0) {
		throw std::invalid_argument("URL must start with http:// or https://");
	}
	for (unsigned char c : url) {
		if (c <= 32 || c == 127 || c == '\\' || c == '#') {
			throw std::invalid_argument("URL contains forbidden characters");
		}
	}
	const auto end = url.find_first_of("/?", begin);
	const auto authority = url.substr(begin, end == std::string::npos ? end : end - begin);
	if (authority.empty() || authority.find_first_of("@%") != std::string::npos) {
		throw std::invalid_argument("URL authority must not contain userinfo or escapes");
	}
	std::string host, port;
	bool has_port = false;
	if (authority[0] == '[') {
		const auto bracket = authority.find(']');
		if (bracket == std::string::npos || bracket == 1) {
			throw std::invalid_argument("URL has invalid IPv6 authority");
		}
		host = authority.substr(0, bracket + 1);
		for (size_t i = 1; i < bracket; i++) {
			const auto c = authority[i];
			if (!(c == ':' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
				throw std::invalid_argument("URL has invalid IPv6 authority");
			}
		}
		if (bracket + 1 < authority.size()) {
			if (authority[bracket + 1] != ':') {
				throw std::invalid_argument("URL has invalid authority suffix");
			}
			has_port = true;
			port = authority.substr(bracket + 2);
		}
	} else {
		const auto colon = authority.find(':');
		host = authority.substr(0, colon);
		has_port = colon != std::string::npos;
		if (has_port) {
			port = authority.substr(colon + 1);
		}
		for (auto &c : host) {
			if (c >= 'A' && c <= 'Z') {
				c += 'a' - 'A';
			}
			if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) {
				throw std::invalid_argument("URL has invalid hostname");
			}
		}
	}
	if (host.empty()) {
		throw std::invalid_argument("URL hostname cannot be empty");
	}
	if (has_port) {
		unsigned value = 0;
		if (port.empty() || port.size() > 5) {
			throw std::invalid_argument("URL has invalid port");
		}
		for (auto c : port) {
			if (c < '0' || c > '9') {
				throw std::invalid_argument("URL has invalid port");
			}
			value = value * 10 + (c - '0');
		}
		if (!value || value > 65535) {
			throw std::invalid_argument("URL has invalid port");
		}
	}
	if (!secure && host != "localhost" && host != "127.0.0.1" && host != "[::1]") {
		throw std::invalid_argument("URL must use HTTPS (or localhost for testing)");
	}
}

// Own the temporary buffer returned by yyjson_mut_write, including allocation
// failure while copying it to the destination string.
struct WipeFreeCString {
	char *value;
	~WipeFreeCString() {
		if (value) {
			volatile char *bytes = value;
			const auto size = std::strlen(value);
			for (size_t i = 0; i < size; i++) {
				bytes[i] = 0;
			}
			std::free(value);
		}
	}
};

constexpr size_t MAX_HTTP_RESPONSE_BYTES = 10ULL * 1024 * 1024;
inline void CheckResponseSize(size_t size) {
	if (size > MAX_HTTP_RESPONSE_BYTES) {
		throw std::runtime_error("HTTP response exceeds size limit");
	}
}
inline void AppendResponse(std::string &body, const char *data, size_t size) {
	if (body.size() > MAX_HTTP_RESPONSE_BYTES || size > MAX_HTTP_RESPONSE_BYTES - body.size()) {
		throw std::runtime_error("HTTP response exceeds size limit");
	}
	if (body.size() + size > body.capacity()) {
		// std::string growth would free the old credential-bearing allocation
		// without erasing it. Allocate first, then erase before swapping owners.
		std::string grown;
		const auto required = body.size() + size;
		grown.reserve(required <= MAX_HTTP_RESPONSE_BYTES / 2 ? required * 2 : MAX_HTTP_RESPONSE_BYTES);
		grown.assign(body);
		WipeMemory(body.data(), body.size());
		body.swap(grown);
	}
	body.append(data, size);
}

template <class Container>
inline void Wipe(Container &value) noexcept {
	volatile unsigned char *data = reinterpret_cast<volatile unsigned char *>(value.data());
	for (size_t i = 0; i < value.size() * sizeof(typename Container::value_type); i++) {
		data[i] = 0;
	}
}

template <class T, size_t N>
inline void Wipe(T (&value)[N]) noexcept {
	volatile unsigned char *data = reinterpret_cast<volatile unsigned char *>(value);
	for (size_t i = 0; i < sizeof(value); i++) {
		data[i] = 0;
	}
}

template <class Container>
class WipeOnExit {
public:
	explicit WipeOnExit(Container &value) : value(value) {
	}
	~WipeOnExit() {
		Wipe(value);
	}
	WipeOnExit(const WipeOnExit &) = delete;
	WipeOnExit &operator=(const WipeOnExit &) = delete;

private:
	Container &value;
};
template <class Container>
WipeOnExit(Container &) -> WipeOnExit<Container>;

} // namespace boilstream
