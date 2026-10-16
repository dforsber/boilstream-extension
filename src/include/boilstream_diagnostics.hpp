#pragma once
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/exception.hpp"
#include <iostream>
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

namespace duckdb {
// Callers pass fixed event literals, never credentials, URLs, server payloads
// or nested exception messages. Streams and std::string values are rejected.
template <size_t N>
inline void BoilstreamLogEvent(const char (&event)[N]) {
	static_assert(N <= 512, "Diagnostic event must be bounded");
#ifdef __EMSCRIPTEN__
	emscripten_log(EM_LOG_CONSOLE, "[BOILSTREAM] %s", event);
#elif defined(BOILSTREAM_DEBUG)
	std::cerr << "[BOILSTREAM] " << event << std::endl;
#endif
}

template <size_t N>
[[noreturn]] inline void BoilstreamThrowHttpStatus(const char (&stage)[N], int status) {
	if (status >= 100 && status <= 599) {
		unordered_map<string, string> safe_info {{"status_code", std::to_string(status)}};
		throw IOException(safe_info, "%s: HTTP %d", stage, status);
	}
	throw IOException("%s", stage);
}

// HTTP exceptions may carry the full body, URL and headers in structured extra
// info. Copy only a validated status code into a fresh exception at our boundary.
template <size_t N>
[[noreturn]] inline void BoilstreamRethrowSafe(const char (&stage)[N], const std::exception &exception) {
	int status = 0;
	try {
		ErrorData error(exception);
		auto it = error.ExtraInfo().find("status_code");
		if (it != error.ExtraInfo().end() && it->second.size() == 3) {
			const auto &value = it->second;
			if (value[0] >= '1' && value[0] <= '5' && value[1] >= '0' && value[1] <= '9' && value[2] >= '0' &&
			    value[2] <= '9')
				status = (value[0] - '0') * 100 + (value[1] - '0') * 10 + value[2] - '0';
		}
	} catch (...) { /* Never fall back to the original exception text. */
	}
	BoilstreamThrowHttpStatus(stage, status);
}
} // namespace duckdb
