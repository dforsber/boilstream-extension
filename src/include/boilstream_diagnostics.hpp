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
// Preserve only reviewed public diagnostics at the core query-error boundary.
// This allowlist intentionally defaults unknown future messages to redaction.
inline string BoilstreamPrivateErrorMessageUnwrapped(const ErrorData &error) {
	if (error.Type() != ExceptionType::IO && error.Type() != ExceptionType::INVALID_INPUT &&
	    error.Type() != ExceptionType::HTTP)
		return "";
	static const char *const public_messages[] = {
	    "Authentication result ID is required",
	    "Authentication result is unavailable",
	    "Bootstrap token is empty",
	    "Bootstrap token response missing bootstrap_token field",
	    "CSRF response missing csrf_token field",
	    "CSRF token is empty",
	    "Extracted session token is empty from Set-Cookie header",
	    "Failed to build TOTP URI",
	    "Failed to parse CSRF response",
	    "Failed to parse MFA response",
	    "Failed to parse TOTP enrollment response",
	    "Failed to parse bootstrap token response",
	    "Failed to parse login response",
	    "Failed to parse signup response",
	    "Failed to parse verification response",
	    "HTTP GET failed: Could not initialize HTTP parameters",
	    "HTTP POST failed: Could not initialize HTTP parameters",
	    "Invalid TOTP secret length",
	    "Invalid recovery-code count",
	    "Invalid recovery-code response",
	    "Invalid recovery-code value",
	    "Login failed",
	    "Login failed: No session cookie returned",
	    "Login response missing Set-Cookie header",
	    "MFA authentication failed",
	    "MFA verification failed",
	    "No boilstream storage available",
	    "Set-Cookie header missing session cookie",
	    "Signup failed",
	    "TOTP enrollment response missing secret",
	    "TOTP secret is empty",
	    "TOTP secret is missing",
	    "boilstream_login requires url_with_email, password, and mfa_code parameters",
	    "boilstream_login: Email cannot be empty",
	    "boilstream_login: Invalid URL format. Expected: https://host/email@example.com",
	    "boilstream_login: Invalid email format",
	    "boilstream_login: MFA code must be 6 digits",
	    "boilstream_login: MFA code must contain only digits",
	    "boilstream_login: Password must be at least 12 characters",
	    "boilstream_login: URL must start with http:// or https://",
	    "boilstream_login: URL must use HTTPS (or localhost for testing)",
	    "boilstream_register_user requires url_with_email and password parameters",
	    "boilstream_register_user: Invalid email address format",
	    "boilstream_register_user: Password must be at least 12 characters",
	    "boilstream_register_user: URL must start with http:// or https://",
	    "boilstream_register_user: URL must use HTTPS (or localhost for testing)",
	    "boilstream_verify_mfa requires totp_code parameter",
	    "boilstream_verify_mfa: TOTP code must be 6 digits",
	    "boilstream_verify_mfa: TOTP code must contain only digits",
	    "rest_set_endpoint requires a URL parameter",
	    "rest_set_endpoint: Bootstrap token cannot be empty",
	    "rest_set_endpoint: Invalid URL format",
	    "rest_set_endpoint: Storage not initialized",
	    "rest_set_endpoint: URL cannot be empty",
	    "rest_set_endpoint: URL must start with http:// or https://",
	    "rest_set_endpoint: URL must use HTTPS (or localhost for testing)",
	};
	for (const auto message : public_messages) {
		if (error.RawMessage() == message)
			return message;
	}
	string status;
	auto entry = error.ExtraInfo().find("status_code");
	if (entry != error.ExtraInfo().end() && entry->second.size() == 3)
		status = entry->second;
	// ProcessError may run again after a safe exception crosses an API boundary.
	// Recognize only our exact canonical form, never arbitrary HTTP error text.
	const string prefix = "Authentication request failed: HTTP ";
	if (status.empty() && error.RawMessage().size() == prefix.size() + 3 &&
	    error.RawMessage().compare(0, prefix.size(), prefix) == 0)
		status = error.RawMessage().substr(prefix.size());
	if (status.size() == 3 && status[0] >= '1' && status[0] <= '5' && status[1] >= '0' && status[1] <= '9' &&
	    status[2] >= '0' && status[2] <= '9')
		return prefix + status;
	return "";
}

inline string BoilstreamPrivateErrorMessage(const ErrorData &error) {
	// DuckDB can process the same ErrorData again after converting its raw
	// message to JSON. Decode at most one bounded envelope, then apply exactly
	// the same public allowlist; never forward the envelope or its extra info.
	const auto &raw = error.RawMessage();
	if (!raw.empty() && raw[0] == '{') {
		if (raw.size() > 1024)
			return "";
		try {
			ErrorData decoded(raw);
			if (decoded.Type() != error.Type())
				return "";
			return BoilstreamPrivateErrorMessageUnwrapped(decoded);
		} catch (...) {
			return "";
		}
	}
	return BoilstreamPrivateErrorMessageUnwrapped(error);
}

} // namespace duckdb
