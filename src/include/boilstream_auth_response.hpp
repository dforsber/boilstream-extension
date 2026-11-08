#pragma once
#include "boilstream_json.hpp"
#include "boilstream_registration_state.hpp"
#include <chrono>
#include <cstring>
#include <memory>

namespace duckdb {
// Pure parsing of already authenticated application bodies. This grants no
// authority: callers must verify the protocol envelope before invoking it.
class BoilstreamAuthResponse {
public:
	explicit BoilstreamAuthResponse(const string &body)
	    : doc(arena.Read(body.data(), body.size(), 0), duckdb_yyjson::yyjson_doc_free) {
		if (!doc || !duckdb_yyjson::yyjson_is_obj(duckdb_yyjson::yyjson_doc_get_root(doc.get()))) {
			throw IOException("Invalid authentication response");
		}
	}
	duckdb_yyjson::yyjson_val *Field(const char *name) const {
		auto root = duckdb_yyjson::yyjson_doc_get_root(doc.get());
		auto iter = duckdb_yyjson::yyjson_obj_iter_with(root);
		duckdb_yyjson::yyjson_val *key;
		duckdb_yyjson::yyjson_val *value = nullptr;
		while ((key = duckdb_yyjson::yyjson_obj_iter_next(&iter))) {
			if (duckdb_yyjson::yyjson_get_len(key) == std::strlen(name) &&
			    std::memcmp(duckdb_yyjson::yyjson_get_str(key), name, std::strlen(name)) == 0) {
				if (value) {
					throw IOException("Duplicate authentication response field");
				}
				value = duckdb_yyjson::yyjson_obj_iter_get_val(key);
			}
		}
		return value;
	}
	void RequireSuccess() const {
		auto value = Field("success");
		auto error = Field("error");
		if (!duckdb_yyjson::yyjson_is_bool(value) || !duckdb_yyjson::yyjson_get_bool(value) ||
		    (error && !duckdb_yyjson::yyjson_is_null(error))) {
			throw IOException("Authentication operation was not successful");
		}
	}
	static void ValidateText(duckdb_yyjson::yyjson_val *value, size_t limit) {
		const auto length = duckdb_yyjson::yyjson_get_len(value);
		if (!duckdb_yyjson::yyjson_is_str(value) || length == 0 || length > limit) {
			throw IOException("Invalid authentication response value");
		}
		const auto data = duckdb_yyjson::yyjson_get_str(value);
		for (size_t i = 0; i < length; ++i) {
			if (static_cast<unsigned char>(data[i]) < 32 || data[i] == 127) {
				throw IOException("Invalid authentication response value");
			}
		}
	}
	string Text(const char *name, size_t limit = 4096) const {
		auto value = Field(name);
		ValidateText(value, limit);
		return string(duckdb_yyjson::yyjson_get_str(value), duckdb_yyjson::yyjson_get_len(value));
	}
	string OpaqueAccessToken() const {
		auto token = Text("access_token", 64);
		boilstream::WipeOnExit wipe_token(token);
		if (token.size() != 64 || token.find_first_not_of("0123456789abcdef") != string::npos) {
			throw IOException("Invalid authentication access token");
		}
		return string(token);
	}
	// The server contract uses Unix seconds. Reject missing, ambiguous, expired
	// or unrepresentable values instead of inventing a local session lifetime.
	std::chrono::system_clock::time_point SessionExpiry(std::chrono::system_clock::time_point now) const {
		using std::chrono::duration_cast;
		using std::chrono::seconds;
		using std::chrono::system_clock;
		auto value = Field("expires_at");
		if (!duckdb_yyjson::yyjson_is_uint(value)) {
			throw IOException("Invalid authentication expiry");
		}
		const auto count = duckdb_yyjson::yyjson_get_uint(value);
		const auto max_seconds = duration_cast<seconds>(system_clock::duration::max()).count();
		if (count == 0 || count > static_cast<uint64_t>(max_seconds)) {
			throw IOException("Invalid authentication expiry");
		}
		const auto expiry = system_clock::time_point(duration_cast<system_clock::duration>(seconds(count)));
		if (expiry <= now) {
			throw IOException("Authentication response has expired");
		}
		return expiry;
	}
	unique_ptr<BoilstreamRegistrationOutput> RecoveryCodes() const {
		RequireSuccess();
		auto output = make_uniq<BoilstreamRegistrationOutput>();
		auto codes = Field("backup_codes");
		if (!codes) {
			return output;
		}
		if (!duckdb_yyjson::yyjson_is_arr(codes) || duckdb_yyjson::yyjson_arr_size(codes) > 128) {
			throw IOException("Invalid recovery-code response");
		}
		const auto count = duckdb_yyjson::yyjson_arr_size(codes);
		output->rows.reserve(count);
		for (size_t i = 0; i < count; ++i) {
			auto value = duckdb_yyjson::yyjson_arr_get(codes, i);
			ValidateText(value, 8192);
			// Allocate directly in the wiping owner, including failure paths.
			output->rows.push_back({"", false});
			output->rows.back().value.assign(duckdb_yyjson::yyjson_get_str(value),
			                                 duckdb_yyjson::yyjson_get_len(value));
		}
		return output;
	}

private:
	boilstream::JsonArena arena;
	std::unique_ptr<duckdb_yyjson::yyjson_doc, decltype(&duckdb_yyjson::yyjson_doc_free)> doc;
};

// Set-Cookie here is metadata decoded from the verified body, never an HTTP
// response header. Match the cookie name exactly; do not accept xsession= or a
// session= substring hidden inside another cookie's value or attributes.
inline string BoilstreamSessionCookie(const string &cookie) {
	if (cookie.size() > 8192 || cookie.compare(0, 8, "session=") != 0) {
		throw IOException("Invalid authenticated session cookie");
	}
	for (auto c : cookie) {
		if (static_cast<unsigned char>(c) < 32 || c == 127) {
			throw IOException("Invalid authenticated session cookie");
		}
	}
	auto end = cookie.find(';', 8);
	if (end == string::npos) {
		end = cookie.size();
	}
	if (end == 8 || end - 8 > 4096) {
		throw IOException("Invalid authenticated session cookie");
	}
	for (size_t i = 8; i < end; ++i) {
		const auto c = static_cast<unsigned char>(cookie[i]);
		if (c < 0x21 || c > 0x7e || c == '"' || c == ',' || c == '\\') {
			throw IOException("Invalid authenticated session cookie");
		}
	}
	return cookie.substr(8, end - 8);
}
} // namespace duckdb
