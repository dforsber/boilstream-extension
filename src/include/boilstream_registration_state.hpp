#pragma once
#include "boilstream_connection_state.hpp"

namespace duckdb {
// A bounded copy held only by the current operation; never persisted.
struct BoilstreamRegistrationSnapshot {
	BoilstreamRegistrationSnapshot(uint64_t generation, const string &base_url, const string &email,
	                               const string &session_token, const string &totp_uri)
	    : generation(generation), base_url(base_url), email(email), session_token(session_token), totp_uri(totp_uri) {
	}
	BoilstreamRegistrationSnapshot(BoilstreamRegistrationSnapshot &&) noexcept = default;
	BoilstreamRegistrationSnapshot(const BoilstreamRegistrationSnapshot &) = delete;
	BoilstreamRegistrationSnapshot &operator=(const BoilstreamRegistrationSnapshot &) = delete;
	uint64_t generation = 0;
	string base_url, email, session_token, totp_uri;
	~BoilstreamRegistrationSnapshot() {
		BoilstreamConnectionState::SecureZeroString(session_token);
		BoilstreamConnectionState::SecureZeroString(totp_uri);
	}
};
class BoilstreamRegistrationContext;
} // namespace duckdb
