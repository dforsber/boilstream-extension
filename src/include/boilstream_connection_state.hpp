//===----------------------------------------------------------------------===//
//                         DuckDB
//
// boilstream_connection_state.hpp
//
// Per-connection authentication state for multi-tenant support.
// Each DuckDB connection gets its own OPAQUE session credentials.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/main/client_context_state.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/case_insensitive_map.hpp"
#include <chrono>
#include <vector>
#include <string>

namespace duckdb {

//! Per-connection authentication state for boilstream extension.
//! Stored in ClientContext via RegisteredStateManager with key "boilstream_auth".
//! Each connection has independent OPAQUE session credentials for multi-tenant isolation.
class BoilstreamConnectionState : public ClientContextState {
public:
	//! Catalog version info from server
	struct CatalogVersionInfo {
		uint64_t version;
		string catalog_name;
	};

	//! Session state snapshot for thread-safe access
	struct SessionSnapshot {
		string access_token;
		vector<uint8_t> session_key;
		string region;
		uint64_t sequence;
		bool has_session_key;
	};

	BoilstreamConnectionState()
	    : client_sequence(0), is_exchanging(false),
	      token_expires_at(std::chrono::system_clock::time_point::min()),
	      last_version_check(std::chrono::system_clock::time_point::min()) {
	}

	//! Prevent copying (contains mutex)
	BoilstreamConnectionState(const BoilstreamConnectionState &) = delete;
	BoilstreamConnectionState &operator=(const BoilstreamConnectionState &) = delete;

	//========================================================================
	// Per-Connection Authentication State
	//========================================================================

	//! OPAQUE access token (JWT-like, in-memory only)
	string access_token;

	//! OPAQUE session key (32 bytes, HKDF-derived, in-memory only)
	vector<uint8_t> session_key;

	//! OPAQUE refresh token (32 bytes, for session resumption)
	vector<uint8_t> refresh_token;

	//! Lock-step sequence counter (increments per request)
	uint64_t client_sequence;

	//! Region identifier from login response (e.g., "us-east-1")
	string region;

	//! Session token expiration timestamp
	std::chrono::system_clock::time_point token_expires_at;

	//! Flag indicating OPAQUE exchange in progress
	bool is_exchanging;

	//! Hash of bootstrap token (for reuse detection)
	string bootstrap_token_hash;

	//========================================================================
	// Per-Connection Caches
	//========================================================================

	//! Secret expiration timestamps (name -> expiration time)
	case_insensitive_map_t<std::chrono::system_clock::time_point> secret_expiration;

	//! Catalog version tracking (catalog_id UUID -> version info)
	case_insensitive_map_t<CatalogVersionInfo> catalog_versions;

	//! Last time catalog versions were checked
	std::chrono::system_clock::time_point last_version_check;

	//========================================================================
	// Thread Safety (per-connection locks - no cross-connection contention)
	//========================================================================

	//! Lock for session credentials (access_token, session_key, etc.)
	mutex session_lock;

	//! Lock for secret expiration map
	mutex expiration_lock;

	//! Lock for catalog versions map
	mutex version_lock;

	//========================================================================
	// Session Management Methods
	//========================================================================

	//! Get thread-safe snapshot of session state (atomically reads and increments sequence)
	SessionSnapshot GetSessionSnapshot() {
		SessionSnapshot snapshot;
		{
			lock_guard<mutex> lock(session_lock);
			snapshot.access_token = access_token;
			snapshot.session_key = session_key;
			snapshot.region = region;
			snapshot.sequence = client_sequence;
			snapshot.has_session_key = !session_key.empty();

			// CRITICAL: Increment sequence counter after reading
			client_sequence++;
		}
		return snapshot;
	}

	//! Check if session token is valid (not expired, with 30min buffer)
	bool IsSessionTokenValid() {
		lock_guard<mutex> lock(session_lock);
		if (access_token.empty() || session_key.empty()) {
			return false;
		}
		// Check expiration with 30 minute buffer
		auto now = std::chrono::system_clock::now();
		auto buffer = std::chrono::minutes(30);
		return (token_expires_at - buffer) > now;
	}

	//! Clear session state (on error or logout)
	void ClearSession() {
		lock_guard<mutex> lock(session_lock);
		// Secure memory wiping
		std::fill(access_token.begin(), access_token.end(), '\0');
		access_token.clear();
		std::fill(session_key.begin(), session_key.end(), 0);
		session_key.clear();
		std::fill(refresh_token.begin(), refresh_token.end(), 0);
		refresh_token.clear();
		client_sequence = 0;
		region.clear();
		token_expires_at = std::chrono::system_clock::time_point::min();
		is_exchanging = false;
		bootstrap_token_hash.clear();
	}

	//! Get stored bootstrap token hash (for reuse detection)
	string GetBootstrapTokenHash() {
		lock_guard<mutex> lock(session_lock);
		return bootstrap_token_hash;
	}

	//! Set bootstrap token hash (after successful exchange)
	void SetBootstrapTokenHash(const string &hash) {
		lock_guard<mutex> lock(session_lock);
		bootstrap_token_hash = hash;
	}

	//! Get session token expiration timestamp
	std::chrono::system_clock::time_point GetTokenExpiresAt() {
		lock_guard<mutex> lock(session_lock);
		return token_expires_at;
	}

	//========================================================================
	// Secret Expiration Methods
	//========================================================================

	//! Store expiration timestamp for a secret
	void StoreExpiration(const string &secret_name, std::chrono::system_clock::time_point expiration) {
		lock_guard<mutex> lock(expiration_lock);
		secret_expiration[secret_name] = expiration;
	}

	//! Get expiration timestamp for a secret (returns min time_point if not found)
	std::chrono::system_clock::time_point GetSecretExpiration(const string &secret_name) {
		lock_guard<mutex> lock(expiration_lock);
		auto it = secret_expiration.find(secret_name);
		if (it != secret_expiration.end()) {
			return it->second;
		}
		return std::chrono::system_clock::time_point::min();
	}

	//! Check if a secret has expired (with 5 minute buffer for proactive refresh)
	bool IsSecretExpired(const string &secret_name) {
		lock_guard<mutex> lock(expiration_lock);
		auto it = secret_expiration.find(secret_name);
		if (it == secret_expiration.end()) {
			return true; // Unknown secrets are considered expired
		}
		auto now = std::chrono::system_clock::now();
		auto buffer = std::chrono::minutes(5);
		return (it->second - buffer) <= now;
	}

	//! Clear expiration data for a secret
	void ClearExpiration(const string &secret_name) {
		lock_guard<mutex> lock(expiration_lock);
		secret_expiration.erase(secret_name);
	}

	//========================================================================
	// Lifecycle Hooks
	//========================================================================

	//! Called when connection is destroyed - secure cleanup
	~BoilstreamConnectionState() override {
		ClearSession();
	}

	//! Version check interval in seconds (default 60)
	static constexpr int VERSION_CHECK_INTERVAL_SECONDS = 60;
};

} // namespace duckdb
