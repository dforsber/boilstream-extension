//===----------------------------------------------------------------------===//
//                         DuckDB
//
// boilstream_secret_storage.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/main/secret/secret_storage.hpp"
#include "duckdb/common/mutex.hpp"
#include <string>
#include <chrono>

namespace duckdb {

class DatabaseInstance;
class SecretManager;

//! REST API-based secret storage that communicates with an external service
//! for multi-tenant secret management
class RestApiSecretStorage : public CatalogSetSecretStorage {
public:
	RestApiSecretStorage(DatabaseInstance &db, const string &api_base_url);

	//! Set the endpoint URL (without token)
	void SetEndpoint(const string &endpoint);

	//! Perform PKCE token exchange with bootstrap token
	void PerformTokenExchange(const string &bootstrap_token);

	//! Rotate session token using stored code_verifier
	void RotateSessionToken();

	//! Clear session state (on error or logout)
	void ClearSession();

	//! Set user context for a connection
	void SetUserContextForConnection(idx_t connection_id, const string &user_id);

	//! Get user context for a connection
	string GetUserContextForConnection(idx_t connection_id);

	//! Clear connection mapping (for cleanup)
	void ClearConnectionMapping(idx_t connection_id);

	//! Generate PKCE code_verifier (64-char base64url random string)
	string GenerateCodeVerifier();

	//! Compute PKCE code_challenge from code_verifier (SHA256 + base64url)
	string ComputeCodeChallenge(const string &code_verifier);

	//! Validate token format and length
	void ValidateTokenFormat(const string &token, const string &context);

	//! Check if session token is valid (not expired, with 30min buffer)
	bool IsSessionTokenValid();

	//! Check if session token should be rotated (< 30min remaining)
	bool ShouldRotateToken();

	//! Override to fetch all secrets from REST API
	vector<SecretEntry> AllSecrets(optional_ptr<CatalogTransaction> transaction) override;

	//! Override to lookup secrets from REST API
	SecretMatch LookupSecret(const string &path, const string &type,
	                         optional_ptr<CatalogTransaction> transaction) override;

	//! Override to get secret by name from REST API
	unique_ptr<SecretEntry> GetSecretByName(const string &name, optional_ptr<CatalogTransaction> transaction) override;

	//! Override to store secret to REST API
	unique_ptr<SecretEntry> StoreSecret(unique_ptr<const BaseSecret> secret, OnCreateConflict on_conflict,
	                                    optional_ptr<CatalogTransaction> transaction) override;

	//! Override to drop secret from REST API
	void DropSecretByName(const string &name, OnEntryNotFound on_entry_not_found,
	                      optional_ptr<CatalogTransaction> transaction) override;

protected:
	//! Override WriteSecret to persist to REST API
	void WriteSecret(const BaseSecret &secret, OnCreateConflict on_conflict) override;

	//! Override RemoveSecret to delete from REST API
	void RemoveSecret(const string &name, OnEntryNotFound on_entry_not_found) override;

private:
	//! Extract user context from transaction (user_context_id from ClientData)
	string ExtractUserContext(optional_ptr<CatalogTransaction> transaction);

	//! Serialize secret to JSON string
	string SerializeSecret(const BaseSecret &secret);

	//! Deserialize secret from JSON string
	unique_ptr<BaseSecret> DeserializeSecret(const string &json_data, SecretManager &manager);

	//! Parse ISO 8601 UTC timestamp to system_clock time_point
	std::chrono::system_clock::time_point ParseExpiresAt(const string &expires_at_str);

	//! Check if a secret has expired
	bool IsExpired(const string &secret_name);

	//! Store expiration timestamp for a secret
	void StoreExpiration(const string &secret_name, const string &expires_at_str);

	//! Clear expiration data for a secret
	void ClearExpiration(const string &secret_name);

	//! Add or update secret in local catalog
	void AddOrUpdateSecretInCatalog(unique_ptr<BaseSecret> secret, optional_ptr<CatalogTransaction> transaction);

	//! Make HTTP GET request to REST API
	string HttpGet(const string &url);

	//! Make HTTP POST request to REST API (returns response body)
	string HttpPost(const string &url, const string &body);

	//! Make HTTP DELETE request to REST API
	void HttpDelete(const string &url);

	//! Base URL for REST API endpoint (e.g., "https://api.example.com/secrets")
	string endpoint_url;

	//! Lock for thread-safe endpoint updates
	mutex endpoint_lock;

	//! Session token (obtained via PKCE exchange, in-memory only)
	string session_token;

	//! PKCE code verifier (never transmitted, used for rotation)
	string code_verifier;

	//! Session token expiration timestamp
	std::chrono::system_clock::time_point token_expires_at;

	//! Lock for session token state
	mutex session_lock;

	//! Lock for token rotation (prevents concurrent rotations)
	mutex rotation_lock;

	//! Flag indicating rotation in progress
	bool is_rotating;

	//! Flag indicating token exchange in progress
	bool is_exchanging;

	//! Connection ID to user ID mapping
	case_insensitive_map_t<string> connection_user_map;

	//! Lock for connection user map
	mutex connection_lock;

	//! Secret expiration timestamps (name -> expiration time)
	case_insensitive_map_t<std::chrono::system_clock::time_point> secret_expiration;

	//! Lock for expiration map
	mutex expiration_lock;
};

} // namespace duckdb
