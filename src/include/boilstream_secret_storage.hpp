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
#include "duckdb/common/http_util.hpp"
#include <string>
#include <chrono>

// Forward declarations for test friend access (outside namespace)
class BoilstreamCryptoTestAccess;
class BoilstreamConformanceTestAccess;
class BoilstreamEncryptionTestAccess;

namespace duckdb {

class DatabaseInstance;
class SecretManager;

//! REST API-based secret storage that communicates with an external service
//! for multi-tenant secret management
class RestApiSecretStorage : public CatalogSetSecretStorage {
	// Allow test code to access private methods for testing
	friend class ::BoilstreamCryptoTestAccess;
	friend class ::BoilstreamConformanceTestAccess;
	friend class ::BoilstreamEncryptionTestAccess;

public:
	RestApiSecretStorage(DatabaseInstance &db, const string &api_base_url);

	//! Set the endpoint URL (without token)
	void SetEndpoint(const string &endpoint);

	//! Perform OPAQUE registration with password
	void PerformOpaqueRegistration(const string &password);

	//! Perform OPAQUE login with password
	void PerformOpaqueLogin(const string &password);

	//! Perform OPAQUE session resumption with stored refresh token
	void PerformOpaqueResume();

	//! Clear session state (on error or logout)
	void ClearSession();

	//! Common helper for OPAQUE login flow (used by both login and resume)
	void PerformOpaqueLoginCommon(const string &password, bool is_resume);

	//! Set user context for a connection
	void SetUserContextForConnection(idx_t connection_id, const string &user_id);

	//! Get user context for a connection
	string GetUserContextForConnection(idx_t connection_id);

	//! Clear connection mapping (for cleanup)
	void ClearConnectionMapping(idx_t connection_id);

	//! Validate token format and length
	void ValidateTokenFormat(const string &token, const string &context);

	//! Check if session token is valid (not expired, with 30min buffer)
	bool IsSessionTokenValid();

	//! Get stored bootstrap token hash (for reuse detection)
	string GetBootstrapTokenHash();

	//! Set bootstrap token hash (after successful exchange)
	void SetBootstrapTokenHash(const string &hash);

	//! Get session token expiration timestamp
	std::chrono::system_clock::time_point GetTokenExpiresAt();

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
	//! Request signing result containing all required headers
	struct SigningResult {
		string signature;        // Base64-encoded HMAC signature
		string date_time;        // ISO8601 timestamp (YYYYMMDDTHHMMSSZ)
		string credential_scope; // AWS-style credential scope
	};

	//! Stored refresh token metadata
	struct RefreshTokenData {
		vector<uint8_t> refresh_token;
		string endpoint_url;
		string region;
		std::chrono::system_clock::time_point expires_at;
	};

	//! Session state snapshot for thread-safe access
	struct SessionSnapshot {
		string access_token;
		vector<uint8_t> session_key;
		string region;
		uint64_t sequence;
		bool has_session_key;
	};

	//! Get thread-safe snapshot of current session state
	SessionSnapshot GetSessionSnapshot();

	//! Extract all x-boilstream-* headers from HTTP response
	case_insensitive_map_t<string> ExtractBoilstreamHeaders(const HTTPHeaders &headers);

	//! Build authenticated request headers with signature
	HTTPHeaders BuildAuthenticatedHeaders(const string &method, const string &url, const string &body);

	//! Verify authenticated response signature and timestamp
	void VerifyAuthenticatedResponse(const string &response_body, uint16_t status_code,
	                                 const HTTPHeaders &response_headers, const vector<uint8_t> &session_key_param);

	//! Extract user context from transaction (user_context_id from ClientData)
	string ExtractUserContext(optional_ptr<CatalogTransaction> transaction);

	//! Derive signing key from session_key using HKDF-SHA256
	vector<uint8_t> DeriveSigningKey(const vector<uint8_t> &session_key_param);

	//! Derive encryption key from session_key using HKDF-SHA256
	vector<uint8_t> DeriveEncryptionKey(const vector<uint8_t> &session_key_param);

	//! Derive integrity key from session_key using HKDF-SHA256 (for response verification)
	vector<uint8_t> DeriveIntegrityKey(const vector<uint8_t> &session_key_param);

	//! Sign an HTTP request with HMAC-SHA256 (canonical request format)
	//! Returns signing result with signature, date_time, and credential_scope
	SigningResult SignRequest(const string &method, const string &url, const string &body, uint64_t timestamp,
	                          uint64_t sequence, const vector<uint8_t> &session_key_param,
	                          const string &access_token_param, const string &region_param);

	//! Verify HTTP response signature (HMAC-SHA256 over canonical response format)
	//! Throws IOException if signature verification fails
	void VerifyResponseSignature(const string &response_body, uint16_t status_code,
	                             const case_insensitive_map_t<string> &headers,
	                             const vector<uint8_t> &session_key_param);

	//! Decrypt encrypted response body (AES-256-GCM or ChaCha20-Poly1305)
	//! Performs HMAC verification before decryption per SECURITY_SPECIFICATION.md
	//! Returns plaintext JSON string
	string DecryptResponse(const string &encrypted_response_body, const vector<uint8_t> &session_key_param,
	                       uint16_t cipher_suite);

	//! Check if response is encrypted by examining X-Boilstream-Encrypted header
	//! Returns true if header is present and set to "true"
	bool IsResponseEncrypted(const case_insensitive_map_t<string> &headers);

	//! Parse cipher suite from X-Boilstream-Cipher header
	//! Returns cipher suite ID (e.g., 0x0001 for AES-256-GCM)
	//! Throws IOException if header is missing or invalid
	uint16_t ParseCipherSuite(const case_insensitive_map_t<string> &headers);

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
	string HttpPost(const string &url, const string &body, HTTPHeaders *out_headers = nullptr);

	//! Make HTTP DELETE request to REST API
	void HttpDelete(const string &url);

	//! Get the file path for stored refresh token
	string GetRefreshTokenPath();

	//! Save refresh token to file on disk (protected by file permissions)
	void SaveRefreshToken(bool resumption_enabled);

	//! Load refresh token from encrypted file on disk
	//! Returns true if loaded successfully, false if not found or expired
	bool LoadRefreshToken();

	//! Delete refresh token file from disk
	void DeleteRefreshToken();

	//! Base URL for REST API endpoint (e.g., "https://api.example.com/secrets")
	string endpoint_url;

	//! Lock for thread-safe endpoint updates
	mutex endpoint_lock;

	//! Access token (obtained via OPAQUE login, in-memory only)
	string access_token;

	//! OPAQUE session key (32 bytes, OPAQUE-derived with SHA-256, in-memory only)
	vector<uint8_t> session_key;

	//! OPAQUE refresh token (32 bytes, for session resumption, will be persisted)
	vector<uint8_t> refresh_token;

	//! Lock-step sequence counter (starts at 0, increments with each request)
	uint64_t client_sequence;

	//! Region identifier (e.g., "us-east-1", from server login response)
	string region;

	//! Session token expiration timestamp
	std::chrono::system_clock::time_point token_expires_at;

	//! Lock for session token state
	mutex session_lock;

	//! Flag indicating token exchange in progress
	bool is_exchanging;

	//! Hash of successful bootstrap token (to detect reuse attempts)
	string bootstrap_token_hash;

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
