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
#include "boilstream_connection_state.hpp"
#include "boilstream_registration_state.hpp"
#include <string>
#include <chrono>
#include <unordered_map>

// Forward declarations for test friend access (outside namespace)
class BoilstreamCryptoTestAccess;
class BoilstreamConformanceTestAccess;
class BoilstreamEncryptionTestAccess;
class BoilstreamCatalogVersionTestAccess;
class BoilstreamInputValidationTestAccess;
class BoilstreamSessionPublicationTestAccess;

namespace duckdb {

class DatabaseInstance;
class SecretManager;

//! Strictly parse the managed catalog credential response. Returns false for
//! missing, malformed, or partial transport identities so callers fail closed.
bool ParseManagedCatalogCredentialEnvelope(const string &json, ManagedCatalogCredentialEnvelope &out);

//! Catalog-qualified lookup key shared by the BoilStream and Quack extensions.
//! It is a secret scope only; the network URI remains `quack:<endpoint>`.
string ManagedCatalogSecretScope(const string &endpoint, const string &catalog_id);

//! Build the signed OPAQUE secrets-API URL used to vend one managed catalog
//! credential. Rejects non-canonical secrets endpoints and catalog UUIDs.
string ManagedCatalogCredentialUrl(const string &secrets_endpoint, const string &catalog_id);

//! Build the credential-free ATTACH statement returned by the managed-catalog
//! PRAGMA. Authorization and placement fields come only from the vended bundle.
string BuildManagedCatalogAttachSql(const ManagedCatalogCredentialEnvelope &credential, const string &alias);

//! REST API-based secret storage that communicates with an external service
//! for multi-tenant secret management
class RestApiSecretStorage : public CatalogSetSecretStorage {
	// Allow test code to access private methods for testing
	friend class ::BoilstreamCryptoTestAccess;
	friend class ::BoilstreamConformanceTestAccess;
	friend class ::BoilstreamEncryptionTestAccess;
	friend class ::BoilstreamCatalogVersionTestAccess;
	friend class ::BoilstreamInputValidationTestAccess;
	friend class ::BoilstreamSessionPublicationTestAccess;

public:
	//! Use CatalogVersionInfo from BoilstreamConnectionState
	using CatalogVersionInfo = BoilstreamConnectionState::CatalogVersionInfo;

	RestApiSecretStorage(DatabaseInstance &db, const string &api_base_url);

	//! Set the endpoint URL (without token)
	void SetEndpoint(const string &endpoint);

	//! Get active session from transaction context
	//! Returns an owning handle retained through each authenticated operation
	//! Returns nullptr if no active session exists
	shared_ptr<BoilstreamConnectionState> GetSession(optional_ptr<CatalogTransaction> transaction);

	//! Get or create session for a specific session key (bootstrap_token_hash)
	//! Creates new session if none exists for this key
	//! Explicit storage clients use this helper; PRAGMA authenticates private state
	BoilstreamConnectionState &GetOrCreateSession(const string &session_key);

	//! Check if a session exists for a session key
	bool HasSession(const string &session_key);

	//! Get session by key (returns nullptr if not found)
	shared_ptr<BoilstreamConnectionState> GetSessionByKey(const string &session_key);

	//! Set the active session key for a specific connection (concurrent-safe)
	void SetActiveSessionKeyForConnection(idx_t connection_id, const string &session_key);

	//! Get session by connection ID (returns nullptr if not found)
	shared_ptr<BoilstreamConnectionState> GetSessionForConnection(idx_t connection_id);

	//! Context-aware authority access; a changed tenant must authenticate again.
	shared_ptr<BoilstreamConnectionState> GetSessionForContext(ClientContext &context);

    //! Private embedding API. No SQL binding or constructor from claimed IDs.
    void InstallLocalSession(ClientContext &context, const BoilstreamLocalSecretHostV2 &host);
    string RequestLocal(ClientContext &context, BoilstreamConnectionState &state, const string &request);
    BoilstreamLocalSecretProvider::Response RequestLocalResponse(ClientContext &context, BoilstreamConnectionState &state, const string &request);
    void ValidateLocal(ClientContext &context, BoilstreamConnectionState &state);

	//! Perform OPAQUE login with password
	//! Authenticate private state, then publish it for this connection
	void PerformOpaqueLogin(ClientContext &context, const string &password, const string &token_hash,
	                        const string &endpoint);

	//! Perform OPAQUE resumption using only this connection's in-memory refresh token
	void PerformOpaqueResume(ClientContext &context);

	//! Clear the active session (on error or logout)
	void ClearSession(ClientContext &context);

	//! Common helper for OPAQUE login flow (used by both login and resume)
	//! Only receives unpublished state; returns whether the server supports in-memory resumption
	bool PerformOpaqueLoginCommon(const string &password, bool is_resume, BoilstreamConnectionState &pending);

	//! Set user context for a connection
	void SetUserContextForConnection(idx_t connection_id, const string &user_id);

	//! Get user context for a connection
	string GetUserContextForConnection(idx_t connection_id);

	//! Clear connection mapping (for cleanup)
	void ClearConnectionMapping(idx_t connection_id);

	//! Validate token format and length
	void ValidateTokenFormat(const string &token, const string &token_context);

	//! Check if active session token is valid (not expired, with 30min buffer)
	bool IsSessionTokenValid(ClientContext &context);

	//! Get stored bootstrap token hash for active session (for reuse detection)
	string GetBootstrapTokenHash(ClientContext &context);

	//! Set bootstrap token hash for active session (after successful exchange)
	void SetBootstrapTokenHash(ClientContext &context, const string &hash);

	//! Get session token expiration timestamp for active session
	std::chrono::system_clock::time_point GetTokenExpiresAt(ClientContext &context);

	//! Override to fetch all secrets from REST API
	vector<SecretEntry> AllSecrets(optional_ptr<CatalogTransaction> transaction) override;

	//! Get cached secrets without triggering server fetch (for WASM table function)
	vector<SecretEntry> GetCachedSecrets(optional_ptr<CatalogTransaction> transaction);

	//! Fetch all secrets from server (always fetches, bypasses WASM AllSecrets guard)
	//! Use this for bootstrap/login instead of AllSecrets() in WASM
	//! When explicit_conn_state is non-null, the call bypasses session lookup, the
	//! re-entrancy guards (SecretLookupGuard / in_http_operation) and the AllSecrets
	//! cache TTL. Bootstrap callers must use this overload: they own a freshly
	//! established conn_state but the connection-id-to-session mapping may not yet
	//! be observable through the just-built CatalogTransaction, so GetSession()
	//! cannot be relied on to find it.
	vector<SecretEntry> FetchAllSecretsFromServer(optional_ptr<CatalogTransaction> transaction,
	                                              shared_ptr<BoilstreamConnectionState> explicit_conn_state = nullptr);

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

	//! Make HTTP GET request to REST API (uses connection state from transaction)
	string HttpGet(const string &url, optional_ptr<CatalogTransaction> transaction = nullptr);

	//! Make HTTP POST request to REST API (uses connection state from transaction)
	string HttpPost(const string &url, const string &body, optional_ptr<CatalogTransaction> transaction = nullptr,
	                HTTPHeaders *out_headers = nullptr);

	//! Make HTTP GET request using explicit connection state (for PRAGMAs)
	string HttpGetWithState(const string &url, BoilstreamConnectionState &conn_state);

	//! Make HTTP POST request using explicit connection state (for PRAGMAs)
	string HttpPostWithState(const string &url, const string &body, BoilstreamConnectionState &conn_state,
	                         HTTPHeaders *out_headers = nullptr);

	//! Get expiration timestamp for a secret from connection state (for table functions)
	std::chrono::system_clock::time_point GetSecretExpiration(const string &secret_name,
	                                                          optional_ptr<CatalogTransaction> transaction);

	//! Fetch and cache one exact managed-catalog credential. The canonical
	//! catalog UUID selects both authorization and secret scope; display names
	//! and ATTACH aliases are never authority inputs.
	ManagedCatalogCredentialEnvelope VendManagedCatalogCredential(const string &catalog_id,
	                                                              optional_ptr<CatalogTransaction> transaction);

	//! Get the endpoint URL (for constructing API URLs in table functions)
	string GetEndpointUrl();
	//! Authenticated routing never falls back to the database default.
	string GetEndpointUrl(ClientContext &context);

	//! Check if multi-tenant mode is active (boilstream.tenant_id setting is set and non-empty)
	static bool IsMultiTenantMode(ClientContext &context);

	//! Get the tenant ID from context (returns empty string if not in multi-tenant mode)
	static string GetTenantId(ClientContext &context);

	//! Strip tenant prefix from a name (e.g., "__BS_u123__duckie" -> "duckie")
	//! Returns the original name if no prefix found or not in multi-tenant mode
	static string StripTenantPrefix(const string &name, ClientContext &context);

	//! Check if running in WASM environment (compile-time constant)
	static constexpr bool IsWasmMode() {
#ifdef __EMSCRIPTEN__
		return true;
#else
		return false;
#endif
	}

	//! Append ?multitenant=true to URL if in multi-tenant mode
	//! Uses transaction to access ClientContext for checking the tenant_id setting
	string AppendMultiTenantParam(const string &url, optional_ptr<CatalogTransaction> transaction);

	//! Append ?multitenant=true to URL if in multi-tenant mode (using explicit context)
	static string AppendMultiTenantParam(const string &url, ClientContext &context);

	//! Append platform query parameters to URL (multitenant, wasm)
	//! Combines IsMultiTenantMode and IsWasmMode checks
	static string AppendPlatformParams(const string &url, ClientContext &context);

	//! Append platform query parameters using transaction context
	string AppendPlatformParams(const string &url, optional_ptr<CatalogTransaction> transaction);

	//! Begin one exclusive registration/MFA operation for this connection and tenant.
	//! A ready registration is reusable only for the same authority and email.
	BoilstreamRegistrationSnapshot BeginRegistration(ClientContext &context, const string &base_url,
	                                                 const string &email);
	BoilstreamRegistrationSnapshot BeginMfaVerification(ClientContext &context);
	void StoreRegistrationState(ClientContext &context, uint64_t generation, const string &session_token,
	                            const string &totp_uri);
	uint64_t CompleteRegistration(ClientContext &context, uint64_t generation,
	                              unique_ptr<BoilstreamRegistrationOutput> output = nullptr);
	uint64_t PublishRegistrationOutput(ClientContext &context, uint64_t generation,
	                                   unique_ptr<BoilstreamRegistrationOutput> output);
	unique_ptr<BoilstreamRegistrationOutput> TakeRegistrationOutput(ClientContext &context, uint64_t id);
	//! Release a failed operation; cancellation/failed signup discard its state.
	void EndRegistrationOperation(ClientContext &context, uint64_t generation) noexcept;

protected:
	//! Override WriteSecret to persist to REST API
	void WriteSecret(const BaseSecret &secret, OnCreateConflict on_conflict) override;

	//! Override RemoveSecret to delete from REST API
	void RemoveSecret(const string &name, OnEntryNotFound on_entry_not_found) override;

private:
	struct SecretOwner {
		shared_ptr<BoilstreamConnectionState> session;
		shared_ptr<BoilstreamSecretCache> cache;
	};
	SecretOwner GetSecretOwner(optional_ptr<CatalogTransaction> transaction, bool create = false);
	shared_ptr<BoilstreamSecretCache> GetSecretCache(optional_ptr<CatalogTransaction> transaction, bool create = false);
	SecretMatch LookupCachedSecret(const string &path, const string &type, const shared_ptr<BoilstreamSecretCache> &cache);
	void FetchSecret(const string &selector, const string &type, bool match, optional_ptr<CatalogTransaction> transaction,
	                 const shared_ptr<BoilstreamSecretCache> &expected_cache);
	void PublishSecretList(const string &response, BoilstreamConnectionState &state, uint64_t revision);

	//! Write secret with explicit connection state (called from StoreSecret)
	void WriteSecretWithState(const BaseSecret &secret, OnCreateConflict on_conflict,
	                          BoilstreamConnectionState &conn_state, optional_ptr<CatalogTransaction> transaction);

	//! Request signing result containing all required headers
	struct SigningResult {
		string signature;        // Base64-encoded HMAC signature
		string date_time;        // ISO8601 timestamp (YYYYMMDDTHHMMSSZ)
		string credential_scope; // AWS-style credential scope
	};

	//! Use SessionSnapshot from BoilstreamConnectionState
	using SessionSnapshot = BoilstreamConnectionState::SessionSnapshot;

	//! Extract all x-boilstream-* headers from HTTP response
	case_insensitive_map_t<string> ExtractBoilstreamHeaders(const HTTPHeaders &headers);

	//! Build authenticated request headers with signature (uses connection state)
	HTTPHeaders BuildAuthenticatedHeaders(const string &method, const string &url, const string &body,
	                                      BoilstreamConnectionState &conn_state, vector<uint8_t> *response_key = nullptr);

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

	//! Parse an RFC3339 timestamp to system_clock time_point
	std::chrono::system_clock::time_point ParseExpiresAt(const string &expires_at_str);
	//! Check the authoritative expiry without applying the cache refresh window
	bool IsManagedCatalogCredentialExpiredAt(const string &expires_at_str, std::chrono::system_clock::time_point now);

	//! Check if a secret has expired (uses connection state)
	bool IsExpired(const string &secret_name, BoilstreamConnectionState &conn_state);

	//! Store expiration timestamp for a secret (uses connection state)
	void StoreExpiration(const string &secret_name, const string &expires_at_str,
	                     BoilstreamConnectionState &conn_state);

	//! Clear expiration data for a secret (uses connection state)
	void ClearExpiration(const string &secret_name, BoilstreamConnectionState &conn_state);

	//! Make HTTP DELETE request to REST API (uses connection state)
	void HttpDelete(const string &url, BoilstreamConnectionState &conn_state);

	//! Check catalog versions and refresh credentials for changed catalogs (uses connection state)
	//! Rate-limited to VERSION_CHECK_INTERVAL_SECONDS
	void CheckCatalogVersions(BoilstreamConnectionState &conn_state, optional_ptr<ClientContext> context = nullptr);

	//! Fetch catalog versions from server (uses connection state)
	//! Returns map of catalog_id (UUID) -> CatalogVersionInfo
	case_insensitive_map_t<CatalogVersionInfo> FetchCatalogVersions(BoilstreamConnectionState &conn_state, optional_ptr<ClientContext> context = nullptr);

	//! Force refresh credentials for a specific catalog by name (uses connection state)
	void RefreshCatalogCredentials(const string &catalog_name, BoilstreamConnectionState &conn_state);

	//! Quack auto-vend (Phase 2.2): fetch a fresh Quack JWT from the boilstream server
	//! at GET /secrets/quack/credentials and materialise it as a `quack`-typed
	//! KeyValueSecret in the local catalog. Returns a SecretMatch on success, or an
	//! empty SecretMatch on miss / network failure so the caller can fall back.
	//! Implements 30s near-expiry refresh (tighter than the generic 5min IsExpired buffer).
	SecretMatch LookupQuackSecret(const string &path, optional_ptr<CatalogTransaction> transaction);

	//! Fetch a server-owned credential for one canonical catalog UUID.
	ManagedCatalogCredentialEnvelope FetchManagedCatalogCredential(const string &catalog_id,
	                                                               BoilstreamConnectionState &conn_state,
	                                                               optional_ptr<CatalogTransaction> transaction);

	//! Install a complete credential bundle under its catalog-qualified Quack
	//! secret scope and record its short-lived expiry.
	void CacheManagedCatalogCredential(const string &scope_path, const ManagedCatalogCredentialEnvelope &credential,
	                                   BoilstreamConnectionState &conn_state);

	//! Materialize a connection-local credential as a SecretMatch without
	//! publishing it into DuckDB's catalog-global secret set.
	SecretMatch BuildManagedCatalogSecretMatch(const string &scope_path,
	                                           const ManagedCatalogCredentialEnvelope &credential);

	//========================================================================
	// Shared State (across all connections)
	//========================================================================

	void PublishSession(ClientContext &context, shared_ptr<BoilstreamConnectionState> pending,
	                    const shared_ptr<BoilstreamConnectionState> &previous, uint64_t generation,
	                    bool supports_resumption);

	//! Base URL for REST API endpoint (e.g., "https://api.example.com/secrets")
	string endpoint_url;

	//! Lock for thread-safe endpoint updates
	mutex endpoint_lock;

	//! Connection ID to user ID mapping (for user context extraction)
	case_insensitive_map_t<string> connection_user_map;

	//! Lock for connection user map
	mutex connection_lock;

	shared_ptr<BoilstreamRegistrationContext> RegistrationOwner(ClientContext &context, bool create);

	//! Version check interval in seconds (default 60)
	static constexpr int VERSION_CHECK_INTERVAL_SECONDS = 60;

	//========================================================================
	// Session Storage (database-level, shared across all ClientContexts)
	// Authenticated sessions are published under connection-owned keys.
	// Legacy explicit keys remain available for direct storage/test clients.
	// Owning handles preserve in-flight request lifetimes during replacement.
	// Historical explicit-key semantics provide:
	// - Session reuse: same token = same session (across connections)
	// - Isolation: different tokens = different sessions
	// - Works with vanilla DuckDB (no TenantIsolation dependency)
	// - Works uniformly for WASM and native builds
	// - Survives context switches during ATTACH and catalog operations
	//========================================================================

	//! Map of session_key (bootstrap_token_hash) -> session state
	std::unordered_map<string, shared_ptr<BoilstreamConnectionState>> sessions_;

	//! Per-connection session keys: connection_id -> session_key
	//! Prevents concurrent bootstrap from clobbering each other's sessions
	std::unordered_map<idx_t, string> connection_session_keys_;

	//! Lock for sessions_ and connection_session_keys_
	mutex sessions_lock_;
};

} // namespace duckdb
