//===----------------------------------------------------------------------===//
//                         DuckDB
//
// boilstream_secret_storage.cpp
//
//
//===----------------------------------------------------------------------===//

#include "boilstream_secret_storage.hpp"
#include "boilstream_connection_state.hpp"
#include "opaque_wrapper.hpp"
#include "opaque_client.h"
#include "opaque_client_ffi.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
// Use the fork's authoritative context, including worker-thread propagation.
// Community DuckDB has no tenant subsystem; its extension setting remains the
// standalone mode selector. Never interpret an absent fork setting as no tenant.
#if __has_include("duckdb/main/tenant/active_tenant_registry.hpp")
#include "duckdb/main/tenant/active_tenant_registry.hpp"
#include "duckdb/main/tenant/tenant_isolation.hpp"
#define BOILSTREAM_HAS_TENANT_CONTEXT 1
#endif
#include "duckdb/common/serializer/memory_stream.hpp"
#include "duckdb/common/serializer/binary_serializer.hpp"
#include "duckdb/common/serializer/binary_deserializer.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/common/types/date.hpp"
#include "duckdb/common/types/time.hpp"
#include "duckdb/common/types/uuid.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/common/random_engine.hpp"
#include "yyjson.hpp"
#include <sstream>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <optional>

// Platform-specific secure memory zeroization
// Prevents compiler from optimizing away memory clearing operations
#if defined(_WIN32)
#define NOMINMAX // Prevent Windows from defining min/max macros that conflict with std::min/std::max
#include <windows.h>
#undef CreateDirectory // Undefine Windows macro that conflicts with DuckDB FileSystem::CreateDirectory
#define SECURE_ZERO_MEMORY(ptr, size) SecureZeroMemory(ptr, size)
#elif defined(__EMSCRIPTEN__) || defined(__wasm__) || defined(__wasm32__)
// WASM: Use volatile loop (portable, works in browser environment)
// Note: WASM has limited security guarantees due to sandboxing, but we still
// zero memory to prevent leakage within the WASM instance
#define SECURE_ZERO_MEMORY(ptr, size)                                                                                  \
	do {                                                                                                               \
		volatile unsigned char *p = (volatile unsigned char *)(ptr);                                                   \
		size_t n = (size);                                                                                             \
		while (n--)                                                                                                    \
			*p++ = 0;                                                                                                  \
	} while (0)
#elif defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
// explicit_bzero available in glibc 2.25+
#define SECURE_ZERO_MEMORY(ptr, size) explicit_bzero(ptr, size)
#else
// Fallback for older glibc
#define SECURE_ZERO_MEMORY(ptr, size)                                                                                  \
	do {                                                                                                               \
		volatile unsigned char *p = (volatile unsigned char *)(ptr);                                                   \
		size_t n = (size);                                                                                             \
		while (n--)                                                                                                    \
			*p++ = 0;                                                                                                  \
	} while (0)
#endif
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
// BSD systems have explicit_bzero
#define SECURE_ZERO_MEMORY(ptr, size) explicit_bzero(ptr, size)
#else
// Portable fallback using volatile to prevent compiler optimization
// Works on most platforms including WASM, macOS, Linux, etc.
#define SECURE_ZERO_MEMORY(ptr, size)                                                                                  \
	do {                                                                                                               \
		volatile unsigned char *p = (volatile unsigned char *)(ptr);                                                   \
		size_t n = (size);                                                                                             \
		while (n--)                                                                                                    \
			*p++ = 0;                                                                                                  \
	} while (0)
#endif

#include "boilstream_diagnostics.hpp"
#define BOILSTREAM_LOG(event) duckdb::BoilstreamLogEvent("" event)

using namespace duckdb_yyjson;

namespace duckdb {

// Read BOILSTREAM_INSECURE_TLS env var and, when set to "1"/"true"/"yes",
// disable TLS certificate verification on the supplied HTTPParams.
//
// This is *only* for local-dev work where the boilstream auth server is
// reachable through a self-signed cert that the host's libcurl trust store
// can't validate (e.g., macOS where SSL_CERT_FILE / CURL_CA_BUNDLE are
// silently ignored by the statically-linked OpenSSL backend). On any other
// platform the proper fix is to put the cert on the system trust path —
// this knob is intentionally undocumented and intentionally per-process so
// it can't be accidentally toggled on a deployed binary.
//
// Setting both `override_verify_ssl = true` *and* `verify_ssl = false` is
// what HTTPFSCurlUtil (and the httplib counterpart) checks when deciding
// whether to call `curl_easy_setopt(..., CURLOPT_SSL_VERIFYPEER, 0L)` /
// `client->enable_server_certificate_verification(false)`.
static void MaybeDisableTlsVerificationFromEnv(HTTPParams &params) {
	const char *env = std::getenv("BOILSTREAM_INSECURE_TLS");
	if (!env || env[0] == '\0') {
		return;
	}
	const std::string val(env);
	if (val == "1" || val == "true" || val == "TRUE" || val == "yes" || val == "YES") {
		params.override_verify_ssl = true;
		params.verify_ssl = false;
	}
}

// Serialize a yyjson mutable doc to string, throwing on allocation failure.
static string SafeJsonSerialize(yyjson_mut_doc *doc) {
	auto json_str = yyjson_mut_write(doc, 0, nullptr);
	if (!json_str) {
		throw IOException("Failed to serialize JSON document");
	}
	string result(json_str);
	free(json_str);
	return result;
}

//===----------------------------------------------------------------------===//
// Security Limits - Prevent DoS via oversized payloads
//===----------------------------------------------------------------------===//
// Maximum sizes to prevent memory exhaustion attacks from malicious servers

//! Maximum encrypted response size (10MB) - includes ciphertext + overhead
static constexpr size_t MAX_ENCRYPTED_RESPONSE_SIZE = 10 * 1024 * 1024;

//! Maximum base64 encoded field size (1MB) - for nonce, ciphertext, hmac
static constexpr size_t MAX_BASE64_FIELD_SIZE = 1 * 1024 * 1024;

//! Maximum JSON response size from server (10MB)
static constexpr size_t MAX_JSON_RESPONSE_SIZE = 10 * 1024 * 1024;

//! Maximum secret data size (1MB) - serialized secret payload
static constexpr size_t MAX_SECRET_DATA_SIZE = 1 * 1024 * 1024;

//! Maximum OPAQUE protocol message size (64KB) - registration/login messages
static constexpr size_t MAX_OPAQUE_MESSAGE_SIZE = 64 * 1024;

// Thread-local guard to prevent recursive lookups during HTTP operations
static thread_local bool in_http_operation = false;

// RAII guard for thread-local HTTP operation flag
// Ensures flag is always cleared, even on exception
struct HttpOperationGuard {
	HttpOperationGuard() {
		in_http_operation = true;
	}
	~HttpOperationGuard() {
		in_http_operation = false;
	}
	// Prevent copying
	HttpOperationGuard(const HttpOperationGuard &) = delete;
	HttpOperationGuard &operator=(const HttpOperationGuard &) = delete;
};

//! Safe string extraction from yyjson - returns empty string if NULL or not a string
//! This prevents undefined behavior from constructing std::string with NULL
static inline string SafeGetStr(yyjson_val *val) {
	if (!val) {
		return "";
	}
	const char *str = yyjson_get_str(val);
	return str ? string(str) : "";
}

static bool IsManagedCatalogEndpoint(const string &endpoint) {
	const auto separator = endpoint.rfind(':');
	if (separator == string::npos || separator == 0 || separator + 1 >= endpoint.size()) {
		return false;
	}
	const auto host = endpoint.substr(0, separator);
	if (host.find(':') != string::npos && (host.front() != '[' || host.back() != ']')) {
		return false;
	}
	if (endpoint.find_first_of("/\\'\"?#@ \t\r\n") != string::npos) {
		return false;
	}
	uint32_t port = 0;
	for (idx_t index = separator + 1; index < endpoint.size(); index++) {
		const auto c = endpoint[index];
		if (c < '0' || c > '9') {
			return false;
		}
		port = port * 10 + static_cast<uint32_t>(c - '0');
		if (port > 65535) {
			return false;
		}
	}
	return port != 0;
}

bool ParseManagedCatalogCredentialEnvelope(const string &json, ManagedCatalogCredentialEnvelope &out) {
	out = ManagedCatalogCredentialEnvelope {};
	if (json.empty() || json.size() > MAX_JSON_RESPONSE_SIZE) {
		return false;
	}
	auto doc = yyjson_read(json.c_str(), json.size(), 0);
	if (!doc) {
		return false;
	}
	auto root = yyjson_doc_get_root(doc);
	if (!root || !yyjson_is_obj(root)) {
		yyjson_doc_free(doc);
		return false;
	}
	out.token = SafeGetStr(yyjson_obj_get(root, "token"));
	out.expires_at = SafeGetStr(yyjson_obj_get(root, "expires_at"));
	out.endpoint = SafeGetStr(yyjson_obj_get(root, "endpoint"));
	out.catalog_id = SafeGetStr(yyjson_obj_get(root, "catalog_id"));
	auto owner = yyjson_obj_get(root, "storage_owner_tenant_id");
	if (owner && yyjson_is_uint(owner) && yyjson_get_uint(owner) <= std::numeric_limits<uint32_t>::max()) {
		out.storage_owner_tenant_id = static_cast<uint32_t>(yyjson_get_uint(owner));
	}
	out.catalog_group = SafeGetStr(yyjson_obj_get(root, "catalog_group"));
	// Client identity is the short-lived capability. Reject the obsolete mTLS
	// envelope explicitly so a compromised server cannot inject a reusable
	// client private key into the public extension process.
	const bool contains_client_identity = yyjson_obj_get(root, "transport_identity") ||
	                                      yyjson_obj_get(root, "client_certificate_pem") ||
	                                      yyjson_obj_get(root, "client_private_key_pem");
	out.server_ca_pem = SafeGetStr(yyjson_obj_get(root, "server_ca_pem"));
	yyjson_doc_free(doc);
	hugeint_t parsed_catalog_id;
	const bool canonical_catalog_id = UUID::FromString(out.catalog_id, parsed_catalog_id, true) &&
	                                  UUID::ToString(parsed_catalog_id) == out.catalog_id;
	const bool complete = !out.token.empty() && !out.expires_at.empty() && IsManagedCatalogEndpoint(out.endpoint) &&
	                      canonical_catalog_id && out.storage_owner_tenant_id != 0 && !out.catalog_group.empty() &&
	                      !contains_client_identity &&
	                      out.server_ca_pem.find("-----BEGIN CERTIFICATE-----") != string::npos;
	if (!complete) {
		out = ManagedCatalogCredentialEnvelope {};
	}
	return complete;
}

string ManagedCatalogSecretScope(const string &endpoint, const string &catalog_id) {
	return "quack:" + endpoint + "/catalog/" + catalog_id;
}

string ManagedCatalogCredentialUrl(const string &secrets_endpoint, const string &catalog_id) {
	const auto secrets_pos = secrets_endpoint.rfind("/secrets");
	if (secrets_pos == string::npos || secrets_pos + string("/secrets").size() != secrets_endpoint.size()) {
		throw InvalidInputException("Managed DuckDB credential vending requires the canonical /secrets endpoint");
	}
	hugeint_t parsed_catalog_id;
	if (!UUID::FromString(catalog_id, parsed_catalog_id, true) || UUID::ToString(parsed_catalog_id) != catalog_id) {
		throw InvalidInputException("Managed DuckDB credential vending requires a canonical catalog UUID");
	}
	return secrets_endpoint + "/quack/credentials?catalog_id=" + StringUtil::URLEncode(catalog_id);
}

static string EscapeManagedAttachLiteral(const string &value) {
	string escaped;
	escaped.reserve(value.size());
	for (const auto c : value) {
		escaped += c == '\'' ? "''" : string(1, c);
	}
	return escaped;
}

static string QuoteManagedAttachIdentifier(const string &value) {
	if (value.empty() || value.find('\0') != string::npos) {
		throw InvalidInputException("Managed DuckDB ATTACH alias must be non-empty and contain no NUL bytes");
	}
	string quoted = "\"";
	quoted.reserve(value.size() + 2);
	for (const auto c : value) {
		quoted += c == '\"' ? "\"\"" : string(1, c);
	}
	quoted += "\"";
	return quoted;
}

string BuildManagedCatalogAttachSql(const ManagedCatalogCredentialEnvelope &credential, const string &alias) {
	if (credential.endpoint.empty() || credential.catalog_id.empty() || credential.storage_owner_tenant_id == 0 ||
	    credential.catalog_group.empty()) {
		throw InvalidInputException("Managed DuckDB ATTACH requires a complete authoritative catalog scope");
	}
	return "ATTACH 'quack:" + EscapeManagedAttachLiteral(credential.endpoint) + "' AS " +
	       QuoteManagedAttachIdentifier(alias) + " (TYPE quack, CATALOG_ID '" +
	       EscapeManagedAttachLiteral(credential.catalog_id) + "', TENANT_ID '" +
	       std::to_string(credential.storage_owner_tenant_id) + "', CATALOG_GROUP '" +
	       EscapeManagedAttachLiteral(credential.catalog_group) + "', DISABLE_SSL false)";
}

//! Safe string extraction with required validation - throws if NULL or empty
//! Use this for required fields that must have a value
static inline string RequireStr(yyjson_val *val, const char *field_name) {
	if (!val) {
		throw IOException("Missing required field: %s", field_name);
	}
	const char *str = yyjson_get_str(val);
	if (!str || str[0] == '\0') {
		throw IOException("Required field '%s' is null or empty", field_name);
	}
	return string(str);
}

RestApiSecretStorage::RestApiSecretStorage(DatabaseInstance &db_p, const string &endpoint_url_p)
    : CatalogSetSecretStorage(db_p, "boilstream", 5), // offset=5 for higher priority than built-in storages (10, 20)
      endpoint_url(endpoint_url_p) {
	secrets = make_uniq<CatalogSet>(Catalog::GetSystemCatalog(db));
	persistent = true; // Acts as persistent storage
	                   // Sessions are stored in sessions_ map keyed by bootstrap_token_hash
	                   // This works uniformly for WASM and native, and survives context switches
}

//! Get active session (for secret operations like AllSecrets, LookupSecret)
//! Routes through per-connection session lookup. Returns nullptr for system
//! transactions without context (no authenticated session exists without a connection).
shared_ptr<BoilstreamConnectionState> RestApiSecretStorage::GetSession(optional_ptr<CatalogTransaction> transaction) {
	if (transaction && transaction->HasContext()) {
		auto &ctx = transaction->GetContext();
		auto state = GetSessionForConnection(ctx.GetConnectionId());
		if (state && state->authenticated_tenant != GetTenantId(ctx)) {
			throw IOException("BoilStream session belongs to a different tenant context");
		}
		return state;
	}
	return nullptr;
}

//! Get or create session for a specific session key (bootstrap_token_hash)
BoilstreamConnectionState &RestApiSecretStorage::GetOrCreateSession(const string &session_key) {
	auto endpoint = GetEndpointUrl();
	lock_guard<mutex> lock(sessions_lock_);
	auto &session = sessions_[session_key];
	if (!session) {
		session = make_shared_ptr<BoilstreamConnectionState>(endpoint);
	}
	return *session;
}

//! Check if a session exists for a session key
bool RestApiSecretStorage::HasSession(const string &session_key) {
	lock_guard<mutex> lock(sessions_lock_);
	return sessions_.find(session_key) != sessions_.end();
}

//! Get session by key (returns nullptr if not found)
shared_ptr<BoilstreamConnectionState> RestApiSecretStorage::GetSessionByKey(const string &session_key) {
	lock_guard<mutex> lock(sessions_lock_);
	auto it = sessions_.find(session_key);
	if (it != sessions_.end()) {
		return it->second;
	}
	return nullptr;
}

//! Set the active session key for a specific connection (concurrent-safe)
void RestApiSecretStorage::SetActiveSessionKeyForConnection(idx_t connection_id, const string &session_key) {
	lock_guard<mutex> lock(sessions_lock_);

	// Prevent unbounded map growth - limit to 10,000 connections
	// Matches the same limit used by connection_user_map in SetUserContextForConnection
	const size_t MAX_CONNECTIONS = 10000;
	if (connection_session_keys_.size() >= MAX_CONNECTIONS) {
		auto it = connection_session_keys_.begin();
		size_t to_remove = MAX_CONNECTIONS / 2;
		while (to_remove-- > 0 && it != connection_session_keys_.end()) {
			it = connection_session_keys_.erase(it);
		}
	}

	connection_session_keys_[connection_id] = session_key;
}

//! Get session by connection ID (returns nullptr if not found)
shared_ptr<BoilstreamConnectionState> RestApiSecretStorage::GetSessionForConnection(idx_t connection_id) {
	lock_guard<mutex> lock(sessions_lock_);
	auto conn_it = connection_session_keys_.find(connection_id);
	if (conn_it == connection_session_keys_.end()) {
		return nullptr;
	}
	auto it = sessions_.find(conn_it->second);
	return (it != sessions_.end()) ? it->second : nullptr;
}

shared_ptr<BoilstreamConnectionState> RestApiSecretStorage::GetSessionForContext(ClientContext &context) {
	auto state = GetSessionForConnection(context.GetConnectionId());
	return state && state->authenticated_tenant == GetTenantId(context) ? state : nullptr;
}

void RestApiSecretStorage::SetEndpoint(const string &endpoint) {
	lock_guard<mutex> lock(endpoint_lock);
	endpoint_url = endpoint;
}

void RestApiSecretStorage::ClearSession(ClientContext &context) {
	shared_ptr<BoilstreamConnectionState> retired;
	{
		lock_guard<mutex> lock(sessions_lock_);
		auto conn_it = connection_session_keys_.find(context.GetConnectionId());
		if (conn_it == connection_session_keys_.end()) return;
		auto it = sessions_.find(conn_it->second);
		if (it != sessions_.end()) {
			retired = it->second;
			// Reject an exchange already in flight before dropping the registry
			// lock. Credential/cache destruction stays outside the global lock.
			retired->authentication_generation.fetch_add(1);
		}
	}
	if (retired) retired->ClearSession();
}

bool RestApiSecretStorage::IsSessionTokenValid(ClientContext &context) {
	auto session = GetSessionForContext(context);
	if (!session) {
		return false;
	}
	return session->IsSessionTokenValid();
}

string RestApiSecretStorage::GetBootstrapTokenHash(ClientContext &context) {
	auto session = GetSessionForContext(context);
	if (!session) {
		return "";
	}
	return session->GetBootstrapTokenHash();
}

void RestApiSecretStorage::SetBootstrapTokenHash(ClientContext &context, const string &hash) {
	auto session = GetSessionForContext(context);
	if (!session) {
		return;
	}
	auto &conn_state = *session;
	conn_state.SetBootstrapTokenHash(hash);
}

std::chrono::system_clock::time_point RestApiSecretStorage::GetTokenExpiresAt(ClientContext &context) {
	auto session = GetSessionForContext(context);
	if (!session) {
		return std::chrono::system_clock::time_point::min();
	}
	return session->GetTokenExpiresAt();
}

void RestApiSecretStorage::ValidateTokenFormat(const string &token, const string &context) {
	// Validate token is not empty
	if (token.empty()) {
		throw IOException(context + ": Empty token received from server");
	}

	// Validate token length (must be between 32 and 512 characters)
	if (token.length() < 32 || token.length() > 512) {
		throw IOException(context + ": Invalid token length (" + std::to_string(token.length()) + " chars)");
	}

	// Validate token contains only valid characters (alphanumeric, -, _)
	for (char c : token) {
		if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
			throw IOException(context + ": Token contains invalid characters");
		}
	}
}

bool RestApiSecretStorage::PerformOpaqueLoginCommon(const string &password, bool is_resume,
                                                     BoilstreamConnectionState &conn_state) {
	// This state is private until the complete exchange succeeds. It cannot
	// overwrite an active session's key, sequence, endpoint or exchange flag.
	conn_state.is_exchanging = true;
	string url = conn_state.GetEndpointUrl();

	if (url.empty()) {
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.is_exchanging = false;
		throw InvalidInputException("Boilstream endpoint not configured");
	}

	// Remove trailing /secrets if present
	auto secrets_pos = url.find("/secrets");
	if (secrets_pos != string::npos) {
		url = url.substr(0, secrets_pos);
	}

	// Compute user_id: SHA-256 hash of password (bootstrap_token or refresh_token)
	// Following spec: user_id = lowercase_hex(SHA256(password))
	uint8_t password_hash[32];
	opaque_client_sha256(reinterpret_cast<const uint8_t *>(password.c_str()), password.size(), password_hash);

	// Convert hash to lowercase hex string (64 characters)
	string user_id;
	user_id.reserve(64);
	const char *hex_chars = "0123456789abcdef";
	for (size_t i = 0; i < 32; i++) {
		unsigned char byte = static_cast<unsigned char>(password_hash[i]);
		user_id += hex_chars[(byte >> 4) & 0xF];
		user_id += hex_chars[byte & 0xF];
	}

	// Step 1: Client starts login
	auto login_start = OpaqueClientWrapper::LoginStart(password);
	BOILSTREAM_LOG("PerformOpaqueLogin: credential request generated");

	// Step 2: Send CredentialRequest to server with user_id
	string login_url = url + "/auth/api/opaque-login-start";

	auto doc = yyjson_mut_doc_new(nullptr);
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);
	yyjson_mut_obj_add_strcpy(doc, obj, "user_id", user_id.c_str());
	yyjson_mut_obj_add_strcpy(doc, obj, "credential_request", login_start.credential_request_base64.c_str());

	string body = SafeJsonSerialize(doc);
	yyjson_mut_doc_free(doc);

	string response;
	try {
		response = HttpPostWithState(login_url, body, conn_state);
	} catch (const std::exception &e) {
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.is_exchanging = false;
		opaque_free_login_state(login_start.state);
		BoilstreamRethrowSafe("OPAQUE login failed (server request)", e);
	}

	// Parse server response
	auto response_doc = yyjson_read(response.c_str(), response.size(), 0);
	if (!response_doc) {
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.is_exchanging = false;
		opaque_free_login_state(login_start.state);
		throw IOException("OPAQUE login failed: Invalid JSON response from server");
	}

	auto response_root = yyjson_doc_get_root(response_doc);
	auto credential_response_val = yyjson_obj_get(response_root, "credential_response");
	if (!credential_response_val || !yyjson_is_str(credential_response_val)) {
		yyjson_doc_free(response_doc);
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.is_exchanging = false;
		opaque_free_login_state(login_start.state);
		throw IOException("OPAQUE login failed: No credential_response in server response");
	}

	string credential_response_base64 = SafeGetStr(credential_response_val);
	if (credential_response_base64.empty()) {
		yyjson_doc_free(response_doc);
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.is_exchanging = false;
		opaque_free_login_state(login_start.state);
		throw IOException("OPAQUE login failed: credential_response is empty");
	}

	// Extract state_id if present (required by server for stateful OPAQUE)
	string state_id = SafeGetStr(yyjson_obj_get(response_root, "state_id"));
	if (state_id.empty()) {
		BOILSTREAM_LOG("PerformOpaqueLogin: WARNING - state_id not found in server response");
	}

	yyjson_doc_free(response_doc);

	// Step 3: Client finishes login
	auto login_finish = OpaqueClientWrapper::LoginFinish(login_start.state, // consumed by this call
	                                                     credential_response_base64);
	BOILSTREAM_LOG("PerformOpaqueLogin: credential finalization generated");

	// Decode session_key and export_key from base64
	auto session_key_decoded = Blob::FromBase64(string_t(login_finish.session_key_base64));
	auto export_key_decoded = Blob::FromBase64(string_t(login_finish.export_key_base64));

	// Store session_key early so HttpPost can use it for response decryption
	// The server sends encrypted responses during login-finish
	// We're still in the is_exchanging=true state, so other operations are blocked
	{
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.session_key.assign(session_key_decoded.begin(), session_key_decoded.end());
	}

	// Step 4: Send CredentialFinalization to server
	string finalize_url = url + "/auth/api/opaque-login-finish";

	auto final_doc = yyjson_mut_doc_new(nullptr);
	auto final_obj = yyjson_mut_obj(final_doc);
	yyjson_mut_doc_set_root(final_doc, final_obj);

	// Add state_id if it was provided by server (required for stateful OPAQUE)

	if (!state_id.empty()) {
		yyjson_mut_obj_add_strcpy(final_doc, final_obj, "state_id", state_id.c_str());
		BOILSTREAM_LOG("PerformOpaqueLogin: Added state_id to finalization request");
	} else {
		BOILSTREAM_LOG("PerformOpaqueLogin: ERROR - state_id is EMPTY, not adding to request");
	}

	yyjson_mut_obj_add_strcpy(final_doc, final_obj, "credential_finalization",
	                          login_finish.credential_finalization_base64.c_str());

	string final_body = SafeJsonSerialize(final_doc);
	yyjson_mut_doc_free(final_doc);

	// Use HttpPostWithState with out_headers parameter to capture X-Boilstream-Session-Resumption
	HTTPHeaders final_response_headers(db);
	string final_response;
	try {
		final_response = HttpPostWithState(finalize_url, final_body, conn_state, &final_response_headers);
	} catch (const std::exception &e) {
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.session_key.clear(); // Clear session_key on error
		conn_state.is_exchanging = false;
		BoilstreamRethrowSafe("OPAQUE login failed (finalization)", e);
	}

	// Parse finalization response (contains access_token and expires_at)
	auto final_response_doc = yyjson_read(final_response.c_str(), final_response.size(), 0);
	if (!final_response_doc) {
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.session_key.clear(); // Clear session_key on error
		conn_state.is_exchanging = false;
		throw IOException("OPAQUE login failed: Invalid finalization response from server (JSON parse error)");
	}

	auto final_response_root = yyjson_doc_get_root(final_response_doc);

	// Check if response indicates an error (success=false or error field present)
	auto success_val = yyjson_obj_get(final_response_root, "success");
	auto error_val = yyjson_obj_get(final_response_root, "error");

	if ((success_val && yyjson_is_bool(success_val) && !yyjson_get_bool(success_val)) ||
	    (error_val && yyjson_is_str(error_val))) {
		yyjson_doc_free(final_response_doc);
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.session_key.clear(); // Clear session_key on error
		conn_state.is_exchanging = false;
		throw IOException("OPAQUE login failed: server rejected authentication");
	}

	auto access_token_val = yyjson_obj_get(final_response_root, "access_token");
	if (!access_token_val || !yyjson_is_str(access_token_val)) {
		yyjson_doc_free(final_response_doc);
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.session_key.clear(); // Clear session_key on error
		conn_state.is_exchanging = false;
		throw IOException("OPAQUE login failed: No access_token in finalization response");
	}

	string new_access_token = SafeGetStr(access_token_val);

	// Validate access_token format per SECURITY_SPECIFICATION.md:1309
	// Must be exactly 64 lowercase hexadecimal characters
	if (new_access_token.length() != 64) {
		yyjson_doc_free(final_response_doc);
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.session_key.clear(); // Clear session_key on error
		conn_state.is_exchanging = false;
		throw IOException("OPAQUE login failed: Invalid access_token format - must be 64 characters (got " +
		                  std::to_string(new_access_token.length()) + ")");
	}

	// Validate all characters are lowercase hexadecimal
	for (size_t i = 0; i < new_access_token.length(); i++) {
		char c = new_access_token[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			yyjson_doc_free(final_response_doc);
			lock_guard<mutex> lock(conn_state.session_lock);
			conn_state.session_key.clear(); // Clear session_key on error
			conn_state.is_exchanging = false;
			throw IOException("OPAQUE login failed: Invalid access_token format - must be lowercase hexadecimal");
		}
	}

	// Extract expires_at
	auto expires_val = yyjson_obj_get(final_response_root, "expires_at");
	std::chrono::system_clock::time_point new_expires_at;
	if (expires_val && yyjson_is_int(expires_val)) {
		auto expires_timestamp = yyjson_get_int(expires_val);
		new_expires_at = std::chrono::system_clock::from_time_t(expires_timestamp);
	} else if (expires_val && yyjson_is_str(expires_val)) {
		string expires_str = SafeGetStr(expires_val);
		if (!expires_str.empty()) {
			new_expires_at = ParseExpiresAt(expires_str);
		} else {
			new_expires_at = std::chrono::system_clock::now() + std::chrono::hours(8);
		}
	} else {
		new_expires_at = std::chrono::system_clock::now() + std::chrono::hours(8);
	}

	// Extract region (required - server must provide this)
	string new_region = SafeGetStr(yyjson_obj_get(final_response_root, "region"));
	if (new_region.empty()) {
		yyjson_doc_free(final_response_doc);
		throw IOException("PerformOpaqueLogin: Server response missing required 'region' field");
	}

	yyjson_doc_free(final_response_doc);

	// Store session state atomically
	{
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.access_token = new_access_token;

		// Store OPAQUE session_key (convert string to vector<uint8_t>)
		conn_state.session_key.assign(session_key_decoded.begin(), session_key_decoded.end());

		// Derive refresh_token from session_key using HKDF-Expand per SECURITY_SPECIFICATION.md:158
		// Using Rust crypto implementation (works on all platforms including WASM)
		uint8_t derived_key[32];
		int result = opaque_client_derive_refresh_token(conn_state.session_key.data(), conn_state.session_key.size(),
		                                                derived_key);
		if (result != 0) {
			throw IOException("Failed to derive refresh token");
		}
		conn_state.refresh_token.assign(derived_key, derived_key + 32);

		// Reset sequence counter (starts at 0 for new session)
		conn_state.client_sequence = 0;

		// Store region from server response
		conn_state.region = new_region;

		conn_state.token_expires_at = new_expires_at;
		conn_state.is_exchanging = false;
	}

	// Server capability permits in-memory resumption, never local persistence.
	bool resumption_enabled = false;
	auto header_map = ExtractBoilstreamHeaders(final_response_headers);
	auto resumption_it = header_map.find("x-boilstream-session-resumption");
	if (resumption_it != header_map.end()) {
		string resumption_value = resumption_it->second;
		std::transform(resumption_value.begin(), resumption_value.end(), resumption_value.begin(), ::tolower);
		resumption_enabled = (resumption_value == "enabled");
	}

	return resumption_enabled;
}

// ClientContext retains its database until after registered state destruction,
// so the database-owned storage outlives this connection cleanup callback.
class BoilstreamSessionCleanup : public ClientContextState {
public:
	BoilstreamSessionCleanup(RestApiSecretStorage &storage, idx_t connection_id)
	    : storage(storage), connection_id(connection_id) {}
	~BoilstreamSessionCleanup() override { storage.ClearConnectionMapping(connection_id); }
private:
	RestApiSecretStorage &storage;
	idx_t connection_id;
};

void RestApiSecretStorage::PublishSession(ClientContext &context, shared_ptr<BoilstreamConnectionState> pending,
                                          const shared_ptr<BoilstreamConnectionState> &previous,
                                          uint64_t generation, bool supports_resumption) {
	const auto connection_id = context.GetConnectionId();
	context.registered_state->GetOrCreate<BoilstreamSessionCleanup>("boilstream_session_cleanup", *this, connection_id);
	const auto key = "@connection:" + std::to_string(connection_id);
	pending->authenticated_tenant = GetTenantId(context);
	// This state is still private. Retain a refresh credential only when the
	// server supports using it; all credentials remain connection-owned memory.
	if (!supports_resumption) {
		BoilstreamConnectionState::SecureZeroVector(pending->refresh_token);
		pending->refresh_token.clear();
	}
	{
		lock_guard<mutex> lock(sessions_lock_);
		auto current_mapping = connection_session_keys_.find(connection_id);
		shared_ptr<BoilstreamConnectionState> current;
		if (current_mapping != connection_session_keys_.end()) {
			auto found = sessions_.find(current_mapping->second);
			if (found != sessions_.end()) current = found->second;
		}
		if (context.IsInterrupted() || current != previous ||
		    (previous && previous->authentication_generation.load() != generation)) {
			throw IOException("Authentication was interrupted or superseded");
		}
		if (current_mapping == connection_session_keys_.end() && connection_session_keys_.size() >= 10000) {
			throw IOException("Authenticated connection capacity exhausted");
		}
		// Never evict another live connection to admit a new one.
		sessions_[key] = pending;
		connection_session_keys_[connection_id] = key;
	}
	if (previous) previous->secret_cache->Close();
}

void RestApiSecretStorage::PerformOpaqueLogin(ClientContext &context, const string &password,
                                              const string &token_hash, const string &endpoint) {
	auto previous = GetSessionForConnection(context.GetConnectionId());
	auto generation = previous ? previous->authentication_generation.load() : 0;
	auto pending = make_shared_ptr<BoilstreamConnectionState>(endpoint);
	pending->bootstrap_token_hash = token_hash;
	auto supports_resumption = PerformOpaqueLoginCommon(password, false, *pending);
	PublishSession(context, std::move(pending), previous, generation, supports_resumption);
}

void RestApiSecretStorage::PerformOpaqueResume(ClientContext &context) {
	auto previous = GetSessionForContext(context);
	if (!previous || context.IsInterrupted()) {
		throw IOException("Session resumption requires an authenticated connection; log in again");
	}
	auto pending = make_shared_ptr<BoilstreamConnectionState>(previous->GetEndpointUrl());
	uint64_t generation;
	{
		lock_guard<mutex> lock(previous->session_lock);
		if (previous->refresh_token.size() != 32 || pending->GetEndpointUrl().empty() ||
		    previous->token_expires_at <= std::chrono::system_clock::now()) {
			throw IOException("Session resumption requires a valid in-memory refresh token; log in again");
		}
		generation = previous->authentication_generation.load();
		pending->refresh_token = previous->refresh_token;
		pending->bootstrap_token_hash = previous->bootstrap_token_hash;
	}
	string password(pending->refresh_token.begin(), pending->refresh_token.end());
	struct PasswordGuard {
		string &value;
		~PasswordGuard() { BoilstreamConnectionState::SecureZeroString(value); }
	} password_guard {password};
	// A failed exchange leaves the published session intact. The pending state
	// owns the same authority and identity; it cannot borrow another connection.
	auto supports_resumption = PerformOpaqueLoginCommon(password, true, *pending);
	PublishSession(context, std::move(pending), previous, generation, supports_resumption);
}

void RestApiSecretStorage::SetUserContextForConnection(idx_t connection_id, const string &user_id) {
	lock_guard<mutex> lock(connection_lock);

	// Prevent unbounded map growth - limit to 10,000 connections
	// In practice, DuckDB processes rarely have this many concurrent connections
	const size_t MAX_CONNECTIONS = 10000;
	if (connection_user_map.size() >= MAX_CONNECTIONS) {
		// Clear oldest half of entries (simple LRU approximation)
		// Note: This is not perfect LRU but prevents unbounded growth
		auto it = connection_user_map.begin();
		size_t to_remove = MAX_CONNECTIONS / 2;
		while (to_remove-- > 0 && it != connection_user_map.end()) {
			it = connection_user_map.erase(it);
		}
	}

	connection_user_map[std::to_string(connection_id)] = user_id;
}

string RestApiSecretStorage::GetUserContextForConnection(idx_t connection_id) {
	lock_guard<mutex> lock(connection_lock);
	auto it = connection_user_map.find(std::to_string(connection_id));
	if (it != connection_user_map.end()) {
		return it->second;
	}
	return "anonymous";
}

void RestApiSecretStorage::ClearConnectionMapping(idx_t connection_id) {
	shared_ptr<BoilstreamConnectionState> retired;
	{
		lock_guard<mutex> lock(connection_lock);
		connection_user_map.erase(std::to_string(connection_id));
	}
	{
		lock_guard<mutex> lock(sessions_lock_);
		auto it = connection_session_keys_.find(connection_id);
		if (it != connection_session_keys_.end()) {
			const auto owned_key = "@connection:" + std::to_string(connection_id);
			if (it->second == owned_key) {
				auto owned = sessions_.find(owned_key);
				if (owned != sessions_.end()) {
					retired = std::move(owned->second);
					sessions_.erase(owned);
				}
			}
			connection_session_keys_.erase(it);
		}
	}
	if (retired) retired->secret_cache->Close();
}

string RestApiSecretStorage::ExtractUserContext(optional_ptr<CatalogTransaction> transaction) {
	if (!transaction) {
		return "anonymous";
	}

	// Check if the transaction has a context before accessing it
	if (!transaction->HasContext()) {
		return "anonymous";
	}

	auto &context = transaction->GetContext();
	return GetUserContextForConnection(context.GetConnectionId());
}

vector<uint8_t> RestApiSecretStorage::DeriveSigningKey(const vector<uint8_t> &session_key_param) {
	// HKDF-SHA256 key derivation for request signing (base key) - 32 bytes
	// Using Rust crypto implementation (works on all platforms including WASM)
	// NOTE: Rust function is named "integrity_key" but uses info="request-integrity-v1" (correct for base_signing_key)

	if (session_key_param.empty()) {
		throw IOException("Cannot derive signing key: session_key not initialized");
	}

	uint8_t derived[32];
	// Despite the name, opaque_client_derive_integrity_key uses info="request-integrity-v1"
	// which is correct for base_signing_key per SECURITY_SPECIFICATION.md
	int result = opaque_client_derive_integrity_key(session_key_param.data(), session_key_param.size(), derived);

	if (result != 0) {
		throw IOException("Failed to derive signing key");
	}

	return vector<uint8_t>(derived, derived + 32);
}

vector<uint8_t> RestApiSecretStorage::DeriveEncryptionKey(const vector<uint8_t> &session_key_param) {
	// HKDF-SHA256 key derivation for response decryption - 32 bytes
	// Using Rust crypto implementation (works on all platforms including WASM)

	if (session_key_param.empty()) {
		throw IOException("Cannot derive encryption key: session_key not initialized");
	}

	uint8_t derived[32];
	int result = opaque_client_derive_encryption_key(session_key_param.data(), session_key_param.size(), derived);

	if (result != 0) {
		throw IOException("Failed to derive encryption key");
	}

	return vector<uint8_t>(derived, derived + 32);
}

vector<uint8_t> RestApiSecretStorage::DeriveIntegrityKey(const vector<uint8_t> &session_key_param) {
	// HKDF-SHA256 key derivation for response integrity verification - 32 bytes
	// Using Rust crypto implementation (works on all platforms including WASM)
	// NOTE: Rust function is named "signing_key" but uses info="response-integrity-v1" (correct for integrity_key)

	if (session_key_param.empty()) {
		throw IOException("Cannot derive integrity key: session_key not initialized");
	}

	uint8_t derived[32];
	// Despite the name, opaque_client_derive_signing_key uses info="response-integrity-v1"
	// which is correct for integrity_key per SECURITY_SPECIFICATION.md
	int result = opaque_client_derive_signing_key(session_key_param.data(), session_key_param.size(), derived);

	if (result != 0) {
		throw IOException("Failed to derive integrity key");
	}

	return vector<uint8_t>(derived, derived + 32);
}

// NOTE: GetSessionSnapshot() has been moved to BoilstreamConnectionState::GetSessionSnapshot()
// Each connection now has its own session state for multi-tenant support

case_insensitive_map_t<string> RestApiSecretStorage::ExtractBoilstreamHeaders(const HTTPHeaders &headers) {
	// Extract ALL x-boilstream-* headers from response
	// CRITICAL: We must extract ALL boilstream headers because they're included in the signature
	// Using a whitelist would miss headers and cause signature verification to fail
	case_insensitive_map_t<string> header_map;

	// Iterate through all headers and extract any starting with "x-boilstream-"
	for (const auto &header_pair : headers) {
		string header_name_lower = StringUtil::Lower(header_pair.first);
		if (header_name_lower.find("x-boilstream-") == 0) {
			header_map[header_name_lower] = header_pair.second;
		}
	}

	return header_map;
}

HTTPHeaders RestApiSecretStorage::BuildAuthenticatedHeaders(const string &method, const string &url, const string &body,
                                                            BoilstreamConnectionState &conn_state, vector<uint8_t> *response_key) {
	// Get session snapshot from connection state (thread-safe, increments sequence)
	auto snapshot = conn_state.GetSessionSnapshot();

	if (!snapshot.has_session_key) {
		throw IOException("BuildAuthenticatedHeaders: No active session for this connection");
	}

	// Get current timestamp
	auto now = std::chrono::system_clock::now();
	auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

	// Sign request
	auto signing_result = SignRequest(method, url, body, timestamp, snapshot.sequence, snapshot.session_key,
	                                  snapshot.access_token, snapshot.region);

	// Build headers
	HTTPHeaders headers(db);
	headers.Insert("Authorization", "Bearer " + snapshot.access_token);
	headers.Insert("Content-Type", "application/json");
	headers.Insert("X-Boilstream-Date", signing_result.date_time);
	headers.Insert("X-Boilstream-Sequence", std::to_string(snapshot.sequence));
	headers.Insert("X-Boilstream-Signature", signing_result.signature);
	headers.Insert("X-Boilstream-Credential", signing_result.credential_scope);
	headers.Insert("X-Boilstream-Ciphers", "0x0001,0x0002");
	headers.Insert("X-Boilstream-Cipher-Version", "1");

	// Bind verification to the same snapshot used to sign this request. A concurrent
	// logout must not turn an authenticated in-flight reply into an unsigned one.
	if (response_key) {
		*response_key = snapshot.session_key;
	}
	return headers;
}

void RestApiSecretStorage::VerifyAuthenticatedResponse(const string &response_body, uint16_t status_code,
                                                       const HTTPHeaders &response_headers,
                                                       const vector<uint8_t> &session_key_param) {
	// Extract boilstream headers and delegate to existing verification
	auto header_map = ExtractBoilstreamHeaders(response_headers);
	VerifyResponseSignature(response_body, status_code, header_map, session_key_param);
}

void RestApiSecretStorage::VerifyResponseSignature(const string &response_body, uint16_t status_code,
                                                   const case_insensitive_map_t<string> &headers,
                                                   const vector<uint8_t> &session_key_param) {
	// Verify response signature per SECURITY_SPECIFICATION.md:878-890
	// This implements the client-side response verification

	// Check if response has signature header
	auto sig_it = headers.find("x-boilstream-response-signature");
	if (sig_it == headers.end()) {
		// Pre-key login-start bypasses this verifier at the HTTP boundary.
		throw IOException("Response signature verification failed: missing signature");
	}

	string received_signature_b64 = sig_it->second;
	BOILSTREAM_LOG("VerifyResponseSignature: Found signature header");

	// Derive integrity key from session_key
	auto integrity_key = DeriveIntegrityKey(session_key_param);

	// Hash response body (SHA-256, lowercase hex)
	uint8_t body_hash[32];
	opaque_client_sha256(reinterpret_cast<const uint8_t *>(response_body.c_str()), response_body.size(), body_hash);

	// Convert to lowercase hex string
	string hashed_payload;
	hashed_payload.reserve(64);
	const char *hex_chars = "0123456789abcdef";
	for (size_t i = 0; i < 32; i++) {
		unsigned char byte = static_cast<unsigned char>(body_hash[i]);
		hashed_payload += hex_chars[(byte >> 4) & 0xF];
		hashed_payload += hex_chars[byte & 0xF];
	}

	// Build canonical response format per SECURITY_SPECIFICATION.md:616-625
	// Response Canonical Format (4 components):
	// HTTPStatusCode
	// CanonicalHeaders
	// SignedHeaders
	// HashedPayload

	// 1. Status code
	string canonical_response = std::to_string(status_code) + "\n";

	// 2. Build canonical headers (ALL x-boilstream-* headers except x-boilstream-response-signature)
	//    Sorted lexicographically, lowercase names, with trailing newline
	vector<std::pair<string, string>> boilstream_headers;
	for (const auto &header : headers) {
		string header_name_lower = StringUtil::Lower(header.first);
		// Include all x-boilstream-* headers except the signature itself
		if (header_name_lower.find("x-boilstream-") == 0 && header_name_lower != "x-boilstream-response-signature") {
			boilstream_headers.push_back({header_name_lower, header.second});
		}
	}
	std::sort(boilstream_headers.begin(), boilstream_headers.end());

	string canonical_headers;
	string signed_headers;
	for (size_t i = 0; i < boilstream_headers.size(); i++) {
		canonical_headers += boilstream_headers[i].first + ":" + boilstream_headers[i].second + "\n";
		if (i > 0)
			signed_headers += ";";
		signed_headers += boilstream_headers[i].first;
	}

	canonical_response += canonical_headers;
	canonical_response += "\n"; // Blank line after canonical headers

	// 3. Signed headers list
	canonical_response += signed_headers + "\n";

	// 4. Hashed payload
	canonical_response += hashed_payload;

	BOILSTREAM_LOG("VerifyResponseSignature: Canonical response built");

	// Compute expected signature: HMAC-SHA256(integrity_key, canonical_response)
	// Using Rust crypto implementation (works on all platforms including WASM)
	uint8_t expected_signature[32];
	opaque_client_hmac_sha256(integrity_key.data(), integrity_key.size(),
	                          reinterpret_cast<const uint8_t *>(canonical_response.c_str()), canonical_response.size(),
	                          expected_signature);

	// Encode expected signature as base64
	string expected_signature_str(reinterpret_cast<const char *>(expected_signature), 32);
	string expected_signature_b64 = Blob::ToBase64(string_t(expected_signature_str));

	// Constant-time comparison (CRITICAL for security)
	// Using simple byte-by-byte comparison with constant time
	if (received_signature_b64.length() != expected_signature_b64.length()) {
		SECURE_ZERO_MEMORY(expected_signature, sizeof(expected_signature));
		throw IOException("Response signature verification failed: signature length mismatch");
	}

	// Constant-time byte comparison
	volatile uint8_t diff = 0;
	for (size_t i = 0; i < received_signature_b64.length(); i++) {
		diff |= (received_signature_b64[i] ^ expected_signature_b64[i]);
	}

	// Securely zero expected signature
	SECURE_ZERO_MEMORY(expected_signature, sizeof(expected_signature));

	if (diff != 0) {
		throw IOException("Response signature verification failed: HMAC mismatch (potential tampering detected)");
	}

	// Validate timestamp (must be within 60 seconds)
	auto date_it = headers.find("x-boilstream-date");
	if (date_it == headers.end()) {
		throw IOException("Response signature verification failed: missing x-boilstream-date header");
	}
	const auto &timestamp = date_it->second;
	if (timestamp.size() != 16 || timestamp[8] != 'T' || timestamp[15] != 'Z') {
		throw IOException("Response signature verification failed: invalid timestamp");
	}
	for (idx_t i = 0; i < timestamp.size(); ++i) {
		if (i != 8 && i != 15 && (timestamp[i] < '0' || timestamp[i] > '9')) {
			throw IOException("Response signature verification failed: invalid timestamp");
		}
	}
	auto decimal = [&](idx_t start, idx_t length) {
		int32_t value = 0;
		for (idx_t i = start; i < start + length; ++i) {
			value = value * 10 + timestamp[i] - '0';
		}
		return value;
	};
	date_t date;
	const auto hour = decimal(9, 2), minute = decimal(11, 2), second = decimal(13, 2);
	if (!Date::TryFromDate(decimal(0, 4), decimal(4, 2), decimal(6, 2), date) ||
	    hour > 23 || minute > 59 || second > 59) {
		throw IOException("Response signature verification failed: invalid timestamp");
	}
	const auto response_time = Timestamp::GetEpochSeconds(Timestamp::FromDatetime(date, Time::FromTime(hour, minute, second)));
	const auto now = std::chrono::duration_cast<std::chrono::seconds>(
	                     std::chrono::system_clock::now().time_since_epoch()).count();
	if (response_time < now - 60 || response_time > now + 60) {
		throw IOException("Response signature verification failed: timestamp outside 60-second window");
	}

	BOILSTREAM_LOG("VerifyResponseSignature: Signature verified successfully");
}

string RestApiSecretStorage::DecryptResponse(const string &encrypted_response_body,
                                             const vector<uint8_t> &session_key_param, uint16_t cipher_suite) {
	// Decrypt encrypted response per SECURITY_SPECIFICATION.md:988-1048
	// Order of operations (CRITICAL):
	// 1. Parse response JSON
	// 2. Validate cipher suite (before expensive operations)
	// 3. Derive keys from session_key
	// 4. Decode base64/hex fields
	// 5. Verify HMAC BEFORE decryption
	// 6. Decrypt ciphertext (only after HMAC verification succeeds)

	// Security: Validate response size before parsing
	if (encrypted_response_body.size() > MAX_ENCRYPTED_RESPONSE_SIZE) {
		throw IOException("DecryptResponse: Response too large (" + std::to_string(encrypted_response_body.size()) +
		                  " bytes, max " + std::to_string(MAX_ENCRYPTED_RESPONSE_SIZE) + ")");
	}

	// 1. Parse response JSON to extract nonce, ciphertext, hmac
	yyjson_doc *doc = yyjson_read(encrypted_response_body.c_str(), encrypted_response_body.size(), 0);
	if (!doc) {
		throw IOException("DecryptResponse: Failed to parse encrypted response JSON");
	}
	yyjson_val *root = yyjson_doc_get_root(doc);
	if (!root || !yyjson_is_obj(root)) {
		yyjson_doc_free(doc);
		throw IOException("DecryptResponse: Invalid encrypted response structure");
	}

	// Extract fields
	yyjson_val *encrypted_val = yyjson_obj_get(root, "encrypted");
	yyjson_val *nonce_val = yyjson_obj_get(root, "nonce");
	yyjson_val *ciphertext_val = yyjson_obj_get(root, "ciphertext");
	yyjson_val *hmac_val = yyjson_obj_get(root, "hmac");

	if (!encrypted_val || !yyjson_is_bool(encrypted_val) || !yyjson_get_bool(encrypted_val)) {
		yyjson_doc_free(doc);
		throw IOException("DecryptResponse: Response is not encrypted (encrypted field missing or false)");
	}

	if (!nonce_val || !yyjson_is_str(nonce_val)) {
		yyjson_doc_free(doc);
		throw IOException("DecryptResponse: Missing or invalid nonce field");
	}
	if (!ciphertext_val || !yyjson_is_str(ciphertext_val)) {
		yyjson_doc_free(doc);
		throw IOException("DecryptResponse: Missing or invalid ciphertext field");
	}
	if (!hmac_val || !yyjson_is_str(hmac_val)) {
		yyjson_doc_free(doc);
		throw IOException("DecryptResponse: Missing or invalid hmac field");
	}

	string nonce_b64 = SafeGetStr(nonce_val);
	string ciphertext_b64 = SafeGetStr(ciphertext_val);
	string hmac_hex = SafeGetStr(hmac_val);

	yyjson_doc_free(doc);

	// Security: Validate field sizes before decoding
	if (ciphertext_b64.size() > MAX_BASE64_FIELD_SIZE) {
		throw IOException("DecryptResponse: Ciphertext field too large (" + std::to_string(ciphertext_b64.size()) +
		                  " bytes, max " + std::to_string(MAX_BASE64_FIELD_SIZE) + ")");
	}

	// Validate required fields are not empty
	if (nonce_b64.empty() || ciphertext_b64.empty() || hmac_hex.empty()) {
		throw IOException("DecryptResponse: Required encryption field is empty (nonce=%d, ciphertext=%d, hmac=%d)",
		                  (int)nonce_b64.size(), (int)ciphertext_b64.size(), (int)hmac_hex.size());
	}

	// 2. Validate cipher suite early (before expensive operations)
	if (cipher_suite != 0x0001 && cipher_suite != 0x0002) {
		throw IOException("DecryptResponse: Unsupported cipher suite 0x" + std::to_string(cipher_suite));
	}

	// 3. Derive keys from session_key
	auto encryption_key = DeriveEncryptionKey(session_key_param);
	auto integrity_key = DeriveIntegrityKey(session_key_param);

	// 4. Decode fields
	// Decode nonce (base64 → 12 bytes)
	string nonce_bytes_str = Blob::FromBase64(nonce_b64);
	if (nonce_bytes_str.size() != 12) {
		throw IOException("DecryptResponse: Invalid nonce size (expected 12 bytes, got " +
		                  std::to_string(nonce_bytes_str.size()) + ")");
	}
	vector<uint8_t> nonce_bytes(nonce_bytes_str.begin(), nonce_bytes_str.end());

	// Decode ciphertext (base64 → N+16 bytes, where 16 is AEAD tag)
	string ciphertext_with_tag_str = Blob::FromBase64(ciphertext_b64);
	if (ciphertext_with_tag_str.size() < 16) {
		throw IOException("DecryptResponse: Invalid ciphertext size (must be at least 16 bytes for AEAD tag)");
	}
	vector<uint8_t> ciphertext_with_tag(ciphertext_with_tag_str.begin(), ciphertext_with_tag_str.end());

	// Decode hmac (lowercase hex → 32 bytes)
	if (hmac_hex.size() != 64) {
		throw IOException("DecryptResponse: Invalid HMAC size (expected 64 hex chars, got " +
		                  std::to_string(hmac_hex.size()) + ")");
	}
	vector<uint8_t> hmac_bytes;
	hmac_bytes.reserve(32);
	for (size_t i = 0; i < 64; i += 2) {
		string byte_str = hmac_hex.substr(i, 2);
		uint8_t byte_val = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
		hmac_bytes.push_back(byte_val);
	}

	// 5. Verify HMAC BEFORE decryption (CRITICAL for security)
	// hmac_input = nonce_bytes || ciphertext_with_tag
	vector<uint8_t> hmac_input;
	hmac_input.reserve(nonce_bytes.size() + ciphertext_with_tag.size());
	hmac_input.insert(hmac_input.end(), nonce_bytes.begin(), nonce_bytes.end());
	hmac_input.insert(hmac_input.end(), ciphertext_with_tag.begin(), ciphertext_with_tag.end());

	// Using Rust crypto implementation (works on all platforms including WASM)
	uint8_t expected_hmac[32];
	opaque_client_hmac_sha256(integrity_key.data(), integrity_key.size(), hmac_input.data(), hmac_input.size(),
	                          expected_hmac);

	// Constant-time comparison (CRITICAL for security)
	volatile uint8_t diff = 0;
	for (size_t i = 0; i < 32; i++) {
		diff |= (hmac_bytes[i] ^ expected_hmac[i]);
	}

	// Securely zero expected HMAC
	SECURE_ZERO_MEMORY(expected_hmac, sizeof(expected_hmac));

	if (diff != 0) {
		BOILSTREAM_LOG("DecryptResponse: HMAC verification FAILED (tampering detected)");
		throw IOException("DecryptResponse: Response tampering detected (HMAC verification failed)");
	}

	BOILSTREAM_LOG("DecryptResponse: HMAC verified successfully");

	// 6. Decrypt ciphertext using AEAD (only after HMAC verification succeeds)
	// ciphertext_with_tag format: ciphertext || 16-byte AEAD tag
	// Per SECURITY_SPECIFICATION.md: AES-256-GCM produces ciphertext with 16-byte tag appended

	if (cipher_suite == 0x0001) {
		// AES-256-GCM AEAD decryption using Rust crypto (works on all platforms including WASM)
		BOILSTREAM_LOG("DecryptResponse: Using AES-256-GCM AEAD");

		// Validate ciphertext size (must include 16-byte authentication tag)
		constexpr size_t AEAD_TAG_SIZE = 16;
		if (ciphertext_with_tag.size() < AEAD_TAG_SIZE) {
			throw IOException("DecryptResponse: Ciphertext too short for AEAD tag");
		}

		size_t ciphertext_len = ciphertext_with_tag.size() - AEAD_TAG_SIZE;

		// Allocate output buffer for plaintext
		vector<uint8_t> plaintext_bytes(ciphertext_len);

		// Decrypt and verify using Rust (includes AEAD tag verification)
		BOILSTREAM_LOG("DecryptResponse: Calling opaque_client_aes_gcm_decrypt");

		long decrypted_len = opaque_client_aes_gcm_decrypt(
		    ciphertext_with_tag.data(), ciphertext_with_tag.size(), nonce_bytes.data(), nonce_bytes.size(),
		    encryption_key.data(), encryption_key.size(), plaintext_bytes.data(), plaintext_bytes.size());

		if (decrypted_len < 0) {
			std::ostringstream err;
			err << "DecryptResponse: AES-GCM decryption failed (error code: " << decrypted_len << "). ";
			err << "ciphertext=" << ciphertext_with_tag.size() << "B, ";
			err << "nonce=" << nonce_bytes.size() << "B, ";
			err << "key=" << encryption_key.size() << "B. ";
			err << "Possible causes: wrong key, corrupted ciphertext, or AEAD tag mismatch";
			throw IOException(err.str());
		}

		BOILSTREAM_LOG("DecryptResponse: AEAD tag verified successfully");

		// Convert to string
		string plaintext(reinterpret_cast<char *>(plaintext_bytes.data()), static_cast<size_t>(decrypted_len));

		// Securely zero keys and sensitive data
		SECURE_ZERO_MEMORY(encryption_key.data(), encryption_key.size());
		SECURE_ZERO_MEMORY(integrity_key.data(), integrity_key.size());
		SECURE_ZERO_MEMORY(plaintext_bytes.data(), plaintext_bytes.size());

		return plaintext;

	} else {
		// ChaCha20-Poly1305 AEAD decryption (cipher_suite == 0x0002)
		BOILSTREAM_LOG("DecryptResponse: ChaCha20-Poly1305 not yet implemented");
		// TODO: Implement ChaCha20-Poly1305 when needed
		throw IOException("DecryptResponse: ChaCha20-Poly1305 not yet implemented");
	}
}

bool RestApiSecretStorage::IsResponseEncrypted(const case_insensitive_map_t<string> &headers) {
	// Check for X-Boilstream-Encrypted header
	auto it = headers.find("x-boilstream-encrypted");
	if (it == headers.end()) {
		// Header not present - response is not encrypted
		return false;
	}

	// Check if value is "true" (case-insensitive)
	string value = it->second;
	std::transform(value.begin(), value.end(), value.begin(), ::tolower);
	return value == "true";
}

uint16_t RestApiSecretStorage::ParseCipherSuite(const case_insensitive_map_t<string> &headers) {
	// Extract X-Boilstream-Cipher header
	auto it = headers.find("x-boilstream-cipher");
	if (it == headers.end()) {
		throw IOException("ParseCipherSuite: X-Boilstream-Cipher header missing from encrypted response");
	}

	const auto &value = it->second;
	if (value.size() != 6 || value[0] != '0' || value[1] != 'x')
		throw IOException("ParseCipherSuite: Invalid cipher suite format (expected 0xNNNN)");
	uint16_t cipher = 0;
	for (idx_t i = 2; i < value.size(); ++i) {
		const auto c = value[i];
		uint16_t digit;
		if (c >= '0' && c <= '9')
			digit = c - '0';
		else if (c >= 'a' && c <= 'f')
			digit = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			digit = c - 'A' + 10;
		else
			throw IOException("ParseCipherSuite: Invalid hexadecimal digit");
		cipher = static_cast<uint16_t>((cipher << 4) | digit);
	}
	if (cipher != 1 && cipher != 2)
		throw IOException("ParseCipherSuite: Unsupported cipher suite");
	return cipher;
}

RestApiSecretStorage::SigningResult
RestApiSecretStorage::SignRequest(const string &method, const string &url, const string &body, uint64_t timestamp,
                                  uint64_t sequence, const vector<uint8_t> &session_key_param,
                                  const string &access_token_param, const string &region_param) {
	// AWS SigV4-style request signing
	// Following SECURITY_SPECIFICATION.md format

	// Derive base signing key from session_key using HKDF
	auto base_signing_key = DeriveSigningKey(session_key_param);

	// Format timestamp as ISO8601: YYYYMMDDTHHMMSSZ
	auto timestamp_time_t = static_cast<time_t>(timestamp);
	std::tm timestamp_tm;
#ifdef _WIN32
	gmtime_s(&timestamp_tm, &timestamp_time_t);
#else
	gmtime_r(&timestamp_time_t, &timestamp_tm);
#endif

	char date_time_buf[32];
	std::strftime(date_time_buf, sizeof(date_time_buf), "%Y%m%dT%H%M%SZ", &timestamp_tm);
	string date_time_str(date_time_buf);

	// Extract date part: YYYYMMDD
	char date_buf[16];
	std::strftime(date_buf, sizeof(date_buf), "%Y%m%d", &timestamp_tm);
	string date_str(date_buf);

	// Get access token prefix (first 8 characters) and region
	// Validate access_token length before substr
	if (access_token_param.length() < 8) {
		throw IOException("SignRequest: access_token too short (expected 64 chars, got " +
		                  std::to_string(access_token_param.length()) + ")");
	}
	string access_token_prefix = access_token_param.substr(0, 8);
	if (region_param.empty()) {
		throw IOException("SignRequest: region parameter is required (cannot be empty)");
	}
	string current_region = region_param;

	// Build credential scope: <access-token-prefix>/<date>/<region>/<service>/boilstream_request
	string service = "secrets";
	string credential_scope =
	    access_token_prefix + "/" + date_str + "/" + current_region + "/" + service + "/boilstream_request";

	// Build canonical headers (sorted, lowercase, with trailing newline)
	// Include ALL x-boilstream-* headers (except x-boilstream-signature)
	// Following spec: All headers starting with x-boilstream- must be signed
	string canonical_headers = "x-boilstream-cipher-version:1\n"
	                           "x-boilstream-ciphers:0x0001,0x0002\n"
	                           "x-boilstream-credential:" +
	                           credential_scope +
	                           "\n"
	                           "x-boilstream-date:" +
	                           date_time_str +
	                           "\n"
	                           "x-boilstream-sequence:" +
	                           std::to_string(sequence) + "\n";

	// Signed headers list (semicolon-separated, sorted)
	string signed_headers = "x-boilstream-cipher-version;x-boilstream-ciphers;x-boilstream-credential;x-boilstream-"
	                        "date;x-boilstream-sequence";

	// Extract URI path from URL (remove protocol and host)
	string canonical_uri = "/";
	auto uri_start = url.find("://");
	if (uri_start != string::npos) {
		auto path_start = url.find('/', uri_start + 3);
		if (path_start != string::npos) {
			canonical_uri = url.substr(path_start);
		}
	}

	// Extract query string (if any)
	string canonical_query = "";
	auto query_pos = canonical_uri.find('?');
	if (query_pos != string::npos) {
		canonical_query = canonical_uri.substr(query_pos + 1);
		canonical_uri = canonical_uri.substr(0, query_pos);
	}

	// Step 1: Build canonical request using Rust function
	auto canonical_result = aws_build_canonical_request(
	    method.c_str(), method.size(), canonical_uri.c_str(), canonical_uri.size(), canonical_query.c_str(),
	    canonical_query.size(), canonical_headers.c_str(), canonical_headers.size(), signed_headers.c_str(),
	    signed_headers.size(), reinterpret_cast<const uint8_t *>(body.c_str()), body.size());

	if (canonical_result.error != OPAQUE_SUCCESS) {
		throw IOException("AWS SigV4 signing failed: Could not build canonical request");
	}

	// Step 2: Derive date-scoped signing key using Rust function
	// Use current_region and service from credential scope building above
	auto signing_key_result =
	    aws_derive_signing_key(base_signing_key.data(), base_signing_key.size(), date_str.c_str(), date_str.size(),
	                           current_region.c_str(), current_region.size(), service.c_str(), service.size());

	if (signing_key_result.error != OPAQUE_SUCCESS) {
		opaque_free_buffer(canonical_result.buffer);
		throw IOException("AWS SigV4 signing failed: Could not derive signing key");
	}

	// Step 3: Sign canonical request using Rust function
	auto signature_result = aws_sign_canonical_request(signing_key_result.buffer.data, signing_key_result.buffer.len,
	                                                   reinterpret_cast<const char *>(canonical_result.buffer.data),
	                                                   canonical_result.buffer.len);

	// Cleanup intermediate buffers
	opaque_free_buffer(canonical_result.buffer);
	opaque_free_buffer(signing_key_result.buffer);

	if (signature_result.error != OPAQUE_SUCCESS) {
		throw IOException("AWS SigV4 signing failed: Could not sign request");
	}

	// Extract base64 signature from result
	string signature(reinterpret_cast<const char *>(signature_result.buffer.data), signature_result.buffer.len);

	// Cleanup signature buffer
	opaque_free_buffer(signature_result.buffer);

	// Return signing result with all required information
	SigningResult result;
	result.signature = signature;
	result.date_time = date_time_str;
	result.credential_scope = credential_scope;
	return result;
}

string RestApiSecretStorage::SerializeSecret(const BaseSecret &secret) {
	// Serialize secret to base64-encoded binary format
	MemoryStream stream;
	BinarySerializer serializer(stream);
	serializer.Begin();
	secret.Serialize(serializer);
	serializer.End();

	auto data = stream.GetData();
	string data_str((const char *)data, stream.GetPosition());
	auto encoded = Blob::ToBase64(string_t(data_str));

	// Create JSON with metadata using yyjson (safe from injection)
	auto doc = yyjson_mut_doc_new(nullptr);
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);

	yyjson_mut_obj_add_strcpy(doc, obj, "name", secret.GetName().c_str());
	yyjson_mut_obj_add_strcpy(doc, obj, "type", secret.GetType().c_str());
	yyjson_mut_obj_add_strcpy(doc, obj, "provider", secret.GetProvider().c_str());

	// Add scope array
	auto scope_arr = yyjson_mut_arr(doc);
	auto &scope = secret.GetScope();
	for (idx_t i = 0; i < scope.size(); i++) {
		yyjson_mut_arr_add_strcpy(doc, scope_arr, scope[i].c_str());
	}
	yyjson_mut_obj_add_val(doc, obj, "scope", scope_arr);

	yyjson_mut_obj_add_strcpy(doc, obj, "data", encoded.c_str());

	// Determine expires_at based on secret type
	// Temporary credentials (with SESSION_TOKEN) get 1 hour expiration (placeholder)
	// Permanent credentials get current time + 1 year
	auto now = std::chrono::system_clock::now();

	// Check if this is a temporary credential by looking for SESSION_TOKEN in the serialized data
	// This is a heuristic - we check the encoded data for the presence of session token markers
	bool is_temporary =
	    (encoded.find("SESSION_TOKEN") != string::npos || encoded.find("session_token") != string::npos);

	std::chrono::system_clock::time_point expires_at_time;
	if (is_temporary) {
		// Temporary credential - set short expiration (will be updated by server with actual STS expiration)
		// Use 1 hour as placeholder since we don't have access to the actual STS expiration here
		expires_at_time = now + std::chrono::hours(1);
	} else {
		// Permanent credential - set expiration to 1 year from now
		expires_at_time = now + std::chrono::hours(24 * 365); // 1 year
	}

	// Format the expiration time as ISO 8601
	auto expires_at_time_t = std::chrono::system_clock::to_time_t(expires_at_time);
	std::tm expires_at_tm;
#ifdef _WIN32
	gmtime_s(&expires_at_tm, &expires_at_time_t);
#else
	gmtime_r(&expires_at_time_t, &expires_at_tm);
#endif
	char expires_at_buf[64];
	std::strftime(expires_at_buf, sizeof(expires_at_buf), "%Y-%m-%dT%H:%M:%SZ", &expires_at_tm);

	yyjson_mut_obj_add_strcpy(doc, obj, "expires_at", expires_at_buf);

	// Convert to string
	string result = SafeJsonSerialize(doc);
	yyjson_mut_doc_free(doc);

	return result;
}

unique_ptr<BaseSecret> RestApiSecretStorage::DeserializeSecret(const string &json_data, SecretManager &manager) {
	// Security: Validate JSON size before parsing
	if (json_data.size() > MAX_JSON_RESPONSE_SIZE) {
		throw IOException("DeserializeSecret: JSON data too large (" + std::to_string(json_data.size()) +
		                  " bytes, max " + std::to_string(MAX_JSON_RESPONSE_SIZE) + ")");
	}

	// Parse JSON using yyjson
	auto doc = yyjson_read(json_data.c_str(), json_data.size(), 0);
	if (!doc) {
		return nullptr;
	}

	auto root = yyjson_doc_get_root(doc);
	if (!root || !yyjson_is_obj(root)) {
		yyjson_doc_free(doc);
		return nullptr;
	}

	// Extract the "data" field
	auto data_val = yyjson_obj_get(root, "data");
	if (!data_val || !yyjson_is_str(data_val)) {
		yyjson_doc_free(doc);
		return nullptr;
	}

	string encoded = SafeGetStr(data_val);
	if (encoded.empty()) {
		yyjson_doc_free(doc);
		BOILSTREAM_LOG("DeserializeSecret: data field is empty");
		return nullptr;
	}

	// Security: Validate encoded data size before decoding
	if (encoded.size() > MAX_SECRET_DATA_SIZE) {
		yyjson_doc_free(doc);
		throw IOException("DeserializeSecret: Encoded data too large (" + std::to_string(encoded.size()) +
		                  " bytes, max " + std::to_string(MAX_SECRET_DATA_SIZE) + ")");
	}

	// Decode and deserialize under one cleanup/error boundary. DuckDB's base64
	// errors include their input, so they must never escape with secret material.
	unique_ptr<BaseSecret> secret;
	try {
		auto decoded = Blob::FromBase64(string_t(encoded.c_str(), encoded.size()));
		MemoryStream stream((data_ptr_t)decoded.c_str(), decoded.size());
		BinaryDeserializer deserializer(stream);
		deserializer.Begin();
		secret = manager.DeserializeSecret(deserializer);
		deserializer.End();
	} catch (const std::exception &e) {
		yyjson_doc_free(doc);
		BoilstreamRethrowSafe("Secret decoding failed", e);
	} catch (...) {
		yyjson_doc_free(doc);
		throw;
	}

	yyjson_doc_free(doc);
	return secret;
}

std::chrono::system_clock::time_point RestApiSecretStorage::ParseExpiresAt(const string &expires_at_str) {
	// The credential contract is RFC3339, including an explicit UTC designator
	// or numeric offset. Use DuckDB's parser so Z, +00:00, fractional seconds,
	// calendar validation, and offset normalization follow one implementation.
	if (expires_at_str.size() < 20 || expires_at_str[4] != '-' || expires_at_str[7] != '-' ||
	    expires_at_str[10] != 'T' || expires_at_str[13] != ':' || expires_at_str[16] != ':') {
		return std::chrono::system_clock::time_point::min();
	}
	idx_t offset_pos = 19;
	if (expires_at_str[offset_pos] == '.') {
		offset_pos++;
		const auto fraction_start = offset_pos;
		while (offset_pos < expires_at_str.size() && StringUtil::CharacterIsDigit(expires_at_str[offset_pos])) {
			offset_pos++;
		}
		if (offset_pos == fraction_start) {
			return std::chrono::system_clock::time_point::min();
		}
	}
	if (offset_pos >= expires_at_str.size()) {
		return std::chrono::system_clock::time_point::min();
	}
	if (expires_at_str[offset_pos] == 'Z') {
		if (offset_pos + 1 != expires_at_str.size()) {
			return std::chrono::system_clock::time_point::min();
		}
	} else {
		if ((expires_at_str[offset_pos] != '+' && expires_at_str[offset_pos] != '-') ||
		    offset_pos + 6 != expires_at_str.size() || expires_at_str[offset_pos + 3] != ':' ||
		    !StringUtil::CharacterIsDigit(expires_at_str[offset_pos + 1]) ||
		    !StringUtil::CharacterIsDigit(expires_at_str[offset_pos + 2]) ||
		    !StringUtil::CharacterIsDigit(expires_at_str[offset_pos + 4]) ||
		    !StringUtil::CharacterIsDigit(expires_at_str[offset_pos + 5])) {
			return std::chrono::system_clock::time_point::min();
		}
		const auto offset_hours = (expires_at_str[offset_pos + 1] - '0') * 10 + expires_at_str[offset_pos + 2] - '0';
		const auto offset_minutes = (expires_at_str[offset_pos + 4] - '0') * 10 + expires_at_str[offset_pos + 5] - '0';
		if (offset_hours > 23 || offset_minutes > 59) {
			return std::chrono::system_clock::time_point::min();
		}
	}

	timestamp_t parsed;
	bool has_offset = false;
	string_t timezone(nullptr, 0);
	const auto result = Timestamp::TryConvertTimestampTZ(expires_at_str.c_str(), expires_at_str.size(), parsed, true,
	                                                     has_offset, timezone);
	if (result != TimestampCastResult::SUCCESS || !has_offset || timezone.GetSize() != 0 ||
	    !Timestamp::IsFinite(parsed)) {
		return std::chrono::system_clock::time_point::min();
	}

	using clock_duration = std::chrono::system_clock::duration;
	const auto min_micros = std::chrono::duration<long double, std::micro>(clock_duration::min()).count();
	const auto max_micros = std::chrono::duration<long double, std::micro>(clock_duration::max()).count();
	if (static_cast<long double>(parsed.value) < min_micros || static_cast<long double>(parsed.value) > max_micros) {
		return std::chrono::system_clock::time_point::min();
	}
	return std::chrono::system_clock::time_point(
	    std::chrono::duration_cast<clock_duration>(std::chrono::microseconds(parsed.value)));
}

bool RestApiSecretStorage::IsManagedCatalogCredentialExpiredAt(const string &expires_at_str,
                                                               std::chrono::system_clock::time_point now) {
	return ParseExpiresAt(expires_at_str) <= now;
}

bool RestApiSecretStorage::IsExpired(const string &secret_name, BoilstreamConnectionState &conn_state) {
	return conn_state.IsSecretExpired(secret_name);
}

void RestApiSecretStorage::StoreExpiration(const string &secret_name, const string &expires_at_str,
                                           BoilstreamConnectionState &conn_state) {
	auto expiration_time = ParseExpiresAt(expires_at_str);

	lock_guard<mutex> lock(conn_state.expiration_lock);

	// Prevent unbounded map growth - limit to 10,000 secrets
	const size_t MAX_SECRETS = 10000;
	if (conn_state.secret_expiration.size() >= MAX_SECRETS) {
		// Clear oldest half of entries (simple LRU approximation)
		auto it = conn_state.secret_expiration.begin();
		size_t to_remove = MAX_SECRETS / 2;
		while (to_remove-- > 0 && it != conn_state.secret_expiration.end()) {
			it = conn_state.secret_expiration.erase(it);
		}
	}

	conn_state.secret_expiration[secret_name] = expiration_time;
}

void RestApiSecretStorage::ClearExpiration(const string &secret_name, BoilstreamConnectionState &conn_state) {
	lock_guard<mutex> lock(conn_state.expiration_lock);
	conn_state.secret_expiration.erase(secret_name);
}

std::chrono::system_clock::time_point
RestApiSecretStorage::GetSecretExpiration(const string &secret_name, optional_ptr<CatalogTransaction> transaction) {
	auto conn_state = GetSession(transaction);
	if (!conn_state) {
		// No connection state available
		return std::chrono::system_clock::time_point();
	}

	auto generic_expiry = conn_state->secret_cache->Expiration(secret_name);
	if (generic_expiry != BoilstreamSecretCache::Time::min()) return generic_expiry;
	lock_guard<mutex> lock(conn_state->expiration_lock);

	auto it = conn_state->secret_expiration.find(secret_name);
	if (it == conn_state->secret_expiration.end()) {
		// No expiration data available
		return std::chrono::system_clock::time_point();
	}

	return it->second;
}

string RestApiSecretStorage::GetEndpointUrl() {
	lock_guard<mutex> lock(endpoint_lock);
	return endpoint_url;
}

string RestApiSecretStorage::GetEndpointUrl(ClientContext &context) {
	auto state = GetSessionForContext(context);
	return state ? state->GetEndpointUrl() : "";
}

bool RestApiSecretStorage::IsMultiTenantMode(ClientContext &context) {
	return !GetTenantId(context).empty();
}

string RestApiSecretStorage::GetTenantId(ClientContext &context) {
#ifdef BOILSTREAM_HAS_TENANT_CONTEXT
	auto &tenant = TenantIsolation::GetTenant(context);
	if (tenant.IsActive()) return tenant.tenant_id;
	auto active = ActiveTenantRegistry::GetCurrentTenant(DatabaseInstance::GetDatabase(context));
	return active && active->IsActive() ? active->tenant_id : "";
#else
	Value tenant_id;
	return context.TryGetCurrentSetting("boilstream.tenant_id", tenant_id) ? tenant_id.ToString() : "";
#endif
}

string RestApiSecretStorage::StripTenantPrefix(const string &name, ClientContext &context) {
	auto tenant_id = GetTenantId(context);
	if (tenant_id.empty()) {
		return name;
	}

	// Tenant prefix format: __BS_u{tenant_id}__
	string prefix = "__BS_u" + tenant_id + "__";
	if (name.find(prefix) == 0) {
		return name.substr(prefix.length());
	}
	return name;
}

string RestApiSecretStorage::AppendMultiTenantParam(const string &url, optional_ptr<CatalogTransaction> transaction) {
	// If no transaction or no context, return URL unchanged
	if (!transaction || !transaction->HasContext()) {
		return url;
	}
	return AppendMultiTenantParam(url, transaction->GetContext());
}

string RestApiSecretStorage::AppendMultiTenantParam(const string &url, ClientContext &context) {
	if (!IsMultiTenantMode(context)) {
		return url;
	}

	// Append ?multitenant=true (or &multitenant=true if URL already has query params)
	if (url.find('?') != string::npos) {
		return url + "&multitenant=true";
	}
	return url + "?multitenant=true";
}

string RestApiSecretStorage::AppendPlatformParams(const string &url, optional_ptr<CatalogTransaction> transaction) {
	// If no transaction or no context, only add WASM param if applicable
	if (!transaction || !transaction->HasContext()) {
		if (IsWasmMode()) {
			if (url.find('?') != string::npos) {
				return url + "&platform=wasm";
			}
			return url + "?platform=wasm";
		}
		return url;
	}
	return AppendPlatformParams(url, transaction->GetContext());
}

string RestApiSecretStorage::AppendPlatformParams(const string &url, ClientContext &context) {
	string result = url;
	bool has_params = (url.find('?') != string::npos);

	// Add multitenant param if in multi-tenant mode
	if (IsMultiTenantMode(context)) {
		if (has_params) {
			result += "&multitenant=true";
		} else {
			result += "?multitenant=true";
			has_params = true;
		}
		BOILSTREAM_LOG("AppendPlatformParams: Added multitenant=true");
	}

	// Add platform=wasm if running in WASM environment (compile-time constant)
	if (IsWasmMode()) {
		if (has_params) {
			result += "&platform=wasm";
		} else {
			result += "?platform=wasm";
		}
		BOILSTREAM_LOG("AppendPlatformParams: Added platform=wasm");
	}

	return result;
}

// Pending enrollment has no database-global credentials or connection-id map.
// Only the real ClientContext owns this state; no API exposes an owning handle.
class BoilstreamRegistrationContext : public ClientContextState {
public:
	explicit BoilstreamRegistrationContext(RestApiSecretStorage &storage) : storage(storage) {
	}
	RestApiSecretStorage &storage;
	weak_ptr<BoilstreamConnectionState> authentication;
	bool had_authentication = false;
	uint64_t authentication_generation = 0;
	bool MatchesAuthentication(const shared_ptr<BoilstreamConnectionState> &current) const {
		auto previous = authentication.lock();
		return had_authentication ? previous && previous == current &&
		                                current->authentication_generation.load() == authentication_generation
		                          : !current;
	}
	mutex lock;
	uint64_t generation = 0;
	bool bound = false, ready = false, busy = false, verifying = false;
	string tenant, base_url, email, session_token, totp_uri;
	void Reset() {
		generation = 0;
		authentication.reset();
		had_authentication = false;
		authentication_generation = 0;
		bound = ready = busy = verifying = false;
		for (auto value : {&tenant, &base_url, &email, &session_token, &totp_uri}) {
			BoilstreamConnectionState::SecureZeroString(*value);
			value->clear();
		}
	}
	~BoilstreamRegistrationContext() override {
		Reset();
	}
	void QueryBegin(ClientContext &context) override {
		const auto current = RestApiSecretStorage::GetTenantId(context);
		const auto current_auth = storage.GetSessionForConnection(context.GetConnectionId());
		lock_guard<mutex> guard(lock);
		if (bound && (current != tenant || !MatchesAuthentication(current_auth) || context.IsInterrupted()))
			Reset();
	}
	void QueryEnd(ClientContext &context, optional_ptr<ErrorData>) override {
		if (context.IsInterrupted()) {
			lock_guard<mutex> guard(lock);
			Reset();
		}
	}
	BoilstreamRegistrationSnapshot Snapshot() const {
		return {generation, base_url, email, session_token, totp_uri};
	}
	void Check(uint64_t expected) const {
		if (!bound || !busy || generation != expected || expected == 0)
			throw IOException("Registration operation was interrupted or superseded");
	}
};

// IDs carry no identity or credentials. Never reuse an operation ID, including
// across connections, so a foreign or delayed completion cannot match a lease.
static uint64_t NextRegistrationOperation() {
	static std::atomic<uint64_t> next {1};
	auto value = next.load(std::memory_order_relaxed);
	do {
		if (value == NumericLimits<uint64_t>::Maximum())
			throw IOException("Registration operation limit reached");
	} while (!next.compare_exchange_weak(value, value + 1, std::memory_order_relaxed));
	return value;
}

shared_ptr<BoilstreamRegistrationContext> RestApiSecretStorage::RegistrationOwner(ClientContext &context, bool create) {
	if (&DatabaseInstance::GetDatabase(context) != &db)
		throw IOException("Registration belongs to a different database");
	const auto tenant = GetTenantId(context);
	auto owner =
	    create ? context.registered_state->GetOrCreate<BoilstreamRegistrationContext>("boilstream_registration", *this)
	           : context.registered_state->Get<BoilstreamRegistrationContext>("boilstream_registration");
	const auto current_auth = GetSessionForConnection(context.GetConnectionId());
	if (owner) {
		lock_guard<mutex> guard(owner->lock);
		if (owner->bound &&
		    (owner->tenant != tenant || !owner->MatchesAuthentication(current_auth) || context.IsInterrupted()))
			owner->Reset();
	}
	if (tenant.size() > 4096)
		throw InvalidInputException("Registration tenant identity is too long");
	if (context.IsInterrupted())
		throw IOException("Registration was interrupted");
	return owner;
}

static bool ValidRegistrationField(const string &value, size_t limit) {
	if (value.empty() || value.size() > limit)
		return false;
	for (unsigned char c : value)
		if (c < 32 || c == 127)
			return false;
	return true;
}

BoilstreamRegistrationSnapshot RestApiSecretStorage::BeginRegistration(ClientContext &context, const string &base_url,
                                                                       const string &email) {
	if (!ValidRegistrationField(base_url, 4096) || !ValidRegistrationField(email, 320))
		throw InvalidInputException("Invalid registration authority or account length");
	auto owner = RegistrationOwner(context, true);
	const auto tenant = GetTenantId(context);
	const auto current_auth = GetSessionForConnection(context.GetConnectionId());
	// Allocate identity copies before invalidating any ready registration.
	string new_base = base_url, new_email = email, new_tenant = tenant;
	lock_guard<mutex> guard(owner->lock);
	if (owner->busy)
		throw IOException("A registration operation is already in progress for this connection");
	if (!owner->ready || owner->base_url != base_url || owner->email != email) {
		owner->Reset();
		owner->base_url.swap(new_base);
		owner->email.swap(new_email);
		owner->tenant.swap(new_tenant);
		owner->bound = true;
		owner->authentication = current_auth;
		owner->had_authentication = bool(current_auth);
		owner->authentication_generation = current_auth ? current_auth->authentication_generation.load() : 0;
	}
	auto snapshot = owner->Snapshot(); // A failed allocation must not strand busy=true.
	snapshot.generation = NextRegistrationOperation();
	owner->generation = snapshot.generation;
	owner->verifying = false;
	owner->busy = true;
	return snapshot;
}

BoilstreamRegistrationSnapshot RestApiSecretStorage::BeginMfaVerification(ClientContext &context) {
	auto owner = RegistrationOwner(context, false);
	if (!owner)
		throw IOException("No registration state found for this connection; register first");
	lock_guard<mutex> guard(owner->lock);
	if (!owner->ready || owner->busy)
		throw IOException("Registration is unavailable or already in progress for this connection");
	auto snapshot = owner->Snapshot();
	snapshot.generation = NextRegistrationOperation();
	owner->generation = snapshot.generation;
	owner->verifying = true;
	owner->busy = true;
	return snapshot;
}

void RestApiSecretStorage::StoreRegistrationState(ClientContext &context, uint64_t generation,
                                                  const string &session_token, const string &totp_uri) {
	if (!ValidRegistrationField(session_token, 4096) || !ValidRegistrationField(totp_uri, 4096))
		throw InvalidInputException("Invalid registration credential length");
	string token_copy = session_token, uri_copy = totp_uri;
	auto owner = RegistrationOwner(context, false);
	if (!owner)
		throw IOException("No pending registration operation");
	lock_guard<mutex> guard(owner->lock);
	owner->Check(generation);
	if (owner->ready || owner->verifying)
		throw IOException("Registration was already published");
	owner->session_token.swap(token_copy);
	owner->totp_uri.swap(uri_copy);
	owner->ready = true;
}

void RestApiSecretStorage::CompleteRegistration(ClientContext &context, uint64_t generation) {
	auto owner = RegistrationOwner(context, false);
	if (!owner)
		throw IOException("No pending registration operation");
	lock_guard<mutex> guard(owner->lock);
	owner->Check(generation);
	if (!owner->ready || !owner->verifying)
		throw IOException("Registration is not ready for verification");
	owner->Reset();
}

void RestApiSecretStorage::EndRegistrationOperation(ClientContext &context, uint64_t generation) noexcept {
	try {
		auto owner = RegistrationOwner(context, false);
		if (!owner)
			return;
		lock_guard<mutex> guard(owner->lock);
		if (owner->generation != generation)
			return; // A late cleanup cannot erase its successor.
		if (!owner->ready)
			owner->Reset();
		else
			owner->busy = false; // A rejected MFA code may be retried by the same owner.
	} catch (...) {              /* Cancellation already invalidates state in RegistrationOwner. */
	}
}

namespace {
class LocalBoilstreamSecrets : public ClientContextState {
public:
	explicit LocalBoilstreamSecrets(string tenant) : tenant(std::move(tenant)) {}
	const string tenant;
	shared_ptr<BoilstreamSecretCache> cache = make_shared_ptr<BoilstreamSecretCache>();
	~LocalBoilstreamSecrets() override { cache->Close(); }
};
}

RestApiSecretStorage::SecretOwner RestApiSecretStorage::GetSecretOwner(
    optional_ptr<CatalogTransaction> transaction, bool create) {
	if (!transaction || !transaction->HasContext()) return {};
	auto &context = transaction->GetContext();
	auto state = GetSession(transaction);
	if (state) {
		lock_guard<mutex> lock(state->session_lock);
		if (state->access_token.empty() || state->session_key.empty() ||
		    state->token_expires_at <= std::chrono::system_clock::now()) return {};
		return {state, state->secret_cache};
	}
	// Explicit secrets without a login are local to this connection and tenant.
	// They are never mirrored into database-wide memory storage.
	auto local = create ? context.registered_state->GetOrCreate<LocalBoilstreamSecrets>(
	                          "boilstream_local_secrets", GetTenantId(context))
	                    : context.registered_state->Get<LocalBoilstreamSecrets>("boilstream_local_secrets");
	if (local && local->tenant != GetTenantId(context)) {
		throw IOException("Local BoilStream secrets belong to a different tenant context");
	}
	return {nullptr, local ? local->cache : nullptr};
}

shared_ptr<BoilstreamSecretCache> RestApiSecretStorage::GetSecretCache(
    optional_ptr<CatalogTransaction> transaction, bool create) {
	return GetSecretOwner(transaction, create).cache;
}

static vector<SecretEntry> CloneSecretSnapshot(const shared_ptr<BoilstreamSecretCache> &cache) {
	vector<SecretEntry> result;
	if (cache) for (auto &entry : cache->Snapshot()) result.emplace_back(*entry);
	return result;
}

SecretMatch RestApiSecretStorage::LookupCachedSecret(
    const string &path, const string &type, const shared_ptr<BoilstreamSecretCache> &cache) {
	SecretMatch best;
	if (cache) {
		for (auto &entry : cache->Snapshot()) {
			if (StringUtil::CIEquals(entry->secret->GetType(), type)) {
				SecretEntry copy(*entry);
				best = SelectBestMatch(copy, path, tie_break_offset, best);
			}
		}
	}
	return best;
}

string RestApiSecretStorage::HttpGet(const string &url, optional_ptr<CatalogTransaction> transaction) {
	auto conn_state = GetSession(transaction);
	if (!conn_state) {
		throw IOException("HttpGet: No connection state available. Call PRAGMA boilstream_bootstrap_session first.");
	}
	return HttpGetWithState(url, *conn_state);
}

string RestApiSecretStorage::HttpGetWithState(const string &url, BoilstreamConnectionState &conn_state) {
	try {
		// Prevent recursive lookups during HTTP operations
		// httpfs may try to look up secrets when making HTTP requests - return empty to avoid infinite loop
		if (in_http_operation) {
			return ""; // Return empty - httpfs will proceed without credentials
		}

		// RAII guard automatically manages flag (exception-safe)
		HttpOperationGuard guard;
		BOILSTREAM_LOG("HttpGetWithState: Guard set, in_http_op now TRUE");

		auto &http_util = HTTPUtil::Get(db);
		BOILSTREAM_LOG("HttpGetWithState: Calling InitializeParameters...");
		auto params = http_util.InitializeParameters(db, url);
		BOILSTREAM_LOG("HttpGetWithState: InitializeParameters returned");
		if (!params) {
			BOILSTREAM_LOG("HttpGetWithState EXIT: InitializeParameters FAILED");
			return "";
		}
		MaybeDisableTlsVerificationFromEnv(*params);

		// Retry configuration: 3 retries with short exponential backoff
		// Total attempts: 4 (1 initial + 3 retries)
		// Total worst-case delay: 100ms + 200ms + 400ms = 700ms
		const int MAX_RETRIES = 3;
		const int BASE_DELAY_MS = 100;
		string response_body_result;
		bool request_sent = false;

		for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
			request_sent = true; // Mark that we're attempting to send

			// Build authenticated headers INSIDE retry loop - each attempt needs fresh sequence number
			HTTPHeaders headers(db);
			vector<uint8_t> current_session_key;
			headers = BuildAuthenticatedHeaders("GET", url, "", conn_state, &current_session_key);
			const bool has_session_key = true;

			string response_body;
			HTTPHeaders response_headers_captured(db);
			auto response_handler = [&](const HTTPResponse &response) {
				// Don't use response.body - it may be empty when content_handler is used
				// Capture response headers for signature verification
				response_headers_captured = response.headers;
				return true;
			};
			auto content_handler = [&](const_data_ptr_t data, idx_t size) {
				response_body.append(reinterpret_cast<const char *>(data), size);
				return true;
			};

			GetRequestInfo request(url, headers, *params, response_handler, content_handler);
			BOILSTREAM_LOG("HttpGet: sending request...");
			auto response = http_util.Request(request);

			// Check if we should retry (only on transient errors)
			if (response->ShouldRetry() && attempt < MAX_RETRIES) {
				// Exponential backoff: 100ms, 200ms, 400ms
				std::this_thread::sleep_for(std::chrono::milliseconds(BASE_DELAY_MS * (1 << attempt)));
				continue;
			}

			// Get HTTP status code first
			auto status_code = static_cast<uint16_t>(response->status);

			if (!response->Success()) {
				return "";
			}

			// Verify response signature and decrypt BEFORE checking status code
			// This ensures error responses are also decrypted before being thrown
			if (has_session_key) {
				try {
					VerifyAuthenticatedResponse(response_body, status_code, response_headers_captured,
					                            current_session_key);
					BOILSTREAM_LOG("HttpGet: Response signature verified successfully");
				} catch (const std::exception &e) {
					conn_state.ClearSession();
					BoilstreamRethrowSafe("Response integrity check failed", e);
				}

				// Check if response is encrypted and decrypt if needed
				auto header_map = ExtractBoilstreamHeaders(response_headers_captured);

				bool is_encrypted_via_header = IsResponseEncrypted(header_map);

				// Also check JSON body for "encrypted":true (fallback if server doesn't send header)
				bool is_encrypted_via_body = (response_body.find("\"encrypted\"") != string::npos &&
				                              response_body.find("\"ciphertext\"") != string::npos);

				if (is_encrypted_via_header || is_encrypted_via_body) {
					if (is_encrypted_via_body && !is_encrypted_via_header) {
						BOILSTREAM_LOG("HttpGet: Response is encrypted (detected from JSON body, header missing)");
					} else {
						BOILSTREAM_LOG("HttpGet: Response is encrypted (via header)");
					}

					try {
						// Try to get cipher suite from header
						uint16_t cipher_suite = 0x0001; // Default to AES-256-GCM
						if (header_map.find("x-boilstream-cipher") != header_map.end()) {
							cipher_suite = ParseCipherSuite(header_map);
						} else {
							BOILSTREAM_LOG(
							    "HttpGet: X-Boilstream-Cipher header missing, defaulting to 0x0001 (AES-256-GCM)");
						}
						response_body = DecryptResponse(response_body, current_session_key, cipher_suite);

					} catch (const std::exception &e) {
						BoilstreamRethrowSafe("Response decryption failed", e);
					}
				} else {
					BOILSTREAM_LOG("HttpGet: Response is not encrypted (plaintext)");
				}
			}

			// Now check status code with decrypted response body
			// 4xx Client Errors - fail fast, don't retry
			if (status_code >= 400 && status_code < 500) {
				BoilstreamThrowHttpStatus("HTTP GET failed", status_code);
			}

			// 5xx Server Errors - classify for retry decision
			if (status_code >= 500 && status_code < 600) {
				// 501 Not Implemented, 505 HTTP Version Not Supported - don't retry
				if (status_code == 501 || status_code == 505) {
					BoilstreamThrowHttpStatus("HTTP GET failed", status_code);
				}

				// 500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout
				// These are retryable - return empty to trigger retry logic
				if (attempt < MAX_RETRIES) {
					continue; // Will retry with exponential backoff
				} else {
					// All retries exhausted
					BoilstreamThrowHttpStatus("HTTP GET failed", status_code);
				}
			}

			// 3xx Redirects or other non-2xx
			if (status_code < 200 || status_code >= 300) {
				return ""; // Return empty for redirects
			}

			return response_body;
		}

		BOILSTREAM_LOG("HttpGetWithState EXIT: All retries exhausted");
		return ""; // All retries exhausted

	} catch (const std::exception &e) {
		BoilstreamRethrowSafe("HTTP GET failed", e);
	}
}

string RestApiSecretStorage::HttpPost(const string &url, const string &body,
                                      optional_ptr<CatalogTransaction> transaction, HTTPHeaders *out_headers) {
	auto conn_state = GetSession(transaction);
	if (!conn_state) {
		throw IOException("HttpPost: No connection state available. Call PRAGMA boilstream_bootstrap_session first.");
	}
	return HttpPostWithState(url, body, *conn_state, out_headers);
}

string RestApiSecretStorage::HttpPostWithState(const string &url, const string &body,
                                               BoilstreamConnectionState &conn_state, HTTPHeaders *out_headers) {
	try {
		// Check if URL is empty
		if (url.empty()) {
			throw IOException(
			    "HTTP POST failed: No endpoint URL configured. Use PRAGMA duckdb_secrets_rest_endpoint() first.");
		}

		// Prevent recursive lookups during HTTP operations
		if (in_http_operation) {
			BOILSTREAM_LOG("HttpPostWithState EXIT: BLOCKED by recursion guard");
			throw IOException("HTTP POST failed: Recursive secret lookup detected");
		}

		// RAII guard automatically manages flag (exception-safe)
		HttpOperationGuard guard;

		auto &http_util = HTTPUtil::Get(db);
		// Initialize parameters with nullptr to avoid looking up secrets (which could recurse)
		auto params = http_util.InitializeParameters(db, url);
		if (!params) {
			BOILSTREAM_LOG("HttpPostWithState: InitializeParameters FAILED");
			throw IOException("HTTP POST failed: Could not initialize HTTP parameters");
		}
		MaybeDisableTlsVerificationFromEnv(*params);

		// Generate idempotency key for safe retries (prevents duplicate secret creation)
		// Use a hash of the request body - same content always gets same key for idempotency
		// Note: Hash collisions are unlikely for typical secret payloads but theoretically possible
		// Backend should validate secret name matches to detect collisions
		auto idempotency_key = std::to_string(std::hash<string> {}(body));

		// Retry configuration: 3 retries with short exponential backoff
		// Total attempts: 4 (1 initial + 3 retries)
		// Total worst-case delay: 100ms + 200ms + 400ms = 700ms
		const int MAX_RETRIES = 3;
		const int BASE_DELAY_MS = 100;
		string last_error;

		for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
			// Build authenticated headers INSIDE retry loop - each attempt needs fresh sequence number
			// During OPAQUE login/registration, we don't have a session yet
			HTTPHeaders headers(db);
			vector<uint8_t> current_session_key;
			bool has_session_key = false;
			bool is_exchanging_now = false;

			{
				lock_guard<mutex> lock(conn_state.session_lock);
				is_exchanging_now = conn_state.is_exchanging;
				current_session_key = conn_state.session_key;
				has_session_key = !conn_state.session_key.empty();
			}

			if (!is_exchanging_now) {
				// Normal API request - add authenticated headers
				headers = BuildAuthenticatedHeaders("POST", url, body, conn_state, &current_session_key);
				has_session_key = true;
			}

			// Add idempotency key (same for all retries - prevents duplicate operations)
			headers.Insert("Idempotency-Key", idempotency_key);

			PostRequestInfo request(url, headers, *params, const_data_ptr_cast(body.c_str()), body.size());
			auto response = http_util.Request(request);

			// Check if we should retry (only on transient errors)
			if (response->ShouldRetry() && attempt < MAX_RETRIES) {
				last_error = "HTTP transport request failed";
				// Exponential backoff: 100ms, 200ms, 400ms
				std::this_thread::sleep_for(std::chrono::milliseconds(BASE_DELAY_MS * (1 << attempt)));
				continue;
			}

			// Get HTTP status code
			auto status_code = static_cast<uint16_t>(response->status);

			// Capture response headers if requested
			if (out_headers) {
				*out_headers = response->headers;
			}

			// Verify response signature and decrypt BEFORE checking status code
			// This ensures error responses are also decrypted before being thrown
			if (has_session_key) {
				try {
					VerifyAuthenticatedResponse(request.buffer_out, status_code, response->headers,
					                            current_session_key);
					BOILSTREAM_LOG("HttpPost: Response signature verified successfully");
				} catch (const std::exception &e) {
					conn_state.ClearSession();
					BoilstreamRethrowSafe("Response integrity check failed", e);
				}

				// Check if response is encrypted and decrypt if needed
				auto header_map = ExtractBoilstreamHeaders(response->headers);

				// Debug: Log all received headers

				// Check for encryption via header OR body (WASM doesn't always expose headers)
				bool is_encrypted = IsResponseEncrypted(header_map);

				// Fallback: Check if response body has {"encrypted":true,...} format
				if (!is_encrypted && !request.buffer_out.empty() && request.buffer_out[0] == '{') {
					// Try to parse as JSON to check for encrypted field
					yyjson_doc *doc = yyjson_read(request.buffer_out.c_str(), request.buffer_out.size(), 0);
					if (doc) {
						yyjson_val *root = yyjson_doc_get_root(doc);
						if (root && yyjson_is_obj(root)) {
							yyjson_val *encrypted_val = yyjson_obj_get(root, "encrypted");
							if (encrypted_val && yyjson_is_bool(encrypted_val) && yyjson_get_bool(encrypted_val)) {
								is_encrypted = true;
								BOILSTREAM_LOG(
								    "HttpPost: Detected encryption from response body (headers unavailable in WASM)");
							}
						}
						yyjson_doc_free(doc);
					}
				}

				if (is_encrypted) {
					BOILSTREAM_LOG("HttpPost: Response is encrypted, decrypting...");
					try {
						// Try to get cipher suite from header
						uint16_t cipher_suite = 0x0001; // Default to AES-256-GCM
						if (header_map.find("x-boilstream-cipher") != header_map.end()) {
							cipher_suite = ParseCipherSuite(header_map);
						} else {
							BOILSTREAM_LOG(
							    "HttpPost: X-Boilstream-Cipher header missing, defaulting to 0x0001 (AES-256-GCM)");
						}
						request.buffer_out = DecryptResponse(request.buffer_out, current_session_key, cipher_suite);

					} catch (const std::exception &e) {
						BoilstreamRethrowSafe("Response decryption failed", e);
					}
				} else {
					BOILSTREAM_LOG("HttpPost: Response is not encrypted (plaintext)");
				}
			}

			// Now check status code with decrypted response body
			// 4xx Client Errors - fail fast, don't retry
			if (status_code >= 400 && status_code < 500) {
				// Special handling for rate limit errors
				if (status_code == 429) {
					BoilstreamThrowHttpStatus("HTTP POST failed", 429);
				}

				BoilstreamThrowHttpStatus("HTTP POST failed", status_code);
			}

			// 5xx Server Errors - classify for retry decision
			if (status_code >= 500 && status_code < 600) {
				// 501 Not Implemented, 505 HTTP Version Not Supported - don't retry
				if (status_code == 501 || status_code == 505) {
					BoilstreamThrowHttpStatus("HTTP POST failed", status_code);
				}

				// 500, 502, 503, 504 - retryable server errors
				if (attempt < MAX_RETRIES) {
					last_error = "HTTP " + std::to_string(status_code) + " server error";
					continue; // Will retry with exponential backoff
				}
				// Fall through to throw after all retries
			}

			// Non-2xx status (including exhausted 5xx retries)
			if (status_code < 200 || status_code >= 300) {
				BoilstreamThrowHttpStatus("HTTP POST failed", status_code);
			}

			return request.buffer_out;
		}

		// All retries exhausted
		BOILSTREAM_LOG("HttpPostWithState EXIT: All retries exhausted");
		throw IOException("HTTP POST failed after " + std::to_string(MAX_RETRIES + 1) + " attempts: " + last_error);

	} catch (const std::exception &e) {
		BoilstreamRethrowSafe("HTTP POST failed", e);
	}
}

void RestApiSecretStorage::HttpDelete(const string &url, BoilstreamConnectionState &conn_state) {
	try {
		// Prevent recursive lookups during HTTP operations
		if (in_http_operation) {
			BOILSTREAM_LOG("HttpDelete: BLOCKED by recursion guard");
			throw IOException("HTTP DELETE failed: Recursive secret lookup detected");
		}

		// RAII guard automatically manages flag (exception-safe)
		HttpOperationGuard guard;

		auto &http_util = HTTPUtil::Get(db);
		auto params = http_util.InitializeParameters(db, url);
		if (!params) {
			throw IOException("HTTP DELETE failed: Could not initialize HTTP parameters");
		}
		MaybeDisableTlsVerificationFromEnv(*params);

		// Retry configuration: 3 retries with short exponential backoff
		// Total attempts: 4 (1 initial + 3 retries)
		// Total worst-case delay: 100ms + 200ms + 400ms = 700ms
		const int MAX_RETRIES = 3;
		const int BASE_DELAY_MS = 100;
		string last_error;

		for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
			// Build authenticated headers INSIDE retry loop - each attempt needs fresh sequence number
			vector<uint8_t> current_session_key;
			HTTPHeaders headers = BuildAuthenticatedHeaders("DELETE", url, "", conn_state, &current_session_key);
			const bool has_session_key = true;

			DeleteRequestInfo request(url, headers, *params);
			auto response = http_util.Request(request);

			// Check if we should retry (only on transient errors)
			if (response->ShouldRetry() && attempt < MAX_RETRIES) {
				last_error = "HTTP transport request failed";
				// Exponential backoff: 100ms, 200ms, 400ms
				std::this_thread::sleep_for(std::chrono::milliseconds(BASE_DELAY_MS * (1 << attempt)));
				continue;
			}

			if (!response->Success()) {
				BoilstreamThrowHttpStatus("HTTP DELETE failed", static_cast<int>(response->status));
			}

			// Get HTTP status code
			auto status_code = static_cast<uint16_t>(response->status);

			// Store response body (may be decrypted below)
			string response_body = response->body;

			// Verify response signature and decrypt BEFORE checking status code
			// This ensures error responses are also decrypted before being thrown
			if (has_session_key) {
				try {
					VerifyAuthenticatedResponse(response_body, status_code, response->headers, current_session_key);
					BOILSTREAM_LOG("HttpDelete: Response signature verified successfully");
				} catch (const std::exception &e) {
					conn_state.ClearSession();
					BoilstreamRethrowSafe("Response integrity check failed", e);
				}

				// Check if response is encrypted and decrypt if needed
				auto header_map = ExtractBoilstreamHeaders(response->headers);
				if (IsResponseEncrypted(header_map)) {
					BOILSTREAM_LOG("HttpDelete: Response is encrypted, decrypting...");
					try {
						uint16_t cipher_suite = ParseCipherSuite(header_map);
						response_body = DecryptResponse(response_body, current_session_key, cipher_suite);

					} catch (const std::exception &e) {
						BoilstreamRethrowSafe("Response decryption failed", e);
					}
				} else {
					BOILSTREAM_LOG("HttpDelete: Response is not encrypted (plaintext)");
				}
			}

			// Now check status code with decrypted response body
			// 4xx Client Errors (except 404) - fail fast, don't retry
			if (status_code >= 400 && status_code < 500 && status_code != 404) {
				BoilstreamThrowHttpStatus("HTTP DELETE failed", status_code);
			}

			// 5xx Server Errors - classify for retry decision
			if (status_code >= 500 && status_code < 600) {
				// 501 Not Implemented, 505 HTTP Version Not Supported - don't retry
				if (status_code == 501 || status_code == 505) {
					BoilstreamThrowHttpStatus("HTTP DELETE failed", status_code);
				}

				// 500, 502, 503, 504 - retryable server errors
				if (attempt < MAX_RETRIES) {
					last_error = "HTTP " + std::to_string(status_code) + " server error";
					continue; // Will retry with exponential backoff
				}
				// Fall through to throw after all retries
			}

			// Non-2xx status (except 404, including exhausted 5xx retries)
			if (status_code < 200 || (status_code >= 300 && status_code != 404)) {
				BoilstreamThrowHttpStatus("HTTP DELETE failed", status_code);
			}

			return; // Success
		}

		// All retries exhausted
		throw IOException("HTTP DELETE failed after " + std::to_string(MAX_RETRIES + 1) + " attempts: " + last_error);

	} catch (const std::exception &e) {
		BoilstreamRethrowSafe("HTTP DELETE failed", e);
	}
}

unique_ptr<SecretEntry> RestApiSecretStorage::StoreSecret(unique_ptr<const BaseSecret> secret,
                                                          OnCreateConflict on_conflict,
                                                          optional_ptr<CatalogTransaction> transaction) {
	auto owner = GetSecretOwner(transaction, true);
	auto state = owner.session;
	auto cache = owner.cache;
	if (!cache) throw IOException("A live connection is required to store a BoilStream secret");
	if (on_conflict == OnCreateConflict::ALTER_ON_CONFLICT) throw InvalidInputException("Unsupported secret conflict mode");
	const auto revision = cache->Revision();
	const auto name = secret->GetName();
	auto existing = cache->Get(name, true);
	if (existing) {
		if (on_conflict == OnCreateConflict::IGNORE_ON_CONFLICT) return nullptr;
		if (on_conflict == OnCreateConflict::ERROR_ON_CONFLICT) throw InvalidInputException("Secret already exists");
	}
	const auto bytes = SerializeSecret(*secret).size();
	// Remote writes do not establish credential expiry: refetch the authoritative
	// server response before using them. Explicit local secrets have no remote TTL.
	auto entry = BoilstreamSecretCache::Prepare(secret->Clone(),
	    state ? BoilstreamSecretCache::Time::min() : BoilstreamSecretCache::Time::max(), bytes);
	auto result = make_uniq<SecretEntry>(*entry.secret);
	cache->ValidatePut(entry, revision);
	if (state) WriteSecretWithState(*secret, on_conflict, *state, transaction);
	cache->Put(std::move(entry), revision);
	return result;
}

void RestApiSecretStorage::WriteSecret(const BaseSecret &secret, OnCreateConflict on_conflict) {
	// This method is called by the base class but we need connection state for authentication.
	// It should not be called directly - use StoreSecret instead which provides proper context.
	BOILSTREAM_LOG("WriteSecret: ERROR - called without connection state");
	throw InvalidInputException(
	    "WriteSecret called without connection state. Use StoreSecret with transaction instead.");
}

void RestApiSecretStorage::WriteSecretWithState(const BaseSecret &secret, OnCreateConflict on_conflict,
                                                BoilstreamConnectionState &conn_state, optional_ptr<CatalogTransaction> transaction) {

	// Check if endpoint is configured
	string url = conn_state.GetEndpointUrl();

	if (url.empty()) {
		BOILSTREAM_LOG("WriteSecretWithState: ERROR - endpoint is empty!");
		throw InvalidInputException("Boilstream endpoint not configured. Use PRAGMA "
		                            "boilstream_bootstrap_session('https://host/path/:TOKEN') to set it.");
	}

	// Serialize secret
	BOILSTREAM_LOG("WriteSecretWithState: serializing secret...");
	string secret_json = SerializeSecret(secret);

	// Prepare request body using yyjson (safe from injection)
	auto doc = yyjson_mut_doc_new(nullptr);
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);

	// Parse the secret JSON and add as object
	auto secret_doc = yyjson_read(secret_json.c_str(), secret_json.size(), 0);
	auto secret_root = yyjson_doc_get_root(secret_doc);
	auto secret_mut = yyjson_val_mut_copy(doc, secret_root);
	yyjson_mut_obj_add_val(doc, obj, "secret", secret_mut);
	yyjson_doc_free(secret_doc);

	yyjson_mut_obj_add_strcpy(doc, obj, "on_conflict",
	                          on_conflict == OnCreateConflict::REPLACE_ON_CONFLICT ? "replace" : "error");

	string body = SafeJsonSerialize(doc);
	yyjson_mut_doc_free(doc);

	// Make HTTP POST request with connection state for authentication
	HttpPostWithState(AppendPlatformParams(url, transaction), body, conn_state);
	BOILSTREAM_LOG("WriteSecretWithState: POST successful");
}

SecretMatch RestApiSecretStorage::LookupSecret(const string &path, const string &type,
                                               optional_ptr<CatalogTransaction> transaction) {
	if (StringUtil::Lower(type) == "quack" && path.find("/catalog/") != string::npos) {
		return LookupQuackSecret(path, transaction); // Managed scopes always fail closed.
	}
	auto cache = GetSecretCache(transaction);
	auto cached = LookupCachedSecret(path, type, cache);
	if (cached.HasMatch() || IsWasmMode()) return cached;
	FetchSecret(path, type, true, transaction, cache);
	if (GetSecretCache(transaction) != cache) return SecretMatch();
	return LookupCachedSecret(path, type, cache);
}

unique_ptr<SecretEntry> RestApiSecretStorage::GetSecretByName(
    const string &name, optional_ptr<CatalogTransaction> transaction) {
	auto cache = GetSecretCache(transaction);
	auto owned_entry = cache ? cache->Get(name) : nullptr;
	auto cached = owned_entry ? make_uniq<SecretEntry>(*owned_entry) : nullptr;
	if (cached || IsWasmMode()) return cached;
	FetchSecret(name, "", false, transaction, cache);
	if (GetSecretCache(transaction) != cache) return nullptr;
	auto entry = cache ? cache->Get(name) : nullptr;
	return entry ? make_uniq<SecretEntry>(*entry) : nullptr;
}

void RestApiSecretStorage::FetchSecret(const string &selector, const string &type, bool match,
                                       optional_ptr<CatalogTransaction> transaction,
                                       const shared_ptr<BoilstreamSecretCache> &expected_cache) {
	auto owner = GetSecretOwner(transaction);
	auto state = owner.session;
	auto cache = owner.cache;
	if (!state || !cache || cache != expected_cache || state->GetEndpointUrl().empty() || in_http_operation) return;
	BoilstreamConnectionState::SecretLookupGuard guard(*state);
	if (!guard.Acquired()) return;
	const auto revision = cache->Revision();
	auto doc = yyjson_mut_doc_new(nullptr);
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);
	yyjson_mut_obj_add_strcpy(doc, obj, match ? "path" : "name", selector.c_str());
	if (match) yyjson_mut_obj_add_strcpy(doc, obj, "type", StringUtil::Lower(type).c_str());
	bool expired = !match && cache->Get(selector, true) != nullptr;
	if (match) {
		for (auto &entry : cache->Snapshot(true)) {
			if (StringUtil::CIEquals(entry->secret->GetType(), type) &&
			    entry->secret->MatchScore(selector) != NumericLimits<int64_t>::Minimum()) { expired = true; break; }
		}
	}
	yyjson_mut_obj_add_bool(doc, obj, "expired", expired);
	string body = SafeJsonSerialize(doc);
	yyjson_mut_doc_free(doc);
	try {
		auto response = HttpPostWithState(AppendPlatformParams(state->GetEndpointUrl() +
		    (match ? "/match" : "/get"), transaction), body, *state);
		if (response.size() > BoilstreamSecretCache::MAX_ENTRY_BYTES) throw IOException("Oversized secret response");
		auto parsed = unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)>(
		    yyjson_read(response.c_str(), response.size(), 0), yyjson_doc_free);
		if (!parsed) return;
		auto root = yyjson_doc_get_root(parsed.get());
		if (!yyjson_is_obj(root)) return;
		auto expires = ParseExpiresAt(SafeGetStr(yyjson_obj_get(root, "expires_at")));
		if (expires == BoilstreamSecretCache::Time::min()) return;
		auto secret = DeserializeSecret(response, SecretManager::Get(db));
		if (!secret || (!match && !StringUtil::CIEquals(secret->GetName(), selector))) return;
		// The captured owner must still be current after network/deserialization.
		if (GetSession(transaction) != state || transaction->GetContext().IsInterrupted()) return;
		cache->Put(BoilstreamSecretCache::Prepare(std::move(secret), expires, response.size()), revision);
	} catch (...) {
		// Failed, malformed, expired or superseded requests cannot broaden access.
		// A still-fresh owned entry may be used by the caller; no global fallback.
	}
}

vector<SecretEntry> RestApiSecretStorage::AllSecrets(optional_ptr<CatalogTransaction> transaction) {
	return IsWasmMode() ? GetCachedSecrets(transaction) : FetchAllSecretsFromServer(transaction);
}

void RestApiSecretStorage::PublishSecretList(const string &response, BoilstreamConnectionState &state,
                                             uint64_t revision) {
	if (response.size() > BoilstreamSecretCache::MAX_BYTES) throw IOException("Oversized secret list");
	auto doc = unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)>(
	    yyjson_read(response.c_str(), response.size(), 0), yyjson_doc_free);
	if (!doc) throw IOException("Invalid secret list JSON");
	auto root = yyjson_doc_get_root(doc.get());
	if (!yyjson_is_arr(root) || yyjson_arr_size(root) > BoilstreamSecretCache::MAX_ENTRIES)
		throw IOException("Invalid secret list");
	BoilstreamSecretCache::Entries staged;
	size_t idx, max;
	yyjson_val *val;
	yyjson_arr_foreach(root, idx, max, val) {
		if (!yyjson_is_obj(val)) throw IOException("Invalid secret list entry");
		auto expires = ParseExpiresAt(SafeGetStr(yyjson_obj_get(val, "expires_at")));
		if (expires == BoilstreamSecretCache::Time::min()) throw IOException("Invalid secret expiry");
		auto encoded = unique_ptr<char, decltype(&free)>(yyjson_val_write(val, 0, nullptr), free);
		if (!encoded) throw IOException("Cannot serialize secret list entry");
		string json(encoded.get());
		if (json.size() > BoilstreamSecretCache::MAX_ENTRY_BYTES) throw IOException("Oversized secret list entry");
		auto secret = DeserializeSecret(json, SecretManager::Get(db));
		if (!secret) throw IOException("Invalid serialized secret");
		auto name = secret->GetName();
		auto entry = BoilstreamSecretCache::Prepare(std::move(secret), expires, json.size());
		if (!staged.emplace(name, std::move(entry)).second) throw IOException("Duplicate secret name");
	}
	// One complete validated response replaces the old snapshot, including deletions.
	state.secret_cache->Replace(std::move(staged), revision);
}

vector<SecretEntry> RestApiSecretStorage::FetchAllSecretsFromServer(
    optional_ptr<CatalogTransaction> transaction, shared_ptr<BoilstreamConnectionState> explicit_conn_state) {
	auto owner = GetSecretOwner(transaction);
	auto state = owner.session;
	if (explicit_conn_state && explicit_conn_state != state) throw IOException("Secret owner was superseded");
	auto cache = owner.cache;
	if (!state || !cache || state->GetEndpointUrl().empty() || in_http_operation ||
	    (!explicit_conn_state && cache->RecentlyFetched())) return CloneSecretSnapshot(cache);
	BoilstreamConnectionState::SecretLookupGuard guard(*state);
	if (!guard.Acquired()) return CloneSecretSnapshot(cache);
	CheckCatalogVersions(*state);
	const auto revision = cache->Revision();
	try {
		auto response = HttpGetWithState(AppendPlatformParams(state->GetEndpointUrl(), transaction), *state);
		if (GetSession(transaction) != state || transaction->GetContext().IsInterrupted())
			throw IOException("Secret fetch was superseded");
		PublishSecretList(response, *state, revision);
	} catch (...) {
		if (explicit_conn_state) throw;
		// Keep only this owner's previously validated, unexpired snapshot.
	}
	return CloneSecretSnapshot(cache);
}

vector<SecretEntry> RestApiSecretStorage::GetCachedSecrets(optional_ptr<CatalogTransaction> transaction) {
	return CloneSecretSnapshot(GetSecretCache(transaction));
}

void RestApiSecretStorage::RemoveSecret(const string &name, OnEntryNotFound on_entry_not_found) {
	// This override is kept for interface compatibility but the actual implementation
	// is in DropSecretByName which has access to connection state via transaction.
	// RemoveSecret is not directly called - DropSecretByName handles the HTTP DELETE.
}

void RestApiSecretStorage::DropSecretByName(const string &name, OnEntryNotFound on_entry_not_found,
                                            optional_ptr<CatalogTransaction> transaction) {
	auto owner = GetSecretOwner(transaction);
	auto state = owner.session;
	auto cache = owner.cache;
	if (!cache) {
		if (on_entry_not_found == OnEntryNotFound::THROW_EXCEPTION) throw CatalogException("Secret not found");
		return;
	}
	const auto revision = cache->Revision();
	if (state) {
		if (state->GetEndpointUrl().empty()) throw IOException("Secret endpoint is not configured");
		// HTTP failure must leave the last valid cache untouched, even for IF EXISTS.
		HttpDelete(AppendPlatformParams(state->GetEndpointUrl() + "/" + StringUtil::URLEncode(name), transaction), *state);
	} else if (!cache->Get(name, true) && on_entry_not_found == OnEntryNotFound::THROW_EXCEPTION) {
		throw CatalogException("Secret not found");
	}
	cache->Remove(name, revision);
}

case_insensitive_map_t<RestApiSecretStorage::CatalogVersionInfo>
RestApiSecretStorage::FetchCatalogVersions(BoilstreamConnectionState &conn_state) {
	case_insensitive_map_t<CatalogVersionInfo> versions;

	// Guard: Check if we have a valid session before making HTTP calls
	// This prevents crashes when HTTP infrastructure isn't available
	{
		lock_guard<mutex> lock(conn_state.session_lock);
		if (conn_state.access_token.empty()) {
			BOILSTREAM_LOG("FetchCatalogVersions: No active session, skipping version check");
			return versions;
		}
	}

	string base_url = conn_state.GetEndpointUrl();

	if (base_url.empty()) {
		return versions;
	}

	// Use the sibling route protected by the server's OPAQUE middleware.
	// An unregistered path spends the client's sequence without advancing the
	// server's sequence, causing the next authenticated request to be rejected.
	auto pos = base_url.rfind("/secrets");
	if (pos == string::npos || pos + string("/secrets").size() != base_url.size()) {
		return versions;
	}
	string url = base_url.substr(0, pos) + "/catalog-versions";

	string response;
	try {
		response = HttpGetWithState(url, conn_state);
	} catch (const std::exception &e) {
		return versions;
	} catch (...) {
		BOILSTREAM_LOG("FetchCatalogVersions: HTTP request failed with unknown error");
		return versions;
	}

	// Parse nested structure: {"catalogs": {"uuid": {"version": 3, "catalog_name": "name"}, ...}}
	auto doc = yyjson_read(response.c_str(), response.size(), 0);
	if (!doc) {
		return versions;
	}

	auto root = yyjson_doc_get_root(doc);
	auto catalogs_obj = yyjson_obj_get(root, "catalogs");
	if (!catalogs_obj || !yyjson_is_obj(catalogs_obj)) {
		yyjson_doc_free(doc);
		return versions;
	}

	yyjson_obj_iter iter;
	yyjson_obj_iter_init(catalogs_obj, &iter);
	yyjson_val *key, *val;
	while ((key = yyjson_obj_iter_next(&iter))) {
		val = yyjson_obj_iter_get_val(key);
		if (!yyjson_is_obj(val)) {
			continue;
		}

		auto version_val = yyjson_obj_get(val, "version");
		auto name_val = yyjson_obj_get(val, "catalog_name");

		if (version_val && yyjson_is_uint(version_val) && name_val && yyjson_is_str(name_val)) {
			string catalog_name = SafeGetStr(name_val);
			string catalog_key = SafeGetStr(key);
			if (!catalog_name.empty() && !catalog_key.empty()) {
				CatalogVersionInfo info;
				info.version = yyjson_get_uint(version_val);
				info.catalog_name = catalog_name;
				versions[catalog_key] = info;
			}
		}
	}

	yyjson_doc_free(doc);

	return versions;
}

// ---------------------------------------------------------------------------
// Quack auto-vend (Phase 2.2)
//
// When the user runs `ATTACH 'quack:server-host'` after `LOAD boilstream`,
// DuckDB's secret manager calls LookupSecret with a catalog-qualified managed
// scope. We intercept that, hit the BoilStream server's dedicated credential
// endpoint, and materialise a KeyValueSecret holding the
// token, endpoint, canonical scope, and public server trust. The user never
// types CREATE SECRET or handles transport credentials directly.
//
// The endpoint is GET /secrets/quack/credentials. The request and response use
// the existing OPAQUE secrets session; the JWT inside is signed server-side.
// The response shape is:
//
//   { "token": "<JWT>", "expires_at": "<RFC3339>", "endpoint": "<host:port>",
//     "catalog_id": "<uuid>", "storage_owner_tenant_id": <u32>,
//     "catalog_group": "<group>", "server_ca_pem": "..." }
//
// We treat the JWT as opaque — server-side bridge verifies it.
// ---------------------------------------------------------------------------
static bool ParseManagedCatalogSecretScope(const string &path, string &catalog_id) {
	static const string marker = "/catalog/";
	auto marker_pos = path.rfind(marker);
	if (marker_pos == string::npos || marker_pos + marker.size() >= path.size()) {
		return false;
	}
	const auto endpoint_scope = path.substr(0, marker_pos);
	catalog_id = path.substr(marker_pos + marker.size());
	if (endpoint_scope.compare(0, 6, "quack:") != 0 || endpoint_scope.size() == 6 ||
	    endpoint_scope.find('/', 6) != string::npos || catalog_id.find('/') != string::npos) {
		return false;
	}
	hugeint_t parsed_catalog_id;
	return UUID::FromString(catalog_id, parsed_catalog_id, true) && UUID::ToString(parsed_catalog_id) == catalog_id;
}

ManagedCatalogCredentialEnvelope
RestApiSecretStorage::FetchManagedCatalogCredential(const string &catalog_id, BoilstreamConnectionState &conn_state,
                                                    optional_ptr<CatalogTransaction> transaction) {
	string base_url = conn_state.GetEndpointUrl();
	if (base_url.empty()) {
		throw IOException("Managed DuckDB credential vending requires an active Boilstream endpoint");
	}
	string url = ManagedCatalogCredentialUrl(base_url, catalog_id);
	url = AppendPlatformParams(url, transaction);
	const auto response = HttpGetWithState(url, conn_state);
	ManagedCatalogCredentialEnvelope credential;
	if (!ParseManagedCatalogCredentialEnvelope(response, credential)) {
		throw IOException("Managed DuckDB credential response is incomplete or malformed");
	}
	if (credential.catalog_id != catalog_id) {
		throw IOException("Managed DuckDB credential response catalog does not match the requested catalog");
	}
	// A capability may intentionally expire in less than the cache's 30-second
	// refresh window. A freshly vended credential remains usable until its
	// authoritative expiry; Quack enforces that same boundary during execution.
	if (IsManagedCatalogCredentialExpiredAt(credential.expires_at, std::chrono::system_clock::now())) {
		throw IOException("Managed DuckDB credential response is expired");
	}
	return credential;
}

void RestApiSecretStorage::CacheManagedCatalogCredential(const string &scope_path,
                                                         const ManagedCatalogCredentialEnvelope &credential,
                                                         BoilstreamConnectionState &conn_state) {
	const string secret_name = "__quack__" + scope_path;
	conn_state.StoreManagedCatalogCredential(scope_path, credential);
	StoreExpiration(secret_name, credential.expires_at, conn_state);
}

SecretMatch RestApiSecretStorage::BuildManagedCatalogSecretMatch(const string &scope_path,
                                                                 const ManagedCatalogCredentialEnvelope &credential) {
	const string secret_name = "__quack__" + scope_path;
	vector<string> scope {scope_path};
	auto secret = make_uniq<KeyValueSecret>(scope, "quack", "config", secret_name);
	secret->secret_map["token"] = Value(credential.token);
	secret->secret_map["endpoint"] = Value(credential.endpoint);
	secret->secret_map["catalog_id"] = Value(credential.catalog_id);
	secret->secret_map["storage_owner_tenant_id"] = Value::UINTEGER(credential.storage_owner_tenant_id);
	secret->secret_map["catalog_group"] = Value(credential.catalog_group);
	secret->secret_map["server_ca_pem"] = Value(credential.server_ca_pem);
	secret->redact_keys.insert("token");
	unique_ptr<const BaseSecret> immutable_secret = std::move(secret);
	SecretEntry entry(std::move(immutable_secret));
	auto best_match = SecretMatch();
	return SelectBestMatch(entry, scope_path, tie_break_offset, best_match);
}

ManagedCatalogCredentialEnvelope
RestApiSecretStorage::VendManagedCatalogCredential(const string &catalog_id,
                                                   optional_ptr<CatalogTransaction> transaction) {
	hugeint_t parsed_catalog_id;
	if (!UUID::FromString(catalog_id, parsed_catalog_id, true) || UUID::ToString(parsed_catalog_id) != catalog_id) {
		throw InvalidInputException("Managed DuckDB catalog_id must be a canonical UUID");
	}
	auto conn_state = GetSession(transaction);
	if (!conn_state) {
		throw IOException("Managed DuckDB credential vending requires an active Boilstream session");
	}
	BoilstreamConnectionState::SecretLookupGuard guard(*conn_state);
	if (!guard.Acquired()) {
		throw IOException("Managed DuckDB credential vending was blocked by a recursive secret lookup");
	}
	auto credential = FetchManagedCatalogCredential(catalog_id, *conn_state, transaction);
	const string scope_path = ManagedCatalogSecretScope(credential.endpoint, catalog_id);
	CacheManagedCatalogCredential(scope_path, credential, *conn_state);
	return credential;
}

SecretMatch RestApiSecretStorage::LookupQuackSecret(const string &path, optional_ptr<CatalogTransaction> transaction) {

	// Need an active session for authenticated GET — quack credentials are gated
	// behind the same OPAQUE-authenticated REST API as everything else.
	auto conn_state = GetSession(transaction);
	if (!conn_state) {
		BOILSTREAM_LOG("LookupQuackSecret EXIT: no connection state");
		return SecretMatch();
	}

	// Use the same recursion guard as the main LookupSecret path. Without this,
	// the inner HttpGetWithState below could re-enter LookupSecret via httpfs.
	std::optional<BoilstreamConnectionState::SecretLookupGuard> guard;
	guard.emplace(*conn_state);
	if (!guard->Acquired()) {
		BOILSTREAM_LOG("LookupQuackSecret EXIT: recursion guard blocked");
		return SecretMatch();
	}

	// Only the catalog-qualified path is eligible for managed auto-vend. A
	// plain endpoint remains available to an explicitly user-supplied Quack
	// secret but cannot accidentally obtain an unscoped product credential.
	string catalog_id;
	if (!ParseManagedCatalogSecretScope(path, catalog_id)) {
		BOILSTREAM_LOG("LookupQuackSecret EXIT: missing canonical catalog scope");
		return LookupCachedSecret(path, "quack", GetSecretCache(transaction));
	}

	// Managed credentials are cached in the authenticated connection state,
	// never DuckDB's catalog-global secret set. This prevents two tenants in
	// one process from replacing each other's capability or server trust.
	const string secret_name = "__quack__" + path;

	// Check local cache: if we have a non-near-expiry copy, return it.
	// IsExpired uses a 5-minute buffer (good for long-lived S3 creds) — too
	// aggressive for short-lived JWTs. So we do our own 30s window check
	// against the recorded expires_at and only treat as miss when within 30s.
	ManagedCatalogCredentialEnvelope credential;
	if (conn_state->TryGetManagedCatalogCredential(path, credential)) {
		std::chrono::system_clock::time_point expires_at;
		{
			lock_guard<mutex> lock(conn_state->expiration_lock);
			auto it = conn_state->secret_expiration.find(secret_name);
			if (it != conn_state->secret_expiration.end()) {
				expires_at = it->second;
			}
		}
		// If we have no expiry record, treat as miss (re-vend). Otherwise check
		// the 30s near-expiry window. Mirrors RefreshCatalogCredentials' force-
		// expire-by-setting-time semantics, but as a read-side check.
		if (expires_at != std::chrono::system_clock::time_point()) {
			auto now = std::chrono::system_clock::now();
			if (expires_at > now + std::chrono::seconds(30)) {
				BOILSTREAM_LOG("LookupQuackSecret EXIT: cached, fresh (>30s remaining)");
				return BuildManagedCatalogSecretMatch(path, credential);
			}
			BOILSTREAM_LOG("LookupQuackSecret: cached but near-expiry, re-vending");
		}
	}

	try {
		credential = FetchManagedCatalogCredential(catalog_id, *conn_state, transaction);
	} catch (const std::exception &e) {
		return SecretMatch();
	} catch (...) {
		BOILSTREAM_LOG("LookupQuackSecret EXIT: HTTP failure (unknown)");
		return SecretMatch();
	}
	CacheManagedCatalogCredential(path, credential, *conn_state);

	return BuildManagedCatalogSecretMatch(path, credential);
}

void RestApiSecretStorage::RefreshCatalogCredentials(const string &catalog_name,
                                                     BoilstreamConnectionState &conn_state) {

	conn_state.secret_cache->SetExpiration(catalog_name, std::chrono::system_clock::time_point::min());

	// Force expiration by setting expires_at to past
	// The secret name matches the catalog_name from the version response
	{
		lock_guard<mutex> lock(conn_state.expiration_lock);
		conn_state.secret_expiration[catalog_name] = std::chrono::system_clock::time_point::min();
	}

	// The next LookupSecret or GetSecretByName call will see IsExpired()=true
	// and fetch fresh credentials with expired=true flag, triggering server
	// to return new credentials with updated master IP
}

void RestApiSecretStorage::CheckCatalogVersions(BoilstreamConnectionState &conn_state) {
	// Rate limit: only check every 60 seconds
	auto now = std::chrono::system_clock::now();
	{
		lock_guard<mutex> lock(conn_state.version_lock);
		// Compare timestamps directly: subtracting the initial minimum sentinel overflows.
		if (conn_state.last_version_check > now - std::chrono::seconds(VERSION_CHECK_INTERVAL_SECONDS)) {
			return; // Too soon, skip check
		}
		conn_state.last_version_check = now;
	}

	BOILSTREAM_LOG("CheckCatalogVersions: Checking for version changes");

	// Fetch current versions from server
	auto new_versions = FetchCatalogVersions(conn_state);
	if (new_versions.empty()) {
		return; // Request failed or no catalogs
	}

	// Collect catalogs that need refresh (to avoid holding lock while refreshing)
	vector<string> catalogs_to_refresh;

	// Compare with cached versions and identify changed catalogs
	{
		lock_guard<mutex> lock(conn_state.version_lock);
		for (const auto &entry : new_versions) {
			const auto &catalog_id = entry.first;
			const auto &new_info = entry.second;
			auto it = conn_state.catalog_versions.find(catalog_id);
			if (it != conn_state.catalog_versions.end()) {
				if (new_info.version > it->second.version) {
					catalogs_to_refresh.push_back(new_info.catalog_name);
				}
			}
			conn_state.catalog_versions[catalog_id] = new_info;
		}
	}

	// Refresh credentials for changed catalogs (outside version_lock)
	for (const auto &catalog_name : catalogs_to_refresh) {
		RefreshCatalogCredentials(catalog_name, conn_state);
	}
}

} // namespace duckdb
