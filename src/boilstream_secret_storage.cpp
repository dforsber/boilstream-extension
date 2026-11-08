#include "boilstream_auth_response.hpp"
#include "boilstream_security.hpp"
#include "boilstream_json.hpp"
#include "boilstream_credential_stream.hpp"
#include "boilstream_http_cleanup.hpp"
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

#include "boilstream_diagnostics.hpp"
#define BOILSTREAM_LOG(event) duckdb::BoilstreamLogEvent("" event)

// yyjson is namespaced by DuckDB; confine its C API aliases to this implementation.
using namespace duckdb_yyjson; // NOLINT(google-build-using-namespace)

namespace duckdb {

static bool ParseManagedCatalogSecretScope(const string &path, string &catalog_id);

// Serialize a yyjson mutable doc to string, throwing on allocation failure.
static string SafeJsonSerialize(yyjson_mut_doc *doc) {
	boilstream::JsonArena writer_arena;
	size_t length = 0;
	auto json_str = yyjson_mut_write_opts(doc, 0, &writer_arena.Allocator(), &length, nullptr);
	if (!json_str) {
		throw IOException("Failed to serialize JSON document");
	}
	string result(json_str, length);
	return result;
}

//===----------------------------------------------------------------------===//
// Security Limits - Prevent DoS via oversized payloads
//===----------------------------------------------------------------------===//
// Maximum sizes to prevent memory exhaustion attacks from malicious servers

//! Maximum JSON response size from server (10MB)
static constexpr size_t MAX_JSON_RESPONSE_SIZE = 10ULL * 1024 * 1024;

//! Maximum secret data size (1MB) - serialized secret payload
static constexpr size_t MAX_SECRET_DATA_SIZE = 1ULL * 1024 * 1024;

//! Maximum OPAQUE protocol message size (64KB) - registration/login messages
static constexpr size_t MAX_OPAQUE_MESSAGE_SIZE = 64ULL * 1024;

// Thread-local guard to prevent recursive lookups during HTTP operations
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables) -- per-thread recursion guard
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
//! Preserve embedded NUL bytes so field validators see the complete value.
static inline string SafeGetStr(yyjson_val *val) {
	if (!val) {
		return "";
	}
	const char *str = yyjson_get_str(val);
	return str ? string(str, yyjson_get_len(val)) : "";
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
	boilstream::JsonArena doc_arena;
	auto doc = doc_arena.Read(json.c_str(), json.size(), 0);
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
	       QuoteManagedAttachIdentifier(alias) + " (TYPE quack, SECRET '" +
	       EscapeManagedAttachLiteral("__quack__" +
	                                  ManagedCatalogSecretScope(credential.endpoint, credential.catalog_id)) +
	       "', CATALOG_ID '" + EscapeManagedAttachLiteral(credential.catalog_id) + "', TENANT_ID '" +
	       std::to_string(credential.storage_owner_tenant_id) + "', CATALOG_GROUP '" +
	       EscapeManagedAttachLiteral(credential.catalog_group) +
	       "', DISABLE_SSL false, HTTP_VERSION '1.1', CATALOG_MODE 'product', READ_ONLY)";
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
    // Tie-break offset 7: below the connection-scoped storage (5), so a secret a user created for this
    // connection wins a tie, but ahead of the temporary (10) and local file (20) storages.
    : CatalogSetSecretStorage(db_p, "boilstream", 7), endpoint_url(endpoint_url_p) {
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
		return GetSessionForContext(transaction->GetContext());
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
	return GetSessionForConnection(context.GetConnectionId());
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
		if (conn_it == connection_session_keys_.end()) {
			return;
		}
		auto it = sessions_.find(conn_it->second);
		if (it != sessions_.end()) {
			retired = it->second;
			// Reject an exchange already in flight before dropping the registry
			// lock. Credential/cache destruction stays outside the global lock.
			retired->authentication_generation.fetch_add(1);
		}
	}
	if (retired) {
		retired->ClearSession();
	}
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

bool RestApiSecretStorage::PerformOpaqueLoginCommon(const string &password, BoilstreamConnectionState &conn_state) {
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
	boilstream::WipeOnExit wipe_password_hash(password_hash);
	opaque_client_sha256(reinterpret_cast<const uint8_t *>(password.c_str()), password.size(), password_hash);

	// Convert hash to lowercase hex string (64 characters)
	string user_id;
	boilstream::WipeOnExit wipe_user_id(user_id);
	user_id.reserve(64);
	const char *hex_chars = "0123456789abcdef";
	for (size_t i = 0; i < 32; i++) {
		unsigned char byte = static_cast<unsigned char>(password_hash[i]);
		user_id += hex_chars[(byte >> 4) & 0xF];
		user_id += hex_chars[byte & 0xF];
	}

	// Step 1: Client starts login
	auto login_start = OpaqueClientWrapper::LoginStart(password);
	std::unique_ptr<LoginState, decltype(&opaque_free_login_state)> owned_login_state(login_start.state,
	                                                                                  opaque_free_login_state);
	BOILSTREAM_LOG("PerformOpaqueLogin: credential request generated");

	// Step 2: Send CredentialRequest to server with user_id
	string login_url = url + "/auth/api/opaque-login-start";

	boilstream::JsonArena doc_arena;
	auto doc = doc_arena.New();
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);
	yyjson_mut_obj_add_strcpy(doc, obj, "user_id", user_id.c_str());
	yyjson_mut_obj_add_strcpy(doc, obj, "credential_request", login_start.credential_request_base64.c_str());

	string body = SafeJsonSerialize(doc);
	boilstream::WipeOnExit wipe_body(body);
	yyjson_mut_doc_free(doc);

	string response;
	boilstream::WipeOnExit wipe_response(response);
	try {
		response = HttpPostWithState(login_url, body, conn_state);
	} catch (const std::exception &e) {
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.is_exchanging = false;
		BoilstreamRethrowSafe("OPAQUE login failed (server request)", e);
	}

	// The verified body must still satisfy the OPAQUE application schema.
	BoilstreamAuthResponse start_response(response);
	start_response.RequireSuccess();
	string credential_response_base64 = start_response.Text("credential_response", 64ULL * 1024);
	boilstream::WipeOnExit wipe_credential_response(credential_response_base64);
	string state_id = start_response.Text("state_id");
	boilstream::WipeOnExit wipe_state_id(state_id);

	// Step 3: Client finishes login
	auto login_finish = OpaqueClientWrapper::LoginFinish(owned_login_state.release(), // consumed by this call
	                                                     credential_response_base64);
	BOILSTREAM_LOG("PerformOpaqueLogin: credential finalization generated");

	// Keep the new key private until the server confirms authentication. The
	// installation-pinned channel already protects the finalization exchange.
	auto session_key_decoded = Blob::FromBase64(string_t(login_finish.session_key_base64));
	boilstream::WipeOnExit wipe_session_key_decoded(session_key_decoded);

	// Step 4: Send CredentialFinalization to server
	string finalize_url = url + "/auth/api/opaque-login-finish";

	boilstream::JsonArena final_doc_arena;
	auto final_doc = final_doc_arena.New();
	auto final_obj = yyjson_mut_obj(final_doc);
	yyjson_mut_doc_set_root(final_doc, final_obj);

	yyjson_mut_obj_add_strncpy(final_doc, final_obj, "state_id", state_id.data(), state_id.size());

	yyjson_mut_obj_add_strcpy(final_doc, final_obj, "credential_finalization",
	                          login_finish.credential_finalization_base64.c_str());

	string final_body = SafeJsonSerialize(final_doc);
	boilstream::WipeOnExit wipe_final_body(final_body);
	yyjson_mut_doc_free(final_doc);

	// Use HttpPostWithState with out_headers parameter to capture X-Boilstream-Session-Resumption
	HTTPHeaders final_response_headers(db);
	boilstream::HeaderCleanup wipe_headers_final_response_headers(final_response_headers);
	string final_response;
	boilstream::WipeOnExit wipe_final_response(final_response);
	try {
		final_response = HttpPostWithState(finalize_url, final_body, conn_state, &final_response_headers);
	} catch (const std::exception &e) {
		lock_guard<mutex> lock(conn_state.session_lock);
		BoilstreamConnectionState::SecureZeroVector(conn_state.session_key);
		conn_state.session_key.clear();
		conn_state.is_exchanging = false;
		BoilstreamRethrowSafe("OPAQUE login failed (finalization)", e);
	}

	BoilstreamAuthResponse finalization(final_response);
	finalization.RequireSuccess();
	string new_access_token = finalization.OpaqueAccessToken();
	boilstream::WipeOnExit wipe_new_access_token(new_access_token);
	const auto new_expires_at = finalization.SessionExpiry(std::chrono::system_clock::now());
	string new_region = finalization.Text("region");

	// Store session state atomically
	{
		lock_guard<mutex> lock(conn_state.session_lock);
		conn_state.access_token = new_access_token;

		// Store OPAQUE session_key (convert string to vector<uint8_t>)
		conn_state.session_key.assign(session_key_decoded.begin(), session_key_decoded.end());

		// Derive the refresh credential with the production HKDF-Expand FFI.
		// Using Rust crypto implementation (works on all platforms including WASM)
		uint8_t derived_key[32];
		boilstream::WipeOnExit wipe_derived_key(derived_key);
		int result = opaque_client_derive_refresh_token(conn_state.session_key.data(), conn_state.session_key.size(),
		                                                derived_key);
		if (result != 0) {
			throw IOException("Failed to derive refresh token");
		}
		conn_state.refresh_token.assign(derived_key, derived_key + 32);

		// Store region from server response
		conn_state.region = new_region;

		conn_state.token_expires_at = new_expires_at;
		conn_state.is_exchanging = false;
	}

	// These synthetic headers contain only metadata from the verified body.
	return final_response_headers.GetHeaderValue("X-Boilstream-Session-Resumption") == "enabled";
}

// ClientContext retains its database until after registered state destruction,
// so the database-owned storage outlives this connection cleanup callback.
class BoilstreamSessionCleanup : public ClientContextState {
public:
	BoilstreamSessionCleanup(RestApiSecretStorage &storage, idx_t connection_id)
	    : storage(storage), connection_id(connection_id) {
	}
	~BoilstreamSessionCleanup() override {
		storage.ClearConnectionMapping(connection_id);
	}

private:
	RestApiSecretStorage &storage;
	idx_t connection_id;
};

// NOLINTNEXTLINE(performance-unnecessary-value-param) -- retain ownership through callbacks and cache replacement
void RestApiSecretStorage::PublishSession(ClientContext &context, shared_ptr<BoilstreamConnectionState> pending,
                                          const shared_ptr<BoilstreamConnectionState> &previous, uint64_t generation,
                                          bool supports_resumption) {
	const auto connection_id = context.GetConnectionId();
	context.registered_state->GetOrCreate<BoilstreamSessionCleanup>("boilstream_session_cleanup", *this, connection_id);
	const auto key = "@connection:" + std::to_string(connection_id);
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
			if (found != sessions_.end()) {
				current = found->second;
			}
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
	if (previous) {
		previous->secret_cache->Close();
	}
}

void RestApiSecretStorage::PerformOpaqueLogin(ClientContext &context, const string &password, const string &token_hash,
                                              const string &endpoint) {
	auto previous = GetSessionForConnection(context.GetConnectionId());
	auto generation = previous ? previous->authentication_generation.load() : 0;
	auto pending = make_shared_ptr<BoilstreamConnectionState>(endpoint);
	pending->protocol = BoilstreamProtocol::Create(context, endpoint);
	pending->bootstrap_token_hash = token_hash;
	auto supports_resumption = PerformOpaqueLoginCommon(password, *pending);
	PublishSession(context, std::move(pending), previous, generation, supports_resumption);
}

void RestApiSecretStorage::PerformOpaqueResume(ClientContext &context) {
	auto previous = GetSessionForContext(context);
	if (!previous || context.IsInterrupted()) {
		throw IOException("Session resumption requires an authenticated connection; log in again");
	}
	auto pending = make_shared_ptr<BoilstreamConnectionState>(previous->GetEndpointUrl());
	if (!previous->protocol) {
		throw IOException("Missing application channel");
	}
	pending->protocol = previous->protocol->Fresh();
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
		~PasswordGuard() {
			BoilstreamConnectionState::SecureZeroString(value);
		}
	} password_guard {password};
	// A failed exchange leaves the published session intact. The pending state
	// owns the same authority and identity; it cannot borrow another connection.
	auto supports_resumption = PerformOpaqueLoginCommon(password, *pending);
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
	if (retired) {
		retired->secret_cache->Close();
	}
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

string RestApiSecretStorage::SerializeSecret(const BaseSecret &secret) {
	// Serialize secret to base64-encoded binary format
	boilstream::CredentialWriteStream stream;
	BinarySerializer serializer(stream);
	serializer.Begin();
	secret.Serialize(serializer);
	serializer.End();

	auto data = stream.GetData();
	string data_str(reinterpret_cast<const char *>(data), stream.GetPosition());
	boilstream::WipeOnExit wipe_data_str(data_str);
	auto encoded = Blob::ToBase64(string_t(data_str));
	boilstream::WipeOnExit wipe_encoded(encoded);

	// Preserve exact metadata bytes, including embedded zeroes. The binary
	// secret retains them too; truncating only JSON changes identity/scope.
	// Use yyjson rather than interpolating values into JSON.
	boilstream::JsonArena doc_arena;
	auto doc = doc_arena.New();
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);

	const auto &name = secret.GetName().GetIdentifierName();
	const auto &type = secret.GetType().GetIdentifierName();
	const auto &provider = secret.GetProvider().GetIdentifierName();
	yyjson_mut_obj_add_strncpy(doc, obj, "name", name.data(), name.size());
	yyjson_mut_obj_add_strncpy(doc, obj, "type", type.data(), type.size());
	yyjson_mut_obj_add_strncpy(doc, obj, "provider", provider.data(), provider.size());

	// Add scope array
	auto scope_arr = yyjson_mut_arr(doc);
	auto &scope = secret.GetScope();
	for (idx_t i = 0; i < scope.size(); i++) {
		yyjson_mut_arr_add_strncpy(doc, scope_arr, scope[i].data(), scope[i].size());
	}
	yyjson_mut_obj_add_val(doc, obj, "scope", scope_arr);

	yyjson_mut_obj_add_strcpy(doc, obj, "data", encoded.c_str());

	// BaseSecret carries no authoritative credential deadline. Missing expiry
	// means fetch again for each use, never a guessed or unlimited lifetime.
	yyjson_mut_obj_add_null(doc, obj, "expires_at");

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
	boilstream::JsonArena doc_arena;
	auto doc = doc_arena.Read(json_data.c_str(), json_data.size(), 0);
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
	boilstream::WipeOnExit wipe_encoded(encoded);
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
		boilstream::WipeOnExit wipe_decoded(decoded);
		MemoryStream stream(reinterpret_cast<data_ptr_t>(decoded.data()), decoded.size());
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
	if (result != TimestampCastResult::SUCCESS || !has_offset || timezone.GetSize() != 0 || !parsed.IsFinite()) {
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

std::optional<BoilstreamSecretCache::Time> RestApiSecretStorage::ParseSecretExpiry(yyjson_val *root) {
	auto value = yyjson_obj_get(root, "expires_at");
	if (!value || yyjson_is_null(value)) {
		return std::nullopt;
	}
	if (!yyjson_is_str(value)) {
		throw IOException("Invalid secret response expiry");
	}
	const auto expires = ParseExpiresAt(string(yyjson_get_str(value), yyjson_get_len(value)));
	if (expires == BoilstreamSecretCache::Time::min()) {
		throw IOException("Invalid secret response expiry");
	}
	return expires;
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
	if (generic_expiry != BoilstreamSecretCache::Time::min()) {
		return generic_expiry;
	}
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

string RestApiSecretStorage::AppendPlatformParams(const string &url) {
	if (IsWasmMode()) {
		return url + (url.find('?') == string::npos ? "?platform=wasm" : "&platform=wasm");
	}
	return url;
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
	uint64_t output_id = 0;
	unique_ptr<BoilstreamRegistrationOutput> output;
	bool bound = false, ready = false, busy = false, verifying = false;
	string base_url, email, session_token, totp_uri;
	shared_ptr<BoilstreamProtocol> protocol;
	void ClearOutput() {
		output.reset();
		output_id = 0;
	}
	void ClearEnrollment() {
		if (protocol) {
			protocol->Close();
			protocol.reset();
		}
		generation = 0;
		ready = busy = verifying = false;
		for (auto value : {&base_url, &email, &session_token, &totp_uri}) {
			BoilstreamConnectionState::SecureZeroString(*value);
			value->clear();
		}
	}
	void Reset() {
		if (protocol) {
			protocol->Close();
			protocol.reset();
		}
		ClearOutput();
		generation = 0;
		authentication.reset();
		had_authentication = false;
		authentication_generation = 0;
		bound = ready = busy = verifying = false;
		for (auto value : {&base_url, &email, &session_token, &totp_uri}) {
			BoilstreamConnectionState::SecureZeroString(*value);
			value->clear();
		}
	}
	~BoilstreamRegistrationContext() override {
		Reset();
	}
	void QueryBegin(ClientContext &context) override {
		const auto current_auth = storage.GetSessionForConnection(context.GetConnectionId());
		lock_guard<mutex> guard(lock);
		if (bound && (!MatchesAuthentication(current_auth) || context.IsInterrupted())) {
			Reset();
		}
	}
	void QueryEnd(ClientContext &context, optional_ptr<ErrorData> error) override {
		// Executor::PushError also sets interrupted for ordinary query failures.
		// Only cancellation retires a pending result; a stale query must not erase
		// its replacement. Taken payloads are wiped by the executing query's owner.
		if ((error && error->Type() == ExceptionType::INTERRUPT) || (!error && context.IsInterrupted())) {
			lock_guard<mutex> guard(lock);
			Reset();
		}
	}
	BoilstreamRegistrationSnapshot Snapshot() const {
		return {generation, base_url, email, session_token, totp_uri, protocol};
	}
	void Check(uint64_t expected) const {
		if (!bound || !busy || generation != expected || expected == 0) {
			throw IOException("Registration operation was interrupted or superseded");
		}
	}
};

// IDs carry no identity or credentials. Never reuse an operation ID, including
// across connections, so a foreign or delayed completion cannot match a lease.
static uint64_t NextRegistrationOperation() {
	static std::atomic<uint64_t> next {1};
	auto value = next.load(std::memory_order_relaxed);
	do {
		if (value == NumericLimits<uint64_t>::Maximum()) {
			throw IOException("Registration operation limit reached");
		}
	} while (!next.compare_exchange_weak(value, value + 1, std::memory_order_relaxed));
	return value;
}

shared_ptr<BoilstreamRegistrationContext> RestApiSecretStorage::RegistrationOwner(ClientContext &context, bool create) {
	if (&DatabaseInstance::GetDatabase(context) != &db) {
		throw IOException("Registration belongs to a different database");
	}
	auto owner =
	    create ? context.registered_state->GetOrCreate<BoilstreamRegistrationContext>("boilstream_registration", *this)
	           : context.registered_state->Get<BoilstreamRegistrationContext>("boilstream_registration");
	const auto current_auth = GetSessionForConnection(context.GetConnectionId());
	if (owner) {
		lock_guard<mutex> guard(owner->lock);
		if (owner->bound && (!owner->MatchesAuthentication(current_auth) || context.IsInterrupted())) {
			owner->Reset();
		}
	}
	if (context.IsInterrupted()) {
		throw IOException("Registration was interrupted");
	}
	return owner;
}

static bool ValidRegistrationField(const string &value, size_t limit) {
	if (value.empty() || value.size() > limit) {
		return false;
	}
	for (unsigned char c : value) {
		if (c < 32 || c == 127) {
			return false;
		}
	}
	return true;
}

BoilstreamRegistrationSnapshot RestApiSecretStorage::BeginRegistration(ClientContext &context, const string &base_url,
                                                                       const string &email) {
	if (!ValidRegistrationField(base_url, 4096) || !ValidRegistrationField(email, 320)) {
		throw InvalidInputException("Invalid registration authority or account length");
	}
	auto owner = RegistrationOwner(context, true);
	const auto current_auth = GetSessionForConnection(context.GetConnectionId());
	// Allocate identity copies before invalidating any ready registration.
	string new_base = base_url, new_email = email;
	lock_guard<mutex> guard(owner->lock);
	if (owner->busy) {
		throw IOException("A registration operation is already in progress for this connection");
	}
	if (!owner->ready || owner->base_url != base_url || owner->email != email) {
		owner->Reset();
		owner->protocol = BoilstreamProtocol::Create(context, base_url);
		owner->base_url.swap(new_base);
		owner->email.swap(new_email);
		owner->bound = true;
		owner->authentication = current_auth;
		owner->had_authentication = bool(current_auth);
		owner->authentication_generation = current_auth ? current_auth->authentication_generation.load() : 0;
	}
	owner->ClearOutput();
	auto snapshot = owner->Snapshot(); // A failed allocation must not strand busy=true.
	snapshot.generation = NextRegistrationOperation();
	owner->generation = snapshot.generation;
	owner->verifying = false;
	owner->busy = true;
	return snapshot;
}

BoilstreamRegistrationSnapshot RestApiSecretStorage::BeginMfaVerification(ClientContext &context) {
	auto owner = RegistrationOwner(context, false);
	if (!owner) {
		throw IOException("No registration state found for this connection; register first");
	}
	lock_guard<mutex> guard(owner->lock);
	if (!owner->ready || owner->busy) {
		throw IOException("Registration is unavailable or already in progress for this connection");
	}
	owner->ClearOutput();
	auto snapshot = owner->Snapshot();
	snapshot.generation = NextRegistrationOperation();
	owner->generation = snapshot.generation;
	owner->verifying = true;
	owner->busy = true;
	return snapshot;
}

void RestApiSecretStorage::StoreRegistrationState(ClientContext &context, uint64_t generation,
                                                  const string &session_token, const string &totp_uri) {
	if (!ValidRegistrationField(session_token, 4096) || !ValidRegistrationField(totp_uri, 4096)) {
		throw InvalidInputException("Invalid registration credential length");
	}
	string token_copy = session_token, uri_copy = totp_uri;
	auto owner = RegistrationOwner(context, false);
	if (!owner) {
		throw IOException("No pending registration operation");
	}
	lock_guard<mutex> guard(owner->lock);
	owner->Check(generation);
	if (owner->ready || owner->verifying) {
		throw IOException("Registration was already published");
	}
	owner->session_token.swap(token_copy);
	owner->totp_uri.swap(uri_copy);
	owner->ready = true;
}

static void ValidateRegistrationOutput(const BoilstreamRegistrationOutput &output) {
	if (output.rows.empty() || output.rows.size() > 128) {
		throw InvalidInputException("Invalid authentication result row count");
	}
	for (const auto &row : output.rows) {
		if (!ValidRegistrationField(row.value, 8192)) {
			throw InvalidInputException("Invalid authentication result value");
		}
	}
}

uint64_t RestApiSecretStorage::PublishRegistrationOutput(ClientContext &context, uint64_t generation,
                                                         unique_ptr<BoilstreamRegistrationOutput> output) {
	if (!output) {
		throw InvalidInputException("Missing authentication result");
	}
	ValidateRegistrationOutput(*output);
	auto id = NextRegistrationOperation();
	auto owner = RegistrationOwner(context, false);
	if (!owner) {
		throw IOException("No pending registration operation");
	}
	lock_guard<mutex> guard(owner->lock);
	owner->Check(generation);
	if (!owner->ready || owner->verifying) {
		throw IOException("Registration result is unavailable");
	}
	owner->output = std::move(output);
	owner->output_id = id;
	return id;
}

uint64_t RestApiSecretStorage::CompleteRegistration(ClientContext &context, uint64_t generation,
                                                    unique_ptr<BoilstreamRegistrationOutput> output) {
	if (output) {
		ValidateRegistrationOutput(*output);
	}
	const auto id = output ? NextRegistrationOperation() : 0;
	auto owner = RegistrationOwner(context, false);
	if (!owner) {
		throw IOException("No pending registration operation");
	}
	lock_guard<mutex> guard(owner->lock);
	owner->Check(generation);
	if (!owner->ready || !owner->verifying) {
		throw IOException("Registration is not ready for verification");
	}
	if (output) {
		// Retain only the account binding for the one-shot recovery result.
		owner->ClearEnrollment();
		owner->output = std::move(output);
		owner->output_id = id;
	} else {
		owner->Reset();
	}
	return id;
}

unique_ptr<BoilstreamRegistrationOutput> RestApiSecretStorage::TakeRegistrationOutput(ClientContext &context,
                                                                                      uint64_t id) {
	auto owner = RegistrationOwner(context, false);
	if (!owner) {
		throw IOException("Authentication result is unavailable");
	}
	lock_guard<mutex> guard(owner->lock);
	if (!id || owner->output_id != id || !owner->output || owner->busy) {
		throw IOException("Authentication result is unavailable or already consumed");
	}
	owner->output_id = 0;
	return std::move(owner->output);
}

void RestApiSecretStorage::EndRegistrationOperation(ClientContext &context, uint64_t generation) noexcept {
	try {
		auto owner = RegistrationOwner(context, false);
		if (!owner) {
			return;
		}
		lock_guard<mutex> guard(owner->lock);
		if (owner->generation != generation) {
			return; // A late cleanup cannot erase its successor.
		}
		if (!owner->ready) {
			owner->Reset();
		} else {
			owner->busy = false; // A rejected MFA code may be retried by the same owner.
		}
	} catch (...) { /* Cancellation already invalidates state in RegistrationOwner. */
	}
}

namespace {
class LocalBoilstreamSecrets : public ClientContextState {
public:
	shared_ptr<BoilstreamSecretCache> cache = make_shared_ptr<BoilstreamSecretCache>();
	~LocalBoilstreamSecrets() override {
		cache->Close();
	}
};
} // namespace

RestApiSecretStorage::SecretOwner RestApiSecretStorage::GetSecretOwner(optional_ptr<CatalogTransaction> transaction,
                                                                       bool create) {
	if (!transaction || !transaction->HasContext()) {
		return {};
	}
	auto &context = transaction->GetContext();
	auto state = GetSession(transaction);
	if (state) {
		lock_guard<mutex> lock(state->session_lock);
		if (state->access_token.empty() || state->session_key.empty() ||
		    state->token_expires_at <= std::chrono::system_clock::now()) {
			return {};
		}
		return {state, state->secret_cache};
	}
	// Explicit secrets without a login are local to this connection.
	// They are never mirrored into database-wide memory storage.
	auto local = create ? context.registered_state->GetOrCreate<LocalBoilstreamSecrets>("boilstream_local_secrets")
	                    : context.registered_state->Get<LocalBoilstreamSecrets>("boilstream_local_secrets");
	return {nullptr, local ? local->cache : nullptr};
}

shared_ptr<BoilstreamSecretCache> RestApiSecretStorage::GetSecretCache(optional_ptr<CatalogTransaction> transaction,
                                                                       bool create) {
	return GetSecretOwner(transaction, create).cache;
}

static vector<SecretEntry> CloneSecretSnapshot(const shared_ptr<BoilstreamSecretCache> &cache) {
	vector<SecretEntry> result;
	if (cache) {
		for (auto &entry : cache->Snapshot()) {
			result.emplace_back(*entry);
		}
	}
	return result;
}

SecretMatch RestApiSecretStorage::LookupCachedSecret(const string &path, const string &type,
                                                     const shared_ptr<BoilstreamSecretCache> &cache) {
	SecretMatch best;
	if (cache) {
		for (auto &entry : cache->Snapshot()) {
			if (StringUtil::CIEquals(entry->secret->GetType().GetIdentifierName(), type)) {
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
	if (in_http_operation) {
		return "";
	}
	HttpOperationGuard guard;
	if (!conn_state.protocol) {
		throw IOException("Missing pinned application channel");
	}
	try {
		return conn_state.protocol->Exchange(db, "GET", url, "");
	} catch (const BoilstreamApplicationError &e) {
		// A verified application failure consumed this sequence normally. Keep
		// the channel for later explicit requests; never retry the failed call.
		if (e.InvalidatesIdentity()) {
			conn_state.ClearSession();
		}
		throw;
	} catch (...) {
		conn_state.ClearSession();
		throw;
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
	if (in_http_operation) {
		throw IOException("Recursive application request refused");
	}
	HttpOperationGuard guard;
	if (!conn_state.protocol) {
		throw IOException("Missing pinned application channel");
	}
	try {
		return conn_state.protocol->Exchange(db, "POST", url, body, "", out_headers);
	} catch (const BoilstreamApplicationError &e) {
		// A verified application failure consumed this sequence normally. Keep
		// the channel for later explicit requests; never retry the failed call.
		if (e.InvalidatesIdentity()) {
			conn_state.ClearSession();
		}
		throw;
	} catch (...) {
		conn_state.ClearSession();
		throw;
	}
}

void RestApiSecretStorage::HttpDelete(const string &url, BoilstreamConnectionState &conn_state) {
	if (in_http_operation) {
		throw IOException("Recursive application request refused");
	}
	HttpOperationGuard guard;
	if (!conn_state.protocol) {
		throw IOException("Missing pinned application channel");
	}
	try {
		conn_state.protocol->Exchange(db, "DELETE", url, "");
	} catch (const BoilstreamApplicationError &e) {
		// A verified application failure consumed this sequence normally. Keep
		// the channel for later explicit requests; never retry the failed call.
		if (e.InvalidatesIdentity()) {
			conn_state.ClearSession();
		}
		throw;
	} catch (...) {
		conn_state.ClearSession();
		throw;
	}
}

unique_ptr<SecretEntry> RestApiSecretStorage::StoreSecret(unique_ptr<const BaseSecret> secret,
                                                          OnCreateConflict on_conflict,
                                                          optional_ptr<CatalogTransaction> transaction) {
	auto owner = GetSecretOwner(transaction, true);
	auto state = owner.session;
	auto cache = owner.cache;
	if (!cache) {
		throw IOException("A live connection is required to store a BoilStream secret");
	}
	if (on_conflict == OnCreateConflict::ALTER_ON_CONFLICT) {
		throw InvalidInputException("Unsupported secret conflict mode");
	}
	const auto revision = cache->Revision();
	const auto name = secret->GetName().GetIdentifierName();
	auto existing = cache->Get(name, true);
	if (!state && existing) {
		if (on_conflict == OnCreateConflict::IGNORE_ON_CONFLICT) {
			return nullptr;
		}
		if (on_conflict == OnCreateConflict::ERROR_ON_CONFLICT) {
			throw InvalidInputException("Secret already exists");
		}
	}
	const auto bytes = SerializeSecret(*secret).size();
	// Remote writes do not establish credential expiry: refetch the authoritative
	// server response before using them. Explicit local secrets have no remote TTL.
	auto entry = BoilstreamSecretCache::Prepare(
	    secret->Clone(), state ? BoilstreamSecretCache::Time::min() : BoilstreamSecretCache::Time::max(), bytes);
	cache->ValidatePut(entry, revision);
	if (state) {
		// Conflict decisions belong to the server, not a possibly stale cache.
		// A successful Ignore may preserve a different credential. Never publish
		// the proposed value as though it were the result of the server write.
		WriteSecretWithState(*secret, on_conflict, *state, transaction);
		cache->Remove(name, revision);
		auto stored = FetchSecret(name, "", false, transaction, cache);
		auto current = GetSecretOwner(transaction);
		if (current.session != state || current.cache != cache || transaction->GetContext().IsInterrupted()) {
			throw IOException("Secret write owner changed during readback");
		}
		auto result = stored.CopyIfUsable();
		if (!result) {
			throw IOException("Secret write completed but authoritative readback failed");
		}
		return result;
	}
	auto result = make_uniq<SecretEntry>(*entry.secret);
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
                                                BoilstreamConnectionState &conn_state,
                                                optional_ptr<CatalogTransaction> transaction) {
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
	boilstream::WipeOnExit wipe_secret_json(secret_json);

	// Prepare request body using yyjson (safe from injection)
	boilstream::JsonArena doc_arena;
	auto doc = doc_arena.New();
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);

	// Parse the secret JSON and add as object
	boilstream::JsonArena secret_doc_arena;
	auto secret_doc = secret_doc_arena.Read(secret_json.c_str(), secret_json.size(), 0);
	auto secret_root = yyjson_doc_get_root(secret_doc);
	auto secret_mut = yyjson_val_mut_copy(doc, secret_root);
	yyjson_mut_obj_add_val(doc, obj, "secret", secret_mut);
	yyjson_doc_free(secret_doc);

	yyjson_mut_obj_add_strcpy(doc, obj, "on_conflict",
	                          on_conflict == OnCreateConflict::REPLACE_ON_CONFLICT  ? "replace"
	                          : on_conflict == OnCreateConflict::IGNORE_ON_CONFLICT ? "ignore"
	                                                                                : "error");

	string body = SafeJsonSerialize(doc);
	boilstream::WipeOnExit wipe_body(body);
	yyjson_mut_doc_free(doc);

	HttpPostWithState(AppendPlatformParams(url), body, conn_state);

	BOILSTREAM_LOG("WriteSecretWithState: POST successful");
}

SecretMatch RestApiSecretStorage::LookupSecret(const string &path, const string &type,
                                               optional_ptr<CatalogTransaction> transaction) {
	if (StringUtil::Lower(type) == "quack" && path.find("/catalog/") != string::npos) {
		return LookupQuackSecret(path, transaction); // Managed scopes always fail closed.
	}
	auto cache = GetSecretCache(transaction);
	auto cached = LookupCachedSecret(path, type, cache);
	if (cached.HasMatch() || IsWasmMode()) {
		return cached;
	}
	auto fresh = FetchSecret(path, type, true, transaction, cache);
	if (GetSecretCache(transaction) != cache) {
		return SecretMatch();
	}
	auto entry = fresh.CopyIfUsable();
	if (entry) {
		SecretMatch best;
		return SelectBestMatch(*entry, path, tie_break_offset, best);
	}
	return LookupCachedSecret(path, type, cache);
}

unique_ptr<SecretEntry> RestApiSecretStorage::GetSecretByName(const string &name,
                                                              optional_ptr<CatalogTransaction> transaction) {
	// Stock Quack supports named secrets, but does not know our catalog-qualified
	// lookup convention. Resolve the exact managed name through the caller's
	// authenticated session; never publish a JWT into the database-global store.
	if (StringUtil::StartsWith(name, "__quack__quack:")) {
		const auto path = name.substr(sizeof("__quack__") - 1);
		string catalog_id;
		if (!ParseManagedCatalogSecretScope(path, catalog_id)) {
			return nullptr;
		}
		auto match = LookupQuackSecret(path, transaction);
		return match.HasMatch() ? std::move(match.secret_entry) : nullptr;
	}
	auto cache = GetSecretCache(transaction);
	auto owned_entry = cache ? cache->Get(name) : nullptr;
	auto cached = owned_entry ? make_uniq<SecretEntry>(*owned_entry) : nullptr;
	if (cached || IsWasmMode()) {
		return cached;
	}
	auto fresh = FetchSecret(name, "", false, transaction, cache);
	if (GetSecretCache(transaction) != cache) {
		return nullptr;
	}
	auto usable = fresh.CopyIfUsable();
	if (usable) {
		return usable;
	}
	auto entry = cache ? cache->Get(name) : nullptr;
	return entry ? make_uniq<SecretEntry>(*entry) : nullptr;
}

unique_ptr<SecretEntry> RestApiSecretStorage::FetchedSecret::CopyIfUsable() const {
	if (!secret) {
		return nullptr;
	}
	auto result = make_uniq<SecretEntry>(*secret);
	// Check after the caller revalidates its owner and after copying. A host
	// validation callback may have waited beyond the credential deadline.
	if (expires && *expires <= std::chrono::system_clock::now()) {
		return nullptr;
	}
	return result;
}

RestApiSecretStorage::FetchedSecret
RestApiSecretStorage::FetchSecret(const string &selector, const string &type, bool match,
                                  optional_ptr<CatalogTransaction> transaction,
                                  const shared_ptr<BoilstreamSecretCache> &expected_cache) {
	auto owner = GetSecretOwner(transaction);
	auto state = owner.session;
	auto cache = owner.cache;
	if (!state || !cache || cache != expected_cache || state->GetEndpointUrl().empty() || in_http_operation) {
		return {};
	}
	BoilstreamConnectionState::SecretLookupGuard guard(*state);
	if (!guard.Acquired()) {
		return {};
	}
	const auto revision = cache->Revision();
	boilstream::JsonArena doc_arena;
	auto doc = doc_arena.New();
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);
	yyjson_mut_obj_add_strncpy(doc, obj, match ? "path" : "name", selector.data(), selector.size());
	if (match) {
		const auto normalized_type = StringUtil::Lower(type);
		yyjson_mut_obj_add_strncpy(doc, obj, "type", normalized_type.data(), normalized_type.size());
	}
	bool expired = !match && cache->Get(selector, true) != nullptr;
	if (match) {
		for (auto &entry : cache->Snapshot(true)) {
			if (StringUtil::CIEquals(entry->secret->GetType().GetIdentifierName(), type) &&
			    entry->secret->MatchScore(selector) != NumericLimits<int64_t>::Minimum()) {
				expired = true;
				break;
			}
		}
	}
	yyjson_mut_obj_add_bool(doc, obj, "expired", expired);
	string body = SafeJsonSerialize(doc);
	boilstream::WipeOnExit wipe_body(body);
	yyjson_mut_doc_free(doc);
	try {
		string response;
		boilstream::WipeOnExit wipe_response(response);

		response = HttpPostWithState(AppendPlatformParams(state->GetEndpointUrl() + (match ? "/match" : "/get")), body,
		                             *state);

		if (response.size() > BoilstreamSecretCache::MAX_ENTRY_BYTES) {
			throw IOException("Oversized secret response");
		}
		boilstream::JsonArena parsed_arena;
		auto parsed = unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)>(
		    parsed_arena.Read(response.c_str(), response.size(), 0), yyjson_doc_free);
		if (!parsed) {
			return {};
		}
		auto root = yyjson_doc_get_root(parsed.get());
		if (!yyjson_is_obj(root)) {
			return {};
		}
		if (match && yyjson_obj_size(root) == 0) {
			return {};
		}
		auto expires = ParseSecretExpiry(root);
		auto secret = DeserializeSecret(response, SecretManager::Get(db));
		if (!secret || (!match && !StringUtil::CIEquals(secret->GetName().GetIdentifierName(), selector)) ||
		    (match && (!StringUtil::CIEquals(secret->GetType().GetIdentifierName(), type) ||
		               secret->MatchScore(selector) == NumericLimits<int64_t>::Minimum()))) {
			return {};
		}
		// The captured owner must still be current after network/deserialization.
		if (GetSession(transaction) != state || transaction->GetContext().IsInterrupted()) {
			return {};
		}
		auto entry = BoilstreamSecretCache::PrepareSecret(std::move(secret), response.size());
		if (expires) {
			cache->Put({entry, *expires, response.size()}, revision);
		} else {
			// Retire any older known-expiry version. The new value belongs only
			// to this request and is never admitted to the reusable cache.
			cache->Remove(entry->secret->GetName().GetIdentifierName(), revision);
		}
		return {std::move(entry), expires};
	} catch (...) {
		// Failed, malformed, expired or superseded requests cannot broaden access.
		// A still-fresh owned entry may be used by the caller; no global fallback.
	}
	return {};
}

vector<SecretEntry> RestApiSecretStorage::AllSecrets(optional_ptr<CatalogTransaction> transaction) {
	return IsWasmMode() ? GetCachedSecrets(transaction) : FetchAllSecretsFromServer(transaction);
}

vector<RestApiSecretStorage::FetchedSecret>
RestApiSecretStorage::PublishSecretList(const string &response, BoilstreamConnectionState &state, uint64_t revision) {
	if (response.size() > BoilstreamSecretCache::MAX_BYTES) {
		throw IOException("Oversized secret list");
	}
	boilstream::JsonArena doc_arena;
	auto doc = unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)>(doc_arena.Read(response.c_str(), response.size(), 0),
	                                                              yyjson_doc_free);
	if (!doc) {
		throw IOException("Invalid secret list JSON");
	}
	auto root = yyjson_doc_get_root(doc.get());
	if (!yyjson_is_arr(root) || yyjson_arr_size(root) > BoilstreamSecretCache::MAX_ENTRIES) {
		throw IOException("Invalid secret list");
	}
	BoilstreamSecretCache::Entries staged;
	vector<FetchedSecret> fresh;
	case_insensitive_map_t<bool> names;
	bool complete = true;
	size_t idx, max;
	yyjson_val *val;
	yyjson_arr_foreach(root, idx, max, val) {
		if (!yyjson_is_obj(val)) {
			throw IOException("Invalid secret list entry");
		}
		auto expires = ParseSecretExpiry(val);
		boilstream::JsonArena writer_arena;
		size_t encoded_length = 0;
		auto encoded = yyjson_val_write_opts(val, 0, &writer_arena.Allocator(), &encoded_length, nullptr);
		if (!encoded) {
			throw IOException("Cannot serialize secret list entry");
		}
		string json(encoded, encoded_length);
		boilstream::WipeOnExit wipe_json(json);
		if (json.size() > BoilstreamSecretCache::MAX_ENTRY_BYTES) {
			throw IOException("Oversized secret list entry");
		}
		auto secret = DeserializeSecret(json, SecretManager::Get(db));
		if (!secret) {
			throw IOException("Invalid serialized secret");
		}
		auto name = secret->GetName().GetIdentifierName();
		if (!names.emplace(name, true).second) {
			throw IOException("Duplicate secret name");
		}
		auto entry = BoilstreamSecretCache::PrepareSecret(std::move(secret), json.size());
		fresh.push_back({entry, expires});
		if (expires) {
			staged.emplace(name, BoilstreamSecretCache::Entry {entry, *expires, json.size()});
		} else {
			complete = false;
		}
	}
	// Validate the whole response before publishing. Unknown deadlines are kept
	// only in this response, so its partial cache cannot satisfy a later list.
	state.secret_cache->Replace(std::move(staged), revision, complete);
	return fresh;
}

vector<SecretEntry>
RestApiSecretStorage::FetchAllSecretsFromServer(optional_ptr<CatalogTransaction> transaction,
                                                // Retain the expected session identity across owner lookup callbacks.
                                                // NOLINTNEXTLINE(performance-unnecessary-value-param)
                                                shared_ptr<BoilstreamConnectionState> explicit_conn_state) {
	auto owner = GetSecretOwner(transaction);
	auto state = owner.session;
	if (explicit_conn_state && explicit_conn_state != state) {
		throw IOException("Secret owner was superseded");
	}
	auto cache = owner.cache;
	if (!state || !cache || state->GetEndpointUrl().empty() || in_http_operation ||
	    (!explicit_conn_state && cache->RecentlyFetched())) {
		return CloneSecretSnapshot(cache);
	}
	BoilstreamConnectionState::SecretLookupGuard guard(*state);
	if (!guard.Acquired()) {
		return CloneSecretSnapshot(cache);
	}
	CheckCatalogVersions(*state, &transaction->GetContext());
	const auto revision = cache->Revision();
	try {
		auto response = HttpGetWithState(AppendPlatformParams(state->GetEndpointUrl()), *state);
		if (GetSession(transaction) != state || transaction->GetContext().IsInterrupted()) {
			throw IOException("Secret fetch was superseded");
		}
		auto fresh = PublishSecretList(response, *state, revision);
		auto current = GetSecretOwner(transaction);
		if (current.session != state || current.cache != cache || transaction->GetContext().IsInterrupted()) {
			throw IOException("Secret fetch was superseded");
		}
		vector<SecretEntry> result;
		for (const auto &entry : fresh) {
			auto usable = entry.CopyIfUsable();
			if (usable) {
				result.push_back(std::move(*usable));
			}
		}
		return result;
	} catch (...) {
		if (explicit_conn_state) {
			throw;
		}
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

void RestApiSecretStorage::DropSecretByName(const Identifier &secret_name, OnEntryNotFound on_entry_not_found,
                                            optional_ptr<CatalogTransaction> transaction) {
	const auto &name = secret_name.GetIdentifierName();
	auto owner = GetSecretOwner(transaction);
	auto state = owner.session;
	auto cache = owner.cache;
	if (!cache) {
		if (on_entry_not_found == OnEntryNotFound::THROW_EXCEPTION) {
			throw CatalogException("Secret not found");
		}
		return;
	}
	const auto revision = cache->Revision();
	if (state) {
		if (state->GetEndpointUrl().empty()) {
			throw IOException("Secret endpoint is not configured");
		}
		HttpDelete(AppendPlatformParams(state->GetEndpointUrl() + "/" + StringUtil::URLEncode(name)), *state);

	} else if (!cache->Get(name, true) && on_entry_not_found == OnEntryNotFound::THROW_EXCEPTION) {
		throw CatalogException("Secret not found");
	}
	cache->Remove(name, revision);
}

case_insensitive_map_t<RestApiSecretStorage::CatalogVersionInfo>
RestApiSecretStorage::FetchCatalogVersions(BoilstreamConnectionState &conn_state, optional_ptr<ClientContext> context) {
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

	// All inner routes share the channel's authenticated sequence handling.
	string url = boilstream::CatalogVersionsURL(base_url);
	if (url.empty()) {
		return versions;
	}

	string response;
	boilstream::WipeOnExit wipe_response(response);
	try {
		response = HttpGetWithState(url, conn_state);

	} catch (const std::exception &e) {
		return versions;
	} catch (...) {
		BOILSTREAM_LOG("FetchCatalogVersions: HTTP request failed with unknown error");
		return versions;
	}

	return boilstream::ParseCatalogVersions(response);
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
	string response;
	boilstream::WipeOnExit wipe_response(response);

	const auto url = AppendPlatformParams(ManagedCatalogCredentialUrl(conn_state.GetEndpointUrl(), catalog_id));
	response = HttpGetWithState(url, conn_state);

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
	auto secret = make_uniq<KeyValueSecret>(scope, "quack", "config", Identifier(secret_name));
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

bool RestApiSecretStorage::BeginCatalogVersionPoll(BoilstreamConnectionState &conn_state,
                                                   std::chrono::system_clock::time_point now) {
	lock_guard<mutex> lock(conn_state.version_lock);
	// Compare timestamps directly: subtracting the initial minimum sentinel overflows.
	if (conn_state.last_version_check > now - std::chrono::seconds(VERSION_CHECK_INTERVAL_SECONDS)) {
		return false;
	}
	conn_state.last_version_check = now;
	return true;
}

void RestApiSecretStorage::CheckCatalogVersions(BoilstreamConnectionState &conn_state,
                                                optional_ptr<ClientContext> context) {
	if (!BeginCatalogVersionPoll(conn_state, std::chrono::system_clock::now())) {
		return;
	}
	ApplyCatalogVersions(conn_state, FetchCatalogVersions(conn_state, context));
}

void RestApiSecretStorage::ApplyCatalogVersions(BoilstreamConnectionState &conn_state,
                                                const boilstream::CatalogVersions &versions) {
	if (versions.empty()) {
		return;
	}
	vector<string> catalogs_to_refresh;
	{
		lock_guard<mutex> lock(conn_state.version_lock);
		auto update = boilstream::ReconcileCatalogVersions(conn_state.catalog_versions, versions);
		conn_state.catalog_versions = std::move(update.versions);
		catalogs_to_refresh = std::move(update.refresh);
	}
	for (const auto &catalog_name : catalogs_to_refresh) {
		RefreshCatalogCredentials(catalog_name, conn_state);
	}
}

} // namespace duckdb
