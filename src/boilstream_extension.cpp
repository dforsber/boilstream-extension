//===----------------------------------------------------------------------===//
//                         DuckDB
//
// boilstream_extension.cpp
//
//
//===----------------------------------------------------------------------===//

#include "duckdb.hpp"
#include "duckdb/main/extension.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/pragma_function.hpp"
#include "mbedtls_wrapper.hpp"
#include "boilstream_secret_storage.hpp"
#include "boilstream_extension.hpp"
#include <ctime>
#include <chrono>

// Debug logging macro - only enabled when BOILSTREAM_DEBUG is defined
// To enable: add -DBOILSTREAM_DEBUG to compiler flags
#ifdef BOILSTREAM_DEBUG
#include <iostream>
#define BOILSTREAM_LOG(msg) std::cerr << "[BOILSTREAM] " << msg << std::endl
#else
#define BOILSTREAM_LOG(msg) ((void)0)
#endif

namespace duckdb {

// Global storage pointer (set during extension load)
// Using raw pointer with careful lifetime management
static RestApiSecretStorage *global_rest_storage = nullptr;
static mutex global_storage_lock;

//! Helper to get the global storage safely
static RestApiSecretStorage *GetGlobalStorage() {
	lock_guard<mutex> lock(global_storage_lock);
	return global_rest_storage;
}

//! Helper to set user context for a connection
static void SetUserContext(ClientContext &context, const string &user_id) {
	auto storage = GetGlobalStorage();
	if (storage) {
		storage->SetUserContextForConnection(context.GetConnectionId(), user_id);
	}
}

//! PRAGMA function to set the REST API endpoint URL
static string SetRestApiEndpoint(ClientContext &context, const FunctionParameters &params) {
	if (params.values.empty()) {
		throw InvalidInputException("rest_set_endpoint requires a URL parameter");
	}

	string input = params.values[0].ToString();

	// Validate input format
	if (input.empty()) {
		throw InvalidInputException("rest_set_endpoint: URL cannot be empty");
	}

	// Check if URL has a valid protocol
	if (input.find("http://") != 0 && input.find("https://") != 0) {
		throw InvalidInputException("rest_set_endpoint: URL must start with http:// or https://");
	}

	// Find where the protocol ends (after ://)
	auto protocol_end = input.find("://");
	if (protocol_end == string::npos) {
		throw InvalidInputException("rest_set_endpoint: Invalid URL format");
	}

	// Find the start of the path (first '/' after protocol)
	auto path_start = input.find('/', protocol_end + 3);
	if (path_start == string::npos) {
		throw InvalidInputException(
		    "rest_set_endpoint: URL must contain a path (e.g., https://host:port/secrets/:TOKEN)");
	}

	// Find the token delimiter ':' after the path starts
	// This avoids matching the port number (e.g., :4332)
	// For https://localhost:4332/secrets/:TOKEN, we want the ':' before TOKEN
	auto token_delimiter = input.find(':', path_start);
	if (token_delimiter == string::npos) {
		throw InvalidInputException(
		    "rest_set_endpoint: URL must include token after ':' (e.g., https://host:port/path/:TOKEN)");
	}

	// Split into endpoint and bootstrap token
	string endpoint_url = input.substr(0, token_delimiter);
	string bootstrap_token = input.substr(token_delimiter + 1);

	// Remove trailing slash from endpoint if present (from /path/:token format)
	if (!endpoint_url.empty() && endpoint_url.back() == '/') {
		endpoint_url = endpoint_url.substr(0, endpoint_url.length() - 1);
	}

	if (bootstrap_token.empty()) {
		throw InvalidInputException("rest_set_endpoint: Bootstrap token cannot be empty");
	}

	// Require HTTPS for security (unless localhost for testing)
	// Properly extract and validate hostname to prevent bypass
	bool is_localhost = false;
	auto proto_end = endpoint_url.find("://");
	if (proto_end != string::npos) {
		auto host_start = proto_end + 3;
		auto host_end = endpoint_url.find('/', host_start);
		auto port_pos = endpoint_url.find(':', host_start);

		// Port comes before path
		if (port_pos != string::npos && (host_end == string::npos || port_pos < host_end)) {
			host_end = port_pos;
		}

		string hostname =
		    endpoint_url.substr(host_start, host_end == string::npos ? string::npos : host_end - host_start);

		// Check for localhost variants (including IPv6)
		is_localhost = (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" || hostname == "[::1]");
	}

	if (!is_localhost && endpoint_url.find("https://") != 0) {
		throw InvalidInputException("rest_set_endpoint: URL must use HTTPS (or localhost for testing)");
	}

	// Update the REST API storage with endpoint first
	auto storage = GetGlobalStorage();
	if (!storage) {
		BOILSTREAM_LOG("SetEndpoint: WARNING - storage is NULL!");
		throw InvalidInputException("rest_set_endpoint: Storage not initialized");
	}

	// Hash the bootstrap token to check for reuse
	duckdb_mbedtls::MbedTlsWrapper::SHA256State sha_state_check;
	sha_state_check.AddString(bootstrap_token);
	string incoming_token_hash = sha_state_check.Finalize();

	// Check if this is the same bootstrap token from an existing valid session
	if (storage->GetBootstrapTokenHash() == incoming_token_hash && !incoming_token_hash.empty() &&
	    storage->IsSessionTokenValid()) {
		BOILSTREAM_LOG("SetEndpoint: Bootstrap token matches existing session, skipping exchange");

		// Get expiration timestamp and format it
		auto expires_at = storage->GetTokenExpiresAt();
		auto expires_time_t = std::chrono::system_clock::to_time_t(expires_at);
		std::tm tm_utc;
#ifdef _WIN32
		gmtime_s(&tm_utc, &expires_time_t);
#else
		gmtime_r(&expires_time_t, &tm_utc);
#endif
		char expires_str[64];
		std::strftime(expires_str, sizeof(expires_str), "%Y-%m-%d %H:%M:%S", &tm_utc);

		return "SELECT 'Session already active' as status, TIMESTAMP '" + string(expires_str) + "' as expires_at;";
	}

	// Clear any existing session before attempting new token exchange
	// This ensures clean state and prevents sending old access_token during bootstrap exchange
	storage->ClearSession();

	// Perform OPAQUE login BEFORE setting endpoint (for consistent state on failure)
	try {
		// Temporarily set endpoint for exchange (will be cleared on failure)
		storage->SetEndpoint(endpoint_url);
		BOILSTREAM_LOG("SetEndpoint: endpoint_url=" << endpoint_url);

		storage->PerformOpaqueLogin(bootstrap_token);
		BOILSTREAM_LOG("SetEndpoint: OPAQUE login successful");

		// Store bootstrap token hash for reuse detection
		storage->SetBootstrapTokenHash(incoming_token_hash);
		BOILSTREAM_LOG("SetEndpoint: Stored bootstrap token hash");
	} catch (const std::exception &e) {
		// Rollback endpoint on failure - ensure consistent state
		storage->SetEndpoint("");
		storage->ClearSession();
		BOILSTREAM_LOG("SetEndpoint: OPAQUE login failed, rolled back: " << e.what());
		throw InvalidInputException("OPAQUE login failed: %s", e.what());
	}

	// Set context for this connection (use hash of bootstrap token, not the token itself)
	// This prevents leaking token material in connection map
	duckdb_mbedtls::MbedTlsWrapper::SHA256State sha_state;
	sha_state.AddString(bootstrap_token);
	string user_id = sha_state.Finalize().substr(0, 16); // First 16 hex chars of hash
	SetUserContext(context, user_id);

	// Get expiration timestamp and format it
	auto expires_at = storage->GetTokenExpiresAt();
	auto expires_time_t = std::chrono::system_clock::to_time_t(expires_at);
	std::tm tm_utc;
#ifdef _WIN32
	gmtime_s(&tm_utc, &expires_time_t);
#else
	gmtime_r(&expires_time_t, &tm_utc);
#endif
	char expires_str[64];
	std::strftime(expires_str, sizeof(expires_str), "%Y-%m-%d %H:%M:%S", &tm_utc);

	// Return a query that will be executed (showing the result)
	// Do NOT echo the token to prevent leakage in logs/query history
	return "SELECT 'Session token obtained' as status, TIMESTAMP '" + string(expires_str) + "' as expires_at;";
}

//! Load the extension
static void LoadInternal(ExtensionLoader &loader) {
	auto &db = loader.GetDatabaseInstance();
	auto &secret_manager = SecretManager::Get(db);

	// Get REST API URL from environment variable (empty by default, requires PRAGMA to set)
	const char *api_url_env = std::getenv("DUCKDB_REST_API_URL");
	string api_url = api_url_env ? string(api_url_env) : "";

	// Register the REST API secret storage
	auto storage = make_uniq<RestApiSecretStorage>(db, api_url);
	// Keep a raw pointer for PRAGMA access - lifetime managed by SecretManager
	// NOTE: This is safe because SecretManager keeps the storage alive for the database lifetime
	auto storage_ptr = storage.get();
	secret_manager.LoadSecretStorage(std::move(storage));

	// Store the pointer globally (protected by mutex)
	{
		lock_guard<mutex> lock(global_storage_lock);
		global_rest_storage = storage_ptr;
	}

	// Set boilstream as the default persistent storage
	secret_manager.SetDefaultStorage("boilstream");

	// Register PRAGMA duckdb_secrets_boilstream_endpoint to set the REST API endpoint URL
	auto set_endpoint_pragma =
	    PragmaFunction::PragmaCall("duckdb_secrets_boilstream_endpoint", SetRestApiEndpoint, {LogicalType::VARCHAR});
	loader.RegisterFunction(set_endpoint_pragma);

	loader.SetDescription("REST API-based secret storage for multi-tenant DuckDB deployments");
}

void BoilstreamExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string BoilstreamExtension::Name() {
	return "boilstream";
}

std::string BoilstreamExtension::Version() const {
#ifdef EXT_VERSION_BOILSTREAM
	return EXT_VERSION_BOILSTREAM;
#else
	return "0.3.0";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(boilstream, loader) {
	duckdb::LoadInternal(loader);
}
}
