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
#include "boilstream_secret_storage.hpp"
#include "boilstream_extension.hpp"
#include "opaque_client_ffi.hpp"
#include <ctime>
#include <chrono>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#endif

// Debug logging macro - always enabled for WASM debugging
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <sstream>
#define BOILSTREAM_LOG(msg)                                                                                            \
	do {                                                                                                               \
		std::ostringstream oss;                                                                                        \
		oss << "[BOILSTREAM] " << msg;                                                                                 \
		emscripten_log(EM_LOG_CONSOLE, "%s", oss.str().c_str());                                                       \
	} while (0)
#elif defined(BOILSTREAM_DEBUG)
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
	BOILSTREAM_LOG("Step 1: Function called");

	if (params.values.empty()) {
		throw InvalidInputException("rest_set_endpoint requires a URL parameter");
	}

	BOILSTREAM_LOG("Step 2: Getting parameter");
	string input = params.values[0].ToString();
	BOILSTREAM_LOG("Step 3: Parameter = " << input.substr(0, 50) << "...");

	// Validate input format
	if (input.empty()) {
		throw InvalidInputException("rest_set_endpoint: URL cannot be empty");
	}
	BOILSTREAM_LOG("Step 4: Validation - not empty");

	// Check if URL has a valid protocol
	BOILSTREAM_LOG("Step 5: Checking protocol");
	if (input.find("http://") != 0 && input.find("https://") != 0) {
		throw InvalidInputException("rest_set_endpoint: URL must start with http:// or https://");
	}

	// Find where the protocol ends (after ://)
	BOILSTREAM_LOG("Step 6: Finding protocol end");
	auto protocol_end = input.find("://");
	if (protocol_end == string::npos) {
		throw InvalidInputException("rest_set_endpoint: Invalid URL format");
	}

	// Find the start of the path (first '/' after protocol)
	BOILSTREAM_LOG("Step 7: Finding path start");
	auto path_start = input.find('/', protocol_end + 3);
	if (path_start == string::npos) {
		throw InvalidInputException(
		    "rest_set_endpoint: URL must contain a path (e.g., https://host:port/secrets/:TOKEN)");
	}
	BOILSTREAM_LOG("Step 8: Path found");

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

	BOILSTREAM_LOG("Step 9: Checking HTTPS requirement");
	if (!is_localhost && endpoint_url.find("https://") != 0) {
		throw InvalidInputException("rest_set_endpoint: URL must use HTTPS (or localhost for testing)");
	}

	// Update the REST API storage with endpoint first
	BOILSTREAM_LOG("Step 10: Getting global storage");
	auto storage = GetGlobalStorage();
	if (!storage) {
		BOILSTREAM_LOG("SetEndpoint: WARNING - storage is NULL!");
		throw InvalidInputException("rest_set_endpoint: Storage not initialized");
	}
	BOILSTREAM_LOG("Step 11: Storage obtained");

	// Hash the bootstrap token to check for reuse
	// Use Rust SHA256 from opaque_client library (works on all platforms including WASM)
	BOILSTREAM_LOG("Step 12: Computing SHA256 hash using Rust");

	uint8_t hash_bytes[32];
	opaque_client_sha256(reinterpret_cast<const uint8_t *>(bootstrap_token.c_str()), bootstrap_token.size(),
	                     hash_bytes);

	// Convert to hex string (lowercase)
	string incoming_token_hash;
	incoming_token_hash.reserve(64);
	const char *hex_chars = "0123456789abcdef";
	for (size_t i = 0; i < 32; i++) {
		incoming_token_hash += hex_chars[(hash_bytes[i] >> 4) & 0xF];
		incoming_token_hash += hex_chars[hash_bytes[i] & 0xF];
	}
	BOILSTREAM_LOG("Step 13: Hash complete");

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
	// All crypto now handled by Rust - works on all platforms including WASM
	BOILSTREAM_LOG("Step 12: Starting OPAQUE login");

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

		// Normalize network-related errors to "Token exchange failed" for consistent test behavior
		// This prevents exposing internal error details when the server is unreachable
		string error_msg = e.what();
		if (error_msg.find("scheme is not supported") != string::npos ||
		    error_msg.find("not implemented") != string::npos || error_msg.find("Connection refused") != string::npos ||
		    error_msg.find("Could not connect") != string::npos ||
		    error_msg.find("Failed to connect") != string::npos || error_msg.find("Timeout") != string::npos ||
		    error_msg.find("timed out") != string::npos) {
			throw InvalidInputException("Token exchange failed");
		}

		// For other errors (validation, parsing, etc.), include the full error message
		throw InvalidInputException("OPAQUE login failed: %s", e.what());
	}

	// Set context for this connection (use hash of bootstrap token, not the token itself)
	// This prevents leaking token material in connection map
	// Reuse the hash we just computed (first 16 hex chars)
	string user_id = incoming_token_hash.substr(0, 16);
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
	BOILSTREAM_LOG("LoadInternal: Extension loading started");

	// Register global storage
	auto &db = loader.GetDatabaseInstance();
	BOILSTREAM_LOG("LoadInternal: Successfully got database instance");

	auto storage = make_uniq<RestApiSecretStorage>(db, "rest_api");

	{
		lock_guard<mutex> lock(global_storage_lock);
		global_rest_storage = storage.get();
	}

	auto &secret_manager = db.GetSecretManager();
	secret_manager.LoadSecretStorage(std::move(storage));
	BOILSTREAM_LOG("LoadInternal: Secret storage registered");

	// Register PRAGMA function with PragmaCall to accept parameters
	auto rest_endpoint =
	    PragmaFunction::PragmaCall("duckdb_secrets_boilstream_endpoint", SetRestApiEndpoint, {LogicalType::VARCHAR});
	loader.RegisterFunction(rest_endpoint);
	BOILSTREAM_LOG("LoadInternal: PRAGMA function registered");

	BOILSTREAM_LOG("LoadInternal: Extension loaded successfully");
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
	return "0.3.4";
#endif
}

} // namespace duckdb

extern "C" {

// DuckDB C++ extension entry point (used when loading by name)
DUCKDB_CPP_EXTENSION_ENTRY(boilstream, loader) {
	duckdb::LoadInternal(loader);
}

// WASM-specific entry point (used when loading by URL)
// Must be explicitly exported for WASM side modules
#ifdef __EMSCRIPTEN__
__attribute__((used, visibility("default"))) void boilstream_init(duckdb::ExtensionLoader &loader) {
	duckdb::LoadInternal(loader);
}
#endif
}
