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
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/function/pragma_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/parser/keyword_helper.hpp"
#include "boilstream_secret_storage.hpp"
#include "boilstream_extension.hpp"
#include "opaque_client_ffi.hpp"
#include "yyjson.hpp"
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

// Helper: Clear query logs to remove sensitive data (passwords, TOTP secrets, backup codes)
// This only clears DuckDB's query logs - shell history (~/.duckdb_history) must be cleared manually
static void ClearQueryLogs(ClientContext &context) {
	try {
		auto &db = DatabaseInstance::GetDatabase(context);
		auto &log_manager = db.GetLogManager();
		log_manager.TruncateLogStorage();
		BOILSTREAM_LOG("ClearQueryLogs: Query logs truncated successfully");
	} catch (const std::exception &e) {
		BOILSTREAM_LOG("ClearQueryLogs: Failed to truncate logs: " << e.what());
		// Don't throw - log clearing is a security best-effort, shouldn't fail the operation
	}
}

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

//===--------------------------------------------------------------------===//
// Boilstream Ducklakes Table Function
//===--------------------------------------------------------------------===//

struct BoilstreamDucklakesBindData : public TableFunctionData {
	// No additional data needed, we get storage from global
};

struct BoilstreamDucklakesGlobalState : public GlobalTableFunctionState {
	BoilstreamDucklakesGlobalState() : current_idx(0) {
	}

	vector<vector<Value>> ducklakes_data;
	idx_t current_idx;
};

static unique_ptr<FunctionData> BoilstreamDucklakesBind(ClientContext &context, TableFunctionBindInput &input,
                                                        vector<LogicalType> &return_types, vector<string> &names) {
	// Define output columns
	names.emplace_back("catalog_id");
	return_types.emplace_back(LogicalType(LogicalTypeId::VARCHAR));

	names.emplace_back("catalog_name");
	return_types.emplace_back(LogicalType(LogicalTypeId::VARCHAR));

	names.emplace_back("description");
	return_types.emplace_back(LogicalType(LogicalTypeId::VARCHAR));

	names.emplace_back("access_mode");
	return_types.emplace_back(LogicalType(LogicalTypeId::VARCHAR));

	names.emplace_back("ownership");
	return_types.emplace_back(LogicalType(LogicalTypeId::VARCHAR));

	names.emplace_back("granted_by");
	return_types.emplace_back(LogicalType(LogicalTypeId::VARCHAR));

	names.emplace_back("granted_at");
	return_types.emplace_back(LogicalType(LogicalTypeId::TIMESTAMP));

	names.emplace_back("created_at");
	return_types.emplace_back(LogicalType(LogicalTypeId::TIMESTAMP));

	return make_uniq<BoilstreamDucklakesBindData>();
}

static unique_ptr<GlobalTableFunctionState> BoilstreamDucklakesInit(ClientContext &context,
                                                                    TableFunctionInitInput &input) {
	auto result = make_uniq<BoilstreamDucklakesGlobalState>();

	// Get global storage
	auto storage = GetGlobalStorage();
	if (!storage) {
		throw InvalidInputException(
		    "boilstream_ducklakes: No active session. Call PRAGMA boilstream_bootstrap_session first.");
	}

	BOILSTREAM_LOG("BoilstreamDucklakesInit: Fetching ducklakes from API");

	// Get the endpoint URL and validate it's configured
	string endpoint_url = storage->GetEndpointUrl();
	if (endpoint_url.empty()) {
		throw InvalidInputException(
		    "boilstream_ducklakes: No endpoint configured. Call PRAGMA boilstream_bootstrap_session first.");
	}

	// Construct the ducklakes API URL
	// endpoint_url is like "https://host:port/secrets"
	// We need "https://host:port/secrets/ducklakes"
	string ducklakes_url = endpoint_url + "/ducklakes";

	BOILSTREAM_LOG("BoilstreamDucklakesInit: ducklakes_url=" << ducklakes_url);

	// Make HTTP GET request
	string response;
	try {
		response = storage->HttpGet(ducklakes_url);
	} catch (const std::exception &e) {
		BOILSTREAM_LOG("BoilstreamDucklakesInit: Failed to fetch ducklakes: " << e.what());
		throw IOException("Failed to fetch ducklakes from boilstream server: %s", e.what());
	}

	// Check if response is empty (indicates error like 401, 403, etc.)
	if (response.empty()) {
		BOILSTREAM_LOG("BoilstreamDucklakesInit: Empty response from server (likely authentication error)");
		throw IOException(
		    "Failed to fetch ducklakes: Server returned an error (possibly authentication issue). "
		    "Check your token permissions or try refreshing the session with: SELECT * FROM duckdb_secrets() LIMIT 1;");
	}

	// Parse JSON response
	BOILSTREAM_LOG("BoilstreamDucklakesInit: Parsing JSON response");
	auto doc = duckdb_yyjson::yyjson_read(response.c_str(), response.size(), 0);
	if (!doc) {
		throw IOException("Failed to parse ducklakes JSON response");
	}

	auto root = duckdb_yyjson::yyjson_doc_get_root(doc);
	if (!root) {
		duckdb_yyjson::yyjson_doc_free(doc);
		throw IOException("Invalid ducklakes response: empty JSON");
	}

	// Handle both formats:
	// 1. Empty array: []
	// 2. Object with catalogs: {"catalogs": [...]}
	duckdb_yyjson::yyjson_val *catalogs_val = nullptr;

	if (duckdb_yyjson::yyjson_is_arr(root)) {
		// Server returned array directly (empty or with catalogs)
		BOILSTREAM_LOG("BoilstreamDucklakesInit: Response is array format");
		catalogs_val = root;
	} else if (duckdb_yyjson::yyjson_is_obj(root)) {
		// Server returned object with "catalogs" field
		BOILSTREAM_LOG("BoilstreamDucklakesInit: Response is object format");
		catalogs_val = duckdb_yyjson::yyjson_obj_get(root, "catalogs");
		if (!catalogs_val || !duckdb_yyjson::yyjson_is_arr(catalogs_val)) {
			duckdb_yyjson::yyjson_doc_free(doc);
			throw IOException("Invalid ducklakes response: 'catalogs' field is missing or not an array");
		}
	} else {
		duckdb_yyjson::yyjson_doc_free(doc);
		throw IOException("Invalid ducklakes response: expected array or object");
	}

	// Parse each catalog entry
	size_t arr_size = duckdb_yyjson::yyjson_arr_size(catalogs_val);
	for (size_t idx = 0; idx < arr_size; idx++) {
		auto val = duckdb_yyjson::yyjson_arr_get(catalogs_val, idx);
		if (!val || !duckdb_yyjson::yyjson_is_obj(val)) {
			continue;
		}

		vector<Value> row;

		// catalog_id
		auto catalog_id_val = duckdb_yyjson::yyjson_obj_get(val, "catalog_id");
		if (catalog_id_val && duckdb_yyjson::yyjson_is_str(catalog_id_val)) {
			row.emplace_back(Value(duckdb_yyjson::yyjson_get_str(catalog_id_val)));
		} else {
			row.emplace_back(Value());
		}

		// catalog_name
		auto catalog_name_val = duckdb_yyjson::yyjson_obj_get(val, "catalog_name");
		if (catalog_name_val && duckdb_yyjson::yyjson_is_str(catalog_name_val)) {
			row.emplace_back(Value(duckdb_yyjson::yyjson_get_str(catalog_name_val)));
		} else {
			row.emplace_back(Value());
		}

		// description
		auto description_val = duckdb_yyjson::yyjson_obj_get(val, "description");
		if (description_val && duckdb_yyjson::yyjson_is_str(description_val)) {
			row.emplace_back(Value(duckdb_yyjson::yyjson_get_str(description_val)));
		} else {
			row.emplace_back(Value());
		}

		// access_mode
		auto access_mode_val = duckdb_yyjson::yyjson_obj_get(val, "access_mode");
		if (access_mode_val && duckdb_yyjson::yyjson_is_str(access_mode_val)) {
			row.emplace_back(Value(duckdb_yyjson::yyjson_get_str(access_mode_val)));
		} else {
			row.emplace_back(Value());
		}

		// ownership
		auto ownership_val = duckdb_yyjson::yyjson_obj_get(val, "ownership");
		if (ownership_val && duckdb_yyjson::yyjson_is_str(ownership_val)) {
			row.emplace_back(Value(duckdb_yyjson::yyjson_get_str(ownership_val)));
		} else {
			row.emplace_back(Value());
		}

		// granted_by (optional)
		auto granted_by_val = duckdb_yyjson::yyjson_obj_get(val, "granted_by");
		if (granted_by_val && duckdb_yyjson::yyjson_is_str(granted_by_val)) {
			row.emplace_back(Value(duckdb_yyjson::yyjson_get_str(granted_by_val)));
		} else {
			row.emplace_back(Value());
		}

		// granted_at (optional, ISO8601 timestamp)
		auto granted_at_val = duckdb_yyjson::yyjson_obj_get(val, "granted_at");
		if (granted_at_val && duckdb_yyjson::yyjson_is_str(granted_at_val)) {
			try {
				string granted_at_str = duckdb_yyjson::yyjson_get_str(granted_at_val);
				row.emplace_back(Value::TIMESTAMP(Timestamp::FromString(granted_at_str, true)));
			} catch (...) {
				row.emplace_back(Value());
			}
		} else {
			row.emplace_back(Value());
		}

		// created_at (ISO8601 timestamp)
		auto created_at_val = duckdb_yyjson::yyjson_obj_get(val, "created_at");
		if (created_at_val && duckdb_yyjson::yyjson_is_str(created_at_val)) {
			try {
				string created_at_str = duckdb_yyjson::yyjson_get_str(created_at_val);
				row.emplace_back(Value::TIMESTAMP(Timestamp::FromString(created_at_str, true)));
			} catch (...) {
				row.emplace_back(Value());
			}
		} else {
			row.emplace_back(Value());
		}

		result->ducklakes_data.push_back(std::move(row));
	}

	duckdb_yyjson::yyjson_doc_free(doc);

	BOILSTREAM_LOG("BoilstreamDucklakesInit: Loaded " << result->ducklakes_data.size() << " ducklakes");

	return std::move(result);
}

static void BoilstreamDucklakesFunction(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<BoilstreamDucklakesGlobalState>();

	idx_t count = 0;
	while (state.current_idx < state.ducklakes_data.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = state.ducklakes_data[state.current_idx];

		// Set each column value
		for (idx_t col_idx = 0; col_idx < row.size(); col_idx++) {
			output.SetValue(col_idx, count, row[col_idx]);
		}

		state.current_idx++;
		count++;
	}

	output.SetCardinality(count);
}

//===--------------------------------------------------------------------===//
// Boilstream Secrets Table Function
//===--------------------------------------------------------------------===//

struct BoilstreamSecretsBindData : public TableFunctionData {
	// No additional data needed, we get storage from global
};

struct BoilstreamSecretsGlobalState : public GlobalTableFunctionState {
	BoilstreamSecretsGlobalState() : current_idx(0) {
	}

	vector<vector<Value>> secrets_data;
	idx_t current_idx;
};

static unique_ptr<FunctionData> BoilstreamSecretsBind(ClientContext &context, TableFunctionBindInput &input,
                                                      vector<LogicalType> &return_types, vector<string> &names) {
	// Define output columns
	names.emplace_back("name");
	return_types.emplace_back(LogicalType(LogicalTypeId::VARCHAR));

	names.emplace_back("type");
	return_types.emplace_back(LogicalType(LogicalTypeId::VARCHAR));

	names.emplace_back("provider");
	return_types.emplace_back(LogicalType(LogicalTypeId::VARCHAR));

	names.emplace_back("scope");
	return_types.emplace_back(LogicalType::LIST(LogicalType(LogicalTypeId::VARCHAR)));

	names.emplace_back("expires_at");
	return_types.emplace_back(LogicalType(LogicalTypeId::TIMESTAMP));

	return make_uniq<BoilstreamSecretsBindData>();
}

static unique_ptr<GlobalTableFunctionState> BoilstreamSecretsInit(ClientContext &context,
                                                                  TableFunctionInitInput &input) {
	auto result = make_uniq<BoilstreamSecretsGlobalState>();

	// Get global storage
	auto storage = GetGlobalStorage();
	if (!storage) {
		throw InvalidInputException(
		    "boilstream_secrets: No active session. Call PRAGMA boilstream_bootstrap_session first.");
	}

	// Validate endpoint is configured
	string endpoint_url = storage->GetEndpointUrl();
	if (endpoint_url.empty()) {
		throw InvalidInputException(
		    "boilstream_secrets: No endpoint configured. Call PRAGMA boilstream_bootstrap_session first.");
	}

	BOILSTREAM_LOG("BoilstreamSecretsInit: Fetching all secrets");

	// Get all secrets
	vector<SecretEntry> secrets;
	try {
		auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
		secrets = storage->AllSecrets(transaction);
	} catch (const std::exception &e) {
		BOILSTREAM_LOG("BoilstreamSecretsInit: Failed to fetch secrets: " << e.what());
		throw IOException("Failed to fetch secrets from boilstream storage: %s", e.what());
	}

	BOILSTREAM_LOG("BoilstreamSecretsInit: Processing " << secrets.size() << " secrets");

	// Process each secret
	for (auto &entry : secrets) {
		if (!entry.secret) {
			continue;
		}

		auto &secret = *entry.secret;
		vector<Value> row;

		// name
		row.emplace_back(Value(secret.GetName()));

		// type
		row.emplace_back(Value(secret.GetType()));

		// provider
		row.emplace_back(Value(secret.GetProvider()));

		// scope (as list)
		auto &scope = secret.GetScope();
		vector<Value> scope_values;
		for (const auto &scope_item : scope) {
			scope_values.emplace_back(Value(scope_item));
		}
		row.emplace_back(Value::LIST(LogicalType(LogicalTypeId::VARCHAR), scope_values));

		// expires_at (get from storage)
		auto expiration = storage->GetSecretExpiration(secret.GetName());
		if (expiration == std::chrono::system_clock::time_point()) {
			// No expiration data
			row.emplace_back(Value());
		} else {
			auto expires_time_t = std::chrono::system_clock::to_time_t(expiration);
			row.emplace_back(Value::TIMESTAMP(Timestamp::FromEpochSeconds(expires_time_t)));
		}

		result->secrets_data.push_back(std::move(row));
	}

	BOILSTREAM_LOG("BoilstreamSecretsInit: Loaded " << result->secrets_data.size() << " secrets");

	return std::move(result);
}

static void BoilstreamSecretsFunction(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &state = data_p.global_state->Cast<BoilstreamSecretsGlobalState>();

	idx_t count = 0;
	while (state.current_idx < state.secrets_data.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = state.secrets_data[state.current_idx];

		// Set each column value
		for (idx_t col_idx = 0; col_idx < row.size(); col_idx++) {
			output.SetValue(col_idx, count, row[col_idx]);
		}

		state.current_idx++;
		count++;
	}

	output.SetCardinality(count);
}

//===--------------------------------------------------------------------===//
// PRAGMA: Create Ducklake
//===--------------------------------------------------------------------===//

static string CreateDucklake(ClientContext &context, const FunctionParameters &params) {
	BOILSTREAM_LOG("CreateDucklake: Function called");

	if (params.values.empty()) {
		throw InvalidInputException("boilstream_create_ducklake requires a catalog_name parameter");
	}

	string catalog_name = params.values[0].ToString();
	string description = "";

	if (params.values.size() > 1 && !params.values[1].IsNull()) {
		description = params.values[1].ToString();
	}

	BOILSTREAM_LOG("CreateDucklake: catalog_name=" << catalog_name << ", description=" << description);

	// Validate catalog_name
	if (catalog_name.empty()) {
		throw InvalidInputException("catalog_name cannot be empty");
	}

	// Get global storage
	auto storage = GetGlobalStorage();
	if (!storage) {
		throw InvalidInputException(
		    "boilstream_create_ducklake: No active session. Call PRAGMA boilstream_bootstrap_session first.");
	}

	// Get endpoint URL
	string endpoint_url = storage->GetEndpointUrl();
	if (endpoint_url.empty()) {
		throw InvalidInputException("boilstream_create_ducklake: No endpoint configured. Call PRAGMA "
		                            "boilstream_bootstrap_session first.");
	}

	// Construct the ducklakes creation URL
	string create_url = endpoint_url + "/ducklakes";
	BOILSTREAM_LOG("CreateDucklake: create_url=" << create_url);

	// Build request body using yyjson
	auto doc = duckdb_yyjson::yyjson_mut_doc_new(nullptr);
	auto obj = duckdb_yyjson::yyjson_mut_obj(doc);
	duckdb_yyjson::yyjson_mut_doc_set_root(doc, obj);

	duckdb_yyjson::yyjson_mut_obj_add_strcpy(doc, obj, "catalog_name", catalog_name.c_str());
	if (!description.empty()) {
		duckdb_yyjson::yyjson_mut_obj_add_strcpy(doc, obj, "description", description.c_str());
	}

	auto body_str = duckdb_yyjson::yyjson_mut_write(doc, 0, nullptr);
	string body(body_str);
	free(body_str);
	duckdb_yyjson::yyjson_mut_doc_free(doc);

	BOILSTREAM_LOG("CreateDucklake: Making POST request, body_len=" << body.size());

	// Make HTTP POST request
	string response;
	try {
		response = storage->HttpPost(create_url, body);
	} catch (const std::exception &e) {
		BOILSTREAM_LOG("CreateDucklake: Failed to create ducklake: " << e.what());
		throw IOException("Failed to create ducklake: %s", e.what());
	}

	BOILSTREAM_LOG("CreateDucklake: Ducklake created successfully");

	// Fetch all secrets to populate the newly created ducklake secrets
	BOILSTREAM_LOG("CreateDucklake: Fetching all secrets to populate new ducklake");
	try {
		auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
		auto secrets = storage->AllSecrets(transaction);
		BOILSTREAM_LOG("CreateDucklake: Successfully fetched and cached secrets");

		// Note: Auto-attach removed to prevent hanging when backends are not ready
		// Users should manually run: ATTACH 'ducklake:catalog_name' AS catalog_name;
		BOILSTREAM_LOG("CreateDucklake: Ducklake created, secrets cached. Use ATTACH to mount when ready.");
	} catch (const std::exception &e) {
		BOILSTREAM_LOG("CreateDucklake: Warning - Failed to fetch secrets: " << e.what());
		// Continue - ducklake was created, just failed to fetch secrets
	}

	// Return success message
	return "SELECT 'Ducklake created successfully' as status, '" + catalog_name + "' as catalog_name;";
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

	// Fetch all secrets and cache them in memory storage for DuckLake
	BOILSTREAM_LOG("SetEndpoint: Fetching all secrets to populate memory storage");
	vector<string> ducklake_names;
	try {
		auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
		auto secrets = storage->AllSecrets(transaction);
		BOILSTREAM_LOG("SetEndpoint: Successfully fetched and cached secrets");

		// Collect all ducklake secret names for auto-attach
		for (const auto &entry : secrets) {
			if (entry.secret && entry.secret->GetType() == "ducklake") {
				ducklake_names.push_back(entry.secret->GetName());
				BOILSTREAM_LOG("SetEndpoint: Found ducklake secret: " << entry.secret->GetName());
			}
		}
	} catch (const std::exception &e) {
		BOILSTREAM_LOG("SetEndpoint: Failed to fetch secrets: " << e.what());
		// Continue - not critical for login success
	}

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

	// Build multi-statement SQL: ATTACH statements + final SELECT
	// DuckDB will parse and execute these sequentially AFTER releasing the PRAGMA lock
	string result_sql = "";

	// Add ATTACH statements for each ducklake
	for (const auto &ducklake_name : ducklake_names) {
		string attach_stmt =
		    "ATTACH 'ducklake:" + ducklake_name + "' AS " + KeywordHelper::WriteOptionallyQuoted(ducklake_name) + ";\n";
		result_sql += attach_stmt;
		BOILSTREAM_LOG("SetEndpoint: Adding ATTACH statement for: " << ducklake_name);
	}

	// Add final SELECT statement showing status
	result_sql += "SELECT 'Session token obtained' as status, TIMESTAMP '" + string(expires_str) + "' as expires_at, " +
	              std::to_string(ducklake_names.size()) + " as ducklakes_attached;";

	BOILSTREAM_LOG("SetEndpoint: Returning multi-statement SQL with " << ducklake_names.size() << " ATTACH command(s)");

	// Return multi-statement SQL - DuckDB will parse and execute after lock is released
	// Do NOT echo the token to prevent leakage in logs/query history
	return result_sql;
}

//! PRAGMA function to register a new user with email/password
//! Usage: PRAGMA boilstream_register_user('https://localhost/email@example.com', 'SecurePassword123!');
//! Format: URL/path/email@domain.com where URL part is the endpoint and last part is email
//! Returns multi-statement SQL that displays:
//! 1. Registration status
//! 2. QR code via tp_qr() for TOTP enrollment
//! 3. Session ID for the next verification step
static string RegisterUser(ClientContext &context, const FunctionParameters &params) {
	BOILSTREAM_LOG("RegisterUser: Function called");

	if (params.values.size() < 2) {
		throw InvalidInputException("boilstream_register_user requires url_with_email and password parameters");
	}

	string url_with_email = params.values[0].ToString();
	string password = params.values[1].ToString();

	// Parse URL/email format: https://host:port/path/email@domain.com
	// Find the last '/' to separate base_url from email
	auto last_slash = url_with_email.rfind('/');
	if (last_slash == string::npos || last_slash == url_with_email.length() - 1) {
		throw InvalidInputException(
		    "boilstream_register_user: Invalid format. Use 'https://host/path/email@domain.com'");
	}

	string base_url = url_with_email.substr(0, last_slash);
	string email = url_with_email.substr(last_slash + 1);

	// Validate URL has protocol
	if (base_url.find("http://") != 0 && base_url.find("https://") != 0) {
		throw InvalidInputException("boilstream_register_user: URL must start with http:// or https://");
	}

	// Require HTTPS for security (unless localhost for testing)
	bool is_localhost = false;
	auto proto_end = base_url.find("://");
	if (proto_end != string::npos) {
		auto host_start = proto_end + 3;
		auto host_end = base_url.find('/', host_start);
		auto port_pos = base_url.find(':', host_start);

		// Port comes before path
		if (port_pos != string::npos && (host_end == string::npos || port_pos < host_end)) {
			host_end = port_pos;
		}

		string hostname = base_url.substr(host_start, host_end == string::npos ? string::npos : host_end - host_start);

		// Check for localhost variants (including IPv6)
		is_localhost = (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" || hostname == "[::1]");
	}

	if (!is_localhost && base_url.find("https://") != 0) {
		throw InvalidInputException("boilstream_register_user: URL must use HTTPS (or localhost for testing)");
	}

	BOILSTREAM_LOG("RegisterUser: base_url=" << base_url << ", email=" << email);

	// Validate email format using Rust FFI
	if (registration_validate_email(email.c_str()) != 0) {
		throw InvalidInputException("boilstream_register_user: Invalid email address format");
	}

	// Validate password strength using Rust FFI
	if (registration_validate_password(reinterpret_cast<const uint8_t *>(password.c_str()), password.size()) != 0) {
		throw InvalidInputException("boilstream_register_user: Password must be at least 12 characters");
	}

	// Check if we already have registration state (cached registration in progress)
	// This allows users to re-run the command to see the QR code again if it was truncated
	auto storage = GetGlobalStorage();
	if (!storage) {
		throw IOException("No boilstream storage available");
	}

	try {
		auto [cached_base_url, cached_session_token, cached_totp_uri] = storage->GetRegistrationState();

		// Only return cached response if it matches the current registration attempt
		if (cached_base_url == base_url && !cached_totp_uri.empty()) {
			BOILSTREAM_LOG("RegisterUser: Found cached registration state, returning cached QR code");

			// Extract secret from TOTP URI for manual entry
			string secret_key;
			size_t secret_pos = cached_totp_uri.find("secret=");
			if (secret_pos != string::npos) {
				size_t secret_start = secret_pos + 7;
				size_t secret_end = cached_totp_uri.find('&', secret_start);
				if (secret_end == string::npos) {
					secret_end = cached_totp_uri.length();
				}
				secret_key = cached_totp_uri.substr(secret_start, secret_end - secret_start);
			}

			// Format secret in groups of 4 characters for readability
			string formatted_secret;
			for (size_t i = 0; i < secret_key.length(); i += 4) {
				if (i > 0)
					formatted_secret += " ";
				formatted_secret += secret_key.substr(i, std::min(size_t(4), secret_key.length() - i));
			}

			// Return cached QR code response
			string result_sql = "INSTALL textplot FROM community;\n";
			result_sql += "LOAD textplot;\n";
			result_sql += "SELECT unnest(['" + formatted_secret +
			              "', 'PRAGMA boilstream_verify_mfa(''123456'');'] || string_split(tp_qr('" + cached_totp_uri +
			              "'), chr(10))) as qr_code;";

			return result_sql;
		}
	} catch (const IOException &) {
		// No cached state found, continue with normal registration flow
		BOILSTREAM_LOG("RegisterUser: No cached registration state, proceeding with normal registration");
	}

	// Helper: Make unauthenticated HTTP GET request (for public registration APIs)
	// Note: Returns response body for ALL status codes (2xx, 4xx, 5xx) - caller must parse JSON to check success
	auto http_get = [&](const string &url) -> string {
		auto &db = DatabaseInstance::GetDatabase(context);
		auto &http_util = HTTPUtil::Get(db);
		auto params = http_util.InitializeParameters(db, url);
		if (!params) {
			throw IOException("HTTP GET failed: Could not initialize HTTP parameters");
		}
		HTTPHeaders headers(db);
		headers.Insert("Content-Type", "application/json");

		// Response handlers for capturing body
		string response_body;
		auto response_handler = [&](const HTTPResponse &response) {
			// Don't use response.body - it may be empty when using content_handler
			return true;
		};
		auto content_handler = [&](const_data_ptr_t data, idx_t size) {
			// Build response body from streamed chunks
			response_body.append(reinterpret_cast<const char *>(data), size);
			return true;
		};

		GetRequestInfo request(url, headers, *params, response_handler, content_handler);
		auto response = http_util.Request(request);

		// Log status and body length for debugging
		auto status_code = static_cast<int>(response->status);
		BOILSTREAM_LOG("HTTP GET " << url << " -> status=" << status_code << " body_len=" << response_body.size());

		// Return body for all responses - registration APIs use JSON to communicate errors
		return response_body;
	};

	// Helper: Make unauthenticated HTTP POST request (for public registration APIs)
	// Note: Returns response body for ALL status codes (2xx, 4xx, 5xx) - caller must parse JSON to check success
	// Optional out_headers parameter to capture response headers (e.g., Set-Cookie)
	auto http_post = [&](const string &url, const string &body, const string &cookie = "",
	                     HTTPHeaders *out_headers = nullptr) -> string {
		auto &db = DatabaseInstance::GetDatabase(context);
		auto &http_util = HTTPUtil::Get(db);
		auto params = http_util.InitializeParameters(db, url);
		if (!params) {
			throw IOException("HTTP POST failed: Could not initialize HTTP parameters");
		}
		HTTPHeaders headers(db);
		headers.Insert("Content-Type", "application/json");
		if (!cookie.empty()) {
			headers.Insert("Cookie", cookie);
		}

		// PostRequestInfo stores response in buffer_out member (not via handlers)
		PostRequestInfo request(url, headers, *params, const_data_ptr_cast(body.c_str()), body.size());
		auto response = http_util.Request(request);

		// Capture response headers if requested
		if (out_headers) {
			*out_headers = response->headers;
		}

		// Get response body from buffer_out
		string response_body = request.buffer_out;

		// Log status and body length for debugging
		auto status_code = static_cast<int>(response->status);
		BOILSTREAM_LOG("HTTP POST " << url << " -> status=" << status_code << " body_len=" << response_body.size());

		// Return body for all responses - registration APIs use JSON to communicate errors
		// Don't check Success() - we need the body even for 4xx status codes
		return response_body;
	};

	// Step 1: Get CSRF token
	string csrf_url = base_url + "/auth/csrf";
	string csrf_response;
	try {
		csrf_response = http_get(csrf_url);
	} catch (const std::exception &e) {
		throw IOException("Failed to fetch CSRF token: %s", e.what());
	}

	// Parse CSRF token from JSON response
	auto csrf_doc = duckdb_yyjson::yyjson_read(csrf_response.c_str(), csrf_response.size(), 0);
	if (!csrf_doc) {
		string preview = csrf_response.substr(0, std::min<size_t>(500, csrf_response.size()));
		throw IOException("Failed to parse CSRF response. Response preview: %s", preview.c_str());
	}
	auto csrf_root = duckdb_yyjson::yyjson_doc_get_root(csrf_doc);
	auto csrf_token_val = duckdb_yyjson::yyjson_obj_get(csrf_root, "csrf_token");
	if (!csrf_token_val || !duckdb_yyjson::yyjson_is_str(csrf_token_val)) {
		duckdb_yyjson::yyjson_doc_free(csrf_doc);
		throw IOException("CSRF response missing csrf_token field");
	}
	string csrf_token = duckdb_yyjson::yyjson_get_str(csrf_token_val);
	duckdb_yyjson::yyjson_doc_free(csrf_doc);

	BOILSTREAM_LOG("RegisterUser: CSRF token obtained");

	// Step 2: POST /auth/email/signup
	string signup_url = base_url + "/auth/email/signup";

	auto signup_doc = duckdb_yyjson::yyjson_mut_doc_new(nullptr);
	auto signup_obj = duckdb_yyjson::yyjson_mut_obj(signup_doc);
	duckdb_yyjson::yyjson_mut_doc_set_root(signup_doc, signup_obj);

	duckdb_yyjson::yyjson_mut_obj_add_strcpy(signup_doc, signup_obj, "email", email.c_str());
	duckdb_yyjson::yyjson_mut_obj_add_strcpy(signup_doc, signup_obj, "password", password.c_str());
	duckdb_yyjson::yyjson_mut_obj_add_strcpy(signup_doc, signup_obj, "csrf_token", csrf_token.c_str());

	auto signup_body_str = duckdb_yyjson::yyjson_mut_write(signup_doc, 0, nullptr);
	string signup_body(signup_body_str);
	free(signup_body_str);
	duckdb_yyjson::yyjson_mut_doc_free(signup_doc);

	string signup_response;
	try {
		signup_response = http_post(signup_url, signup_body);
	} catch (const std::exception &e) {
		throw IOException("Signup failed: %s", e.what());
	}

	// Check if response is empty
	if (signup_response.empty()) {
		throw IOException(
		    "Signup response is empty - server may not be responding or HTTPS certificate validation failed");
	}

	BOILSTREAM_LOG("RegisterUser: signup response size=" << signup_response.size());

	// Parse signup response
	auto signup_resp_doc = duckdb_yyjson::yyjson_read(signup_response.c_str(), signup_response.size(), 0);
	if (!signup_resp_doc) {
		// Show first 500 chars of response for debugging
		string preview = signup_response.substr(0, std::min<size_t>(500, signup_response.size()));
		throw IOException("Failed to parse signup response. Response preview: %s", preview.c_str());
	}
	auto signup_resp_root = duckdb_yyjson::yyjson_doc_get_root(signup_resp_doc);
	auto success_val = duckdb_yyjson::yyjson_obj_get(signup_resp_root, "success");
	bool success = success_val && duckdb_yyjson::yyjson_get_bool(success_val);

	if (!success) {
		auto error_val = duckdb_yyjson::yyjson_obj_get(signup_resp_root, "error");
		string error_msg = error_val ? duckdb_yyjson::yyjson_get_str(error_val) : "Unknown error";
		duckdb_yyjson::yyjson_doc_free(signup_resp_doc);
		throw IOException("Signup failed: %s", error_msg.c_str());
	}
	duckdb_yyjson::yyjson_doc_free(signup_resp_doc);

	BOILSTREAM_LOG("RegisterUser: Signup successful");

	// Step 3: POST /auth/email/login to get session
	// Note: CSRF tokens are valid for 5 minutes, so we can reuse the same token
	string login_url = base_url + "/auth/email/login";

	auto login_doc = duckdb_yyjson::yyjson_mut_doc_new(nullptr);
	auto login_obj = duckdb_yyjson::yyjson_mut_obj(login_doc);
	duckdb_yyjson::yyjson_mut_doc_set_root(login_doc, login_obj);

	duckdb_yyjson::yyjson_mut_obj_add_strcpy(login_doc, login_obj, "email", email.c_str());
	duckdb_yyjson::yyjson_mut_obj_add_strcpy(login_doc, login_obj, "password", password.c_str());
	duckdb_yyjson::yyjson_mut_obj_add_strcpy(login_doc, login_obj, "csrf_token", csrf_token.c_str());

	auto login_body_str = duckdb_yyjson::yyjson_mut_write(login_doc, 0, nullptr);
	string login_body(login_body_str);
	free(login_body_str);
	duckdb_yyjson::yyjson_mut_doc_free(login_doc);

	// Capture response headers to get Set-Cookie
	auto &db = DatabaseInstance::GetDatabase(context);
	HTTPHeaders login_response_headers(db);
	string login_response;
	try {
		login_response = http_post(login_url, login_body, "", &login_response_headers);
	} catch (const std::exception &e) {
		throw IOException("Login failed: %s", e.what());
	}

	// Parse login response to get session_id
	auto login_resp_doc = duckdb_yyjson::yyjson_read(login_response.c_str(), login_response.size(), 0);
	if (!login_resp_doc) {
		string preview = login_response.substr(0, std::min<size_t>(500, login_response.size()));
		throw IOException("Failed to parse login response. Response preview: %s", preview.c_str());
	}
	auto login_resp_root = duckdb_yyjson::yyjson_doc_get_root(login_resp_doc);
	auto login_success_val = duckdb_yyjson::yyjson_obj_get(login_resp_root, "success");
	bool login_success = login_success_val && duckdb_yyjson::yyjson_get_bool(login_success_val);

	if (!login_success) {
		auto error_val = duckdb_yyjson::yyjson_obj_get(login_resp_root, "error");
		string error_msg = error_val ? duckdb_yyjson::yyjson_get_str(error_val) : "Unknown error";
		duckdb_yyjson::yyjson_doc_free(login_resp_doc);
		throw IOException("Login failed: %s", error_msg.c_str());
	}

	duckdb_yyjson::yyjson_doc_free(login_resp_doc);

	// Extract session token from Set-Cookie header (not from JSON body)
	auto set_cookie_header = login_response_headers.GetHeaderValue("set-cookie");
	if (set_cookie_header.empty()) {
		throw IOException("Login response missing Set-Cookie header");
	}

	// Parse session token from Set-Cookie header
	// Format: "session={token}; HttpOnly; SameSite=Lax; Path=/auth; Max-Age={seconds}; Secure"
	string session_token;
	size_t session_pos = set_cookie_header.find("session=");
	if (session_pos == string::npos) {
		throw IOException("Set-Cookie header missing session cookie: %s", set_cookie_header.c_str());
	}

	size_t value_start = session_pos + 8; // Length of "session="
	size_t value_end = set_cookie_header.find(';', value_start);
	if (value_end == string::npos) {
		value_end = set_cookie_header.length();
	}

	session_token = set_cookie_header.substr(value_start, value_end - value_start);
	if (session_token.empty()) {
		throw IOException("Extracted session token is empty from Set-Cookie header");
	}

	BOILSTREAM_LOG("RegisterUser: Session token extracted from Set-Cookie header");

	BOILSTREAM_LOG("RegisterUser: Login successful, session_id obtained");

	// Step 4: POST /auth/api/mfa/enroll/totp to get TOTP secret
	string totp_enroll_url = base_url + "/auth/api/mfa/enroll/totp";

	auto totp_doc = duckdb_yyjson::yyjson_mut_doc_new(nullptr);
	auto totp_obj = duckdb_yyjson::yyjson_mut_obj(totp_doc);
	duckdb_yyjson::yyjson_mut_doc_set_root(totp_doc, totp_obj);
	// Empty body for enrollment
	auto totp_body_str = duckdb_yyjson::yyjson_mut_write(totp_doc, 0, nullptr);
	string totp_body(totp_body_str);
	free(totp_body_str);
	duckdb_yyjson::yyjson_mut_doc_free(totp_doc);

	// Make authenticated request with session cookie
	// Cookie format: "session={token}" as per server spec
	string session_cookie = "session=" + session_token;
	string totp_response;
	try {
		totp_response = http_post(totp_enroll_url, totp_body, session_cookie);
	} catch (const std::exception &e) {
		throw IOException("TOTP enrollment failed: %s", e.what());
	}

	// Parse TOTP enrollment response
	auto totp_resp_doc = duckdb_yyjson::yyjson_read(totp_response.c_str(), totp_response.size(), 0);
	if (!totp_resp_doc) {
		string preview = totp_response.substr(0, std::min<size_t>(500, totp_response.size()));
		throw IOException("Failed to parse TOTP enrollment response. Response preview: %s", preview.c_str());
	}
	auto totp_resp_root = duckdb_yyjson::yyjson_doc_get_root(totp_resp_doc);
	auto secret_val = duckdb_yyjson::yyjson_obj_get(totp_resp_root, "secret");
	if (!secret_val || !duckdb_yyjson::yyjson_is_str(secret_val)) {
		duckdb_yyjson::yyjson_doc_free(totp_resp_doc);
		throw IOException("TOTP enrollment response missing secret");
	}
	string totp_secret = duckdb_yyjson::yyjson_get_str(secret_val);
	duckdb_yyjson::yyjson_doc_free(totp_resp_doc);

	BOILSTREAM_LOG("RegisterUser: TOTP secret obtained");

	// Build TOTP URI using Rust FFI
	char totp_uri_buffer[512];
	long uri_len = registration_build_totp_uri(email.c_str(), totp_secret.c_str(), nullptr, totp_uri_buffer,
	                                           sizeof(totp_uri_buffer));
	if (uri_len < 0) {
		throw IOException("Failed to build TOTP URI");
	}
	string totp_uri(totp_uri_buffer, uri_len);

	BOILSTREAM_LOG("RegisterUser: TOTP URI built successfully");

	// Store registration state for MFA verification step
	BOILSTREAM_LOG("RegisterUser: Storing session token (first 8 chars): "
	               << session_token.substr(0, std::min<size_t>(8, session_token.length()))
	               << "... (total length=" << session_token.length() << ")");
	storage->StoreRegistrationState(base_url, session_token, totp_uri);
	BOILSTREAM_LOG("RegisterUser: Registration state stored successfully");

	// Extract secret from TOTP URI for manual entry
	// URI format: otpauth://totp/email?secret=BASE32SECRET&issuer=BoilStream&algorithm=SHA256&digits=6&period=30
	string secret_key;
	size_t secret_pos = totp_uri.find("secret=");
	if (secret_pos != string::npos) {
		size_t secret_start = secret_pos + 7; // Length of "secret="
		size_t secret_end = totp_uri.find('&', secret_start);
		if (secret_end == string::npos) {
			secret_end = totp_uri.length();
		}
		secret_key = totp_uri.substr(secret_start, secret_end - secret_start);
	}

	// Format secret in groups of 4 characters for readability
	string formatted_secret;
	for (size_t i = 0; i < secret_key.length(); i += 4) {
		if (i > 0)
			formatted_secret += " ";
		formatted_secret += secret_key.substr(i, std::min(size_t(4), secret_key.length() - i));
	}

	// Return QR code split into rows for scanning
	// In .mode csv, the full QR code will display without truncation
	// First row: formatted secret for manual entry (groups of 4, uppercase)
	// Second row: verification command
	// Remaining rows: QR code
	string result_sql = "INSTALL textplot FROM community;\n";
	result_sql += "LOAD textplot;\n";
	result_sql += "SELECT unnest(['" + formatted_secret +
	              "', 'PRAGMA boilstream_verify_mfa(''123456'');'] || string_split(tp_qr('" + totp_uri +
	              "'), chr(10))) as qr_code;";

	return result_sql;
}

//! PRAGMA function to verify MFA enrollment and complete registration
//! Usage: PRAGMA boilstream_verify_mfa('123456');
//! Returns backup codes for account recovery
static string VerifyMfa(ClientContext &context, const FunctionParameters &params) {
	BOILSTREAM_LOG("VerifyMfa: Function called");

	if (params.values.size() < 1) {
		throw InvalidInputException("boilstream_verify_mfa requires totp_code parameter");
	}

	string totp_code = params.values[0].ToString();

	// Validate TOTP code format (6 digits)
	if (totp_code.length() != 6) {
		throw InvalidInputException("boilstream_verify_mfa: TOTP code must be 6 digits");
	}
	for (char c : totp_code) {
		if (!std::isdigit(c)) {
			throw InvalidInputException("boilstream_verify_mfa: TOTP code must contain only digits");
		}
	}

	// Retrieve registration state from storage
	auto storage = GetGlobalStorage();
	if (!storage) {
		throw IOException("No boilstream storage available");
	}
	auto [base_url, session_token, totp_uri] = storage->GetRegistrationState();

	BOILSTREAM_LOG("VerifyMfa: Retrieved registration state, base_url=" << base_url);

	// Helper: Make unauthenticated HTTP POST request with cookie
	// Note: Returns response body for ALL status codes - caller must parse JSON to check success
	// Optional out_headers parameter to capture response headers
	auto http_post = [&](const string &url, const string &body, const string &cookie,
	                     HTTPHeaders *out_headers = nullptr) -> string {
		auto &db = DatabaseInstance::GetDatabase(context);
		auto &http_util = HTTPUtil::Get(db);
		auto params = http_util.InitializeParameters(db, url);
		if (!params) {
			throw IOException("HTTP POST failed: Could not initialize HTTP parameters");
		}
		HTTPHeaders headers(db);
		headers.Insert("Content-Type", "application/json");
		if (!cookie.empty()) {
			headers.Insert("Cookie", cookie);
			BOILSTREAM_LOG("HTTP POST: Added Cookie header: " << cookie.substr(0, std::min<size_t>(30, cookie.length()))
			                                                  << "...");
		} else {
			BOILSTREAM_LOG("HTTP POST: No cookie provided");
		}

		BOILSTREAM_LOG("HTTP POST: Sending request to " << url);
		BOILSTREAM_LOG("HTTP POST: Body length: " << body.size());

		// PostRequestInfo stores response in buffer_out member (not via handlers)
		PostRequestInfo request(url, headers, *params, const_data_ptr_cast(body.c_str()), body.size());
		auto response = http_util.Request(request);

		// Capture response headers if requested
		if (out_headers) {
			*out_headers = response->headers;
		}

		// Get response body from buffer_out
		string response_body = request.buffer_out;

		auto status_code = static_cast<int>(response->status);
		BOILSTREAM_LOG("HTTP POST " << url << " -> status=" << status_code << " body_len=" << response_body.size());

		// Return body for all responses - registration APIs use JSON to communicate errors
		// Don't check Success() - we need the body even for 4xx status codes
		return response_body;
	};

	// POST /auth/api/mfa/verify-enrollment
	string verify_url = base_url + "/auth/api/mfa/verify-enrollment";

	auto verify_doc = duckdb_yyjson::yyjson_mut_doc_new(nullptr);
	auto verify_obj = duckdb_yyjson::yyjson_mut_obj(verify_doc);
	duckdb_yyjson::yyjson_mut_doc_set_root(verify_doc, verify_obj);

	duckdb_yyjson::yyjson_mut_obj_add_strcpy(verify_doc, verify_obj, "method_type", "totp");
	duckdb_yyjson::yyjson_mut_obj_add_strcpy(verify_doc, verify_obj, "code", totp_code.c_str());
	// Note: secret is not needed for verify-enrollment, it's already stored server-side

	auto verify_body_str = duckdb_yyjson::yyjson_mut_write(verify_doc, 0, nullptr);
	string verify_body(verify_body_str);
	free(verify_body_str);
	duckdb_yyjson::yyjson_mut_doc_free(verify_doc);

	// Make authenticated request with session cookie
	// Cookie format: "session={token}" as per server spec
	string session_cookie = "session=" + session_token;

	BOILSTREAM_LOG("VerifyMfa: Sending request body: " << verify_body);
	BOILSTREAM_LOG("VerifyMfa: Session token (first 8 chars): "
	               << session_token.substr(0, std::min<size_t>(8, session_token.length()))
	               << "... (total length=" << session_token.length() << ")");
	BOILSTREAM_LOG("VerifyMfa: Cookie header: "
	               << session_cookie.substr(0, std::min<size_t>(20, session_cookie.length())) << "...");

	HTTPHeaders response_headers(DatabaseInstance::GetDatabase(context));
	string verify_response;
	try {
		verify_response = http_post(verify_url, verify_body, session_cookie, &response_headers);
	} catch (const std::exception &e) {
		throw IOException("MFA verification failed: %s", e.what());
	}

	BOILSTREAM_LOG(
	    "VerifyMfa: Response body: " << verify_response.substr(0, std::min<size_t>(200, verify_response.size())));

	// Handle empty response
	if (verify_response.empty()) {
		throw IOException(
		    "MFA verification failed: Server returned empty response (likely invalid session or expired token)");
	}

	// Parse verification response
	auto verify_resp_doc = duckdb_yyjson::yyjson_read(verify_response.c_str(), verify_response.size(), 0);
	if (!verify_resp_doc) {
		string preview = verify_response.substr(0, std::min<size_t>(500, verify_response.size()));
		throw IOException("Failed to parse verification response. Response preview: %s", preview.c_str());
	}
	auto verify_resp_root = duckdb_yyjson::yyjson_doc_get_root(verify_resp_doc);
	auto success_val = duckdb_yyjson::yyjson_obj_get(verify_resp_root, "success");
	bool success = success_val && duckdb_yyjson::yyjson_get_bool(success_val);

	if (!success) {
		auto error_val = duckdb_yyjson::yyjson_obj_get(verify_resp_root, "error");
		string error_msg = error_val ? duckdb_yyjson::yyjson_get_str(error_val) : "Invalid TOTP code";
		duckdb_yyjson::yyjson_doc_free(verify_resp_doc);
		throw IOException("MFA verification failed: %s", error_msg.c_str());
	}

	// Extract backup codes
	auto backup_codes_val = duckdb_yyjson::yyjson_obj_get(verify_resp_root, "backup_codes");
	vector<string> backup_codes;
	if (backup_codes_val && duckdb_yyjson::yyjson_is_arr(backup_codes_val)) {
		size_t arr_size = duckdb_yyjson::yyjson_arr_size(backup_codes_val);
		for (size_t i = 0; i < arr_size; i++) {
			auto code_val = duckdb_yyjson::yyjson_arr_get(backup_codes_val, i);
			if (code_val && duckdb_yyjson::yyjson_is_str(code_val)) {
				backup_codes.push_back(duckdb_yyjson::yyjson_get_str(code_val));
			}
		}
	}
	duckdb_yyjson::yyjson_doc_free(verify_resp_doc);

	BOILSTREAM_LOG("VerifyMfa: Verification successful, " << backup_codes.size() << " backup codes received");

	// Clear registration state after successful verification
	storage->ClearRegistrationState();

	// Build result SQL showing backup codes (one per row)
	string result_sql;
	if (!backup_codes.empty()) {
		result_sql = "SELECT unnest(['";
		for (size_t i = 0; i < backup_codes.size(); i++) {
			if (i > 0)
				result_sql += "', '";
			result_sql += backup_codes[i];
		}
		result_sql += "']) as backup_code;";
	} else {
		result_sql = "SELECT 'MFA enrollment complete - no backup codes provided' as status;";
	}

	return result_sql;
}

//! PRAGMA function to login with email/password + MFA code
//! Usage: PRAGMA boilstream_login('https://localhost/email@example.com', 'password', '123456');
//! Returns session status and expiration
static string Login(ClientContext &context, const FunctionParameters &params) {
	BOILSTREAM_LOG("Login: Function called");

	if (params.values.size() < 3) {
		throw InvalidInputException("boilstream_login requires url_with_email, password, and mfa_code parameters");
	}

	string url_with_email = params.values[0].ToString();
	string password = params.values[1].ToString();
	string mfa_code = params.values[2].ToString();

	// Parse URL to extract base_url and email
	// Expected format: https://localhost/email@example.com
	size_t last_slash = url_with_email.rfind('/');
	if (last_slash == string::npos || last_slash == url_with_email.length() - 1) {
		throw InvalidInputException("boilstream_login: Invalid URL format. Expected: https://host/email@example.com");
	}

	string base_url = url_with_email.substr(0, last_slash);
	string email = url_with_email.substr(last_slash + 1);

	// Validate URL has protocol
	if (base_url.find("http://") != 0 && base_url.find("https://") != 0) {
		throw InvalidInputException("boilstream_login: URL must start with http:// or https://");
	}

	// Require HTTPS for security (unless localhost for testing)
	bool is_localhost = false;
	auto proto_end = base_url.find("://");
	if (proto_end != string::npos) {
		auto host_start = proto_end + 3;
		auto host_end = base_url.find('/', host_start);
		auto port_pos = base_url.find(':', host_start);

		// Port comes before path
		if (port_pos != string::npos && (host_end == string::npos || port_pos < host_end)) {
			host_end = port_pos;
		}

		string hostname = base_url.substr(host_start, host_end == string::npos ? string::npos : host_end - host_start);

		// Check for localhost variants (including IPv6)
		is_localhost = (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" || hostname == "[::1]");
	}

	if (!is_localhost && base_url.find("https://") != 0) {
		throw InvalidInputException("boilstream_login: URL must use HTTPS (or localhost for testing)");
	}

	if (email.empty()) {
		throw InvalidInputException("boilstream_login: Email cannot be empty");
	}

	// Validate email format
	if (registration_validate_email(email.c_str()) != 0) {
		throw InvalidInputException("boilstream_login: Invalid email format");
	}

	// Validate password
	if (registration_validate_password(reinterpret_cast<const uint8_t *>(password.c_str()), password.size()) != 0) {
		throw InvalidInputException("boilstream_login: Password must be at least 12 characters");
	}

	// Validate MFA code format (6 digits)
	if (mfa_code.length() != 6) {
		throw InvalidInputException("boilstream_login: MFA code must be 6 digits");
	}
	for (char c : mfa_code) {
		if (!std::isdigit(c)) {
			throw InvalidInputException("boilstream_login: MFA code must contain only digits");
		}
	}

	BOILSTREAM_LOG("Login: Parsed base_url=" << base_url << ", email=" << email);

	// Helper: Make HTTP GET request
	auto http_get = [&](const string &url) -> string {
		auto &db = DatabaseInstance::GetDatabase(context);
		auto &http_util = HTTPUtil::Get(db);
		auto params = http_util.InitializeParameters(db, url);
		if (!params) {
			throw IOException("HTTP GET failed: Could not initialize HTTP parameters");
		}

		HTTPHeaders headers(db);
		string response_body;
		auto response_handler = [&](const HTTPResponse &response) -> bool {
			return true;
		};
		auto content_handler = [&](const_data_ptr_t data, idx_t size) -> bool {
			response_body.append(const_char_ptr_cast(data), size);
			return true;
		};

		GetRequestInfo request(url, headers, *params, response_handler, content_handler);
		auto response = http_util.Request(request);

		if (!response->Success()) {
			throw IOException("HTTP GET %s failed with status %d", url.c_str(), static_cast<int>(response->status));
		}

		return response_body;
	};

	// Helper: Make HTTP POST request
	auto http_post = [&](const string &url, const string &body, const string &cookie = "",
	                     HTTPHeaders *out_headers = nullptr) -> string {
		auto &db = DatabaseInstance::GetDatabase(context);
		auto &http_util = HTTPUtil::Get(db);
		auto params = http_util.InitializeParameters(db, url);
		if (!params) {
			throw IOException("HTTP POST failed: Could not initialize HTTP parameters");
		}
		HTTPHeaders headers(db);
		headers.Insert("Content-Type", "application/json");
		if (!cookie.empty()) {
			headers.Insert("Cookie", cookie);
		}

		PostRequestInfo request(url, headers, *params, const_data_ptr_cast(body.c_str()), body.size());
		auto response = http_util.Request(request);

		if (out_headers) {
			*out_headers = response->headers;
		}

		string response_body = request.buffer_out;

		auto status_code = static_cast<int>(response->status);
		BOILSTREAM_LOG("HTTP POST " << url << " -> status=" << status_code << " body_len=" << response_body.size());

		return response_body;
	};

	// Step 1: Get CSRF token
	string csrf_url = base_url + "/auth/csrf";
	string csrf_response;
	try {
		csrf_response = http_get(csrf_url);
	} catch (const std::exception &e) {
		throw IOException("Failed to fetch CSRF token: %s", e.what());
	}

	BOILSTREAM_LOG("Login: CSRF response: " << csrf_response.substr(0, std::min<size_t>(200, csrf_response.size())));

	auto csrf_doc = duckdb_yyjson::yyjson_read(csrf_response.c_str(), csrf_response.size(), 0);
	if (!csrf_doc) {
		string preview = csrf_response.substr(0, std::min<size_t>(100, csrf_response.size()));
		throw IOException("Failed to parse CSRF response. Response preview: %s", preview.c_str());
	}
	auto csrf_root = duckdb_yyjson::yyjson_doc_get_root(csrf_doc);
	auto csrf_token_val = duckdb_yyjson::yyjson_obj_get(csrf_root, "csrf_token");
	if (!csrf_token_val) {
		string preview = csrf_response.substr(0, std::min<size_t>(100, csrf_response.size()));
		duckdb_yyjson::yyjson_doc_free(csrf_doc);
		throw IOException("CSRF response missing csrf_token field. Response preview: %s", preview.c_str());
	}
	string csrf_token = duckdb_yyjson::yyjson_get_str(csrf_token_val);
	duckdb_yyjson::yyjson_doc_free(csrf_doc);

	BOILSTREAM_LOG("Login: CSRF token obtained");

	// Step 2: POST /auth/email/login (without MFA code - two-step flow)
	string login_url = base_url + "/auth/email/login";

	auto login_doc = duckdb_yyjson::yyjson_mut_doc_new(nullptr);
	auto login_obj = duckdb_yyjson::yyjson_mut_obj(login_doc);
	duckdb_yyjson::yyjson_mut_doc_set_root(login_doc, login_obj);

	duckdb_yyjson::yyjson_mut_obj_add_strcpy(login_doc, login_obj, "email", email.c_str());
	duckdb_yyjson::yyjson_mut_obj_add_strcpy(login_doc, login_obj, "password", password.c_str());
	duckdb_yyjson::yyjson_mut_obj_add_strcpy(login_doc, login_obj, "csrf_token", csrf_token.c_str());

	auto login_body_str = duckdb_yyjson::yyjson_mut_write(login_doc, 0, nullptr);
	string login_body(login_body_str);
	free(login_body_str);
	duckdb_yyjson::yyjson_mut_doc_free(login_doc);

	BOILSTREAM_LOG("Login: Posting credentials to /auth/email/login (step 1/2)");

	HTTPHeaders login_response_headers(DatabaseInstance::GetDatabase(context));
	string login_response;
	try {
		login_response = http_post(login_url, login_body, "", &login_response_headers);
	} catch (const std::exception &e) {
		throw IOException("Login request failed: %s", e.what());
	}

	// Check if login was successful by looking for Set-Cookie header
	// If the server returned 405, we need to check the response
	if (login_response.empty()) {
		throw IOException("Login failed: Server returned 405 (Method Not Allowed). The endpoint /auth/api/login might "
		                  "not support this login method.");
	}

	// Extract session token from Set-Cookie header
	string set_cookie_header;
	try {
		set_cookie_header = login_response_headers.GetHeaderValue("set-cookie");
	} catch (...) {
		// No Set-Cookie header - login probably failed
		throw IOException("Login failed: No session cookie returned. Response: %s",
		                  login_response.substr(0, 100).c_str());
	}
	if (set_cookie_header.empty()) {
		throw IOException("Login response missing Set-Cookie header");
	}

	// Parse session token from Set-Cookie header
	// Format: "session={token}; HttpOnly; SameSite=Lax; Path=/auth; Max-Age={seconds}; Secure"
	string session_token;
	size_t session_pos = set_cookie_header.find("session=");
	if (session_pos == string::npos) {
		throw IOException("Set-Cookie header missing session cookie: %s", set_cookie_header.c_str());
	}

	size_t value_start = session_pos + 8; // Length of "session="
	size_t value_end = set_cookie_header.find(';', value_start);
	if (value_end == string::npos) {
		value_end = set_cookie_header.length();
	}

	session_token = set_cookie_header.substr(value_start, value_end - value_start);
	BOILSTREAM_LOG("Login: Session token obtained from login");

	// Step 3: POST /auth/api/mfa/verify/totp with session cookie
	string mfa_url = base_url + "/auth/api/mfa/verify/totp";

	auto mfa_doc = duckdb_yyjson::yyjson_mut_doc_new(nullptr);
	auto mfa_obj = duckdb_yyjson::yyjson_mut_obj(mfa_doc);
	duckdb_yyjson::yyjson_mut_doc_set_root(mfa_doc, mfa_obj);

	duckdb_yyjson::yyjson_mut_obj_add_strcpy(mfa_doc, mfa_obj, "code", mfa_code.c_str());

	auto mfa_body_str = duckdb_yyjson::yyjson_mut_write(mfa_doc, 0, nullptr);
	string mfa_body(mfa_body_str);
	free(mfa_body_str);
	duckdb_yyjson::yyjson_mut_doc_free(mfa_doc);

	BOILSTREAM_LOG("Login: Posting MFA code to /auth/api/mfa/verify/totp (step 2/2)");

	string session_cookie = "session=" + session_token;
	string mfa_response;
	try {
		mfa_response = http_post(mfa_url, mfa_body, session_cookie);
	} catch (const std::exception &e) {
		throw IOException("MFA authentication failed: %s", e.what());
	}

	BOILSTREAM_LOG("Login: MFA response: " << mfa_response);

	// Parse MFA response to verify success
	auto mfa_resp_doc = duckdb_yyjson::yyjson_read(mfa_response.c_str(), mfa_response.size(), 0);
	if (!mfa_resp_doc) {
		string preview = mfa_response.substr(0, std::min<size_t>(100, mfa_response.size()));
		throw IOException("Failed to parse MFA response. Response preview: %s", preview.c_str());
	}
	auto mfa_resp_root = duckdb_yyjson::yyjson_doc_get_root(mfa_resp_doc);
	auto success_val = duckdb_yyjson::yyjson_obj_get(mfa_resp_root, "success");
	bool success = success_val && duckdb_yyjson::yyjson_get_bool(success_val);

	if (!success) {
		auto error_val = duckdb_yyjson::yyjson_obj_get(mfa_resp_root, "error");
		string error_msg = error_val ? duckdb_yyjson::yyjson_get_str(error_val) : "Invalid MFA code";
		duckdb_yyjson::yyjson_doc_free(mfa_resp_doc);
		throw IOException("MFA authentication failed: %s", error_msg.c_str());
	}
	duckdb_yyjson::yyjson_doc_free(mfa_resp_doc);

	BOILSTREAM_LOG("Login: MFA verification successful, now vending bootstrap token");

	// Step 4: POST /auth/api/bootstrap-token to get the bootstrap token
	string bootstrap_url_endpoint = base_url + "/auth/api/bootstrap-token";

	// Empty body for bootstrap token request
	string bootstrap_body = "{}";

	BOILSTREAM_LOG("Login: Requesting bootstrap token from /auth/api/bootstrap-token");

	string bootstrap_response;
	try {
		bootstrap_response = http_post(bootstrap_url_endpoint, bootstrap_body, session_cookie);
	} catch (const std::exception &e) {
		throw IOException("Bootstrap token request failed: %s", e.what());
	}

	BOILSTREAM_LOG("Login: Bootstrap response: " << bootstrap_response);

	// Parse bootstrap token response
	auto bootstrap_resp_doc = duckdb_yyjson::yyjson_read(bootstrap_response.c_str(), bootstrap_response.size(), 0);
	if (!bootstrap_resp_doc) {
		string preview = bootstrap_response.substr(0, std::min<size_t>(100, bootstrap_response.size()));
		throw IOException("Failed to parse bootstrap token response. Response preview: %s", preview.c_str());
	}
	auto bootstrap_resp_root = duckdb_yyjson::yyjson_doc_get_root(bootstrap_resp_doc);
	auto bootstrap_token_val = duckdb_yyjson::yyjson_obj_get(bootstrap_resp_root, "bootstrap_token");
	if (!bootstrap_token_val) {
		duckdb_yyjson::yyjson_doc_free(bootstrap_resp_doc);
		throw IOException("Bootstrap token response missing bootstrap_token field");
	}
	string bootstrap_token = duckdb_yyjson::yyjson_get_str(bootstrap_token_val);
	duckdb_yyjson::yyjson_doc_free(bootstrap_resp_doc);

	BOILSTREAM_LOG("Login: Bootstrap token obtained, now performing OPAQUE exchange");

	// Step 5: Perform OPAQUE bootstrap token exchange
	// This establishes the OPAQUE session with the bootstrap token
	auto storage = GetGlobalStorage();
	if (!storage) {
		throw IOException("No boilstream storage available");
	}

	// Construct endpoint URL (without bootstrap token suffix)
	string endpoint_url = base_url + "/secrets";

	// Hash the bootstrap token to check for reuse
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

	// Check if this is the same bootstrap token from an existing valid session
	if (storage->GetBootstrapTokenHash() == incoming_token_hash && !incoming_token_hash.empty() &&
	    storage->IsSessionTokenValid()) {
		BOILSTREAM_LOG("Login: Bootstrap token matches existing session, skipping exchange");

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
	storage->ClearSession();

	// Perform OPAQUE login
	try {
		storage->SetEndpoint(endpoint_url);
		BOILSTREAM_LOG("Login: endpoint_url=" << endpoint_url);

		storage->PerformOpaqueLogin(bootstrap_token);
		BOILSTREAM_LOG("Login: OPAQUE login successful");

		// Store bootstrap token hash for reuse detection
		storage->SetBootstrapTokenHash(incoming_token_hash);
		BOILSTREAM_LOG("Login: Stored bootstrap token hash");
	} catch (const std::exception &e) {
		// Rollback endpoint on failure - ensure consistent state
		storage->SetEndpoint("");
		storage->ClearSession();
		BOILSTREAM_LOG("Login: OPAQUE login failed, rolled back: " << e.what());
		throw IOException("OPAQUE login failed: %s", e.what());
	}

	// Set context for this connection (use hash of bootstrap token, not the token itself)
	string user_id = incoming_token_hash.substr(0, 16);
	SetUserContext(context, user_id);

	// Fetch all secrets and cache them in memory storage for DuckLake
	BOILSTREAM_LOG("Login: Fetching all secrets to populate memory storage");
	vector<string> ducklake_names;
	try {
		auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
		auto secrets = storage->AllSecrets(transaction);
		BOILSTREAM_LOG("Login: Successfully fetched and cached secrets");

		// Collect all ducklake secret names for auto-attach
		for (const auto &entry : secrets) {
			if (entry.secret && entry.secret->GetType() == "ducklake") {
				ducklake_names.push_back(entry.secret->GetName());
				BOILSTREAM_LOG("Login: Found ducklake secret: " << entry.secret->GetName());
			}
		}
	} catch (const std::exception &e) {
		BOILSTREAM_LOG("Login: Failed to fetch secrets: " << e.what());
		// Continue - not critical for login success
	}

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

	// Build multi-statement SQL: ATTACH statements + final SELECT
	string result_sql = "";

	// Add ATTACH statements for each ducklake
	for (const auto &ducklake_name : ducklake_names) {
		string attach_stmt =
		    "ATTACH 'ducklake:" + ducklake_name + "' AS " + KeywordHelper::WriteOptionallyQuoted(ducklake_name) + ";\n";
		result_sql += attach_stmt;
		BOILSTREAM_LOG("Login: Adding ATTACH statement for: " << ducklake_name);
	}

	// Add final SELECT statement showing status
	result_sql += "SELECT 'Session token obtained' as status, TIMESTAMP '" + string(expires_str) + "' as expires_at, " +
	              std::to_string(ducklake_names.size()) + " as ducklakes_attached;";

	BOILSTREAM_LOG("Login: Returning multi-statement SQL with " << ducklake_names.size() << " ATTACH command(s)");

	return result_sql;
}

//! PRAGMA function to display help for all boilstream PRAGMAs
//! Usage: PRAGMA boilstream_help();
//! Returns table with PRAGMA names, parameters, and descriptions
static string Help(ClientContext &context, const FunctionParameters &params) {
	string result_sql = "SELECT unnest([\n";
	result_sql += "  '═══════════════════════════════════════════════════════════════════',\n";
	result_sql += "  'SECURITY WARNING: Passwords in CLI commands are saved to shell history!',\n";
	result_sql += "  'For production: Use Web Auth GUI or clear history: rm ~/.duckdb_history',\n";
	result_sql += "  '═══════════════════════════════════════════════════════════════════',\n";
	result_sql += "  '',\n";
	result_sql += "  'PRAGMA boilstream_register_user(url_with_email, password)',\n";
	result_sql += "  '  - Register new user with email/password. Returns TOTP secret and QR code.',\n";
	result_sql += "  '  - TIP: Use .maxrows 50 or .mode csv to see the full QR code.',\n";
	result_sql += "  '  - NOTE: Does not work if server uses SAML SSO (centralized user management).',\n";
	result_sql += "  '  - SECURE ALTERNATIVE: Use Web Auth GUI for registration instead.',\n";
	result_sql += "  '  .maxrows 50',\n";
	result_sql += "  '  PRAGMA boilstream_register_user(''https://localhost/email@example.com'', ''password123'');',\n";
	result_sql += "  '',\n";
	result_sql += "  'PRAGMA boilstream_verify_mfa(totp_code)',\n";
	result_sql += "  '  - Verify TOTP code after registration. Returns backup codes.',\n";
	result_sql += "  '  PRAGMA boilstream_verify_mfa(''123456'');',\n";
	result_sql += "  '',\n";
	result_sql += "  'PRAGMA boilstream_login(url_with_email, password, mfa_code)',\n";
	result_sql += "  '  - Login with email/password/MFA. Establishes OPAQUE session.',\n";
	result_sql += "  '  - NOTE: Automatically calls boilstream_bootstrap_session()',\n";
	result_sql += "  '  - SECURE ALTERNATIVE: Use Web Auth GUI for login instead.',\n";
	result_sql +=
	    "  '  PRAGMA boilstream_login(''https://localhost/email@example.com'', ''password123'', ''123456'');',\n";
	result_sql += "  '',\n";
	result_sql += "  'PRAGMA boilstream_bootstrap_session(url_with_token)',\n";
	result_sql += "  '  - Login with bootstrap token. Establishes OPAQUE session.',\n";
	result_sql += "  '  PRAGMA boilstream_bootstrap_session(''https://localhost/secrets/:token'');',\n";
	result_sql += "  '',\n";
	result_sql += "  'PRAGMA boilstream_create_ducklake(name, [description])',\n";
	result_sql += "  '  - Create a new ducklake. Requires active session.',\n";
	result_sql += "  '  PRAGMA boilstream_create_ducklake(''my_lake'', ''Optional description'');',\n";
	result_sql += "  '',\n";
	result_sql += "  'SELECT * FROM boilstream_ducklakes()',\n";
	result_sql += "  '  - List all ducklakes. Requires active session.',\n";
	result_sql += "  '',\n";
	result_sql += "  'SELECT * FROM boilstream_secrets()',\n";
	result_sql += "  '  - List all secrets. Requires active session.'\n";
	result_sql += "]) as help;";

	return result_sql;
}

//! Load the extension
static void LoadInternal(ExtensionLoader &loader) {
	BOILSTREAM_LOG("LoadInternal: Extension loading started");

	// Register global storage
	auto &db = loader.GetDatabaseInstance();
	BOILSTREAM_LOG("LoadInternal: Successfully got database instance");

	// Auto-load httpfs extension for HTTPS support
	BOILSTREAM_LOG("LoadInternal: Attempting to auto-load httpfs extension for HTTPS support");
	if (ExtensionHelper::TryAutoLoadExtension(db, "httpfs")) {
		BOILSTREAM_LOG("LoadInternal: httpfs extension loaded successfully");
	} else {
		BOILSTREAM_LOG("LoadInternal: WARNING - Failed to auto-load httpfs extension. HTTPS may not work.");
	}

	// Auto-load postgres_scanner extension for postgres secrets
	BOILSTREAM_LOG("LoadInternal: Attempting to auto-load postgres_scanner extension for postgres secrets");
	if (ExtensionHelper::TryAutoLoadExtension(db, "postgres_scanner")) {
		BOILSTREAM_LOG("LoadInternal: postgres_scanner extension loaded successfully");
	} else {
		BOILSTREAM_LOG(
		    "LoadInternal: WARNING - Failed to auto-load postgres_scanner extension. Postgres secrets may not work.");
	}

	// Auto-load ducklake extension for ducklake ATTACH support
	BOILSTREAM_LOG("LoadInternal: Attempting to auto-load ducklake extension for ducklake ATTACH");
	if (ExtensionHelper::TryAutoLoadExtension(db, "ducklake")) {
		BOILSTREAM_LOG("LoadInternal: ducklake extension loaded successfully");
	} else {
		BOILSTREAM_LOG(
		    "LoadInternal: WARNING - Failed to auto-load ducklake extension. ATTACH ducklake commands may not work.");
	}

	// Initialize storage with empty endpoint URL (will be set via PRAGMA call)
	auto storage = make_uniq<RestApiSecretStorage>(db, "");

	{
		lock_guard<mutex> lock(global_storage_lock);
		global_rest_storage = storage.get();
	}

	auto &secret_manager = db.GetSecretManager();
	secret_manager.LoadSecretStorage(std::move(storage));
	BOILSTREAM_LOG("LoadInternal: Secret storage registered");

	// Set boilstream as the default persistent storage
	secret_manager.SetDefaultStorage("boilstream");
	BOILSTREAM_LOG("LoadInternal: Set boilstream as default persistent storage");

	// Register PRAGMA function with PragmaCall to accept parameters
	// Use temporary LogicalType objects to avoid ODR violations with static const members
	vector<LogicalType> endpoint_params;
	endpoint_params.push_back(LogicalType(LogicalTypeId::VARCHAR));
	auto rest_endpoint =
	    PragmaFunction::PragmaCall("boilstream_bootstrap_session", SetRestApiEndpoint, endpoint_params);
	loader.RegisterFunction(rest_endpoint);
	BOILSTREAM_LOG("LoadInternal: boilstream_bootstrap_session PRAGMA registered");

	// Register PRAGMA function to create ducklakes (with optional description)
	// Note: We use varargs to make the description parameter optional
	vector<LogicalType> ducklake_params;
	ducklake_params.push_back(LogicalType(LogicalTypeId::VARCHAR));
	auto create_ducklake = PragmaFunction::PragmaCall("boilstream_create_ducklake", CreateDucklake, ducklake_params,
	                                                  LogicalType(LogicalTypeId::VARCHAR));
	loader.RegisterFunction(create_ducklake);
	BOILSTREAM_LOG("LoadInternal: boilstream_create_ducklake PRAGMA registered");

	// Register PRAGMA function for user registration (email + password)
	vector<LogicalType> register_params;
	register_params.push_back(LogicalType(LogicalTypeId::VARCHAR)); // email
	register_params.push_back(LogicalType(LogicalTypeId::VARCHAR)); // password
	auto register_user = PragmaFunction::PragmaCall("boilstream_register_user", RegisterUser, register_params);
	loader.RegisterFunction(register_user);
	BOILSTREAM_LOG("LoadInternal: boilstream_register_user PRAGMA registered");

	// Register PRAGMA function for MFA verification (totp_code only)
	vector<LogicalType> verify_params;
	verify_params.push_back(LogicalType(LogicalTypeId::VARCHAR)); // totp_code
	auto verify_mfa = PragmaFunction::PragmaCall("boilstream_verify_mfa", VerifyMfa, verify_params);
	loader.RegisterFunction(verify_mfa);
	BOILSTREAM_LOG("LoadInternal: boilstream_verify_mfa PRAGMA registered");

	// Register PRAGMA function for login (email + password + MFA code)
	vector<LogicalType> login_params;
	login_params.push_back(LogicalType(LogicalTypeId::VARCHAR)); // url_with_email
	login_params.push_back(LogicalType(LogicalTypeId::VARCHAR)); // password
	login_params.push_back(LogicalType(LogicalTypeId::VARCHAR)); // mfa_code
	auto login_func = PragmaFunction::PragmaCall("boilstream_login", Login, login_params);
	loader.RegisterFunction(login_func);
	BOILSTREAM_LOG("LoadInternal: boilstream_login PRAGMA registered");

	// Register PRAGMA function for help (supports both PRAGMA boilstream_help; and PRAGMA boilstream_help();)
	vector<LogicalType> help_params;
	auto help_func = PragmaFunction::PragmaCall("boilstream_help", Help, help_params);
	loader.RegisterFunction(help_func);
	BOILSTREAM_LOG("LoadInternal: boilstream_help PRAGMA registered");

	// Register boilstream_ducklakes table function
	TableFunction ducklakes_function("boilstream_ducklakes", {}, BoilstreamDucklakesFunction, BoilstreamDucklakesBind,
	                                 BoilstreamDucklakesInit);
	loader.RegisterFunction(ducklakes_function);
	BOILSTREAM_LOG("LoadInternal: boilstream_ducklakes table function registered");

	// Register boilstream_secrets table function
	TableFunction secrets_function("boilstream_secrets", {}, BoilstreamSecretsFunction, BoilstreamSecretsBind,
	                               BoilstreamSecretsInit);
	loader.RegisterFunction(secrets_function);
	BOILSTREAM_LOG("LoadInternal: boilstream_secrets table function registered");

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
	return "0.4.0";
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
