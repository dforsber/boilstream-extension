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
		    "boilstream_ducklakes: No active session. Call PRAGMA duckdb_secrets_boilstream_endpoint first.");
	}

	BOILSTREAM_LOG("BoilstreamDucklakesInit: Fetching ducklakes from API");

	// Get the endpoint URL and validate it's configured
	string endpoint_url = storage->GetEndpointUrl();
	if (endpoint_url.empty()) {
		throw InvalidInputException(
		    "boilstream_ducklakes: No endpoint configured. Call PRAGMA duckdb_secrets_boilstream_endpoint first.");
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
		    "boilstream_secrets: No active session. Call PRAGMA duckdb_secrets_boilstream_endpoint first.");
	}

	// Validate endpoint is configured
	string endpoint_url = storage->GetEndpointUrl();
	if (endpoint_url.empty()) {
		throw InvalidInputException(
		    "boilstream_secrets: No endpoint configured. Call PRAGMA duckdb_secrets_boilstream_endpoint first.");
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
		    "boilstream_create_ducklake: No active session. Call PRAGMA duckdb_secrets_boilstream_endpoint first.");
	}

	// Get endpoint URL
	string endpoint_url = storage->GetEndpointUrl();
	if (endpoint_url.empty()) {
		throw InvalidInputException("boilstream_create_ducklake: No endpoint configured. Call PRAGMA "
		                            "duckdb_secrets_boilstream_endpoint first.");
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
	    PragmaFunction::PragmaCall("duckdb_secrets_boilstream_endpoint", SetRestApiEndpoint, endpoint_params);
	loader.RegisterFunction(rest_endpoint);
	BOILSTREAM_LOG("LoadInternal: duckdb_secrets_boilstream_endpoint PRAGMA registered");

	// Register PRAGMA function to create ducklakes (with optional description)
	// Note: We use varargs to make the description parameter optional
	vector<LogicalType> ducklake_params;
	ducklake_params.push_back(LogicalType(LogicalTypeId::VARCHAR));
	auto create_ducklake = PragmaFunction::PragmaCall("boilstream_create_ducklake", CreateDucklake, ducklake_params,
	                                                  LogicalType(LogicalTypeId::VARCHAR));
	loader.RegisterFunction(create_ducklake);
	BOILSTREAM_LOG("LoadInternal: boilstream_create_ducklake PRAGMA registered");

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
	return "0.3.5";
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
