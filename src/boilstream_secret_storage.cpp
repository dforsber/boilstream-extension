//===----------------------------------------------------------------------===//
//                         DuckDB
//
// boilstream_secret_storage.cpp
//
//
//===----------------------------------------------------------------------===//

#include "boilstream_secret_storage.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/common/serializer/memory_stream.hpp"
#include "duckdb/common/serializer/binary_serializer.hpp"
#include "duckdb/common/serializer/binary_deserializer.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/http_util.hpp"
#include "yyjson.hpp"
#include <sstream>
#include <thread>
#include <chrono>
#include <iostream>

using namespace duckdb_yyjson;

namespace duckdb {

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

RestApiSecretStorage::RestApiSecretStorage(DatabaseInstance &db_p, const string &endpoint_url_p,
                                           const string &auth_token_p)
    : CatalogSetSecretStorage(db_p, "boilstream", 5), // offset=5 for higher priority than built-in storages (10, 20)
      endpoint_url(endpoint_url_p), auth_token(auth_token_p) {
	secrets = make_uniq<CatalogSet>(Catalog::GetSystemCatalog(db));
	persistent = true; // Acts as persistent storage
}

void RestApiSecretStorage::SetEndpoint(const string &endpoint) {
	lock_guard<mutex> lock(endpoint_lock);
	endpoint_url = endpoint;
}

void RestApiSecretStorage::SetAuthToken(const string &token) {
	lock_guard<mutex> lock(endpoint_lock);
	auth_token = token;
}

void RestApiSecretStorage::SetUserContextForConnection(idx_t connection_id, const string &user_id) {
	lock_guard<mutex> lock(connection_lock);
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
	lock_guard<mutex> lock(connection_lock);
	connection_user_map.erase(std::to_string(connection_id));
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
	MemoryStream stream;
	BinarySerializer serializer(stream);
	serializer.Begin();
	secret.Serialize(serializer);
	serializer.End();

	auto data = stream.GetData();
	auto encoded = Blob::ToBase64(string_t((const char *)data, stream.GetPosition()));

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

	// Add expires_at with 1 hour TTL (ISO 8601 UTC format)
	auto now = std::chrono::system_clock::now();
	auto expires_at_time = now + std::chrono::hours(1);
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
	auto json_str = yyjson_mut_write(doc, 0, nullptr);
	string result(json_str);
	free(json_str);
	yyjson_mut_doc_free(doc);

	return result;
}

unique_ptr<BaseSecret> RestApiSecretStorage::DeserializeSecret(const string &json_data, SecretManager &manager) {
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

	auto encoded = yyjson_get_str(data_val);
	auto decoded = Blob::FromBase64(string_t(encoded));

	// Deserialize the secret (ensure yyjson doc is freed even if deserialization throws)
	unique_ptr<BaseSecret> secret;
	try {
		MemoryStream stream((data_ptr_t)decoded.c_str(), decoded.size());
		BinaryDeserializer deserializer(stream);
		deserializer.Begin();
		secret = manager.DeserializeSecret(deserializer);
		deserializer.End();
	} catch (...) {
		yyjson_doc_free(doc);
		throw;
	}

	yyjson_doc_free(doc);
	return secret;
}

std::chrono::system_clock::time_point RestApiSecretStorage::ParseExpiresAt(const string &expires_at_str) {
	// Parse ISO 8601 UTC timestamp (e.g., "2025-10-06T15:30:00Z")
	// Format: YYYY-MM-DDTHH:MM:SSZ
	std::tm tm = {};

	// Manual parsing since std::get_time is not available in C++11
	int year, month, day, hour, minute, second;
	char t_sep, z_suffix;

	std::istringstream ss(expires_at_str);
	ss >> year >> std::noskipws >> std::skipws;
	ss.ignore(1); // skip '-'
	ss >> month;
	ss.ignore(1); // skip '-'
	ss >> day >> t_sep >> hour;
	ss.ignore(1); // skip ':'
	ss >> minute;
	ss.ignore(1); // skip ':'
	ss >> second >> z_suffix;

	if (ss.fail() || t_sep != 'T' || z_suffix != 'Z') {
		// If parsing fails, return a time in the past (already expired)
		return std::chrono::system_clock::time_point::min();
	}

	tm.tm_year = year - 1900;
	tm.tm_mon = month - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = minute;
	tm.tm_sec = second;
	tm.tm_isdst = 0;

	// Convert to time_point (cross-platform UTC conversion)
	// timegm() is POSIX but not portable to Windows
	// Manual UTC calculation: seconds since epoch (1970-01-01 00:00:00)
	time_t time_t_val = 0;

#ifdef _WIN32
	// Windows: use _mkgmtime
	time_t_val = _mkgmtime(&tm);
#else
	// POSIX: use timegm
	time_t_val = timegm(&tm);
#endif

	if (time_t_val == -1) {
		// Invalid time, return expired
		return std::chrono::system_clock::time_point::min();
	}

	return std::chrono::system_clock::from_time_t(time_t_val);
}

bool RestApiSecretStorage::IsExpired(const string &secret_name) {
	lock_guard<mutex> lock(expiration_lock);

	auto it = secret_expiration.find(secret_name);
	if (it == secret_expiration.end()) {
		// No expiration data, consider expired (need to fetch)
		return true;
	}

	// Consider expired if less than 5 minutes remaining
	// This ensures proactive refresh before credentials become invalid
	const auto BUFFER = std::chrono::minutes(5);
	auto now = std::chrono::system_clock::now();
	return now >= (it->second - BUFFER);
}

void RestApiSecretStorage::StoreExpiration(const string &secret_name, const string &expires_at_str) {
	auto expiration_time = ParseExpiresAt(expires_at_str);

	lock_guard<mutex> lock(expiration_lock);
	secret_expiration[secret_name] = expiration_time;
}

void RestApiSecretStorage::ClearExpiration(const string &secret_name) {
	lock_guard<mutex> lock(expiration_lock);
	secret_expiration.erase(secret_name);
}

void RestApiSecretStorage::AddOrUpdateSecretInCatalog(unique_ptr<BaseSecret> secret,
                                                      optional_ptr<CatalogTransaction> transaction) {
	auto trans = GetTransactionOrDefault(transaction);
	auto secret_name = secret->GetName();

	// Check if secret already exists in catalog
	auto existing = secrets->GetEntry(trans, secret_name);
	if (existing) {
		// Drop the existing entry
		secrets->DropEntry(trans, secret_name, false, true);
	}

	// Add new entry to catalog
	auto secret_entry = make_uniq<SecretCatalogEntry>(std::move(secret), Catalog::GetSystemCatalog(db));
	secret_entry->temporary = false;
	secret_entry->secret->storage_mode = GetName();
	secret_entry->secret->persist_type = SecretPersistType::PERSISTENT;
	LogicalDependencyList l;
	secrets->CreateEntry(trans, secret_name, std::move(secret_entry), l);
}

string RestApiSecretStorage::HttpGet(const string &url) {
	std::cerr << "[BOILSTREAM] HttpGet: url=" << url << std::endl;

	// Prevent recursive lookups during HTTP operations
	if (in_http_operation) {
		std::cerr << "[BOILSTREAM] HttpGet: BLOCKED by recursion guard" << std::endl;
		return "";
	}

	// RAII guard automatically manages flag (exception-safe)
	HttpOperationGuard guard;

	auto &http_util = HTTPUtil::Get(db);
	auto params = http_util.InitializeParameters(db, url);
	if (!params) {
		std::cerr << "[BOILSTREAM] HttpGet: InitializeParameters FAILED" << std::endl;
		return "";
	}

	HTTPHeaders headers(db);

	// Add Authorization header with token
	{
		lock_guard<mutex> lock(endpoint_lock);
		if (!auth_token.empty()) {
			headers.Insert("Authorization", "Bearer " + auth_token);
		}
	}

	// Retry configuration: 3 retries with short exponential backoff
	// Total attempts: 4 (1 initial + 3 retries)
	// Total worst-case delay: 100ms + 200ms + 400ms = 700ms
	const int MAX_RETRIES = 3;
	const int BASE_DELAY_MS = 100;

	for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		string response_body;
		auto response_handler = [&](const HTTPResponse &response) {
			response_body = response.body;
			return true;
		};
		auto content_handler = [&](const_data_ptr_t data, idx_t size) {
			response_body.append(reinterpret_cast<const char *>(data), size);
			return true;
		};

		GetRequestInfo request(url, headers, *params, response_handler, content_handler);
		auto response = http_util.Request(request);

		// Check if we should retry (only on transient errors)
		if (response->ShouldRetry() && attempt < MAX_RETRIES) {
			// Exponential backoff: 100ms, 200ms, 400ms
			std::this_thread::sleep_for(std::chrono::milliseconds(BASE_DELAY_MS * (1 << attempt)));
			continue;
		}

		if (!response->Success()) {
			std::cerr << "[BOILSTREAM] HttpGet: Request failed (not successful)" << std::endl;
			return "";
		}

		// Check HTTP status code - must be 2xx for success
		auto status_code = static_cast<uint16_t>(response->status);
		if (status_code < 200 || status_code >= 300) {
			std::cerr << "[BOILSTREAM] HttpGet: HTTP " << status_code << " (non-2xx)" << std::endl;
			return ""; // Return empty for non-success status codes
		}

		std::cerr << "[BOILSTREAM] HttpGet: SUCCESS, body_len=" << response_body.size() << std::endl;
		return response_body;
	}

	std::cerr << "[BOILSTREAM] HttpGet: All retries exhausted" << std::endl;
	return ""; // All retries exhausted
}

string RestApiSecretStorage::HttpPost(const string &url, const string &body) {
	std::cerr << "[BOILSTREAM] HttpPost: url=" << url << ", body_len=" << body.size() << std::endl;

	// Check if URL is empty
	if (url.empty()) {
		throw IOException(
		    "HTTP POST failed: No endpoint URL configured. Use PRAGMA duckdb_secrets_rest_endpoint() first.");
	}

	// Prevent recursive lookups during HTTP operations
	if (in_http_operation) {
		std::cerr << "[BOILSTREAM] HttpPost: BLOCKED by recursion guard" << std::endl;
		throw IOException("HTTP POST failed: Recursive secret lookup detected");
	}

	// RAII guard automatically manages flag (exception-safe)
	HttpOperationGuard guard;

	auto &http_util = HTTPUtil::Get(db);
	// Initialize parameters with nullptr to avoid looking up secrets (which could recurse)
	auto params = http_util.InitializeParameters(db, url);
	if (!params) {
		std::cerr << "[BOILSTREAM] HttpPost: InitializeParameters FAILED" << std::endl;
		throw IOException("HTTP POST failed: Could not initialize HTTP parameters");
	}

	HTTPHeaders headers(db);
	headers.Insert("Content-Type", "application/json");

	// Add Authorization header with token
	{
		lock_guard<mutex> lock(endpoint_lock);
		if (!auth_token.empty()) {
			headers.Insert("Authorization", "Bearer " + auth_token);
		}
	}

	// Generate idempotency key for safe retries (prevents duplicate secret creation)
	// Use a hash of the request body - same content always gets same key for idempotency
	// Note: Hash collisions are unlikely for typical secret payloads but theoretically possible
	// Backend should validate secret name matches to detect collisions
	auto idempotency_key = std::to_string(std::hash<string> {}(body));
	headers.Insert("Idempotency-Key", idempotency_key);

	// Retry configuration: 3 retries with short exponential backoff
	// Total attempts: 4 (1 initial + 3 retries)
	// Total worst-case delay: 100ms + 200ms + 400ms = 700ms
	const int MAX_RETRIES = 3;
	const int BASE_DELAY_MS = 100;
	string last_error;

	for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		PostRequestInfo request(url, headers, *params, const_data_ptr_cast(body.c_str()), body.size());
		auto response = http_util.Request(request);

		// Check if we should retry (only on transient errors)
		if (response->ShouldRetry() && attempt < MAX_RETRIES) {
			last_error = response->GetError();
			// Exponential backoff: 100ms, 200ms, 400ms
			std::this_thread::sleep_for(std::chrono::milliseconds(BASE_DELAY_MS * (1 << attempt)));
			continue;
		}

		// Check HTTP status code - must be 2xx for success
		auto status_code = static_cast<uint16_t>(response->status);
		if (status_code < 200 || status_code >= 300) {
			// Truncate response body to avoid leaking sensitive data in logs
			string error_body = request.buffer_out.substr(0, 200);
			if (request.buffer_out.size() > 200) {
				error_body += "... (truncated)";
			}
			std::cerr << "[BOILSTREAM] HttpPost: HTTP " << status_code << " error" << std::endl;
			throw IOException("HTTP POST failed: HTTP " + std::to_string(status_code) + " - " + error_body);
		}

		std::cerr << "[BOILSTREAM] HttpPost: SUCCESS, body_len=" << request.buffer_out.size() << std::endl;
		return request.buffer_out;
	}

	// All retries exhausted
	throw IOException("HTTP POST failed after " + std::to_string(MAX_RETRIES + 1) + " attempts: " + last_error);
}

void RestApiSecretStorage::HttpDelete(const string &url) {
	std::cerr << "[BOILSTREAM] HttpDelete: url=" << url << std::endl;

	// Prevent recursive lookups during HTTP operations
	if (in_http_operation) {
		std::cerr << "[BOILSTREAM] HttpDelete: BLOCKED by recursion guard" << std::endl;
		throw IOException("HTTP DELETE failed: Recursive secret lookup detected");
	}

	// RAII guard automatically manages flag (exception-safe)
	HttpOperationGuard guard;

	auto &http_util = HTTPUtil::Get(db);
	auto params = http_util.InitializeParameters(db, url);
	if (!params) {
		throw IOException("HTTP DELETE failed: Could not initialize HTTP parameters");
	}

	HTTPHeaders headers(db);

	// Add Authorization header with token
	{
		lock_guard<mutex> lock(endpoint_lock);
		if (!auth_token.empty()) {
			headers.Insert("Authorization", "Bearer " + auth_token);
		}
	}

	// Retry configuration: 3 retries with short exponential backoff
	// Total attempts: 4 (1 initial + 3 retries)
	// Total worst-case delay: 100ms + 200ms + 400ms = 700ms
	const int MAX_RETRIES = 3;
	const int BASE_DELAY_MS = 100;
	string last_error;

	for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		DeleteRequestInfo request(url, headers, *params);
		auto response = http_util.Request(request);

		// Check if we should retry (only on transient errors)
		if (response->ShouldRetry() && attempt < MAX_RETRIES) {
			last_error = response->GetError();
			// Exponential backoff: 100ms, 200ms, 400ms
			std::this_thread::sleep_for(std::chrono::milliseconds(BASE_DELAY_MS * (1 << attempt)));
			continue;
		}

		if (!response->Success()) {
			throw IOException("HTTP DELETE failed: " + response->GetError());
		}

		// Check HTTP status code - must be 2xx for success (404 is also OK for DELETE)
		auto status_code = static_cast<uint16_t>(response->status);
		if (status_code < 200 || (status_code >= 300 && status_code != 404)) {
			// Truncate response body to avoid leaking sensitive data in logs
			string error_body = response->body.substr(0, 200);
			if (response->body.size() > 200) {
				error_body += "... (truncated)";
			}
			throw IOException("HTTP DELETE failed: HTTP " + std::to_string(status_code) + " - " + error_body);
		}

		return; // Success
	}

	// All retries exhausted
	throw IOException("HTTP DELETE failed after " + std::to_string(MAX_RETRIES + 1) + " attempts: " + last_error);
}

unique_ptr<SecretEntry> RestApiSecretStorage::StoreSecret(unique_ptr<const BaseSecret> secret,
                                                          OnCreateConflict on_conflict,
                                                          optional_ptr<CatalogTransaction> transaction) {
	std::cerr << "[BOILSTREAM] StoreSecret: name=" << secret->GetName() << std::endl;

	auto trans = GetTransactionOrDefault(transaction);
	auto secret_name = secret->GetName();

	// Check if secret exists (in cache or remotely)
	auto existing = GetSecretByName(secret_name, transaction);
	if (existing) {
		if (on_conflict == OnCreateConflict::ERROR_ON_CONFLICT) {
			throw InvalidInputException("Persistent secret with name '%s' already exists in secret storage '%s'!",
			                            secret_name, storage_name);
		} else if (on_conflict == OnCreateConflict::IGNORE_ON_CONFLICT) {
			return nullptr;
		} else if (on_conflict == OnCreateConflict::ALTER_ON_CONFLICT) {
			throw InternalException("unknown OnCreateConflict found while registering secret");
		} else if (on_conflict == OnCreateConflict::REPLACE_ON_CONFLICT) {
			// Remove from catalog if present (best effort)
			if (secrets->GetEntry(trans, secret_name)) {
				secrets->DropEntry(trans, secret_name, false, true);
			}
			// Clear expiration
			ClearExpiration(secret_name);
		}
	}

	// Persist to REST API
	WriteSecret(*secret, on_conflict);

	// Add to local catalog
	auto secret_entry = make_uniq<SecretCatalogEntry>(std::move(secret), Catalog::GetSystemCatalog(db));
	secret_entry->temporary = false;
	secret_entry->secret->storage_mode = GetName();
	secret_entry->secret->persist_type = SecretPersistType::PERSISTENT;
	LogicalDependencyList l;
	secrets->CreateEntry(trans, secret_name, std::move(secret_entry), l);

	// Return the stored entry
	auto secret_catalog_entry = &secrets->GetEntry(trans, secret_name)->Cast<SecretCatalogEntry>();
	return make_uniq<SecretEntry>(*secret_catalog_entry->secret);
}

void RestApiSecretStorage::WriteSecret(const BaseSecret &secret, OnCreateConflict on_conflict) {
	// Check if endpoint is configured
	string url;
	{
		lock_guard<mutex> lock(endpoint_lock);
		url = endpoint_url;
	}

	if (url.empty()) {
		throw InvalidInputException("Boilstream endpoint not configured. Use PRAGMA "
		                            "duckdb_secrets_boilstream_endpoint('https://host/path/:TOKEN') to set it.");
	}

	// Serialize secret
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

	auto body_str = yyjson_mut_write(doc, 0, nullptr);
	string body(body_str);
	free(body_str);
	yyjson_mut_doc_free(doc);

	// Make HTTP POST request to the endpoint
	// Token in Authorization header identifies the user
	HttpPost(url, body);
}

SecretMatch RestApiSecretStorage::LookupSecret(const string &path, const string &type,
                                               optional_ptr<CatalogTransaction> transaction) {
	std::cerr << "[BOILSTREAM] LookupSecret: path=" << path << ", type=" << type << std::endl;

	// Prevent recursive lookups during HTTP operations
	if (in_http_operation) {
		std::cerr << "[BOILSTREAM] LookupSecret: BLOCKED by recursion guard" << std::endl;
		return SecretMatch();
	}

	// First, check local catalog for matching secret using parent's implementation
	auto local_match = CatalogSetSecretStorage::LookupSecret(path, type, transaction);

	// Determine if we have an expired cached version
	bool has_expired_cache = false;
	if (local_match.HasMatch()) {
		auto &secret_ref = local_match.GetSecret();
		if (!IsExpired(secret_ref.GetName())) {
			// Not expired, use cached version
			return local_match;
		}
		// Cached version is expired
		has_expired_cache = true;
	}

	// No match in cache or expired - fetch from REST API
	string url;
	{
		lock_guard<mutex> lock(endpoint_lock);
		url = endpoint_url;
	}

	// If endpoint not configured, return no match
	if (url.empty()) {
		return SecretMatch();
	}

	url += "/match";

	// Prepare request body with path, type, and expired flag using yyjson (safe from injection)
	auto doc = yyjson_mut_doc_new(nullptr);
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);

	yyjson_mut_obj_add_strcpy(doc, obj, "path", path.c_str());
	yyjson_mut_obj_add_strcpy(doc, obj, "type", StringUtil::Lower(type).c_str());
	yyjson_mut_obj_add_bool(doc, obj, "expired", has_expired_cache);

	auto body_str = yyjson_mut_write(doc, 0, nullptr);
	string body(body_str);
	free(body_str);
	yyjson_mut_doc_free(doc);

	// Make HTTP POST request
	string response;
	try {
		response = HttpPost(url, body);
	} catch (...) {
		// If request fails, return no match
		return SecretMatch();
	}

	if (response.empty() || response == "null" || response == "{}") {
		return SecretMatch();
	}

	// Parse response to extract expires_at before deserializing secret
	auto response_doc = yyjson_read(response.c_str(), response.size(), 0);
	if (!response_doc) {
		return SecretMatch();
	}

	auto response_root = yyjson_doc_get_root(response_doc);
	string expires_at_str;
	if (response_root && yyjson_is_obj(response_root)) {
		auto expires_at_val = yyjson_obj_get(response_root, "expires_at");
		if (expires_at_val && yyjson_is_str(expires_at_val)) {
			expires_at_str = yyjson_get_str(expires_at_val);
		}
	}
	yyjson_doc_free(response_doc);

	// Deserialize the secret
	auto &manager = SecretManager::Get(db);
	auto secret = DeserializeSecret(response, manager);
	if (!secret) {
		return SecretMatch();
	}

	auto secret_name = secret->GetName();

	// Store expiration if provided
	if (!expires_at_str.empty()) {
		StoreExpiration(secret_name, expires_at_str);
	}

	// Add or update secret in local catalog
	AddOrUpdateSecretInCatalog(std::move(secret), transaction);

	// Return the match from catalog
	return CatalogSetSecretStorage::LookupSecret(path, type, transaction);
}

unique_ptr<SecretEntry> RestApiSecretStorage::GetSecretByName(const string &name,
                                                              optional_ptr<CatalogTransaction> transaction) {
	std::cerr << "[BOILSTREAM] GetSecretByName: name=" << name << std::endl;

	// First, check local catalog using parent's implementation
	auto local_entry = CatalogSetSecretStorage::GetSecretByName(name, transaction);

	// Determine if we have an expired cached version
	bool has_expired_cache = false;
	if (local_entry && local_entry->secret) {
		if (!IsExpired(local_entry->secret->GetName())) {
			// Not expired, use cached version
			return local_entry;
		}
		// Cached version is expired
		has_expired_cache = true;
	}

	// Not in cache or expired - fetch from REST API
	string url;
	{
		lock_guard<mutex> lock(endpoint_lock);
		url = endpoint_url;
	}

	// If endpoint not configured, return null
	if (url.empty()) {
		return nullptr;
	}

	url += "/get";

	// Prepare request body with name and expired flag using yyjson
	auto doc = yyjson_mut_doc_new(nullptr);
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);

	yyjson_mut_obj_add_strcpy(doc, obj, "name", name.c_str());
	yyjson_mut_obj_add_bool(doc, obj, "expired", has_expired_cache);

	auto body_str = yyjson_mut_write(doc, 0, nullptr);
	string body(body_str);
	free(body_str);
	yyjson_mut_doc_free(doc);

	// Make HTTP POST request
	string response;
	try {
		response = HttpPost(url, body);
	} catch (const std::exception &e) {
		std::cerr << "[BOILSTREAM] GetSecretByName: HttpPost exception: " << e.what() << std::endl;
		return nullptr;
	} catch (...) {
		std::cerr << "[BOILSTREAM] GetSecretByName: HttpPost unknown exception" << std::endl;
		return nullptr;
	}

	if (response.empty() || response == "null" || response == "{}") {
		return nullptr;
	}

	// Parse response to extract expires_at before deserializing secret
	auto response_doc = yyjson_read(response.c_str(), response.size(), 0);
	if (!response_doc) {
		return nullptr;
	}

	auto response_root = yyjson_doc_get_root(response_doc);
	string expires_at_str;
	if (response_root && yyjson_is_obj(response_root)) {
		auto expires_at_val = yyjson_obj_get(response_root, "expires_at");
		if (expires_at_val && yyjson_is_str(expires_at_val)) {
			expires_at_str = yyjson_get_str(expires_at_val);
		}
	}
	yyjson_doc_free(response_doc);

	// Deserialize the secret
	auto &manager = SecretManager::Get(db);
	auto secret = DeserializeSecret(response, manager);
	if (!secret) {
		return nullptr;
	}

	// Store expiration if provided
	if (!expires_at_str.empty()) {
		StoreExpiration(name, expires_at_str);
	}

	// Add or update secret in local catalog
	AddOrUpdateSecretInCatalog(std::move(secret), transaction);

	// Return from catalog
	return CatalogSetSecretStorage::GetSecretByName(name, transaction);
}

vector<SecretEntry> RestApiSecretStorage::AllSecrets(optional_ptr<CatalogTransaction> transaction) {
	std::cerr << "[BOILSTREAM] AllSecrets: called" << std::endl;

	// Build URL using the endpoint URL
	string url;
	{
		lock_guard<mutex> lock(endpoint_lock);
		url = endpoint_url;
	}

	std::cerr << "[BOILSTREAM] AllSecrets: endpoint_url=" << url << std::endl;

	// If endpoint not configured, return what's in local catalog
	if (url.empty()) {
		std::cerr << "[BOILSTREAM] AllSecrets: endpoint empty, returning local catalog" << std::endl;
		return CatalogSetSecretStorage::AllSecrets(transaction);
	}

	// Make HTTP GET request to fetch all secrets from REST API
	string response;
	try {
		response = HttpGet(url);
	} catch (...) {
		// On error, return what's in local catalog
		return CatalogSetSecretStorage::AllSecrets(transaction);
	}

	// Parse JSON array using yyjson
	auto doc = yyjson_read(response.c_str(), response.size(), 0);
	if (!doc) {
		return CatalogSetSecretStorage::AllSecrets(transaction);
	}

	auto root = yyjson_doc_get_root(doc);
	if (!root || !yyjson_is_arr(root)) {
		yyjson_doc_free(doc);
		return CatalogSetSecretStorage::AllSecrets(transaction);
	}

	auto &manager = SecretManager::Get(db);

	// Iterate through array elements and add/update in catalog
	size_t idx, max;
	yyjson_val *val;
	yyjson_arr_foreach(root, idx, max, val) {
		if (!yyjson_is_obj(val)) {
			continue;
		}

		// Extract expires_at field
		string expires_at_str;
		auto expires_at_val = yyjson_obj_get(val, "expires_at");
		if (expires_at_val && yyjson_is_str(expires_at_val)) {
			expires_at_str = yyjson_get_str(expires_at_val);
		}

		// Convert object to JSON string for DeserializeSecret
		auto obj_str = yyjson_val_write(val, 0, nullptr);
		if (obj_str) {
			auto secret = DeserializeSecret(string(obj_str), manager);
			free(obj_str);

			if (secret) {
				auto secret_name = secret->GetName();

				// Store expiration if provided
				if (!expires_at_str.empty()) {
					StoreExpiration(secret_name, expires_at_str);
				}

				// Add or update secret in local catalog
				AddOrUpdateSecretInCatalog(std::move(secret), transaction);
			}
		}
	}

	yyjson_doc_free(doc);

	// Return all secrets from local catalog (now includes REST API secrets)
	return CatalogSetSecretStorage::AllSecrets(transaction);
}

void RestApiSecretStorage::RemoveSecret(const string &name, OnEntryNotFound on_entry_not_found) {
	// Build URL using the endpoint URL with URL-encoded name
	string url;
	{
		lock_guard<mutex> lock(endpoint_lock);
		url = endpoint_url + "/" + StringUtil::URLEncode(name);
	}

	// Make HTTP DELETE request
	try {
		HttpDelete(url);
	} catch (...) {
		if (on_entry_not_found == OnEntryNotFound::THROW_EXCEPTION) {
			throw CatalogException("Secret '%s' not found", name);
		}
	}

	// Clear expiration data for this secret
	ClearExpiration(name);
}

void RestApiSecretStorage::DropSecretByName(const string &name, OnEntryNotFound on_entry_not_found,
                                            optional_ptr<CatalogTransaction> transaction) {
	std::cerr << "[BOILSTREAM] DropSecretByName: name=" << name << std::endl;

	// Check if endpoint is configured
	string url;
	{
		lock_guard<mutex> lock(endpoint_lock);
		url = endpoint_url;
	}

	if (url.empty()) {
		throw InvalidInputException("Boilstream endpoint not configured. Use PRAGMA "
		                            "duckdb_secrets_boilstream_endpoint('https://host/path/:TOKEN') to set it.");
	}

	// Delete from REST API first (source of truth)
	RemoveSecret(name, on_entry_not_found);

	// Clean up local cache if present (best effort - ignore if not cached)
	auto trans = GetTransactionOrDefault(transaction);
	if (secrets->GetEntry(trans, name)) {
		secrets->DropEntry(trans, name, false, true);
	}

	// Clear expiration metadata
	ClearExpiration(name);
}

} // namespace duckdb
