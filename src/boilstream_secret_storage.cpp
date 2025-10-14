//===----------------------------------------------------------------------===//
//                         DuckDB
//
// boilstream_secret_storage.cpp
//
//
//===----------------------------------------------------------------------===//

#include "boilstream_secret_storage.hpp"
#include "opaque_wrapper.hpp"
#include "opaque_client.h"
#include "duckdb/main/database.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/common/serializer/memory_stream.hpp"
#include "duckdb/common/serializer/binary_serializer.hpp"
#include "duckdb/common/serializer/binary_deserializer.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/common/random_engine.hpp"
#include "mbedtls_wrapper.hpp"
#include "yyjson.hpp"
#include <sstream>
#include <thread>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <sys/stat.h>

// Platform-specific secure memory zeroization
// Prevents compiler from optimizing away memory clearing operations
#if defined(_WIN32)
#define NOMINMAX // Prevent Windows from defining min/max macros that conflict with std::min/std::max
#include <windows.h>
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

// Debug logging macro - only enabled when BOILSTREAM_DEBUG is defined
// To enable: add -DBOILSTREAM_DEBUG to compiler flags
#ifdef BOILSTREAM_DEBUG
#include <iostream>
#define BOILSTREAM_LOG(msg) std::cerr << "[BOILSTREAM] " << msg << std::endl
#else
#define BOILSTREAM_LOG(msg) ((void)0)
#endif

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

RestApiSecretStorage::RestApiSecretStorage(DatabaseInstance &db_p, const string &endpoint_url_p)
    : CatalogSetSecretStorage(db_p, "boilstream", 5), // offset=5 for higher priority than built-in storages (10, 20)
      endpoint_url(endpoint_url_p), is_exchanging(false) {
	secrets = make_uniq<CatalogSet>(Catalog::GetSystemCatalog(db));
	persistent = true;                                               // Acts as persistent storage
	token_expires_at = std::chrono::system_clock::time_point::min(); // Initialize as expired
}

void RestApiSecretStorage::SetEndpoint(const string &endpoint) {
	lock_guard<mutex> lock(endpoint_lock);
	endpoint_url = endpoint;
}

void RestApiSecretStorage::ClearSession() {
	lock_guard<mutex> lock(session_lock);
	access_token = "";

	// Securely zero session_key before clearing
	if (!session_key.empty()) {
		SECURE_ZERO_MEMORY(session_key.data(), session_key.size());
		session_key.clear();
	}

	// Securely zero refresh_token before clearing
	if (!refresh_token.empty()) {
		SECURE_ZERO_MEMORY(refresh_token.data(), refresh_token.size());
		refresh_token.clear();
	}

	client_sequence = 0;
	region = "";
	bootstrap_token_hash = "";
	token_expires_at = std::chrono::system_clock::time_point::min();
}

bool RestApiSecretStorage::IsSessionTokenValid() {
	lock_guard<mutex> lock(session_lock);

	// If exchange is in progress, wait for it
	if (is_exchanging) {
		return false;
	}

	if (access_token.empty()) {
		return false;
	}

	// Check if token is expired (with 30min buffer)
	const auto BUFFER = std::chrono::minutes(30);
	auto now = std::chrono::system_clock::now();
	return now < (token_expires_at - BUFFER);
}

string RestApiSecretStorage::GetBootstrapTokenHash() {
	lock_guard<mutex> lock(session_lock);
	return bootstrap_token_hash;
}

void RestApiSecretStorage::SetBootstrapTokenHash(const string &hash) {
	lock_guard<mutex> lock(session_lock);
	bootstrap_token_hash = hash;
}

std::chrono::system_clock::time_point RestApiSecretStorage::GetTokenExpiresAt() {
	lock_guard<mutex> lock(session_lock);
	return token_expires_at;
}

string RestApiSecretStorage::GetRefreshTokenPath() {
	// Get home directory
	const char *home = std::getenv("HOME");
	if (!home) {
#ifdef _WIN32
		home = std::getenv("USERPROFILE");
#endif
	}
	if (!home) {
		throw IOException("Cannot determine home directory for refresh token storage");
	}

	// Create ~/.duckdb directory if it doesn't exist
	string duckdb_dir = string(home) + "/.duckdb";
	auto &fs = FileSystem::GetFileSystem(db);

	if (!fs.DirectoryExists(duckdb_dir)) {
		fs.CreateDirectory(duckdb_dir);
	}

	return duckdb_dir + "/.boilstream_refresh_token";
}

void RestApiSecretStorage::SaveRefreshToken(bool resumption_enabled) {
	if (!resumption_enabled) {
		BOILSTREAM_LOG("SaveRefreshToken: Session resumption disabled, not persisting refresh token");
		return;
	}

	BOILSTREAM_LOG("SaveRefreshToken: Saving refresh token to disk");

	// Get current session data
	RefreshTokenData data;
	{
		lock_guard<mutex> lock(session_lock);
		lock_guard<mutex> endpoint_lock_guard(endpoint_lock);

		if (refresh_token.empty()) {
			throw IOException("SaveRefreshToken: No refresh token to save");
		}

		data.refresh_token = refresh_token;
		data.endpoint_url = endpoint_url;
		data.region = region;
		data.expires_at = token_expires_at;
	}

	// Serialize data to JSON (unencrypted, protected by file permissions)
	auto doc = yyjson_mut_doc_new(nullptr);
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);

	yyjson_mut_obj_add_int(doc, obj, "version", 1);

	// Convert refresh_token to base64
	string refresh_token_b64 = Blob::ToBase64(string_t(string(data.refresh_token.begin(), data.refresh_token.end())));
	yyjson_mut_obj_add_strcpy(doc, obj, "refresh_token", refresh_token_b64.c_str());
	yyjson_mut_obj_add_strcpy(doc, obj, "endpoint_url", data.endpoint_url.c_str());
	yyjson_mut_obj_add_strcpy(doc, obj, "region", data.region.c_str());

	// Format expires_at as ISO8601 UTC
	auto expires_time_t = std::chrono::system_clock::to_time_t(data.expires_at);
	std::tm tm_utc;
#ifdef _WIN32
	gmtime_s(&tm_utc, &expires_time_t);
#else
	gmtime_r(&expires_time_t, &tm_utc);
#endif
	char expires_str[64];
	std::strftime(expires_str, sizeof(expires_str), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
	yyjson_mut_obj_add_strcpy(doc, obj, "expires_at", expires_str);

	auto json_str = yyjson_mut_write(doc, 0, nullptr);
	string json_output(json_str);
	free(json_str);
	yyjson_mut_doc_free(doc);

	// Write to file (overwrite if exists for token rotation)
	string file_path = GetRefreshTokenPath();
	auto &fs = FileSystem::GetFileSystem(db);

	// Delete existing file if present (for token rotation)
	if (fs.FileExists(file_path)) {
		fs.RemoveFile(file_path);
	}

	auto handle = fs.OpenFile(file_path, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW);
	fs.Write(*handle, const_cast<char *>(json_output.data()), json_output.size());
	handle->Close();

	// Set file permissions to 0600 (owner read/write only)
	// This provides protection against other users on the system
#ifndef _WIN32
	chmod(file_path.c_str(), S_IRUSR | S_IWUSR);
#endif

	BOILSTREAM_LOG("SaveRefreshToken: Successfully saved to " << file_path);
}

bool RestApiSecretStorage::LoadRefreshToken() {
	BOILSTREAM_LOG("LoadRefreshToken: Attempting to load refresh token from disk");

	string file_path = GetRefreshTokenPath();
	auto &fs = FileSystem::GetFileSystem(db);

	if (!fs.FileExists(file_path)) {
		BOILSTREAM_LOG("LoadRefreshToken: File does not exist");
		return false;
	}

	// Read file
	auto handle = fs.OpenFile(file_path, FileFlags::FILE_FLAGS_READ);
	auto file_size = fs.GetFileSize(*handle);
	string file_contents(file_size, '\0');
	fs.Read(*handle, const_cast<char *>(file_contents.data()), file_size);
	handle->Close();

	// Parse JSON
	auto doc = yyjson_read(file_contents.c_str(), file_contents.size(), 0);
	if (!doc) {
		BOILSTREAM_LOG("LoadRefreshToken: Failed to parse JSON");
		DeleteRefreshToken();
		return false;
	}

	auto root = yyjson_doc_get_root(doc);
	auto version_val = yyjson_obj_get(root, "version");
	auto refresh_token_val = yyjson_obj_get(root, "refresh_token");
	auto endpoint_val = yyjson_obj_get(root, "endpoint_url");
	auto region_val = yyjson_obj_get(root, "region");
	auto expires_val = yyjson_obj_get(root, "expires_at");

	if (!version_val || !yyjson_is_int(version_val) || yyjson_get_int(version_val) != 1) {
		yyjson_doc_free(doc);
		BOILSTREAM_LOG("LoadRefreshToken: Invalid or unsupported version");
		DeleteRefreshToken();
		return false;
	}

	if (!refresh_token_val || !yyjson_is_str(refresh_token_val) || !endpoint_val || !yyjson_is_str(endpoint_val) ||
	    !region_val || !yyjson_is_str(region_val) || !expires_val || !yyjson_is_str(expires_val)) {
		yyjson_doc_free(doc);
		BOILSTREAM_LOG("LoadRefreshToken: Missing required fields");
		DeleteRefreshToken();
		return false;
	}

	string refresh_token_b64 = yyjson_get_str(refresh_token_val);
	string endpoint = yyjson_get_str(endpoint_val);
	string region_str = yyjson_get_str(region_val);
	string expires_str = yyjson_get_str(expires_val);

	yyjson_doc_free(doc);

	// Decode refresh token from base64
	BOILSTREAM_LOG("LoadRefreshToken: Base64 token from file: " << refresh_token_b64);
	string refresh_token_bytes_str = Blob::FromBase64(refresh_token_b64);
	// Refresh token is derived using HKDF-Expand and should be exactly 32 bytes
	if (refresh_token_bytes_str.size() != 32) {
		BOILSTREAM_LOG("LoadRefreshToken: Invalid refresh token size: " << refresh_token_bytes_str.size()
		                                                                << " (expected 32)");
		DeleteRefreshToken();
		return false;
	}
	BOILSTREAM_LOG("LoadRefreshToken: Loaded refresh token, size=" << refresh_token_bytes_str.size() << " bytes");

	// Debug: compute and log what user_id SHOULD be from this token
	char debug_hash[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::ComputeSha256Hash(refresh_token_bytes_str.c_str(), refresh_token_bytes_str.size(),
	                                                  debug_hash);
	string debug_user_id;
	debug_user_id.reserve(64);
	const char *hex_chars = "0123456789abcdef";
	for (size_t i = 0; i < duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES; i++) {
		unsigned char byte = static_cast<unsigned char>(debug_hash[i]);
		debug_user_id += hex_chars[(byte >> 4) & 0xF];
		debug_user_id += hex_chars[byte & 0xF];
	}
	BOILSTREAM_LOG("LoadRefreshToken: Expected resume_user_id=" << debug_user_id);

	// Parse expiration timestamp
	std::chrono::system_clock::time_point expires_at;
	try {
		expires_at = ParseExpiresAt(expires_str);
	} catch (...) {
		BOILSTREAM_LOG("LoadRefreshToken: Failed to parse expires_at");
		DeleteRefreshToken();
		return false;
	}

	// Check if expired
	auto now = std::chrono::system_clock::now();
	if (now >= expires_at) {
		BOILSTREAM_LOG("LoadRefreshToken: Refresh token has expired");
		DeleteRefreshToken();
		return false;
	}

	// Store in session
	{
		lock_guard<mutex> lock(session_lock);
		lock_guard<mutex> endpoint_lock_guard(endpoint_lock);

		refresh_token.assign(refresh_token_bytes_str.begin(), refresh_token_bytes_str.end());
		endpoint_url = endpoint;
		region = region_str;
		token_expires_at = expires_at;
	}

	BOILSTREAM_LOG("LoadRefreshToken: Successfully loaded refresh token");
	return true;
}

void RestApiSecretStorage::DeleteRefreshToken() {
	BOILSTREAM_LOG("DeleteRefreshToken: Deleting refresh token file");

	string file_path = GetRefreshTokenPath();
	auto &fs = FileSystem::GetFileSystem(db);

	if (fs.FileExists(file_path)) {
		fs.RemoveFile(file_path);
		BOILSTREAM_LOG("DeleteRefreshToken: File deleted");
	}
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

void RestApiSecretStorage::PerformOpaqueRegistration(const string &password) {
	BOILSTREAM_LOG("PerformOpaqueRegistration: starting OPAQUE registration");

	// Build registration URL
	string url;
	{
		lock_guard<mutex> lock(endpoint_lock);
		url = endpoint_url;
	}

	if (url.empty()) {
		throw InvalidInputException("Boilstream endpoint not configured");
	}

	// Remove trailing /secrets if present (endpoint should be base URL)
	auto secrets_pos = url.find("/secrets");
	if (secrets_pos != string::npos) {
		url = url.substr(0, secrets_pos);
	}

	// Compute user_id: SHA-256 hash of password (bootstrap_token)
	// Following spec: user_id = lowercase_hex(SHA256(password))
	char password_hash[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::ComputeSha256Hash(password.c_str(), password.size(), password_hash);

	// Convert hash to lowercase hex string (64 characters)
	string user_id;
	user_id.reserve(64);
	const char *hex_chars = "0123456789abcdef";
	for (size_t i = 0; i < duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES; i++) {
		unsigned char byte = static_cast<unsigned char>(password_hash[i]);
		user_id += hex_chars[(byte >> 4) & 0xF];
		user_id += hex_chars[byte & 0xF];
	}
	BOILSTREAM_LOG("PerformOpaqueRegistration: computed user_id=" << user_id.substr(0, 16) << "...");

	// Step 1: Client starts registration
	auto reg_start = OpaqueClientWrapper::RegistrationStart(password);
	BOILSTREAM_LOG("PerformOpaqueRegistration: registration request generated");

	// Step 2: Send RegistrationRequest to server with user_id
	string reg_url = url + "/auth/api/opaque-registration-start";

	auto doc = yyjson_mut_doc_new(nullptr);
	auto obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, obj);
	yyjson_mut_obj_add_strcpy(doc, obj, "user_id", user_id.c_str());
	yyjson_mut_obj_add_strcpy(doc, obj, "registration_request", reg_start.registration_request_base64.c_str());

	auto body_str = yyjson_mut_write(doc, 0, nullptr);
	string body(body_str);
	free(body_str);
	yyjson_mut_doc_free(doc);

	string response;
	try {
		response = HttpPost(reg_url, body);
	} catch (const std::exception &e) {
		opaque_free_registration_state(reg_start.state);
		throw IOException("OPAQUE registration failed (server request): " + string(e.what()));
	}

	// Parse server response
	auto response_doc = yyjson_read(response.c_str(), response.size(), 0);
	if (!response_doc) {
		opaque_free_registration_state(reg_start.state);
		throw IOException("OPAQUE registration failed: Invalid JSON response from server");
	}

	auto response_root = yyjson_doc_get_root(response_doc);
	auto registration_response_val = yyjson_obj_get(response_root, "registration_response");
	if (!registration_response_val || !yyjson_is_str(registration_response_val)) {
		yyjson_doc_free(response_doc);
		opaque_free_registration_state(reg_start.state);
		throw IOException("OPAQUE registration failed: No registration_response in server response");
	}

	string registration_response_base64 = yyjson_get_str(registration_response_val);
	yyjson_doc_free(response_doc);

	// Step 3: Client finishes registration
	auto reg_finish = OpaqueClientWrapper::RegistrationFinish(reg_start.state, // consumed by this call
	                                                          registration_response_base64);
	BOILSTREAM_LOG("PerformOpaqueRegistration: registration upload generated");

	// Step 4: Send RegistrationUpload to server
	string upload_url = url + "/auth/api/opaque-registration-finish";

	auto upload_doc = yyjson_mut_doc_new(nullptr);
	auto upload_obj = yyjson_mut_obj(upload_doc);
	yyjson_mut_doc_set_root(upload_doc, upload_obj);
	yyjson_mut_obj_add_strcpy(upload_doc, upload_obj, "registration_upload",
	                          reg_finish.registration_upload_base64.c_str());

	auto upload_body_str = yyjson_mut_write(upload_doc, 0, nullptr);
	string upload_body(upload_body_str);
	free(upload_body_str);
	yyjson_mut_doc_free(upload_doc);

	try {
		HttpPost(upload_url, upload_body);
	} catch (const std::exception &e) {
		throw IOException("OPAQUE registration failed (upload): " + string(e.what()));
	}

	BOILSTREAM_LOG("PerformOpaqueRegistration: SUCCESS - registration complete");
}

void RestApiSecretStorage::PerformOpaqueLoginCommon(const string &password, bool is_resume) {
	BOILSTREAM_LOG((is_resume ? "PerformOpaqueResume" : "PerformOpaqueLogin")
	               << ": starting OPAQUE " << (is_resume ? "resume" : "login"));

	// Mark exchange as in progress
	{
		lock_guard<mutex> lock(session_lock);
		is_exchanging = true;
	}

	// Build login URL
	string url;
	{
		lock_guard<mutex> lock(endpoint_lock);
		url = endpoint_url;
	}

	if (url.empty()) {
		lock_guard<mutex> lock(session_lock);
		is_exchanging = false;
		throw InvalidInputException("Boilstream endpoint not configured");
	}

	// Remove trailing /secrets if present
	auto secrets_pos = url.find("/secrets");
	if (secrets_pos != string::npos) {
		url = url.substr(0, secrets_pos);
	}

	// Compute user_id: SHA-256 hash of password (bootstrap_token or refresh_token)
	// Following spec: user_id = lowercase_hex(SHA256(password))
	char password_hash[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::ComputeSha256Hash(password.c_str(), password.size(), password_hash);

	// Convert hash to lowercase hex string (64 characters)
	string user_id;
	user_id.reserve(64);
	const char *hex_chars = "0123456789abcdef";
	for (size_t i = 0; i < duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES; i++) {
		unsigned char byte = static_cast<unsigned char>(password_hash[i]);
		user_id += hex_chars[(byte >> 4) & 0xF];
		user_id += hex_chars[byte & 0xF];
	}
	BOILSTREAM_LOG("PerformOpaqueLogin: computed user_id=" << user_id.substr(0, 16) << "...");

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

	auto body_str = yyjson_mut_write(doc, 0, nullptr);
	string body(body_str);
	free(body_str);
	yyjson_mut_doc_free(doc);

	BOILSTREAM_LOG("PerformOpaqueLogin: login-start request: " << body);

	string response;
	try {
		response = HttpPost(login_url, body);
	} catch (const std::exception &e) {
		lock_guard<mutex> lock(session_lock);
		is_exchanging = false;
		opaque_free_login_state(login_start.state);
		throw IOException("OPAQUE login failed (server request): " + string(e.what()));
	}

	BOILSTREAM_LOG("PerformOpaqueLogin: login-start response: " << response);

	// Parse server response
	auto response_doc = yyjson_read(response.c_str(), response.size(), 0);
	if (!response_doc) {
		lock_guard<mutex> lock(session_lock);
		is_exchanging = false;
		opaque_free_login_state(login_start.state);
		throw IOException("OPAQUE login failed: Invalid JSON response from server");
	}

	auto response_root = yyjson_doc_get_root(response_doc);
	auto credential_response_val = yyjson_obj_get(response_root, "credential_response");
	if (!credential_response_val || !yyjson_is_str(credential_response_val)) {
		yyjson_doc_free(response_doc);
		lock_guard<mutex> lock(session_lock);
		is_exchanging = false;
		opaque_free_login_state(login_start.state);
		throw IOException("OPAQUE login failed: No credential_response in server response");
	}

	string credential_response_base64 = yyjson_get_str(credential_response_val);

	// Extract state_id if present (required by server for stateful OPAQUE)
	string state_id;
	auto state_id_val = yyjson_obj_get(response_root, "state_id");
	if (state_id_val && yyjson_is_str(state_id_val)) {
		state_id = yyjson_get_str(state_id_val);
		BOILSTREAM_LOG("PerformOpaqueLogin: extracted state_id=" << state_id);
	} else {
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
		lock_guard<mutex> lock(session_lock);
		session_key.assign(session_key_decoded.begin(), session_key_decoded.end());
		BOILSTREAM_LOG("PerformOpaqueLogin: session_key stored (length=" << session_key.size() << ")");
	}

	// Step 4: Send CredentialFinalization to server
	string finalize_url = url + "/auth/api/opaque-login-finish";

	auto final_doc = yyjson_mut_doc_new(nullptr);
	auto final_obj = yyjson_mut_obj(final_doc);
	yyjson_mut_doc_set_root(final_doc, final_obj);

	// Add state_id if it was provided by server (required for stateful OPAQUE)
	BOILSTREAM_LOG("PerformOpaqueLogin: About to add state_id, empty=" << state_id.empty() << ", value=" << state_id);
	if (!state_id.empty()) {
		yyjson_mut_obj_add_strcpy(final_doc, final_obj, "state_id", state_id.c_str());
		BOILSTREAM_LOG("PerformOpaqueLogin: Added state_id to finalization request");
	} else {
		BOILSTREAM_LOG("PerformOpaqueLogin: ERROR - state_id is EMPTY, not adding to request");
	}

	yyjson_mut_obj_add_strcpy(final_doc, final_obj, "credential_finalization",
	                          login_finish.credential_finalization_base64.c_str());

	auto final_body_str = yyjson_mut_write(final_doc, 0, nullptr);
	string final_body(final_body_str);
	free(final_body_str);
	yyjson_mut_doc_free(final_doc);

	BOILSTREAM_LOG("PerformOpaqueLogin: login-finish request: " << final_body);

	// Use HttpPost with out_headers parameter to capture X-Boilstream-Session-Resumption
	HTTPHeaders final_response_headers(db);
	string final_response;
	try {
		final_response = HttpPost(finalize_url, final_body, &final_response_headers);
	} catch (const std::exception &e) {
		lock_guard<mutex> lock(session_lock);
		session_key.clear(); // Clear session_key on error
		is_exchanging = false;
		throw IOException("OPAQUE login failed (finalization): " + string(e.what()));
	}

	BOILSTREAM_LOG((is_resume ? "PerformOpaqueResume" : "PerformOpaqueLogin")
	               << ": login-finish response: " << final_response);

	// Parse finalization response (contains access_token and expires_at)
	auto final_response_doc = yyjson_read(final_response.c_str(), final_response.size(), 0);
	if (!final_response_doc) {
		lock_guard<mutex> lock(session_lock);
		session_key.clear(); // Clear session_key on error
		is_exchanging = false;
		throw IOException("OPAQUE login failed: Invalid finalization response from server (JSON parse error)");
	}

	auto final_response_root = yyjson_doc_get_root(final_response_doc);

	// Check if response indicates an error (success=false or error field present)
	auto success_val = yyjson_obj_get(final_response_root, "success");
	auto error_val = yyjson_obj_get(final_response_root, "error");

	if ((success_val && yyjson_is_bool(success_val) && !yyjson_get_bool(success_val)) ||
	    (error_val && yyjson_is_str(error_val))) {
		string error_msg = "Unknown error";
		if (error_val && yyjson_is_str(error_val)) {
			error_msg = yyjson_get_str(error_val);
		}
		yyjson_doc_free(final_response_doc);
		lock_guard<mutex> lock(session_lock);
		session_key.clear(); // Clear session_key on error
		is_exchanging = false;
		throw IOException("OPAQUE login failed: " + error_msg);
	}

	auto access_token_val = yyjson_obj_get(final_response_root, "access_token");
	if (!access_token_val || !yyjson_is_str(access_token_val)) {
		yyjson_doc_free(final_response_doc);
		lock_guard<mutex> lock(session_lock);
		session_key.clear(); // Clear session_key on error
		is_exchanging = false;
		throw IOException("OPAQUE login failed: No access_token in finalization response");
	}

	string new_access_token = yyjson_get_str(access_token_val);

	// Validate access_token format per SECURITY_SPECIFICATION.md:1309
	// Must be exactly 64 lowercase hexadecimal characters
	if (new_access_token.length() != 64) {
		yyjson_doc_free(final_response_doc);
		lock_guard<mutex> lock(session_lock);
		session_key.clear(); // Clear session_key on error
		is_exchanging = false;
		throw IOException("OPAQUE login failed: Invalid access_token format - must be 64 characters (got " +
		                  std::to_string(new_access_token.length()) + ")");
	}

	// Validate all characters are lowercase hexadecimal
	for (size_t i = 0; i < new_access_token.length(); i++) {
		char c = new_access_token[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			yyjson_doc_free(final_response_doc);
			lock_guard<mutex> lock(session_lock);
			session_key.clear(); // Clear session_key on error
			is_exchanging = false;
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
		string expires_str = yyjson_get_str(expires_val);
		new_expires_at = ParseExpiresAt(expires_str);
	} else {
		new_expires_at = std::chrono::system_clock::now() + std::chrono::hours(8);
	}

	// Extract region (defaults to "us-east-1" if not provided)
	string new_region = "us-east-1";
	auto region_val = yyjson_obj_get(final_response_root, "region");
	if (region_val && yyjson_is_str(region_val)) {
		new_region = yyjson_get_str(region_val);
	}

	yyjson_doc_free(final_response_doc);

	// Store session state atomically
	{
		lock_guard<mutex> lock(session_lock);
		access_token = new_access_token;

		// Store OPAQUE session_key (convert string to vector<uint8_t>)
		session_key.assign(session_key_decoded.begin(), session_key_decoded.end());

		// Derive refresh_token from session_key using HKDF-Expand per SECURITY_SPECIFICATION.md:158
		// refresh_token = HKDF-Expand(session_key, "session-resumption-v1", 32 bytes)
		// We use session_key directly as PRK (no Extract step needed since session_key is already derived)
		const string info = "session-resumption-v1";
		string info_with_counter = info + string(1, 0x01); // info || 0x01
		char derived_key[32];
		duckdb_mbedtls::MbedTlsWrapper::Hmac256(reinterpret_cast<const char *>(session_key.data()), session_key.size(),
		                                        info_with_counter.c_str(), info_with_counter.size(), derived_key);
		refresh_token.assign(derived_key, derived_key + 32);

		// Reset sequence counter (starts at 0 for new session)
		client_sequence = 0;

		// Store region from server response
		region = new_region;

		token_expires_at = new_expires_at;
		is_exchanging = false;
	}

	// Check for X-Boilstream-Session-Resumption header to determine if we should persist refresh token
	bool resumption_enabled = false;
	auto header_map = ExtractBoilstreamHeaders(final_response_headers);
	auto resumption_it = header_map.find("x-boilstream-session-resumption");
	if (resumption_it != header_map.end()) {
		string resumption_value = resumption_it->second;
		std::transform(resumption_value.begin(), resumption_value.end(), resumption_value.begin(), ::tolower);
		resumption_enabled = (resumption_value == "enabled");
		BOILSTREAM_LOG((is_resume ? "PerformOpaqueResume" : "PerformOpaqueLogin")
		               << ": X-Boilstream-Session-Resumption=" << resumption_value);
	} else {
		BOILSTREAM_LOG((is_resume ? "PerformOpaqueResume" : "PerformOpaqueLogin")
		               << ": X-Boilstream-Session-Resumption header not present, assuming disabled");
	}

	// Save refresh token to disk if resumption is enabled
	if (resumption_enabled) {
		try {
			SaveRefreshToken(true);
			BOILSTREAM_LOG((is_resume ? "PerformOpaqueResume" : "PerformOpaqueLogin")
			               << ": Refresh token saved for session resumption");
		} catch (const std::exception &e) {
			// Log but don't fail the login if we can't persist the token
			BOILSTREAM_LOG((is_resume ? "PerformOpaqueResume" : "PerformOpaqueLogin")
			               << ": WARNING - Failed to save refresh token: " << e.what());
		}
	}

	BOILSTREAM_LOG(
	    (is_resume ? "PerformOpaqueResume" : "PerformOpaqueLogin")
	    << ": SUCCESS, token expires in "
	    << std::chrono::duration_cast<std::chrono::hours>(new_expires_at - std::chrono::system_clock::now()).count()
	    << " hours");
}

void RestApiSecretStorage::PerformOpaqueLogin(const string &password) {
	PerformOpaqueLoginCommon(password, false);
}

void RestApiSecretStorage::PerformOpaqueResume() {
	BOILSTREAM_LOG("PerformOpaqueResume: Loading refresh token from disk");

	// Load refresh token from disk
	if (!LoadRefreshToken()) {
		throw IOException("Session resumption failed: No valid refresh token found");
	}

	// Extract refresh token as password for OPAQUE
	string refresh_token_password;
	{
		lock_guard<mutex> lock(session_lock);
		if (refresh_token.empty()) {
			throw IOException("Session resumption failed: Refresh token is empty");
		}
		refresh_token_password.assign(reinterpret_cast<const char *>(refresh_token.data()), refresh_token.size());
	}

	BOILSTREAM_LOG("PerformOpaqueResume: Loaded refresh token, starting OPAQUE resume");

	// Use the common login flow with the refresh token
	try {
		PerformOpaqueLoginCommon(refresh_token_password, true);

		// On successful resume, the old refresh token is now invalid
		// The new one has been saved by PerformOpaqueLoginCommon
		BOILSTREAM_LOG("PerformOpaqueResume: Session resumed successfully");
	} catch (const std::exception &e) {
		// Only delete token if it's actually invalid (not transient network/httpfs errors)
		string error_msg = e.what();
		bool is_transient_error = (error_msg.find("scheme is not supported") != string::npos) || // httpfs not loaded
		                          (error_msg.find("not implemented") != string::npos) ||         // missing HTTP support
		                          (error_msg.find("Connection refused") != string::npos) ||      // server down
		                          (error_msg.find("Could not connect") != string::npos) ||       // network issue
		                          (error_msg.find("Failed to connect") != string::npos) ||       // network issue
		                          (error_msg.find("Timeout") != string::npos) ||                 // network timeout
		                          (error_msg.find("timed out") != string::npos);                 // network timeout

		if (is_transient_error) {
			// Keep token AND endpoint for transient errors - user can retry later
			BOILSTREAM_LOG(
			    "PerformOpaqueResume: Resume failed due to transient error, keeping token and endpoint: " << error_msg);
			// Don't clear endpoint - it's still valid, just couldn't connect right now
		} else {
			// Delete token for authentication failures (invalid/expired token)
			BOILSTREAM_LOG("PerformOpaqueResume: Resume failed, deleting invalid token: " << error_msg);
			DeleteRefreshToken();

			// Clear endpoint since token is invalid
			// This ensures tests expecting "endpoint not configured" work correctly
			SetEndpoint("");
		}

		throw;
	}

	// Securely zero the refresh token password
	SECURE_ZERO_MEMORY(const_cast<char *>(refresh_token_password.data()), refresh_token_password.size());
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
		BOILSTREAM_LOG("SetUserContextForConnection: WARNING - Connection map exceeded limit, cleared "
		               << (MAX_CONNECTIONS / 2) << " entries");
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

vector<uint8_t> RestApiSecretStorage::DeriveSigningKey(const vector<uint8_t> &session_key_param) {
	// HKDF-SHA256 key derivation for request signing (base key) - 32 bytes
	// Following RFC 5869 and SECURITY_SPECIFICATION.md
	// Step 1: Extract - PRK = HMAC-SHA256(salt, IKM)
	// Step 2: Expand - T(1) = HMAC-SHA256(PRK, info || 0x01)
	// Output: derived_key = T(1)[0:32]

	if (session_key_param.empty()) {
		throw IOException("Cannot derive signing key: session_key not initialized");
	}

	// Step 1: HKDF-Extract
	// PRK = HMAC-SHA256(salt="boilstream-session-v1", IKM=session_key)
	string salt = "boilstream-session-v1";
	char prk[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::Hmac256(salt.c_str(), salt.size(),
	                                        reinterpret_cast<const char *>(session_key_param.data()),
	                                        session_key_param.size(), prk);

	// Step 2: HKDF-Expand
	// T(1) = HMAC-SHA256(PRK, info || 0x01)
	string info = "request-integrity-v1";
	string info_with_counter = info + string(1, (char)0x01);
	char derived[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::Hmac256(prk, sizeof(prk), info_with_counter.c_str(), info_with_counter.size(),
	                                        derived);

	// Return 32-byte key (T(1))
	vector<uint8_t> result(derived, derived + duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES);

	// Securely zero intermediate key material
	SECURE_ZERO_MEMORY(prk, sizeof(prk));
	SECURE_ZERO_MEMORY(derived, sizeof(derived));

	return result;
}

vector<uint8_t> RestApiSecretStorage::DeriveEncryptionKey(const vector<uint8_t> &session_key_param) {
	// HKDF-SHA256 key derivation for response decryption - 32 bytes
	// Following RFC 5869 and SECURITY_SPECIFICATION.md
	// Step 1: Extract - PRK = HMAC-SHA256(salt, IKM)
	// Step 2: Expand - T(1) = HMAC-SHA256(PRK, info || 0x01)
	// Output: derived_key = T(1)[0:32]

	if (session_key_param.empty()) {
		throw IOException("Cannot derive encryption key: session_key not initialized");
	}

	// Step 1: HKDF-Extract
	// PRK = HMAC-SHA256(salt="boilstream-session-v1", IKM=session_key)
	string salt = "boilstream-session-v1";
	char prk[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::Hmac256(salt.c_str(), salt.size(),
	                                        reinterpret_cast<const char *>(session_key_param.data()),
	                                        session_key_param.size(), prk);

	// Step 2: HKDF-Expand
	// T(1) = HMAC-SHA256(PRK, info || 0x01)
	string info = "response-encryption-v1";
	string info_with_counter = info + string(1, (char)0x01);
	char derived[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::Hmac256(prk, sizeof(prk), info_with_counter.c_str(), info_with_counter.size(),
	                                        derived);

	// Return 32-byte key (T(1))
	vector<uint8_t> result(derived, derived + duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES);

	// Securely zero intermediate key material
	SECURE_ZERO_MEMORY(prk, sizeof(prk));
	SECURE_ZERO_MEMORY(derived, sizeof(derived));

	return result;
}

vector<uint8_t> RestApiSecretStorage::DeriveIntegrityKey(const vector<uint8_t> &session_key_param) {
	// HKDF-SHA256 key derivation for response integrity verification - 32 bytes
	// Following RFC 5869 and SECURITY_SPECIFICATION.md
	// Step 1: Extract - PRK = HMAC-SHA256(salt, IKM)
	// Step 2: Expand - T(1) = HMAC-SHA256(PRK, info || 0x01)
	// Output: derived_key = T(1)[0:32]

	if (session_key_param.empty()) {
		throw IOException("Cannot derive integrity key: session_key not initialized");
	}

	// Step 1: HKDF-Extract
	// PRK = HMAC-SHA256(salt="boilstream-session-v1", IKM=session_key)
	string salt = "boilstream-session-v1";
	char prk[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::Hmac256(salt.c_str(), salt.size(),
	                                        reinterpret_cast<const char *>(session_key_param.data()),
	                                        session_key_param.size(), prk);

	// Step 2: HKDF-Expand
	// T(1) = HMAC-SHA256(PRK, info || 0x01)
	string info = "response-integrity-v1";
	string info_with_counter = info + string(1, (char)0x01);
	char derived[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::Hmac256(prk, sizeof(prk), info_with_counter.c_str(), info_with_counter.size(),
	                                        derived);

	// Return 32-byte key (T(1))
	vector<uint8_t> result(derived, derived + duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES);

	// Securely zero intermediate key material
	SECURE_ZERO_MEMORY(prk, sizeof(prk));
	SECURE_ZERO_MEMORY(derived, sizeof(derived));

	return result;
}

RestApiSecretStorage::SessionSnapshot RestApiSecretStorage::GetSessionSnapshot() {
	// Thread-safe extraction of session state
	SessionSnapshot snapshot;
	{
		lock_guard<mutex> lock(session_lock);
		snapshot.access_token = access_token;
		snapshot.session_key = session_key;
		snapshot.region = region;
		snapshot.sequence = client_sequence;
		snapshot.has_session_key = !session_key.empty();

		// Increment sequence counter after reading
		client_sequence++;
	}
	return snapshot;
}

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

HTTPHeaders RestApiSecretStorage::BuildAuthenticatedHeaders(const string &method, const string &url,
                                                            const string &body) {
	// Get session snapshot (thread-safe, increments sequence)
	auto snapshot = GetSessionSnapshot();

	if (!snapshot.has_session_key) {
		throw IOException("BuildAuthenticatedHeaders: No active session");
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
	headers.Insert("X-Boilstream-Ciphers", "0x0001, 0x0002");
	headers.Insert("X-Boilstream-Cipher-Version", "1");

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

	BOILSTREAM_LOG("VerifyResponseSignature: status=" << status_code);

	// Check if response has signature header
	auto sig_it = headers.find("x-boilstream-response-signature");
	if (sig_it == headers.end()) {
		// No signature header - this might be a login-start response (before session_key available)
		BOILSTREAM_LOG("VerifyResponseSignature: No signature header present (OK for login-start)");
		return;
	}

	string received_signature_b64 = sig_it->second;
	BOILSTREAM_LOG("VerifyResponseSignature: Found signature header");

	// Debug: Log ALL headers received (before filtering)
	BOILSTREAM_LOG("VerifyResponseSignature: ALL headers received (" << headers.size() << " total):");
	for (const auto &header : headers) {
		BOILSTREAM_LOG("  " << header.first << ": " << header.second);
	}

	// Derive integrity key from session_key
	auto integrity_key = DeriveIntegrityKey(session_key_param);

	// Hash response body (SHA-256, lowercase hex)
	char body_hash[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::ComputeSha256Hash(response_body.c_str(), response_body.size(), body_hash);

	// Convert to lowercase hex string
	string hashed_payload;
	hashed_payload.reserve(64);
	const char *hex_chars = "0123456789abcdef";
	for (size_t i = 0; i < duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES; i++) {
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
		BOILSTREAM_LOG("VerifyResponseSignature: Response header[" << i << "]: " << boilstream_headers[i].first << "="
		                                                           << boilstream_headers[i].second);
	}

	canonical_response += canonical_headers;
	canonical_response += "\n"; // Blank line after canonical headers

	// 3. Signed headers list
	canonical_response += signed_headers + "\n";

	// 4. Hashed payload
	canonical_response += hashed_payload;

	BOILSTREAM_LOG("VerifyResponseSignature: Canonical response built");
	BOILSTREAM_LOG("VerifyResponseSignature: Canonical response:\n" << canonical_response);
	BOILSTREAM_LOG("VerifyResponseSignature: Received signature (b64): " << received_signature_b64);

	// Compute expected signature: HMAC-SHA256(integrity_key, canonical_response)
	char expected_signature[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::Hmac256(reinterpret_cast<const char *>(integrity_key.data()), integrity_key.size(),
	                                        canonical_response.c_str(), canonical_response.size(), expected_signature);

	// Encode expected signature as base64
	string expected_signature_str(expected_signature, duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES);
	string expected_signature_b64 = Blob::ToBase64(string_t(expected_signature_str));

	BOILSTREAM_LOG("VerifyResponseSignature: Expected signature (b64): " << expected_signature_b64);

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
	if (date_it != headers.end()) {
		string timestamp_str = date_it->second;
		// Parse ISO8601 timestamp: YYYYMMDDTHHMMSSZ
		// Manual parsing (std::get_time not available in C++11)
		if (timestamp_str.length() == 16 && timestamp_str[8] == 'T' && timestamp_str[15] == 'Z') {
			try {
				int year = std::stoi(timestamp_str.substr(0, 4));
				int month = std::stoi(timestamp_str.substr(4, 2));
				int day = std::stoi(timestamp_str.substr(6, 2));
				int hour = std::stoi(timestamp_str.substr(9, 2));
				int minute = std::stoi(timestamp_str.substr(11, 2));
				int second = std::stoi(timestamp_str.substr(13, 2));

				std::tm tm = {};
				tm.tm_year = year - 1900;
				tm.tm_mon = month - 1;
				tm.tm_mday = day;
				tm.tm_hour = hour;
				tm.tm_min = minute;
				tm.tm_sec = second;
				tm.tm_isdst = 0;

				time_t response_time = 0;
#ifdef _WIN32
				response_time = _mkgmtime(&tm);
#else
				response_time = timegm(&tm);
#endif
				if (response_time != -1) {
					auto response_tp = std::chrono::system_clock::from_time_t(response_time);
					auto now = std::chrono::system_clock::now();
					auto diff_seconds = std::chrono::duration_cast<std::chrono::seconds>(
					                        now > response_tp ? now - response_tp : response_tp - now)
					                        .count();

					if (diff_seconds > 60) {
						throw IOException("Response signature verification failed: timestamp outside 60-second window");
					}
				}
			} catch (...) {
				// Timestamp parsing failed - log but don't fail verification
				BOILSTREAM_LOG("VerifyResponseSignature: Failed to parse timestamp");
			}
		}
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

	BOILSTREAM_LOG("DecryptResponse: Starting decryption, cipher_suite=0x" << std::hex << cipher_suite << std::dec);

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

	string nonce_b64 = yyjson_get_str(nonce_val);
	string ciphertext_b64 = yyjson_get_str(ciphertext_val);
	string hmac_hex = yyjson_get_str(hmac_val);

	yyjson_doc_free(doc);

	BOILSTREAM_LOG("DecryptResponse: Parsed JSON - nonce_len=" << nonce_b64.size()
	                                                           << ", ciphertext_len=" << ciphertext_b64.size()
	                                                           << ", hmac_len=" << hmac_hex.size());

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

	BOILSTREAM_LOG("DecryptResponse: Decoded - nonce=" << nonce_bytes.size()
	                                                   << "B, ciphertext=" << ciphertext_with_tag.size()
	                                                   << "B, hmac=" << hmac_bytes.size() << "B");

	// 5. Verify HMAC BEFORE decryption (CRITICAL for security)
	// hmac_input = nonce_bytes || ciphertext_with_tag
	vector<uint8_t> hmac_input;
	hmac_input.reserve(nonce_bytes.size() + ciphertext_with_tag.size());
	hmac_input.insert(hmac_input.end(), nonce_bytes.begin(), nonce_bytes.end());
	hmac_input.insert(hmac_input.end(), ciphertext_with_tag.begin(), ciphertext_with_tag.end());

	char expected_hmac[duckdb_mbedtls::MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::Hmac256(reinterpret_cast<const char *>(integrity_key.data()), integrity_key.size(),
	                                        reinterpret_cast<const char *>(hmac_input.data()), hmac_input.size(),
	                                        expected_hmac);

	// Constant-time comparison (CRITICAL for security)
	volatile uint8_t diff = 0;
	for (size_t i = 0; i < 32; i++) {
		diff |= (hmac_bytes[i] ^ static_cast<uint8_t>(expected_hmac[i]));
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
		// AES-256-GCM AEAD decryption
		BOILSTREAM_LOG("DecryptResponse: Using AES-256-GCM AEAD");

		// Split ciphertext and tag (last 16 bytes is AEAD authentication tag)
		constexpr size_t AEAD_TAG_SIZE = 16;
		if (ciphertext_with_tag.size() < AEAD_TAG_SIZE) {
			throw IOException("DecryptResponse: Ciphertext too short for AEAD tag");
		}

		size_t ciphertext_len = ciphertext_with_tag.size() - AEAD_TAG_SIZE;
		vector<uint8_t> ciphertext_only(ciphertext_with_tag.begin(), ciphertext_with_tag.begin() + ciphertext_len);
		vector<uint8_t> aead_tag(ciphertext_with_tag.begin() + ciphertext_len, ciphertext_with_tag.end());

		BOILSTREAM_LOG("DecryptResponse: ciphertext=" << ciphertext_len << "B, tag=" << aead_tag.size() << "B");

		// Create AES-256-GCM decryption state
		duckdb_mbedtls::MbedTlsWrapper::AESStateMBEDTLS aes_state(EncryptionTypes::CipherType::GCM,
		                                                          32 // 256-bit key (32 bytes)
		);

		// Initialize decryption with nonce, key, and empty AAD (no additional authenticated data)
		aes_state.InitializeDecryption(nonce_bytes.data(), nonce_bytes.size(),       // iv (nonce): 12 bytes
		                               encryption_key.data(), encryption_key.size(), // key: 32 bytes
		                               nullptr, 0 // aad: empty (no additional authenticated data)
		);

		// Allocate output buffer for plaintext
		vector<uint8_t> plaintext_bytes(ciphertext_len);

		// Process ciphertext (decrypt without verifying tag yet)
		size_t processed = aes_state.Process(ciphertext_only.data(), ciphertext_only.size(), plaintext_bytes.data(),
		                                     plaintext_bytes.size());

		if (processed != ciphertext_len) {
			throw IOException("DecryptResponse: AES-GCM Process size mismatch");
		}

		// Finalize and verify AEAD authentication tag (CRITICAL: verifies authenticity)
		// This throws if tag verification fails (tampering/corruption detected)
		aes_state.Finalize(plaintext_bytes.data(), 0,       // output buffer (already written by Process)
		                   aead_tag.data(), aead_tag.size() // expected tag from ciphertext
		);

		BOILSTREAM_LOG("DecryptResponse: AEAD tag verified successfully");

		// Convert to string
		string plaintext(reinterpret_cast<char *>(plaintext_bytes.data()), plaintext_bytes.size());

		// Securely zero keys and sensitive data
		SECURE_ZERO_MEMORY(encryption_key.data(), encryption_key.size());
		SECURE_ZERO_MEMORY(integrity_key.data(), integrity_key.size());
		SECURE_ZERO_MEMORY(plaintext_bytes.data(), plaintext_bytes.size());

		BOILSTREAM_LOG("DecryptResponse: Decryption successful, plaintext_len=" << plaintext.size());

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

	string cipher_str = it->second;
	BOILSTREAM_LOG("ParseCipherSuite: Found cipher header: " << cipher_str);

	// Parse cipher suite (format: "0x0001" or "0x0002")
	if (cipher_str.size() < 3 || cipher_str.substr(0, 2) != "0x") {
		throw IOException("ParseCipherSuite: Invalid cipher suite format '" + cipher_str + "' (expected 0xNNNN)");
	}

	// Parse hex value
	try {
		uint16_t cipher_suite = static_cast<uint16_t>(std::stoul(cipher_str, nullptr, 16));
		BOILSTREAM_LOG("ParseCipherSuite: Parsed cipher suite: 0x" << std::hex << cipher_suite << std::dec);

		// Validate supported cipher suites
		if (cipher_suite != 0x0001 && cipher_suite != 0x0002) {
			throw IOException("ParseCipherSuite: Unsupported cipher suite 0x" + std::to_string(cipher_suite) +
			                  " (only 0x0001 and 0x0002 supported)");
		}

		return cipher_suite;
	} catch (const std::invalid_argument &e) {
		throw IOException("ParseCipherSuite: Failed to parse cipher suite '" + cipher_str + "': " + e.what());
	} catch (const std::out_of_range &e) {
		throw IOException("ParseCipherSuite: Cipher suite value out of range '" + cipher_str + "': " + e.what());
	}
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
	string current_region = region_param.empty() ? "us-east-1" : region_param;

	// Build credential scope: <access-token-prefix>/<date>/<region>/<service>/boilstream_request
	string service = "secrets";
	string credential_scope =
	    access_token_prefix + "/" + date_str + "/" + current_region + "/" + service + "/boilstream_request";

	// Build canonical headers (sorted, lowercase, with trailing newline)
	// Include ALL x-boilstream-* headers (except x-boilstream-signature)
	// Following spec: All headers starting with x-boilstream- must be signed
	string canonical_headers = "x-boilstream-cipher-version:1\n"
	                           "x-boilstream-ciphers:0x0001, 0x0002\n"
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

	// Log canonical request for debugging
	BOILSTREAM_LOG(
	    "SignRequest: Canonical request:\n"
	    << string(reinterpret_cast<const char *>(canonical_result.buffer.data), canonical_result.buffer.len));
	BOILSTREAM_LOG("SignRequest: Credential scope: " << credential_scope);
	BOILSTREAM_LOG("SignRequest: Date/time: " << date_time_str);
	BOILSTREAM_LOG("SignRequest: Sequence: " << sequence);
	BOILSTREAM_LOG("SignRequest: Access token prefix: " << access_token_prefix);

	// Cleanup intermediate buffers
	opaque_free_buffer(canonical_result.buffer);
	opaque_free_buffer(signing_key_result.buffer);

	if (signature_result.error != OPAQUE_SUCCESS) {
		throw IOException("AWS SigV4 signing failed: Could not sign request");
	}

	// Extract base64 signature from result
	string signature(reinterpret_cast<const char *>(signature_result.buffer.data), signature_result.buffer.len);
	BOILSTREAM_LOG("SignRequest: Signature (base64): " << signature.substr(0, 32) << "...");

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

	// Prevent unbounded map growth - limit to 10,000 secrets
	const size_t MAX_SECRETS = 10000;
	if (secret_expiration.size() >= MAX_SECRETS) {
		// Clear oldest half of entries (simple LRU approximation)
		auto it = secret_expiration.begin();
		size_t to_remove = MAX_SECRETS / 2;
		while (to_remove-- > 0 && it != secret_expiration.end()) {
			it = secret_expiration.erase(it);
		}
		BOILSTREAM_LOG("StoreExpiration: WARNING - Secret expiration map exceeded limit, cleared " << (MAX_SECRETS / 2)
		                                                                                           << " entries");
	}

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
	BOILSTREAM_LOG("HttpGet: url=" << url);

	// Prevent recursive lookups during HTTP operations
	// httpfs may try to look up secrets when making HTTP requests - return empty to avoid infinite loop
	if (in_http_operation) {
		BOILSTREAM_LOG("HttpGet: BLOCKED by recursion guard");
		return ""; // Return empty - httpfs will proceed without credentials
	}

	// RAII guard automatically manages flag (exception-safe)
	HttpOperationGuard guard;

	auto &http_util = HTTPUtil::Get(db);
	auto params = http_util.InitializeParameters(db, url);
	if (!params) {
		BOILSTREAM_LOG("HttpGet: InitializeParameters FAILED");
		return "";
	}

	// Build authenticated headers (or empty headers if no session)
	HTTPHeaders headers(db);
	vector<uint8_t> current_session_key;
	bool has_session_key = false;

	try {
		headers = BuildAuthenticatedHeaders("GET", url, "");
		// Save session key for response verification
		lock_guard<mutex> lock(session_lock);
		current_session_key = session_key;
		has_session_key = !session_key.empty();
	} catch (const IOException &e) {
		// No active session - proceed without authentication
		BOILSTREAM_LOG("HttpGet: No active session, proceeding unauthenticated");
	}

	// Retry configuration: 3 retries with short exponential backoff
	// Total attempts: 4 (1 initial + 3 retries)
	// Total worst-case delay: 100ms + 200ms + 400ms = 700ms
	const int MAX_RETRIES = 3;
	const int BASE_DELAY_MS = 100;
	string response_body_result;
	bool request_sent = false;

	for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		BOILSTREAM_LOG("HttpGet: attempt " << (attempt + 1) << "/" << (MAX_RETRIES + 1));
		request_sent = true; // Mark that we're attempting to send
		string response_body;
		HTTPHeaders response_headers_captured(db);
		auto response_handler = [&](const HTTPResponse &response) {
			response_body = response.body;
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
		BOILSTREAM_LOG("HttpGet: response received, status=" << static_cast<uint16_t>(response->status));

		// Check if we should retry (only on transient errors)
		if (response->ShouldRetry() && attempt < MAX_RETRIES) {
			// Exponential backoff: 100ms, 200ms, 400ms
			std::this_thread::sleep_for(std::chrono::milliseconds(BASE_DELAY_MS * (1 << attempt)));
			continue;
		}

		if (!response->Success()) {
			BOILSTREAM_LOG("HttpGet: Request failed (not successful)");
			return "";
		}

		// Get HTTP status code
		auto status_code = static_cast<uint16_t>(response->status);

		// Verify response signature and decrypt BEFORE checking status code
		// This ensures error responses are also decrypted before being thrown
		if (has_session_key) {
			try {
				VerifyAuthenticatedResponse(response_body, status_code, response_headers_captured, current_session_key);
				BOILSTREAM_LOG("HttpGet: Response signature verified successfully");
			} catch (const std::exception &e) {
				BOILSTREAM_LOG("HttpGet: Response signature verification failed: " << e.what());
				throw IOException("Response integrity check failed: " + string(e.what()));
			}

			// Check if response is encrypted and decrypt if needed
			auto header_map = ExtractBoilstreamHeaders(response_headers_captured);
			if (IsResponseEncrypted(header_map)) {
				BOILSTREAM_LOG("HttpGet: Response is encrypted, decrypting...");
				try {
					uint16_t cipher_suite = ParseCipherSuite(header_map);
					response_body = DecryptResponse(response_body, current_session_key, cipher_suite);
					BOILSTREAM_LOG("HttpGet: Response decrypted successfully, plaintext_len=" << response_body.size());
				} catch (const std::exception &e) {
					BOILSTREAM_LOG("HttpGet: Response decryption failed: " << e.what());
					throw IOException("Response decryption failed: " + string(e.what()));
				}
			} else {
				BOILSTREAM_LOG("HttpGet: Response is not encrypted (plaintext)");
			}
		}

		// Now check status code with decrypted response body
		// 4xx Client Errors - fail fast, don't retry
		if (status_code >= 400 && status_code < 500) {
			string error_body = response_body.substr(0, 200);
			if (response_body.size() > 200) {
				error_body += "... (truncated)";
			}
			BOILSTREAM_LOG("HttpGet: HTTP " << status_code << " (client error), body: " << error_body);
			throw IOException("HTTP GET failed: HTTP " + std::to_string(status_code) +
			                  " - Client error: " + error_body);
		}

		// 5xx Server Errors - classify for retry decision
		if (status_code >= 500 && status_code < 600) {
			BOILSTREAM_LOG("HttpGet: HTTP " << status_code << " (server error)");

			// 501 Not Implemented, 505 HTTP Version Not Supported - don't retry
			if (status_code == 501 || status_code == 505) {
				string error_body = response_body.substr(0, 200);
				if (response_body.size() > 200) {
					error_body += "... (truncated)";
				}
				throw IOException("HTTP GET failed: HTTP " + std::to_string(status_code) +
				                  " - Server does not support this operation: " + error_body);
			}

			// 500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout
			// These are retryable - return empty to trigger retry logic
			if (attempt < MAX_RETRIES) {
				continue; // Will retry with exponential backoff
			} else {
				// All retries exhausted
				string error_body = response_body.substr(0, 200);
				if (response_body.size() > 200) {
					error_body += "... (truncated)";
				}
				throw IOException("HTTP GET failed: HTTP " + std::to_string(status_code) + " - Server error after " +
				                  std::to_string(MAX_RETRIES + 1) + " attempts: " + error_body);
			}
		}

		// 3xx Redirects or other non-2xx
		if (status_code < 200 || status_code >= 300) {
			BOILSTREAM_LOG("HttpGet: HTTP " << status_code << " (non-2xx)");
			return ""; // Return empty for redirects
		}

		BOILSTREAM_LOG("HttpGet: SUCCESS, body_len=" << response_body.size());

		return response_body;
	}

	BOILSTREAM_LOG("HttpGet: All retries exhausted");
	return ""; // All retries exhausted
}

string RestApiSecretStorage::HttpPost(const string &url, const string &body, HTTPHeaders *out_headers) {
	BOILSTREAM_LOG("HttpPost: url=" << url << ", body_len=" << body.size());

	// Check if URL is empty
	if (url.empty()) {
		throw IOException(
		    "HTTP POST failed: No endpoint URL configured. Use PRAGMA duckdb_secrets_rest_endpoint() first.");
	}

	// Prevent recursive lookups during HTTP operations
	if (in_http_operation) {
		BOILSTREAM_LOG("HttpPost: BLOCKED by recursion guard");
		throw IOException("HTTP POST failed: Recursive secret lookup detected");
	}

	// RAII guard automatically manages flag (exception-safe)
	HttpOperationGuard guard;

	auto &http_util = HTTPUtil::Get(db);
	// Initialize parameters with nullptr to avoid looking up secrets (which could recurse)
	auto params = http_util.InitializeParameters(db, url);
	if (!params) {
		BOILSTREAM_LOG("HttpPost: InitializeParameters FAILED");
		throw IOException("HTTP POST failed: Could not initialize HTTP parameters");
	}

	// Build authenticated headers if not during OPAQUE authentication
	// During OPAQUE login/registration, we don't have a session yet
	HTTPHeaders headers(db);
	vector<uint8_t> current_session_key;
	bool has_session_key = false;
	bool is_exchanging_now = false;

	{
		lock_guard<mutex> lock(session_lock);
		is_exchanging_now = is_exchanging;
		current_session_key = session_key;
		has_session_key = !session_key.empty();
	}

	if (!is_exchanging_now) {
		// Normal API request - add authenticated headers
		headers = BuildAuthenticatedHeaders("POST", url, body);
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
				VerifyAuthenticatedResponse(request.buffer_out, status_code, response->headers, current_session_key);
				BOILSTREAM_LOG("HttpPost: Response signature verified successfully");
			} catch (const std::exception &e) {
				BOILSTREAM_LOG("HttpPost: Response signature verification failed: " << e.what());
				throw IOException("Response integrity check failed: " + string(e.what()));
			}

			// Check if response is encrypted and decrypt if needed
			auto header_map = ExtractBoilstreamHeaders(response->headers);
			if (IsResponseEncrypted(header_map)) {
				BOILSTREAM_LOG("HttpPost: Response is encrypted, decrypting...");
				try {
					uint16_t cipher_suite = ParseCipherSuite(header_map);
					request.buffer_out = DecryptResponse(request.buffer_out, current_session_key, cipher_suite);
					BOILSTREAM_LOG(
					    "HttpPost: Response decrypted successfully, plaintext_len=" << request.buffer_out.size());
				} catch (const std::exception &e) {
					BOILSTREAM_LOG("HttpPost: Response decryption failed: " << e.what());
					throw IOException("Response decryption failed: " + string(e.what()));
				}
			} else {
				BOILSTREAM_LOG("HttpPost: Response is not encrypted (plaintext)");
			}
		}

		// Now check status code with decrypted response body
		// 4xx Client Errors - fail fast, don't retry
		if (status_code >= 400 && status_code < 500) {
			string error_body = request.buffer_out.substr(0, 200);
			if (request.buffer_out.size() > 200) {
				error_body += "... (truncated)";
			}
			BOILSTREAM_LOG("HttpPost: HTTP " << status_code << " (client error)");
			BOILSTREAM_LOG("HttpPost: Response body length: " << request.buffer_out.size());
			BOILSTREAM_LOG("HttpPost: Response body: " << error_body);
			throw IOException("HTTP POST failed: HTTP " + std::to_string(status_code) +
			                  " - Client error: " + error_body);
		}

		// 5xx Server Errors - classify for retry decision
		if (status_code >= 500 && status_code < 600) {
			BOILSTREAM_LOG("HttpPost: HTTP " << status_code << " (server error)");

			// 501 Not Implemented, 505 HTTP Version Not Supported - don't retry
			if (status_code == 501 || status_code == 505) {
				string error_body = request.buffer_out.substr(0, 200);
				if (request.buffer_out.size() > 200) {
					error_body += "... (truncated)";
				}
				throw IOException("HTTP POST failed: HTTP " + std::to_string(status_code) +
				                  " - Server does not support this operation: " + error_body);
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
			string error_body = request.buffer_out.substr(0, 200);
			if (request.buffer_out.size() > 200) {
				error_body += "... (truncated)";
			}
			BOILSTREAM_LOG("HttpPost: HTTP " << status_code << " error");
			throw IOException("HTTP POST failed: HTTP " + std::to_string(status_code) + " - " + error_body);
		}

		BOILSTREAM_LOG("HttpPost: SUCCESS, body_len=" << request.buffer_out.size());

		return request.buffer_out;
	}

	// All retries exhausted
	throw IOException("HTTP POST failed after " + std::to_string(MAX_RETRIES + 1) + " attempts: " + last_error);
}

void RestApiSecretStorage::HttpDelete(const string &url) {
	BOILSTREAM_LOG("HttpDelete: url=" << url);

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

	// Build authenticated headers (throws if no session)
	HTTPHeaders headers = BuildAuthenticatedHeaders("DELETE", url, "");

	// Save session key for response verification
	vector<uint8_t> current_session_key;
	bool has_session_key = false;
	{
		lock_guard<mutex> lock(session_lock);
		current_session_key = session_key;
		has_session_key = !session_key.empty();
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
				BOILSTREAM_LOG("HttpDelete: Response signature verification failed: " << e.what());
				throw IOException("Response integrity check failed: " + string(e.what()));
			}

			// Check if response is encrypted and decrypt if needed
			auto header_map = ExtractBoilstreamHeaders(response->headers);
			if (IsResponseEncrypted(header_map)) {
				BOILSTREAM_LOG("HttpDelete: Response is encrypted, decrypting...");
				try {
					uint16_t cipher_suite = ParseCipherSuite(header_map);
					response_body = DecryptResponse(response_body, current_session_key, cipher_suite);
					BOILSTREAM_LOG(
					    "HttpDelete: Response decrypted successfully, plaintext_len=" << response_body.size());
				} catch (const std::exception &e) {
					BOILSTREAM_LOG("HttpDelete: Response decryption failed: " << e.what());
					throw IOException("Response decryption failed: " + string(e.what()));
				}
			} else {
				BOILSTREAM_LOG("HttpDelete: Response is not encrypted (plaintext)");
			}
		}

		// Now check status code with decrypted response body
		// 4xx Client Errors (except 404) - fail fast, don't retry
		if (status_code >= 400 && status_code < 500 && status_code != 404) {
			string error_body = response_body.substr(0, 200);
			if (response_body.size() > 200) {
				error_body += "... (truncated)";
			}
			BOILSTREAM_LOG("HttpDelete: HTTP " << status_code << " (client error), body: " << error_body);
			throw IOException("HTTP DELETE failed: HTTP " + std::to_string(status_code) +
			                  " - Client error: " + error_body);
		}

		// 5xx Server Errors - classify for retry decision
		if (status_code >= 500 && status_code < 600) {
			BOILSTREAM_LOG("HttpDelete: HTTP " << status_code << " (server error)");

			// 501 Not Implemented, 505 HTTP Version Not Supported - don't retry
			if (status_code == 501 || status_code == 505) {
				string error_body = response_body.substr(0, 200);
				if (response_body.size() > 200) {
					error_body += "... (truncated)";
				}
				throw IOException("HTTP DELETE failed: HTTP " + std::to_string(status_code) +
				                  " - Server does not support this operation: " + error_body);
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
			string error_body = response_body.substr(0, 200);
			if (response_body.size() > 200) {
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
	BOILSTREAM_LOG("StoreSecret: name=" << secret->GetName());

	auto trans = GetTransactionOrDefault(transaction);
	auto secret_name = secret->GetName();

	// Check if secret exists in LOCAL CACHE ONLY (don't make HTTP request here - server will handle duplicates)
	// This prevents recursive HTTP calls during StoreSecret
	auto existing_local = CatalogSetSecretStorage::GetSecretByName(secret_name, transaction);
	if (existing_local) {
		BOILSTREAM_LOG("StoreSecret: found existing secret in local cache");
		if (on_conflict == OnCreateConflict::ERROR_ON_CONFLICT) {
			// Let the server handle the duplicate check - we'll send the request and it will fail if duplicate
			BOILSTREAM_LOG("StoreSecret: ERROR_ON_CONFLICT, will let server check for duplicates");
		} else if (on_conflict == OnCreateConflict::IGNORE_ON_CONFLICT) {
			BOILSTREAM_LOG("StoreSecret: IGNORE_ON_CONFLICT, returning null");
			return nullptr;
		} else if (on_conflict == OnCreateConflict::ALTER_ON_CONFLICT) {
			throw InternalException("unknown OnCreateConflict found while registering secret");
		} else if (on_conflict == OnCreateConflict::REPLACE_ON_CONFLICT) {
			BOILSTREAM_LOG("StoreSecret: REPLACE_ON_CONFLICT, removing from local cache");
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
	BOILSTREAM_LOG("WriteSecret: name=" << secret.GetName());

	// Check if endpoint is configured
	string url;
	{
		lock_guard<mutex> lock(endpoint_lock);
		url = endpoint_url;
	}

	BOILSTREAM_LOG("WriteSecret: endpoint_url=" << url);

	if (url.empty()) {
		BOILSTREAM_LOG("WriteSecret: ERROR - endpoint is empty!");
		throw InvalidInputException("Boilstream endpoint not configured. Use PRAGMA "
		                            "duckdb_secrets_boilstream_endpoint('https://host/path/:TOKEN') to set it.");
	}

	// Serialize secret
	BOILSTREAM_LOG("WriteSecret: serializing secret...");
	string secret_json = SerializeSecret(secret);
	BOILSTREAM_LOG("WriteSecret: secret serialized, json_len=" << secret_json.size());

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

	BOILSTREAM_LOG("WriteSecret: about to POST, body_len=" << body.size());
	// Make HTTP POST request to the endpoint
	// Token in Authorization header identifies the user
	HttpPost(url, body);
	BOILSTREAM_LOG("WriteSecret: POST successful");
}

SecretMatch RestApiSecretStorage::LookupSecret(const string &path, const string &type,
                                               optional_ptr<CatalogTransaction> transaction) {
	BOILSTREAM_LOG("LookupSecret: path=" << path << ", type=" << type);

	// Prevent recursive lookups during HTTP operations
	if (in_http_operation) {
		BOILSTREAM_LOG("LookupSecret: BLOCKED by recursion guard");
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
	BOILSTREAM_LOG("GetSecretByName: name=" << name);

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
		BOILSTREAM_LOG("GetSecretByName: HttpPost exception: " << e.what());
		return nullptr;
	} catch (...) {
		BOILSTREAM_LOG("GetSecretByName: HttpPost unknown exception");
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
	BOILSTREAM_LOG("AllSecrets: called");

	// Build URL using the endpoint URL
	string url;
	bool has_endpoint = false;
	bool has_session = false;
	{
		lock_guard<mutex> endpoint_lock_guard(endpoint_lock);
		lock_guard<mutex> session_lock_guard(session_lock);
		url = endpoint_url;
		has_endpoint = !endpoint_url.empty();
		has_session = !access_token.empty();
	}

	BOILSTREAM_LOG("AllSecrets: endpoint_url=" << url);

	// If endpoint is set but no active session, try to resume from refresh token
	if (has_endpoint && !has_session) {
		BOILSTREAM_LOG("AllSecrets: Endpoint set but no session, attempting resume");
		try {
			PerformOpaqueResume();
			BOILSTREAM_LOG("AllSecrets: Resume successful");
		} catch (const std::exception &e) {
			BOILSTREAM_LOG("AllSecrets: Resume failed: " << e.what());
			// Continue - will try unauthenticated or fail appropriately
		}
	}

	// If endpoint not configured, return what's in local catalog
	if (url.empty()) {
		BOILSTREAM_LOG("AllSecrets: endpoint empty, returning local catalog");
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
	BOILSTREAM_LOG("DropSecretByName: name=" << name);

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
