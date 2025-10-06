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
#include <string>

namespace duckdb {

class DatabaseInstance;
class SecretManager;

//! REST API-based secret storage that communicates with an external service
//! for multi-tenant secret management
class BoilStreamSecretStorage : public CatalogSetSecretStorage {
public:
	BoilStreamSecretStorage(DatabaseInstance &db, const string &api_base_url, const string &auth_token);

	//! Set the endpoint URL (without token)
	void SetEndpoint(const string &endpoint);

	//! Set the authentication token for API requests
	void SetAuthToken(const string &token);

	//! Set user context for a connection
	void SetUserContextForConnection(idx_t connection_id, const string &user_id);

	//! Get user context for a connection
	string GetUserContextForConnection(idx_t connection_id);

	//! Clear connection mapping (for cleanup)
	void ClearConnectionMapping(idx_t connection_id);

	//! Override to fetch all secrets from REST API
	vector<SecretEntry> AllSecrets(optional_ptr<CatalogTransaction> transaction) override;

	//! Override to lookup secrets from REST API
	SecretMatch LookupSecret(const string &path, const string &type,
	                         optional_ptr<CatalogTransaction> transaction) override;

	//! Override to get secret by name from REST API
	unique_ptr<SecretEntry> GetSecretByName(const string &name, optional_ptr<CatalogTransaction> transaction) override;

	//! Override to drop secret from REST API
	void DropSecretByName(const string &name, OnEntryNotFound on_entry_not_found,
	                      optional_ptr<CatalogTransaction> transaction) override;

protected:
	//! Override WriteSecret to persist to REST API
	void WriteSecret(const BaseSecret &secret, OnCreateConflict on_conflict) override;

	//! Override RemoveSecret to delete from REST API
	void RemoveSecret(const string &name, OnEntryNotFound on_entry_not_found) override;

private:
	//! Extract user context from transaction (user_context_id from ClientData)
	string ExtractUserContext(optional_ptr<CatalogTransaction> transaction);

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
	string HttpPost(const string &url, const string &body);

	//! Make HTTP DELETE request to REST API
	void HttpDelete(const string &url);

	//! Base URL for REST API endpoint (e.g., "https://api.example.com/secrets")
	string endpoint_url;

	//! Authentication token for API requests
	string auth_token;

	//! Lock for thread-safe endpoint/token updates
	mutex endpoint_lock;

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
