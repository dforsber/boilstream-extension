#pragma once
#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/client_config.hpp"
#include <cstdlib>
#include <stdexcept>

// Exercise the client's optional routing setting using stock DuckDB APIs.
// This is not authentication or a server-side tenant authority.
class ScopedClientTenant {
public:
	explicit ScopedClientTenant(duckdb::ClientContext &context, const duckdb::string &value) : context(context) {
		auto &db = duckdb::DBConfig::GetConfig(context);
		if (!db.user_settings.HasExtensionOption("boilstream.tenant_id")) {
			db.AddExtensionOption("boilstream.tenant_id", "Test client routing setting", duckdb::LogicalType::VARCHAR);
		}
		duckdb::optional_ptr<const duckdb::ConfigurationOption> option;
		index = db.TryGetSettingIndex("boilstream.tenant_id", option).GetIndex();
		auto &settings = duckdb::ClientConfig::GetConfig(context).user_settings;
		had_value = settings.IsSet(index);
		if (had_value)
			context.TryGetCurrentSetting("boilstream.tenant_id", previous);
		settings.SetUserSetting(index, duckdb::Value(value));
	}
	~ScopedClientTenant() {
		auto &settings = duckdb::ClientConfig::GetConfig(context).user_settings;
		if (had_value)
			settings.SetUserSetting(index, previous);
		else
			settings.ClearSetting(index);
	}
	ScopedClientTenant(const ScopedClientTenant &) = delete;
	ScopedClientTenant &operator=(const ScopedClientTenant &) = delete;

private:
	duckdb::ClientContext &context;
	duckdb::idx_t index;
	bool had_value;
	duckdb::Value previous;
};

inline void LoadTestHttpfs(duckdb::Connection &connection) {
	const char *path = std::getenv("BOILSTREAM_HTTPFS_EXTENSION_PATH");
	if (!path || !*path)
		throw std::runtime_error("BOILSTREAM_HTTPFS_EXTENSION_PATH is required");
	duckdb::string quoted;
	for (char c : duckdb::string(path)) {
		quoted += c;
		if (c == '\'')
			quoted += c;
	}
	auto result = connection.Query("LOAD '" + quoted + "'");
	if (!result || result->HasError())
		throw std::runtime_error("Test HTTPFS load failed");
}
