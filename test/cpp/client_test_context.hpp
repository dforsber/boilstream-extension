#pragma once
#include "duckdb.hpp"
#include <cstdlib>
#include <stdexcept>

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
