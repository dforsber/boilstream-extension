#pragma once

#include "boilstream_json.hpp"
#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/vector.hpp"

namespace boilstream {

struct CatalogVersionInfo {
	uint64_t version;
	duckdb::string catalog_name;
};
using CatalogVersions = duckdb::case_insensitive_map_t<CatalogVersionInfo>;

// The authenticated channel owns the endpoint. A database default must never
// redirect an existing session. Empty means this is not a canonical secrets URL.
inline duckdb::string CatalogVersionsURL(const duckdb::string &endpoint) {
	const duckdb::string suffix = "/secrets";
	auto pos = endpoint.rfind(suffix);
	if (pos == duckdb::string::npos || pos + suffix.size() != endpoint.size()) {
		return "";
	}
	return endpoint.substr(0, pos) + "/catalog-versions";
}

// Parse only a body already accepted by the application protocol. This pure
// function grants no authentication capability and performs no network or I/O.
inline CatalogVersions ParseCatalogVersions(const duckdb::string &response) {
	namespace json = duckdb_yyjson;
	CatalogVersions versions;
	JsonArena arena;
	auto doc = arena.Read(response.data(), response.size());
	if (!doc) {
		return versions;
	}
	auto catalogs = json::yyjson_obj_get(json::yyjson_doc_get_root(doc), "catalogs");
	if (!json::yyjson_is_obj(catalogs)) {
		return versions;
	}
	json::yyjson_obj_iter iter;
	json::yyjson_obj_iter_init(catalogs, &iter);
	json::yyjson_val *key;
	while ((key = json::yyjson_obj_iter_next(&iter))) {
		auto value = json::yyjson_obj_iter_get_val(key);
		auto version = json::yyjson_obj_get(value, "version");
		auto name = json::yyjson_obj_get(value, "catalog_name");
		if (!json::yyjson_is_uint(version) || !json::yyjson_is_str(name)) {
			continue;
		}
		duckdb::string catalog_name(json::yyjson_get_str(name), json::yyjson_get_len(name));
		duckdb::string catalog_id(json::yyjson_get_str(key), json::yyjson_get_len(key));
		if (!catalog_name.empty() && !catalog_id.empty()) {
			versions[catalog_id] = {json::yyjson_get_uint(version), catalog_name};
		}
	}
	return versions;
}

struct CatalogVersionUpdate {
	CatalogVersions versions;
	duckdb::vector<duckdb::string> refresh;
};

// Return a plan without changing either input. The connection owner applies the
// versions under its lock and expires the affected credentials after releasing it.
inline CatalogVersionUpdate ReconcileCatalogVersions(const CatalogVersions &cached, const CatalogVersions &incoming) {
	CatalogVersionUpdate result {cached, {}};
	for (const auto &entry : incoming) {
		auto previous = cached.find(entry.first);
		if (previous != cached.end() && entry.second.version > previous->second.version) {
			result.refresh.push_back(entry.second.catalog_name);
		}
		result.versions[entry.first] = entry.second;
	}
	return result;
}

} // namespace boilstream
