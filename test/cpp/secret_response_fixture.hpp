#pragma once
#include "yyjson.hpp"
#include "duckdb/common/exception.hpp"
// This is server fixture metadata, never a lifetime inferred by the writer.
static duckdb::string WithFixtureExpiry(const duckdb::string &json) {
 using namespace duckdb_yyjson;
 auto source = std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)>(
     yyjson_read(json.data(), json.size(), 0), yyjson_doc_free);
 if (!source) throw duckdb::InvalidInputException("Invalid fixture JSON");
 auto doc = std::unique_ptr<yyjson_mut_doc, decltype(&yyjson_mut_doc_free)>(
     yyjson_doc_mut_copy(source.get(), nullptr), yyjson_mut_doc_free);
 auto root = yyjson_mut_doc_get_root(doc.get());
 yyjson_mut_obj_remove_key(root, "expires_at");
 yyjson_mut_obj_add_str(doc.get(), root, "expires_at", "2099-01-01T00:00:00Z");
 auto text = std::unique_ptr<char, decltype(&free)>(yyjson_mut_write(doc.get(), 0, nullptr), free);
 if (!text) throw duckdb::InvalidInputException("Invalid fixture JSON");
 return text.get();
}
