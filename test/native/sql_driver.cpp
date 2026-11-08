// Test-only SQL adapter. It loads the selected production extension; there is no
// authentication implementation, injected identity or server key in this runner.
#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "yyjson.hpp"
#include <iostream>
#include <map>
#include <memory>
#include <stdexcept>

namespace json = duckdb_yyjson;
using duckdb::Connection;
using duckdb::DuckDB;
using std::string;

static string Text(json::yyjson_val *root, const char *field) {
	auto value = json::yyjson_obj_get(root, field);
	if (!json::yyjson_is_str(value)) {
		throw std::runtime_error("Missing driver field");
	}
	return string(json::yyjson_get_str(value), json::yyjson_get_len(value));
}
static string Quote(const string &value) {
	return "'" + duckdb::StringUtil::Replace(value, "'", "''") + "'";
}
using Document = std::unique_ptr<json::yyjson_doc, decltype(&json::yyjson_doc_free)>;
static Document Read() {
	string line;
	if (!std::getline(std::cin, line) || line.size() > 65536) {
		throw std::runtime_error("Missing or oversized driver input");
	}
	Document doc(json::yyjson_read(line.data(), line.size(), 0), json::yyjson_doc_free);
	if (!doc || !json::yyjson_is_obj(json::yyjson_doc_get_root(doc.get()))) {
		throw std::runtime_error("Invalid driver JSON");
	}
	return doc;
}
struct Reply {
	json::yyjson_mut_doc *doc = json::yyjson_mut_doc_new(nullptr);
	json::yyjson_mut_val *root = json::yyjson_mut_obj(doc);
	Reply() {
		json::yyjson_mut_doc_set_root(doc, root);
	}
	~Reply() {
		json::yyjson_mut_doc_free(doc);
	}
	void Send() {
		char *encoded = json::yyjson_mut_write(doc, 0, nullptr);
		if (!encoded) {
			throw std::runtime_error("Driver output allocation failed");
		}
		std::cout << encoded << std::endl;
		free(encoded);
	}
};
int main() {
	try {
		auto config_doc = Read();
		auto config_root = json::yyjson_doc_get_root(config_doc.get());
		duckdb::DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", duckdb::Value::BOOLEAN(true));
		config.options.load_extensions = false;
		config.options.maximum_threads = 2;
		DuckDB db(nullptr, &config);
		duckdb::ExtensionHelper::LoadExtension(db, "core_functions");
		Connection initial(db);
		auto settings = initial.Query("SET autoinstall_known_extensions=false; SET autoload_known_extensions=false;");
		if (settings->HasError()) {
			throw std::runtime_error("Cannot disable implicit extension downloads");
		}
		for (auto field : {"httpfs", "quack", "extension"}) {
			auto result = initial.Query("LOAD " + Quote(Text(config_root, field)));
			if (result->HasError()) {
				throw std::runtime_error(string("Cannot load selected ") + field + ": " + result->GetError());
			}
		}
		std::map<uint64_t, std::unique_ptr<Connection>> connections;
		uint64_t next_id = 1;
		{
			Reply reply;
			json::yyjson_mut_obj_add_bool(reply.doc, reply.root, "ready", true);
			reply.Send();
		}
		while (true) {
			auto command = Read();
			auto root = json::yyjson_doc_get_root(command.get());
			auto op = Text(root, "op");
			Reply reply;
			if (op == "connect") {
				auto id = next_id++;
				connections.emplace(id, std::make_unique<Connection>(db));
				json::yyjson_mut_obj_add_uint(reply.doc, reply.root, "connection", id);
			} else if (op == "query" || op == "close") {
				auto value = json::yyjson_obj_get(root, "connection");
				if (!json::yyjson_is_uint(value) || !connections.count(json::yyjson_get_uint(value))) {
					throw std::runtime_error("Invalid driver connection");
				}
				auto id = json::yyjson_get_uint(value);
				if (op == "close") {
					connections.erase(id);
				} else {
					auto result = connections.at(id)->Query(Text(root, "sql"));
					if (result->HasError()) {
						json::yyjson_mut_obj_add_strcpy(reply.doc, reply.root, "error", result->GetError().c_str());
					} else {
						auto rows = json::yyjson_mut_arr(reply.doc);
						json::yyjson_mut_obj_add_val(reply.doc, reply.root, "rows", rows);
						for (duckdb::idx_t r = 0; r < result->RowCount(); ++r) {
							auto row = json::yyjson_mut_obj(reply.doc);
							json::yyjson_mut_arr_append(rows, row);
							for (duckdb::idx_t c = 0; c < result->ColumnCount(); ++c) {
								auto cell = result->Collection().GetValue(c, r);
								auto text = cell.ToString();
								auto encoded = cell.IsNull()
								                   ? json::yyjson_mut_null(reply.doc)
								                   : json::yyjson_mut_strncpy(reply.doc, text.data(), text.size());
								json::yyjson_mut_obj_add(
								    row, json::yyjson_mut_strcpy(reply.doc, result->GetNames()[c].c_str()), encoded);
							}
						}
					}
				}
			} else if (op == "quit") {
				reply.Send();
				break;
			} else {
				throw std::runtime_error("Invalid driver operation");
			}
			reply.Send();
		}
	} catch (const std::exception &error) {
		std::cerr << "Native SQL driver failed: " << error.what() << std::endl;
		return 1;
	}
	return 0;
}
