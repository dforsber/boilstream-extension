#pragma once
#include "duckdb/common/common.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/http_util.hpp"
#include "opaque_client.h"
#include <array>

namespace duckdb {
class ClientContext;
class DatabaseInstance;
// One instance belongs to one logical authentication flow/connection. Its lock
// covers sequence allocation, HTTP and verification; copying keys is impossible.
class BoilstreamProtocol {
public:
	BoilstreamProtocol(string authority, const std::array<uint8_t, 32> &key);
	~BoilstreamProtocol();
	BoilstreamProtocol(const BoilstreamProtocol &) = delete;
	BoilstreamProtocol &operator=(const BoilstreamProtocol &) = delete;
	static void Configure(ClientContext &context, const string &authority, const string &hex_key);
	static shared_ptr<BoilstreamProtocol> Create(ClientContext &context, const string &url);
	shared_ptr<BoilstreamProtocol> Fresh() const;
	string Exchange(DatabaseInstance &db, const string &method, const string &url, const string &body,
	                const string &cookie = "", HTTPHeaders *metadata = nullptr);
	void Close();

private:
	string authority;
	std::array<uint8_t, 32> key;
	mutex lock;
	ApplicationProtocol *handle = nullptr;
	bool closed = false;
	void CloseLocked();
};
} // namespace duckdb
