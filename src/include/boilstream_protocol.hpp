#pragma once
#include "duckdb/common/common.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/http_util.hpp"
#include "opaque_client.h"
#include <array>

namespace duckdb {
class ClientContext;
class DatabaseInstance;
// Only the protocol verifier can construct this error. Ordinary HTTP failures
// cannot masquerade as an authenticated application refusal.
class BoilstreamApplicationError : public IOException {
public:
	bool InvalidatesIdentity() const {
		return status == 401 || status == 403;
	}

private:
	friend class BoilstreamProtocol;
	explicit BoilstreamApplicationError(int status)
	    : IOException(unordered_map<string, string> {{"status_code", std::to_string(status)}},
	                  "Verified application request refused: HTTP %d", status),
	      status(status) {
	}
	int status;
};
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
