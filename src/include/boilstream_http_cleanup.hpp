#pragma once

#include "boilstream_security.hpp"
#include "duckdb/main/http/http_util.hpp"

namespace boilstream {

inline void WipeHeaders(duckdb::HTTPHeaders &headers) noexcept {
	for (auto &entry : headers) {
		Wipe(entry.second);
	}
}
class HeaderCleanup {
public:
	explicit HeaderCleanup(duckdb::HTTPHeaders &headers) : headers(headers) {
	}
	~HeaderCleanup() {
		WipeHeaders(headers);
	}
	HeaderCleanup(const HeaderCleanup &) = delete;
	HeaderCleanup &operator=(const HeaderCleanup &) = delete;

private:
	duckdb::HTTPHeaders &headers;
};

// Existing callers use GetHeaderValue (first field value). Copy only that view
// rather than copying HTTPHeaders' private duplicate-value storage. The provider
// owns the original repeated headers; its internal allocations are not exposed.
inline void CopyHeaders(const duckdb::HTTPHeaders &source, duckdb::HTTPHeaders &target) {
	WipeHeaders(target);
	target = duckdb::HTTPHeaders();
	for (const auto &entry : source) {
		target.Insert(entry.first, entry.second);
	}
}
class ParamsCleanup {
public:
	explicit ParamsCleanup(duckdb::HTTPParams *params) : params(params) {
	}
	~ParamsCleanup() {
		if (!params) {
			return;
		}
		Wipe(params->http_proxy_username);
		Wipe(params->http_proxy_password);
		for (auto &entry : params->extra_headers) {
			Wipe(entry.second);
		}
	}
	ParamsCleanup(const ParamsCleanup &) = delete;
	ParamsCleanup &operator=(const ParamsCleanup &) = delete;

private:
	duckdb::HTTPParams *params;
};

class RequestCleanup {
public:
	explicit RequestCleanup(duckdb::BaseRequest &request) : request(request) {
	}
	~RequestCleanup() {
		WipeHeaders(request.headers);
		Wipe(request.url);
		Wipe(request.path);
		Wipe(request.proto_host_port);
	}
	RequestCleanup(const RequestCleanup &) = delete;
	RequestCleanup &operator=(const RequestCleanup &) = delete;

private:
	duckdb::BaseRequest &request;
};
class ResponseCleanup {
public:
	explicit ResponseCleanup(duckdb::HTTPResponse &response) : response(response) {
	}
	~ResponseCleanup() {
		WipeHeaders(response.headers);
		Wipe(response.body);
		Wipe(response.url);
		Wipe(response.request_error);
		Wipe(response.reason);
	}
	ResponseCleanup(const ResponseCleanup &) = delete;
	ResponseCleanup &operator=(const ResponseCleanup &) = delete;

private:
	duckdb::HTTPResponse &response;
};
} // namespace boilstream
