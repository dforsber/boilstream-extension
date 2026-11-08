#include "boilstream_protocol.hpp"
#include "boilstream_json.hpp"
#include "boilstream_http_cleanup.hpp"
#include "boilstream_diagnostics.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/database.hpp"
#include <map>

namespace duckdb {
namespace {
using namespace duckdb_yyjson;
string Authority(const string &url) {
	boilstream::ValidateEndpoint(url);
	auto start = url.find("://") + 3;
	auto end = url.find_first_of("/?", start);
	return url.substr(0, end);
}
class ProtocolPins : public ClientContextState {
public:
	mutex lock;
	std::map<string, std::array<uint8_t, 32>> pins;
};
string Buffer(OpaqueResult result) {
	struct Owner {
		OpaqueBuffer value;
		~Owner() {
			opaque_free_buffer(value);
		}
	} owner {result.buffer};
	if (result.error != OPAQUE_SUCCESS) {
		throw IOException("Application protocol verification failed; authenticate on a fresh channel");
	}
	return string(reinterpret_cast<char *>(result.buffer.data), result.buffer.len);
}
string Write(boilstream::JsonArena &arena, yyjson_mut_doc *doc) {
	size_t length = 0;
	auto value = yyjson_mut_write_opts(doc, 0, &arena.Allocator(), &length, nullptr);
	if (!value) {
		throw std::bad_alloc();
	}
	return string(value, length);
}
string Send(DatabaseInstance &db, const string &url, const string &body, size_t max_size) {
	auto &http = HTTPUtil::Get(db);
	auto params = http.InitializeParameters(db, url);
	boilstream::ParamsCleanup wipe_params(params.get());
	if (!params) {
		throw IOException("Application protocol transport unavailable");
	}
	params->follow_location = false;
	params->retries = 0;
	// Never carry credentials from HTTP settings into the protocol request.
	for (auto &entry : params->extra_headers) {
		boilstream::Wipe(entry.second);
	}
	params->extra_headers.clear();
	HTTPHeaders headers(db);
	boilstream::HeaderCleanup wipe_headers(headers);
	headers.Insert("Content-Type", "text/plain");
	PostRequestInfo request(url, headers, *params, const_data_ptr_cast(body.data()), body.size());
	boilstream::RequestCleanup wipe_request(request);
	boilstream::WipeOnExit wipe_buffer(request.buffer_out);
	auto response = http.Request(request);
	if (!response) {
		throw IOException("Application protocol transport failed; outcome unknown");
	}
	boilstream::ResponseCleanup wipe_response(*response);
	// The DuckDB host buffers POST data before returning it. This bounds our
	// parsing/copying; it cannot bound that host's earlier allocation.
	if (request.buffer_out.size() > max_size || response->body.size() > max_size) {
		throw IOException("Application protocol response exceeds limit");
	}
	if (static_cast<unsigned>(response->status) != 200) {
		throw IOException("Application protocol transport refused; outcome unknown");
	}
	// Deliberately ignore every response header, including cookies/status metadata.
	return string(request.buffer_out);
}
} // namespace
BoilstreamProtocol::BoilstreamProtocol(string authority, const std::array<uint8_t, 32> &key)
    : authority(std::move(authority)), key(key) {
}
BoilstreamProtocol::~BoilstreamProtocol() {
	bs_protocol_free(handle);
}
void BoilstreamProtocol::CloseLocked() {
	closed = true;
	bs_protocol_free(handle);
	handle = nullptr;
}
void BoilstreamProtocol::Close() {
	lock_guard<mutex> guard(lock);
	CloseLocked();
}
shared_ptr<BoilstreamProtocol> BoilstreamProtocol::Fresh() const {
	return make_shared_ptr<BoilstreamProtocol>(authority, key);
}
void BoilstreamProtocol::Configure(ClientContext &context, const string &authority, const string &hex_key) {
	if (Authority(authority) != authority || hex_key.size() != 64) {
		throw InvalidInputException("Server pin requires an exact URL authority and 64 hex characters");
	}
	std::array<uint8_t, 32> key;
	auto digit = [](char c) -> uint8_t {
		if (c >= '0' && c <= '9') {
			return c - '0';
		}
		if (c >= 'a' && c <= 'f') {
			return c - 'a' + 10;
		}
		if (c >= 'A' && c <= 'F') {
			return c - 'A' + 10;
		}
		throw InvalidInputException("Server public key must be hexadecimal");
	};
	for (size_t i = 0; i < key.size(); ++i) {
		key[i] = (digit(hex_key[2 * i]) << 4) | digit(hex_key[2 * i + 1]);
	}
	// Validate low-order/noncanonical keys with the same Rust Pin implementation.
	ApplicationProtocol *candidate = nullptr;
	auto result = bs_protocol_start(reinterpret_cast<const uint8_t *>(authority.data()), authority.size(), key.data(),
	                                &candidate);
	bs_protocol_free(candidate);
	opaque_free_buffer(result.buffer);
	if (result.error != OPAQUE_SUCCESS) {
		throw InvalidInputException("Invalid server pin or entropy unavailable");
	}
	auto pins = context.registered_state->GetOrCreate<ProtocolPins>("boilstream_protocol_pins");
	lock_guard<mutex> guard(pins->lock);
	if (pins->pins.size() >= 64 && pins->pins.find(authority) == pins->pins.end()) {
		throw InvalidInputException("Too many configured server pins for this connection");
	}
	pins->pins[authority] = key;
}
shared_ptr<BoilstreamProtocol> BoilstreamProtocol::Create(ClientContext &context, const string &url) {
	auto authority = Authority(url);
	auto pins = context.registered_state->Get<ProtocolPins>("boilstream_protocol_pins");
	if (!pins) {
		throw InvalidInputException("Configure the trusted key with PRAGMA boilstream_server_key before login");
	}
	lock_guard<mutex> guard(pins->lock);
	auto entry = pins->pins.find(authority);
	if (entry == pins->pins.end()) {
		throw InvalidInputException("No trusted server key configured for this authority");
	}
	return make_shared_ptr<BoilstreamProtocol>(authority, entry->second);
}
string BoilstreamProtocol::Exchange(DatabaseInstance &db, const string &method, const string &url, const string &body,
                                    const string &cookie, HTTPHeaders *metadata) {
	lock_guard<mutex> guard(lock);
	if (closed) {
		throw IOException("Application channel closed; explicitly authenticate again");
	}
	string verified;
	boilstream::WipeOnExit wipe_verified(verified);
	try {
		if (Authority(url) != authority || url.size() <= authority.size() || url[authority.size()] != '/') {
			throw InvalidInputException("Request authority differs from the pinned channel");
		}
		if (!handle) {
			auto hello = Buffer(bs_protocol_start(reinterpret_cast<const uint8_t *>(authority.data()), authority.size(),
			                                      key.data(), &handle));
			auto answer = Send(db, authority + "/auth/api/protocol/v2/handshake", hello, 166);
			if (bs_protocol_accept(handle, reinterpret_cast<const uint8_t *>(answer.data()), answer.size()) !=
			    OPAQUE_SUCCESS) {
				throw IOException("Server did not prove the configured public key");
			}
		}
		boilstream::JsonArena arena;
		auto doc = arena.New();
		auto obj = yyjson_mut_obj(doc);
		yyjson_mut_doc_set_root(doc, obj);
		auto target = url.substr(authority.size());
		yyjson_mut_obj_add_strcpy(doc, obj, "method", method.c_str());
		yyjson_mut_obj_add_strncpy(doc, obj, "target", target.data(), target.size());
		yyjson_mut_obj_add_strncpy(doc, obj, "body", body.data(), body.size());
		if (cookie.empty()) {
			yyjson_mut_obj_add_null(doc, obj, "cookie");
		} else {
			yyjson_mut_obj_add_strncpy(doc, obj, "cookie", cookie.data(), cookie.size());
		}
		yyjson_mut_obj_add_null(doc, obj, "idempotency_key");
		auto json = Write(arena, doc);
		boilstream::WipeOnExit wipe_json(json);
		auto sealed = Buffer(bs_protocol_seal(handle, reinterpret_cast<const uint8_t *>(json.data()), json.size()));
		auto reply =
		    Send(db, authority + "/auth/api/protocol/v2/request", sealed, ((10 * 1024 * 1024 + 134) * 4 + 2) / 3 + 4);
		verified = Buffer(bs_protocol_open(handle, reinterpret_cast<const uint8_t *>(reply.data()), reply.size()));
	} catch (...) {
		CloseLocked();
		throw IOException("Application protocol exchange failed; outcome unknown, authenticate again");
	}
	// Only authenticated inner status and metadata may affect application behavior.
	boilstream::JsonArena arena;
	auto doc = arena.Read(verified.data(), verified.size());
	if (!doc) {
		CloseLocked();
		throw IOException("Invalid verified application response");
	}
	auto root = yyjson_doc_get_root(doc);
	auto status = yyjson_obj_get(root, "status");
	auto payload = yyjson_obj_get(root, "body");
	if (!yyjson_is_uint(status) || !yyjson_is_str(payload)) {
		CloseLocked();
		throw IOException("Invalid verified application response");
	}
	if (metadata) {
		boilstream::WipeHeaders(*metadata);
		*metadata = HTTPHeaders();
		auto cookies = yyjson_obj_get(root, "cookies");
		for (size_t i = 0; i < yyjson_arr_size(cookies); ++i) {
			auto value = yyjson_arr_get(cookies, i);
			metadata->Insert("Set-Cookie", string(yyjson_get_str(value), yyjson_get_len(value)));
		}
		metadata->Insert("X-Boilstream-Session-Resumption",
		                 yyjson_get_bool(yyjson_obj_get(root, "session_resumption")) ? "enabled" : "disabled");
	}
	auto code = yyjson_get_uint(status);
	if (code < 200 || code >= 300) {
		BoilstreamThrowHttpStatus("Verified application request refused", code);
	}
	return string(yyjson_get_str(payload), yyjson_get_len(payload));
}
} // namespace duckdb
