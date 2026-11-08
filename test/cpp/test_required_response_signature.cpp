// Public adversarial boundary tests. Successful cryptographic exchanges are
// qualified by the private actual-server/native/WASM integration gate.
#include "duckdb.hpp"
#include "duckdb/main/config.hpp"
#include "boilstream_secret_storage.hpp"
#include "boilstream_protocol.hpp"
#include <iostream>
#include <stdexcept>
using namespace duckdb;
struct AssertionFailure {
	int line;
};
static void RequireAt(bool ok, int line) {
	if (!ok)
		throw AssertionFailure {line};
}
#define Require(value) RequireAt((value), __LINE__)
class BoilstreamSessionPublicationTestAccess {
public:
	static void Publish(RestApiSecretStorage &s, ClientContext &ctx,
	                    const shared_ptr<BoilstreamConnectionState> &state) {
		auto old = s.GetSessionForConnection(ctx.GetConnectionId());
		s.PublishSession(ctx, state, old, old ? old->authentication_generation.load() : 0, true);
	}
	static void Delete(RestApiSecretStorage &s, const string &url, BoilstreamConnectionState &state) {
		s.HttpDelete(url, state);
	}
};
struct Config : DBConfig {
	Config() {
		options.load_extensions = false;
		options.maximum_threads = 2;
	}
};
static const string AUTHORITY = "https://synthetic.invalid";
static const string MARKER = "private-boundary-marker";
static shared_ptr<BoilstreamProtocol> Protocol() {
	std::array<uint8_t, 32> key {};
	key[0] = 9;
	return make_shared_ptr<BoilstreamProtocol>(AUTHORITY, key);
}
static void Seed(BoilstreamConnectionState &state) {
	state.session_key.assign(64, 7);
	state.access_token = MARKER;
	state.refresh_token.assign(32, 8);
	state.token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
	state.protocol = Protocol();
}
class UntrustedHTTP : public HTTPUtil {
public:
	string mode;
	size_t requests = 0;
	bool safe_request = false;
	explicit UntrustedHTTP(string mode) : mode(std::move(mode)) {
	}
	unique_ptr<HTTPParams> InitializeParameters(DatabaseInstance &, const string &) override {
		auto params = make_uniq<HTTPParams>(*this);
		params->extra_headers["Authorization"] = MARKER;
		params->extra_headers["Cookie"] = MARKER;
		params->follow_location = true;
		params->retries = 3;
		return params;
	}
	unique_ptr<HTTPResponse> SendRequest(BaseRequest &request, unique_ptr<HTTPClient> &) override {
		++requests;
		auto &post = request.Cast<PostRequestInfo>();
		string body(reinterpret_cast<const char *>(post.buffer_in), post.buffer_in_len);
		safe_request = request.url == AUTHORITY + "/auth/api/protocol/v2/handshake" && body.find("BH2.c.") == 0 &&
		               body.find(MARKER) == string::npos && !request.headers.HasHeader("Authorization") &&
		               !request.headers.HasHeader("Cookie") && request.params.extra_headers.empty() &&
		               request.params.retries == 0 && !request.params.follow_location;
		if (mode == "exception")
			throw IOException(MARKER);
		auto response =
		    make_uniq<HTTPResponse>(mode == "status" ? static_cast<HTTPStatusCode>(403) : HTTPStatusCode::OK_200);
		response->headers.Insert("Set-Cookie", "session=" + MARKER);
		response->headers.Insert("Location", "https://elsewhere.invalid/" + MARKER);
		response->headers.Insert("X-Boilstream-Session-Resumption", "enabled");
		response->headers.Insert("X-Boilstream-Response-Signature", MARKER);
		post.buffer_out = mode == "oversized" ? string(167, 'x')
		                  : mode == "empty"   ? ""
		                                      : "{\"status\":200,\"body\":\"forged-success\"}";
		return response;
	}
};
int main() {
	Config config;
	DuckDB db(nullptr, &config);
	auto owned_storage = make_uniq<RestApiSecretStorage>(*db.instance, "");
	auto &storage = *owned_storage;
	SecretManager::Get(*db.instance).SetEnablePersistentSecrets(false);
	SecretManager::Get(*db.instance).LoadSecretStorage(std::move(owned_storage));
	int failures = 0;
	auto test = [&](const string &name, auto fn) {
		try {
			fn();
			std::cout << "CASE " << name << " PASS\n";
		} catch (const AssertionFailure &error) {
			++failures;
			std::cout << "CASE " << name << " FAIL line " << error.line << "\n";
		} catch (...) {
			++failures;
			std::cout << "CASE " << name << " FAIL\n";
		}
	};
	auto refuse = [&](auto action) {
		bool rejected = false;
		try {
			action();
		} catch (const IOException &error) {
			rejected = true;
			Require(string(error.what()).find(MARKER) == string::npos);
		}
		Require(rejected);
	};
	for (const auto &method : vector<string> {"GET", "POST", "DELETE", "OPAQUE_START", "OPAQUE_FINISH"}) {
		for (const auto &mode : vector<string> {"forged", "empty", "oversized", "status", "exception"}) {
			test(method + "_" + mode, [&] {
				auto http = make_shared_ptr<UntrustedHTTP>(mode);
				DBConfig::GetConfig(*db.instance).SetHTTPUtil(http);
				BoilstreamConnectionState state, other;
				Seed(state);
				Seed(other);
				if (method == "OPAQUE_START" || method == "OPAQUE_FINISH")
					state.is_exchanging = true;
				if (method == "OPAQUE_START") {
					state.session_key.clear();
					state.access_token.clear();
					state.refresh_token.clear();
				}
				other.session_key.assign(64, 9);
				auto generation = state.authentication_generation.load();
				auto send = [&] {
					if (method == "GET")
						storage.HttpGetWithState(AUTHORITY + "/secrets", state);
					else if (method == "DELETE")
						BoilstreamSessionPublicationTestAccess::Delete(storage, AUTHORITY + "/secrets", state);
					else {
						auto path = method == "OPAQUE_START"    ? "/auth/api/opaque-login-start"
						            : method == "OPAQUE_FINISH" ? "/auth/api/opaque-login-finish"
						                                        : "/auth/email/login";
						storage.HttpPostWithState(AUTHORITY + path, MARKER, state);
					}
				};
				refuse(send);
				Require(http->requests == 1 && http->safe_request);
				Require(state.session_key.empty() && state.access_token.empty() && state.refresh_token.empty());
				Require(state.authentication_generation.load() > generation && state.secret_cache->IsClosed());
				Require(other.session_key == vector<uint8_t>(64, 9) && !other.access_token.empty() &&
				        !other.secret_cache->IsClosed());
				refuse(send);
				Require(http->requests == 1); // No retry or use after channel retirement.
			});
		}
	}
	test("failed_old_owner_does_not_retire_replacement", [&] {
		auto http = make_shared_ptr<UntrustedHTTP>("forged");
		DBConfig::GetConfig(*db.instance).SetHTTPUtil(http);
		Connection connection(db);
		auto old = make_shared_ptr<BoilstreamConnectionState>();
		Seed(*old);
		BoilstreamSessionPublicationTestAccess::Publish(storage, *connection.context, old);
		auto replacement = make_shared_ptr<BoilstreamConnectionState>();
		Seed(*replacement);
		replacement->session_key.assign(64, 9);
		BoilstreamSessionPublicationTestAccess::Publish(storage, *connection.context, replacement);
		refuse([&] { storage.HttpGetWithState(AUTHORITY + "/secrets", *old); });
		Require(old->session_key.empty());
		Require(storage.GetSessionForConnection(connection.context->GetConnectionId()) == replacement);
		Require(replacement->session_key == vector<uint8_t>(64, 9) && !replacement->secret_cache->IsClosed());
	});
	test("closed_channel_requires_explicit_fresh_authentication", [&] {
		auto http = make_shared_ptr<UntrustedHTTP>("forged");
		DBConfig::GetConfig(*db.instance).SetHTTPUtil(http);
		auto channel = Protocol();
		HTTPHeaders metadata;
		channel->Close();
		channel->Close();
		refuse([&] {
			channel->Exchange(*db.instance, "POST", AUTHORITY + "/auth/email/login", MARKER, MARKER, &metadata);
		});
		Require(http->requests == 0);
		auto fresh = channel->Fresh();
		refuse(
		    [&] { fresh->Exchange(*db.instance, "POST", AUTHORITY + "/auth/email/login", MARKER, MARKER, &metadata); });
		Require(http->requests == 1 && http->safe_request && !metadata.HasHeader("Set-Cookie"));
	});
	test("authority_mismatch_closes_channel_without_network", [&] {
		auto http = make_shared_ptr<UntrustedHTTP>("forged");
		DBConfig::GetConfig(*db.instance).SetHTTPUtil(http);
		auto channel = Protocol();
		refuse([&] { channel->Exchange(*db.instance, "GET", "https://elsewhere.invalid/secrets", ""); });
		refuse([&] { channel->Exchange(*db.instance, "GET", AUTHORITY + "/secrets", ""); });
		Require(http->requests == 0);
	});
	return failures ? 1 : 0;
}
