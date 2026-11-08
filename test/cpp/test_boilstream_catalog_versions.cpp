#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "boilstream_secret_storage.hpp"
#include "boilstream_catalog_versions.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/common/http_util.hpp"
#include <atomic>
#include <thread>
#include <chrono>

using namespace duckdb;
using namespace std;

class BoilstreamCatalogVersionTestAccess {
public:
	static auto &GetSecretExpiration(BoilstreamConnectionState &state) {
		return state.secret_expiration;
	}
	static void RefreshCatalogCredentials(RestApiSecretStorage &storage, const string &name,
	                                      BoilstreamConnectionState &state) {
		storage.RefreshCatalogCredentials(name, state);
	}
	static void CheckCatalogVersions(RestApiSecretStorage &storage, BoilstreamConnectionState &state) {
		storage.CheckCatalogVersions(state);
	}
	static bool Begin(RestApiSecretStorage &storage, BoilstreamConnectionState &state,
	                  std::chrono::system_clock::time_point now) {
		return storage.BeginCatalogVersionPoll(state, now);
	}
	static void Apply(RestApiSecretStorage &storage, BoilstreamConnectionState &state, const string &body) {
		storage.ApplyCatalogVersions(state, boilstream::ParseCatalogVersions(body));
	}
};
struct TestFixture {
	duckdb::unique_ptr<DuckDB> db;
	duckdb::unique_ptr<RestApiSecretStorage> storage;
	BoilstreamConnectionState conn_state;
	explicit TestFixture(string endpoint = "https://localhost/secrets") : conn_state(endpoint) {
		DBConfig config;
		config.options.load_extensions = false;
		config.options.maximum_threads = 2;
		db = duckdb::make_uniq<DuckDB>(nullptr, &config);
		storage = duckdb::make_uniq<RestApiSecretStorage>(*db->instance, "https://localhost/secrets");
	}
};

// No synthetic successful server crypto. The production client must reject this
// peer before sending an inner catalog request. Positive transport runs privately
// against the real server; parser/planner tests below exercise pure client rules.
class RejectingCatalogHTTP : public HTTPUtil {
public:
	duckdb::vector<string> requests;
	bool valid_hello = false;
	duckdb::unique_ptr<HTTPParams> InitializeParameters(DatabaseInstance &, const string &) override {
		return make_uniq<HTTPParams>(*this);
	}
	duckdb::unique_ptr<HTTPResponse> SendRequest(BaseRequest &request, duckdb::unique_ptr<HTTPClient> &) override {
		requests.push_back(request.url);
		if (request.type != RequestType::POST_REQUEST)
			throw IOException("Unexpected request kind");
		auto &post = request.Cast<PostRequestInfo>();
		string hello(reinterpret_cast<const char *>(post.buffer_in), post.buffer_in_len);
		valid_hello = hello.find("BH2.c.") == 0 && hello.find("catalog-version-test-token") == string::npos;
		post.buffer_out = "forged-server-proof";
		return make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
	}
};
static duckdb::shared_ptr<RejectingCatalogHTTP>
RecordCatalogVersionRequests(TestFixture &fixture, const string &authority = "https://localhost") {
	auto http = make_shared_ptr<RejectingCatalogHTTP>();
	DBConfig::GetConfig(*fixture.db->instance).SetHTTPUtil(http);
	fixture.conn_state.access_token = "catalog-version-test-token";
	fixture.conn_state.session_key.assign(32, 7);
	std::array<uint8_t, 32> key {};
	key[0] = 9;
	fixture.conn_state.protocol = make_shared_ptr<BoilstreamProtocol>(authority, key);
	return http;
}

TEST_CASE("Catalog route derives only from the owning canonical endpoint", "[boilstream][catalog_versions]") {
	for (const auto &base : {"https://localhost", "https://catalog.example:8443", "https://[::1]:8443",
	                         "https://gateway.example/product"}) {
		REQUIRE(boilstream::CatalogVersionsURL(string(base) + "/secrets") == string(base) + "/catalog-versions");
	}
	for (const auto &endpoint : {"", "https://catalog.example", "https://catalog.example/secrets/other",
	                             "https://catalog.example/secrets?other=value"}) {
		REQUIRE(boilstream::CatalogVersionsURL(endpoint).empty());
		TestFixture fixture(endpoint);
		auto http = RecordCatalogVersionRequests(fixture);
		BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);
		REQUIRE(http->requests.empty());
	}
}

TEST_CASE("RefreshCatalogCredentials", "[boilstream][catalog_versions]") {
	TestFixture fixture;

	SECTION("Sets secret expiration to minimum time_point") {
		string catalog_name = "my_catalog";

		// Call refresh
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, catalog_name,
		                                                              fixture.conn_state);

		// Verify expiration was set to minimum
		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(fixture.conn_state);
		REQUIRE(expiration_map.find(catalog_name) != expiration_map.end());
		REQUIRE(expiration_map[catalog_name] == std::chrono::system_clock::time_point::min());
	}

	SECTION("Multiple catalogs can be refreshed independently") {
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, "catalog_1",
		                                                              fixture.conn_state);
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, "catalog_2",
		                                                              fixture.conn_state);
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, "catalog_3",
		                                                              fixture.conn_state);

		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(fixture.conn_state);
		REQUIRE(expiration_map.size() == 3);
		REQUIRE(expiration_map["catalog_1"] == std::chrono::system_clock::time_point::min());
		REQUIRE(expiration_map["catalog_2"] == std::chrono::system_clock::time_point::min());
		REQUIRE(expiration_map["catalog_3"] == std::chrono::system_clock::time_point::min());
	}

	SECTION("Calling refresh twice doesn't cause issues") {
		string catalog_name = "double_refresh_test";

		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, catalog_name,
		                                                              fixture.conn_state);
		BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, catalog_name,
		                                                              fixture.conn_state);

		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(fixture.conn_state);
		REQUIRE(expiration_map[catalog_name] == std::chrono::system_clock::time_point::min());
	}
}

//===----------------------------------------------------------------------===//
// Test: Thread Safety
//===----------------------------------------------------------------------===//
TEST_CASE("Catalog Version Thread Safety", "[boilstream][catalog_versions][threading]") {
	SECTION("Concurrent RefreshCatalogCredentials calls") {
		TestFixture fixture;
		const int num_threads = 10;
		const int ops_per_thread = 50;

		std::vector<std::thread> threads;
		for (int t = 0; t < num_threads; t++) {
			threads.emplace_back([&fixture, t, ops_per_thread]() {
				for (int i = 0; i < ops_per_thread; i++) {
					string catalog_name = "catalog_" + std::to_string(t) + "_" + std::to_string(i);
					BoilstreamCatalogVersionTestAccess::RefreshCatalogCredentials(*fixture.storage, catalog_name,
					                                                              fixture.conn_state);
				}
			});
		}

		for (auto &thread : threads) {
			thread.join();
		}

		// Should not crash, and all catalogs should be in expiration map
		auto &expiration_map = BoilstreamCatalogVersionTestAccess::GetSecretExpiration(fixture.conn_state);
		REQUIRE(expiration_map.size() == num_threads * ops_per_thread);
		for (int thread = 0; thread < num_threads; ++thread) {
			for (int operation = 0; operation < ops_per_thread; ++operation) {
				auto name = "catalog_" + std::to_string(thread) + "_" + std::to_string(operation);
				auto found = expiration_map.find(name);
				REQUIRE(found != expiration_map.end());
				REQUIRE(found->second == std::chrono::system_clock::time_point::min());
			}
		}
	}
}

//===----------------------------------------------------------------------===//
// Test: Empty Endpoint Handling
//===----------------------------------------------------------------------===//
TEST_CASE("Catalog polling without an authenticated session performs no HTTP", "[boilstream][catalog_versions]") {
	TestFixture fixture;
	auto http = make_shared_ptr<RejectingCatalogHTTP>();
	DBConfig::GetConfig(*fixture.db->instance).SetHTTPUtil(http);
	BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);
	REQUIRE(http->requests.empty());
	REQUIRE(fixture.conn_state.catalog_versions.empty());
	REQUIRE(fixture.conn_state.client_sequence == 0);
}

//===----------------------------------------------------------------------===//
// Test: Secret Expiration in Connection State
//===----------------------------------------------------------------------===//
TEST_CASE("Secret Expiration in Connection State", "[boilstream][catalog_versions]") {
	BoilstreamConnectionState conn_state;

	SECTION("StoreExpiration and GetSecretExpiration work correctly") {
		string secret_name = "test_secret";
		auto expiration = std::chrono::system_clock::now() + std::chrono::hours(1);

		conn_state.StoreExpiration(secret_name, expiration);
		auto retrieved = conn_state.GetSecretExpiration(secret_name);

		REQUIRE(retrieved == expiration);
	}

	SECTION("IsSecretExpired returns true for expired secrets") {
		string secret_name = "expired_secret";
		auto past = std::chrono::system_clock::now() - std::chrono::hours(1);

		conn_state.StoreExpiration(secret_name, past);
		REQUIRE(conn_state.IsSecretExpired(secret_name) == true);
	}

	SECTION("IsSecretExpired returns false for valid secrets") {
		string secret_name = "valid_secret";
		auto future = std::chrono::system_clock::now() + std::chrono::hours(1);

		conn_state.StoreExpiration(secret_name, future);
		REQUIRE(conn_state.IsSecretExpired(secret_name) == false);
	}

	SECTION("IsSecretExpired returns true for unknown secrets") {
		REQUIRE(conn_state.IsSecretExpired("nonexistent") == true);
	}

	SECTION("ClearExpiration removes secret from map") {
		string secret_name = "to_clear";
		conn_state.StoreExpiration(secret_name, std::chrono::system_clock::now());

		conn_state.ClearExpiration(secret_name);

		// After clearing, GetSecretExpiration returns min time_point
		REQUIRE(conn_state.GetSecretExpiration(secret_name) == std::chrono::system_clock::time_point::min());
	}
}

TEST_CASE("Polling admission is atomic, time bounded and connection owned", "[boilstream][catalog_versions]") {
	TestFixture fixture;
	auto now = std::chrono::system_clock::now();
	std::atomic<int> admitted {0};
	std::vector<std::thread> threads;
	for (size_t i = 0; i < 16; ++i) {
		threads.emplace_back([&] {
			if (BoilstreamCatalogVersionTestAccess::Begin(*fixture.storage, fixture.conn_state, now))
				++admitted;
		});
	}
	for (auto &thread : threads)
		thread.join();
	REQUIRE(admitted == 1);
	REQUIRE_FALSE(
	    BoilstreamCatalogVersionTestAccess::Begin(*fixture.storage, fixture.conn_state, now - std::chrono::seconds(1)));
	REQUIRE_FALSE(BoilstreamCatalogVersionTestAccess::Begin(*fixture.storage, fixture.conn_state,
	                                                        now + std::chrono::seconds(59)));
	REQUIRE(BoilstreamCatalogVersionTestAccess::Begin(*fixture.storage, fixture.conn_state,
	                                                  now + std::chrono::seconds(60)));
	BoilstreamConnectionState other;
	REQUIRE(BoilstreamCatalogVersionTestAccess::Begin(*fixture.storage, other, now));
	REQUIRE(fixture.conn_state.last_version_check == now + std::chrono::seconds(60));
	REQUIRE(other.last_version_check == now);
}

TEST_CASE("Catalog version parser rejects malformed entries without coercion", "[boilstream][catalog_versions]") {
	for (const auto &body : {"", "{", "null", "[]", "{}", R"({"catalogs":[]})", R"({"catalogs":{"x":null}})",
	                         R"({"catalogs":{"x":{"version":-1,"catalog_name":"a"}}})",
	                         R"({"catalogs":{"x":{"version":1.5,"catalog_name":"a"}}})",
	                         R"({"catalogs":{"x":{"version":"1","catalog_name":"a"}}})",
	                         R"({"catalogs":{"x":{"version":1,"catalog_name":""}}})",
	                         R"({"catalogs":{"":{"version":1,"catalog_name":"a"}}})"}) {
		INFO(body);
		REQUIRE(boilstream::ParseCatalogVersions(body).empty());
	}
	auto parsed = boilstream::ParseCatalogVersions(
	    R"({"catalogs":{"first":{"version":0,"catalog_name":"name\u0000tail"},"bad":{"version":true},"last":{"version":18446744073709551615,"catalog_name":"last"}}})");
	REQUIRE(parsed.size() == 2);
	REQUIRE(parsed.at("first").version == 0);
	REQUIRE(parsed.at("first").catalog_name == string("name\0tail", 9));
	REQUIRE(parsed.at("last").version == UINT64_MAX);
}

TEST_CASE("Version plans preserve inputs and expire exactly the changed credentials",
          "[boilstream][catalog_versions]") {
	struct VersionCase {
		uint64_t old_version, new_version;
		bool known, refresh;
	};
	for (const auto &value : {VersionCase {0, 0, false, false},
	                          {5, 6, true, true},
	                          {5, 5, true, false},
	                          {5, 4, true, false},
	                          {UINT64_MAX - 1, UINT64_MAX, true, true}}) {
		DYNAMIC_SECTION(value.old_version << " -> " << value.new_version << " known=" << value.known) {
			TestFixture fixture;
			const string id = "11111111-1111-4111-8111-111111111111";
			if (value.known)
				fixture.conn_state.catalog_versions[id] = {value.old_version, "alpha"};
			fixture.conn_state.catalog_versions["unchanged"] = {42, "unrelated"};
			auto future = std::chrono::system_clock::now() + std::chrono::hours(1);
			fixture.conn_state.StoreExpiration("alpha", future);
			fixture.conn_state.StoreExpiration("unrelated", future);
			auto secret = make_uniq<KeyValueSecret>(duckdb::vector<string> {"test://"}, Identifier("test"), "config",
			                                        Identifier("alpha"));
			fixture.conn_state.secret_cache->Put(BoilstreamSecretCache::Prepare(std::move(secret), future, 100),
			                                     fixture.conn_state.secret_cache->Revision());
			BoilstreamConnectionState other;
			other.StoreExpiration("alpha", future);
			other.catalog_versions[id] = {99, "alpha"};
			auto body = "{\"catalogs\":{\"" + id + "\":{\"version\":" + std::to_string(value.new_version) +
			            ",\"catalog_name\":\"alpha\"}}}";
			auto incoming = boilstream::ParseCatalogVersions(body);
			auto plan = boilstream::ReconcileCatalogVersions(fixture.conn_state.catalog_versions, incoming);
			REQUIRE(plan.refresh.size() == (value.refresh ? 1 : 0));
			REQUIRE(fixture.conn_state.catalog_versions.size() == (value.known ? 2 : 1));
			if (value.known)
				REQUIRE(fixture.conn_state.catalog_versions.at(id).version == value.old_version);
			REQUIRE(incoming.at(id).version == value.new_version);
			BoilstreamCatalogVersionTestAccess::Apply(*fixture.storage, fixture.conn_state, body);
			REQUIRE(fixture.conn_state.catalog_versions.at(id).version == value.new_version);
			REQUIRE(fixture.conn_state.catalog_versions.at(id).catalog_name == "alpha");
			REQUIRE(fixture.conn_state.catalog_versions.at("unchanged").version == 42);
			auto expected = value.refresh ? std::chrono::system_clock::time_point::min() : future;
			REQUIRE(fixture.conn_state.GetSecretExpiration("alpha") == expected);
			REQUIRE(fixture.conn_state.secret_cache->Expiration("alpha") == expected);
			REQUIRE(fixture.conn_state.GetSecretExpiration("unrelated") == future);
			REQUIRE(other.GetSecretExpiration("alpha") == future);
			REQUIRE(other.catalog_versions.at(id).version == 99);
		}
	}
}

TEST_CASE("Catalog polling refuses forged server proof and retires only its owner", "[boilstream][catalog_versions]") {
	TestFixture fixture;
	auto http = RecordCatalogVersionRequests(fixture);
	fixture.storage->SetEndpoint("https://other.example/secrets");
	BoilstreamConnectionState other;
	other.access_token = "unrelated-test-token";
	other.session_key.assign(32, 19);
	auto future = std::chrono::system_clock::now() + std::chrono::hours(1);
	other.StoreExpiration("alpha", future);
	BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);
	REQUIRE(http->valid_hello);
	REQUIRE(http->requests == duckdb::vector<string> {"https://localhost/auth/api/protocol/v2/handshake"});
	REQUIRE(fixture.conn_state.catalog_versions.empty());
	REQUIRE(fixture.conn_state.access_token.empty());
	REQUIRE(fixture.conn_state.session_key.empty());
	REQUIRE(fixture.conn_state.secret_cache->IsClosed());
	REQUIRE(other.access_token == "unrelated-test-token");
	REQUIRE(other.session_key == duckdb::vector<uint8_t>(32, 19));
	REQUIRE(other.GetSecretExpiration("alpha") == future);
	BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);
	REQUIRE(http->requests.size() == 1);
}
