//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_boilstream_catalog_versions.cpp
//
// Unit tests for Catalog Version Polling Feature
//
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "boilstream_secret_storage.hpp"
#include "boilstream_connection_state.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/common/http_util.hpp"

#include <thread>
#include <chrono>
#include <ctime>
#include "mbedtls_wrapper.hpp"
#include "duckdb/common/types/blob.hpp"

using namespace duckdb;
using namespace std;

//===----------------------------------------------------------------------===//
// Test Access Friend Class - Allows testing private methods
//===----------------------------------------------------------------------===//

class BoilstreamCatalogVersionTestAccess {
public:
	static duckdb::vector<uint8_t> IntegrityKey(RestApiSecretStorage &storage, const duckdb::vector<uint8_t> &key) {
		return storage.DeriveIntegrityKey(key);
	}
	// Access the catalog_versions map from connection state
	static case_insensitive_map_t<BoilstreamConnectionState::CatalogVersionInfo> &
	GetCatalogVersions(BoilstreamConnectionState &conn_state) {
		return conn_state.catalog_versions;
	}

	// Access last_version_check timestamp from connection state
	static std::chrono::system_clock::time_point &GetLastVersionCheck(BoilstreamConnectionState &conn_state) {
		return conn_state.last_version_check;
	}

	// Access secret_expiration map from connection state
	static case_insensitive_map_t<std::chrono::system_clock::time_point> &
	GetSecretExpiration(BoilstreamConnectionState &conn_state) {
		return conn_state.secret_expiration;
	}

	// Call RefreshCatalogCredentials with connection state
	static void RefreshCatalogCredentials(RestApiSecretStorage &storage, const string &catalog_name,
	                                      BoilstreamConnectionState &conn_state) {
		storage.RefreshCatalogCredentials(catalog_name, conn_state);
	}

	// Call CheckCatalogVersions with connection state
	static void CheckCatalogVersions(RestApiSecretStorage &storage, BoilstreamConnectionState &conn_state) {
		storage.CheckCatalogVersions(conn_state);
	}

	// Set endpoint URL (needed to trigger version check logic)
	static void SetEndpoint(RestApiSecretStorage &storage, const string &endpoint) {
		storage.SetEndpoint(endpoint);
	}
};

//===----------------------------------------------------------------------===//
// Test Fixture - Keeps Database alive for Storage
//===----------------------------------------------------------------------===//
struct TestFixture {
	duckdb::unique_ptr<DuckDB> db;
	duckdb::unique_ptr<RestApiSecretStorage> storage;
	BoilstreamConnectionState conn_state;

	explicit TestFixture(string endpoint = "https://localhost/secrets") : conn_state(endpoint) {
		db = duckdb::make_uniq<DuckDB>(nullptr);
		storage = duckdb::make_uniq<RestApiSecretStorage>(*db->instance, "https://localhost/secrets");
	}
};

// Exercise production request signing and response verification at the HTTP seam.
// Authentication is seeded here; real OPAQUE acceptance is covered separately.
class CatalogVersionRecordingHTTPUtil : public HTTPUtil {
public:
	struct RecordedRequest {
		string url;
		string sequence;
		bool signed_request;
	};
	duckdb::vector<RecordedRequest> requests;
	string response_body;
	bool corrupt_signature = false;
	duckdb::vector<uint8_t> integrity_key;

	duckdb::unique_ptr<HTTPParams> InitializeParameters(DatabaseInstance &, const string &) override {
		return make_uniq<HTTPParams>(*this);
	}

	duckdb::unique_ptr<HTTPResponse> SendRequest(BaseRequest &request, duckdb::unique_ptr<HTTPClient> &) override {
		requests.push_back({request.url, request.headers.GetHeaderValue("X-Boilstream-Sequence"),
		                    !request.headers.GetHeaderValue("X-Boilstream-Signature").empty()});
		if (response_body.empty()) {
			throw IOException("catalog version test captured the outgoing request");
		}
		// The transport is controlled; production request signing, response verification,
		// JSON parsing, version comparison and credential invalidation all execute.
		auto response = make_uniq<HTTPResponse>(HTTPStatusCode::OK_200);
		auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		std::tm utc;
#ifdef _WIN32
		gmtime_s(&utc, &now);
#else
		gmtime_r(&now, &utc);
#endif
		char date[17];
		std::strftime(date, sizeof(date), "%Y%m%dT%H%M%SZ", &utc);
		char hash[32], signature[32];
		duckdb_mbedtls::MbedTlsWrapper::ComputeSha256Hash(response_body.data(), response_body.size(), hash);
		string hex;
		for (unsigned char byte : hash) {
			hex += "0123456789abcdef"[byte >> 4];
			hex += "0123456789abcdef"[byte & 15];
		}
		string canonical = string("200\nx-boilstream-date:") + date + "\n\nx-boilstream-date\n" + hex;
		duckdb_mbedtls::MbedTlsWrapper::Hmac256(reinterpret_cast<const char *>(integrity_key.data()),
		                                        integrity_key.size(), canonical.data(), canonical.size(), signature);
		response->headers.Insert("X-Boilstream-Date", date);
		if (corrupt_signature)
			signature[0] ^= 1;
		response->headers.Insert("X-Boilstream-Response-Signature",
		                         Blob::ToBase64(string_t(signature, sizeof(signature))));
		auto &get = request.Cast<GetRequestInfo>();
		get.response_handler(*response);
		get.content_handler(reinterpret_cast<const_data_ptr_t>(response_body.data()), response_body.size());
		return response;
	}
};

static duckdb::shared_ptr<CatalogVersionRecordingHTTPUtil> RecordCatalogVersionRequests(TestFixture &fixture) {
	auto http = make_shared_ptr<CatalogVersionRecordingHTTPUtil>();
	DBConfig::GetConfig(*fixture.db->instance).SetHTTPUtil(http);
	fixture.conn_state.access_token = "catalog-version-test-token";
	fixture.conn_state.session_key = duckdb::vector<uint8_t>(32, 7);
	fixture.conn_state.region = "eu-west-1";
	http->integrity_key =
	    BoilstreamCatalogVersionTestAccess::IntegrityKey(*fixture.storage, fixture.conn_state.session_key);
	return http;
}

TEST_CASE("Catalog version polling uses the authenticated product route", "[boilstream][catalog_versions]") {
	for (const auto &base : {"https://localhost", "https://catalog.example:8443", "https://[::1]:8443",
	                         "https://gateway.example/product"}) {
		DYNAMIC_SECTION(base) {
			TestFixture fixture(string(base) + "/secrets");
			auto http = RecordCatalogVersionRequests(fixture);
			// A database default change must not redirect this authenticated session.
			BoilstreamCatalogVersionTestAccess::SetEndpoint(*fixture.storage, "https://other.example/secrets");
			BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);
			REQUIRE(http->requests.size() == 1);
			REQUIRE(http->requests[0].url == string(base) + "/catalog-versions");
			REQUIRE(http->requests[0].sequence == "0");
			REQUIRE(http->requests[0].signed_request);

			// A second lookup must not spend another lock-step sequence on a
			// rate-limited poll, even when the first request failed in transport.
			BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);
			REQUIRE(http->requests.size() == 1);
			REQUIRE(fixture.conn_state.client_sequence == 1);
		}
	}
}

TEST_CASE("Catalog version polling rejects a noncanonical secrets endpoint", "[boilstream][catalog_versions]") {
	for (const auto &endpoint : {"https://catalog.example", "https://catalog.example/secrets/other",
	                             "https://catalog.example/secrets?other=value"}) {
		DYNAMIC_SECTION(endpoint) {
			TestFixture fixture(endpoint);
			auto http = RecordCatalogVersionRequests(fixture);
			BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);
			REQUIRE(http->requests.empty());
			REQUIRE(fixture.conn_state.client_sequence == 0);
		}
	}
}

//===----------------------------------------------------------------------===//
// Test: RefreshCatalogCredentials
//===----------------------------------------------------------------------===//
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
	auto http = make_shared_ptr<CatalogVersionRecordingHTTPUtil>();
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

TEST_CASE("Catalog polling rate limit expires and remains connection-owned", "[boilstream][catalog_versions]") {
	TestFixture fixture;
	auto http = RecordCatalogVersionRequests(fixture);
	auto poll = [&] {
		BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);
	};
	poll();
	REQUIRE(http->requests.size() == 1);
	poll();
	REQUIRE(http->requests.size() == 1);
	fixture.conn_state.last_version_check = std::chrono::system_clock::now() - std::chrono::seconds(120);
	poll();
	REQUIRE(http->requests.size() == 2);
	REQUIRE(http->requests.back().sequence == "1");
	BoilstreamConnectionState other("https://localhost/secrets");
	other.access_token = "other-test-token";
	other.session_key.assign(32, 7);
	other.region = "eu-west-1";
	auto previous = fixture.conn_state.last_version_check;
	BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, other);
	REQUIRE(http->requests.size() == 3);
	REQUIRE(http->requests.back().sequence == "0");
	REQUIRE(other.client_sequence == 1);
	REQUIRE(fixture.conn_state.client_sequence == 2);
	REQUIRE(fixture.conn_state.last_version_check == previous);
}

TEST_CASE("Signed catalog versions drive exact credential invalidation", "[boilstream][catalog_versions]") {
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
			auto http = RecordCatalogVersionRequests(fixture);
			const string id = "11111111-1111-4111-8111-111111111111";
			if (value.known) {
				fixture.conn_state.catalog_versions[id] = {value.old_version, "alpha"};
			}
			auto future = std::chrono::system_clock::now() + std::chrono::hours(1);
			fixture.conn_state.StoreExpiration("alpha", future);
			fixture.conn_state.StoreExpiration("unrelated", future);
			BoilstreamConnectionState other("https://localhost/secrets");
			other.StoreExpiration("alpha", future);
			other.catalog_versions[id] = {99, "alpha"};
			http->response_body = "{\"catalogs\":{\"" + id + "\":{\"version\":" + std::to_string(value.new_version) +
			                      ",\"catalog_name\":\"alpha\"}}}";
			BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);
			REQUIRE(http->requests.size() == 1);
			REQUIRE(fixture.conn_state.catalog_versions.size() == 1);
			REQUIRE(fixture.conn_state.catalog_versions.at(id).version == value.new_version);
			REQUIRE(fixture.conn_state.catalog_versions.at(id).catalog_name == "alpha");
			REQUIRE(fixture.conn_state.secret_expiration.at("alpha") ==
			        (value.refresh ? std::chrono::system_clock::time_point::min() : future));
			REQUIRE(fixture.conn_state.secret_expiration.at("unrelated") == future);
			REQUIRE_FALSE(fixture.conn_state.session_key.empty());
			REQUIRE(other.GetSecretExpiration("alpha") == future);
			REQUIRE(other.catalog_versions.at(id).version == 99);
		}
	}
}

TEST_CASE("Catalog polling rejects a forged response and clears only its own session",
          "[boilstream][catalog_versions]") {
	TestFixture fixture;
	auto http = RecordCatalogVersionRequests(fixture);
	http->response_body =
	    R"({"catalogs":{"11111111-1111-4111-8111-111111111111":{"version":999,"catalog_name":"alpha"}}})";
	http->corrupt_signature = true;
	BoilstreamConnectionState other("https://localhost/secrets");
	other.access_token = "unrelated-test-token";
	other.session_key.assign(32, 19);
	auto future = std::chrono::system_clock::now() + std::chrono::hours(1);
	other.StoreExpiration("alpha", future);
	BoilstreamCatalogVersionTestAccess::CheckCatalogVersions(*fixture.storage, fixture.conn_state);
	REQUIRE(http->requests.size() == 1);
	REQUIRE(fixture.conn_state.catalog_versions.empty());
	REQUIRE(fixture.conn_state.access_token.empty());
	REQUIRE(fixture.conn_state.session_key.empty());
	REQUIRE(other.access_token == "unrelated-test-token");
	REQUIRE(other.session_key == duckdb::vector<uint8_t>(32, 19));
	REQUIRE(other.GetSecretExpiration("alpha") == future);
}
