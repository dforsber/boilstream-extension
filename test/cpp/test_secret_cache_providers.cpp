#include "secret_response_fixture.hpp"
// Actual DuckLake named-secret ATTACH plus Postgres/S3 secret-reader routing.
// Uses synthetic credentials and isolated local DuckLake data, never a live cloud account.
#include "duckdb.hpp"
#include "boilstream_secret_storage.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
using namespace duckdb;
static void Require(bool ok) {
	if (!ok)
		throw std::runtime_error("assertion");
}
static int stage = 0;
static void Query(Connection &c, const string &sql) {
	auto r = c.Query(sql);
	if (!r || r->HasError()) {
		if (r) {
			auto m = r->GetError();
			for (auto word : {"parquet", "json", "icu", "core_functions", "extension", "syntax", "secret", "directory",
			                  "transaction", "already"})
				if (m.find(word) != string::npos) {
					std::cout << "DIAG provider " << word << std::endl;
					break;
				}
		}
		throw std::runtime_error("query");
	}
	++stage;
}
class BoilstreamSessionPublicationTestAccess {
public:
	static void Publish(RestApiSecretStorage &s, ClientContext &ctx, const string &root, const string &identity) {
		auto state = make_shared_ptr<BoilstreamConnectionState>();
		state->access_token = "synthetic-token";
		state->session_key.assign(32, 7);
		state->bootstrap_token_hash = identity;
		state->token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(2);
		s.PublishSession(ctx, state, nullptr, 0, false);
		auto lake = make_uniq<KeyValueSecret>(vector<string> {}, "ducklake", "config", "owned_lake");
		lake->secret_map["metadata_path"] = Value(root + "/metadata.db");
		lake->secret_map["data_path"] = Value(root + "/data");
		auto pg = make_uniq<KeyValueSecret>(vector<string> {}, "postgres", "config", "owned_pg");
		pg->secret_map["password"] = Value(identity);
		pg->secret_map["host"] = Value("127.0.0.1");
		auto s3 = make_uniq<KeyValueSecret>(vector<string> {"s3://owned-provider-test/"}, "s3", "config", "owned_s3");
		s3->secret_map["key_id"] = Value(identity);
		s3->secret_map["secret"] = Value("synthetic-secret");
		s.PublishSecretList("[" + WithFixtureExpiry(s.SerializeSecret(*lake)) + "," +
		                        WithFixtureExpiry(s.SerializeSecret(*pg)) + "," +
		                        WithFixtureExpiry(s.SerializeSecret(*s3)) + "]",
		                    *state, state->secret_cache->Revision());
	}
};
int main(int argc, char **argv) {
	try {
		Require(argc == 2 && std::filesystem::is_directory(argv[1]));
		const string root = argv[1];
		std::filesystem::create_directory(root + "/a");
		std::filesystem::create_directory(root + "/b");
		DBConfig config;
		config.options.load_extensions = false;
		config.options.maximum_threads = 2;
		config.SetOptionByName("secret_directory", Value(root + "/unused_secrets"));
		DuckDB db(nullptr, &config);
		Connection a(db), b(db), fresh(db);
		for (auto extension : {"parquet", "json", "icu", "core_functions", "ducklake", "httpfs", "postgres_scanner"}) {
			Require(ExtensionHelper::LoadExtension(db, extension) == ExtensionLoadResult::LOADED_EXTENSION);
			++stage;
		}
		auto owned = make_uniq<RestApiSecretStorage>(*db.instance, "");
		auto &storage = *owned;
		SecretManager::Get(*db.instance).LoadSecretStorage(std::move(owned));
		BoilstreamSessionPublicationTestAccess::Publish(storage, *a.context, root + "/a", "synthetic-a");
		BoilstreamSessionPublicationTestAccess::Publish(storage, *b.context, root + "/b", "synthetic-b");
		Query(a, "ATTACH 'ducklake:owned_lake' AS first");
		Query(b, "ATTACH 'ducklake:owned_lake' AS second");
		Query(a, "CREATE TABLE first.events(i INTEGER)");
		Query(a, "INSERT INTO first.events VALUES (11),(12)");
		Query(b, "CREATE TABLE second.events(i INTEGER)");
		Query(b, "INSERT INTO second.events VALUES (21),(22)");
		auto one = a.Query("SELECT sum(i) FROM first.events"), two = b.Query("SELECT sum(i) FROM second.events");
		Require(one && !one->HasError() && one->GetValue(0, 0).GetValue<int64_t>() == 23);
		Require(two && !two->HasError() && two->GetValue(0, 0).GetValue<int64_t>() == 43);
		Query(a, "DETACH first");
		Query(b, "DETACH second");
		auto missing = fresh.Query("ATTACH 'ducklake:owned_lake' AS forbidden");
		Require(missing && missing->HasError());
		std::cout << "CASE real_ducklake_attach_resolves_each_owners_secret PASS" << std::endl;
		for (auto c : {&a, &b}) {
			c->BeginTransaction();
			auto tx = CatalogTransaction::GetSystemCatalogTransaction(*c->context);
			auto pg = SecretManager::Get(*db.instance).GetSecretByName(tx, "owned_pg", "memory");
			Require(pg && pg->secret->GetType() == "postgres");
			auto expected = c == &a ? "synthetic-a" : "synthetic-b";
			Require(static_cast<const KeyValueSecret &>(*pg->secret).TryGetValue("password").ToString() == expected);
			KeyValueSecretReader reader(*c->context, "s3", "s3://owned-provider-test/object");
			Require(reader.GetSecretKey("key_id").ToString() == expected);
			c->Commit();
		}
		std::cout << "CASE postgres_named_and_httpfs_scoped_readers_preserve_owner PASS" << std::endl;
		storage.ClearSession(*a.context);
		a.BeginTransaction();
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*a.context);
		Require(!SecretManager::Get(*db.instance).GetSecretByName(tx, "owned_pg", "memory"));
		Require(!SecretManager::Get(*db.instance).LookupSecret(tx, "s3://owned-provider-test/object", "s3").HasMatch());
		a.Commit();
		std::cout << "CASE provider_logout_leaves_no_shared_memory_mirror PASS" << std::endl;
		return 0;
	} catch (...) {
		std::cout << "DIAG provider_stage " << stage << std::endl;
		std::cout << "CASE provider_integration FAIL" << std::endl;
		return 1;
	}
}
