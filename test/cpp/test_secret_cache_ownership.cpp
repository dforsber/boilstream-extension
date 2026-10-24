#include "secret_response_fixture.hpp"
// Exercise actual native storage and secret-manager paths. Authentication is
// seeded, never represented as a successful OPAQUE/live-service qualification.
#include "duckdb.hpp"
#include "boilstream_secret_storage.hpp"
#include "duckdb/main/config.hpp"
#if __has_include("duckdb/main/tenant/active_tenant_registry.hpp")
#include "duckdb/main/tenant/active_tenant_registry.hpp"
#include "duckdb/main/tenant/tenant_context.hpp"
#define TEST_TENANT_CONTEXT 1
#endif
#include <iostream>
#include <thread>
#include <atomic>
#include <stdexcept>
using namespace duckdb;
using Time = BoilstreamSecretCache::Time;
static void Require(bool value) {
	if (!value)
		throw std::runtime_error("assertion");
}
template <class F>
static void Reject(F action) {
	bool rejected = false;
	try {
		action();
	} catch (const IOException &) {
		rejected = true;
	} catch (const InvalidInputException &) {
		rejected = true;
	}
	Require(rejected);
}
static unique_ptr<BaseSecret> Secret(const string &name, const string &value, const string &scope = "test://shared/",
                                     const string &type = "owned_test") {
	auto secret = make_uniq<KeyValueSecret>(vector<string> {scope}, type, "config", name);
	secret->secret_map["key"] = Value(value);
	return std::move(secret);
}
static string ValueOf(const SecretEntry &entry) {
	return static_cast<const KeyValueSecret &>(*entry.secret).TryGetValue("key").ToString();
}
class BoilstreamSessionPublicationTestAccess {
public:
	static bool Coherent(RestApiSecretStorage &s, CatalogTransaction &tx) {
		auto owner = s.GetSecretOwner(&tx);
		return owner.session && owner.cache == owner.session->secret_cache;
	}
	static shared_ptr<BoilstreamConnectionState> Publish(RestApiSecretStorage &s, ClientContext &ctx,
	                                                     const string &identity = "synthetic-a") {
		auto old = s.GetSessionForConnection(ctx.GetConnectionId());
		auto state = make_shared_ptr<BoilstreamConnectionState>();
		state->bootstrap_token_hash = identity;
		state->access_token = "synthetic-token";
		state->session_key.assign(32, 7);
		state->token_expires_at = std::chrono::system_clock::now() + std::chrono::hours(2);
		s.PublishSession(ctx, state, old, old ? old->authentication_generation.load() : 0, false);
		return state;
	}
	static string Encode(RestApiSecretStorage &s, const string &name, const string &value) {
		return WithFixtureExpiry(s.SerializeSecret(*Secret(name, value)));
	}
	static void List(RestApiSecretStorage &s, BoilstreamConnectionState &state, const string &json, uint64_t revision) {
		s.PublishSecretList(json, state, revision);
	}
	static void Cache(RestApiSecretStorage &s, Connection &c, const string &name, const string &value) {
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*c.context);
		auto state = s.GetSession(&tx);
		s.PublishSecretList("[" + WithFixtureExpiry(s.SerializeSecret(*Secret(name, value))) + "]", *state,
		                    state->secret_cache->Revision());
	}
};
struct TestConfig : DBConfig {
	TestConfig() {
		options.load_extensions = false;
		options.maximum_threads = 2;
	}
};
struct Fixture {
	TestConfig config;
	DuckDB db {nullptr, &config};
	Connection a {db}, b {db};
	RestApiSecretStorage *storage;
	Fixture() {
		SecretManager::Get(*db.instance).SetEnablePersistentSecrets(false);
		auto own = make_uniq<RestApiSecretStorage>(*db.instance, "");
		storage = own.get();
		SecretManager::Get(*db.instance).LoadSecretStorage(std::move(own));
		SecretType type;
		type.name = "owned_test";
		type.default_provider = "config";
		type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
		SecretManager::Get(*db.instance).RegisterSecretType(type);
		a.BeginTransaction();
		b.BeginTransaction();
	}
	shared_ptr<BoilstreamConnectionState> Login(Connection &c, const string &identity = "synthetic-a") {
		return BoilstreamSessionPublicationTestAccess::Publish(*storage, *c.context, identity);
	}
	void Cache(Connection &c, const string &name = "owned", const string &value = "synthetic-a") {
		BoilstreamSessionPublicationTestAccess::Cache(*storage, c, name, value);
	}
	string Read(Connection &c, const string &name = "owned", const string &backend = "boilstream") {
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*c.context);
		auto entry = SecretManager::Get(*db.instance).GetSecretByName(tx, name, backend);
		return entry ? ValueOf(*entry) : "absent";
	}
	string Match(Connection &c, const string &path = "test://shared/object") {
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*c.context);
		auto match = SecretManager::Get(*db.instance).LookupSecret(tx, path, "owned_test");
		return match.HasMatch() ? ValueOf(*match.secret_entry) : "absent";
	}
	void List(BoilstreamConnectionState &state, const string &json) {
		BoilstreamSessionPublicationTestAccess::List(*storage, state, json, state.secret_cache->Revision());
	}
	string Encode(const string &name, const string &value) {
		return BoilstreamSessionPublicationTestAccess::Encode(*storage, name, value);
	}
};
int main() {
	int failed = 0;
	auto test = [&](const char *name, auto fn) {
		try {
			fn();
			std::cout << "CASE " << name << " PASS" << std::endl;
		} catch (const std::exception &e) {
			++failed;
			string message = e.what();
			string category = "other";
			for (auto word : {"already", "transaction", "deserialize", "type", "assertion", "storage", "Conflict"})
				if (message.find(word) != string::npos) {
					category = word;
					break;
				}
			std::cout << "DIAG " << name << " " << category << std::endl;
			std::cout << "CASE " << name << " FAIL" << std::endl;
		}
	};
	test("manager_memory_fallback_preserves_user_isolation", [] {
		Fixture f;
		f.Login(f.a);
		f.Login(f.b, "synthetic-b");
		f.Cache(f.a);
		f.Cache(f.b, "owned", "synthetic-b");
		Require(f.Read(f.a, "owned", "memory") == "synthetic-a" && f.Read(f.b, "owned", "memory") == "synthetic-b");
		Require(f.Match(f.a) == "synthetic-a" && f.Match(f.b) == "synthetic-b");
	});
#ifdef TEST_TENANT_CONTEXT
	test("tls_worker_tenant_switch_requires_new_authentication", [] {
		Fixture f;
		TenantContext first, second;
		first.SetTenantId("42");
		second.SetTenantId("43");
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &first);
			f.Login(f.a);
			f.Cache(f.a);
			Require(f.Read(f.a) == "synthetic-a");
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &second);
			Reject([&] { f.Read(f.a); });
		}
		Reject([&] { f.Read(f.a); });
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &first);
			Require(f.Read(f.a) == "synthetic-a");
		}
	});
	test("same_worker_sequential_tenants_keep_distinct_owned_secrets", [] {
		Fixture f;
		TenantContext first, second;
		first.SetTenantId("42");
		second.SetTenantId("43");
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &first);
			f.Login(f.a);
			f.Cache(f.a);
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &second);
			f.Login(f.b, "synthetic-b");
			f.Cache(f.b, "owned", "synthetic-b");
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &first);
			Require(f.Read(f.a) == "synthetic-a");
		}
		{
			ActiveTenantRegistry::Guard guard(*f.db.instance, &second);
			Require(f.Read(f.b) == "synthetic-b");
		}
	});
#endif
	test("contextless_lookup_never_borrows_thread_tenant_credentials", [] {
		Fixture f;
		f.Login(f.a);
		f.Cache(f.a);
		Require(!f.storage->GetSecretByName("owned", nullptr));
		Require(!f.storage->LookupSecret("test://shared/object", "owned_test", nullptr).HasMatch());
		Require(f.storage->GetCachedSecrets(nullptr).empty());
	});
	test("recursive_lookup_uses_only_current_unexpired_owned_cache", [] {
		Fixture f;
		auto a = f.Login(f.a);
		f.Login(f.b, "synthetic-b");
		f.Cache(f.a);
		f.Cache(f.b, "owned", "synthetic-b");
		BoilstreamConnectionState::SecretLookupGuard guard(*a);
		Require(f.Read(f.a) == "synthetic-a" && f.Match(f.a) == "synthetic-a");
		a->StoreExpiration("owned", Time::min());
		Require(f.Read(f.a) == "absent" && f.Match(f.a) == "absent");
	});
	test("expired_session_cannot_use_fresh_secret", [] {
		Fixture f;
		auto a = f.Login(f.a);
		f.Cache(f.a);
		{
			lock_guard<mutex> lock(a->session_lock);
			a->token_expires_at = Time::min();
		}
		Require(f.Read(f.a) == "absent" && f.Match(f.a) == "absent");
	});
	test("failed_list_is_atomic_and_old_cache_remains_usable", [] {
		Fixture f;
		auto a = f.Login(f.a);
		f.Cache(f.a);
		Reject([&] { f.List(*a, "[" + f.Encode("new", "replacement") + ",false]"); });
		Require(f.Read(f.a) == "synthetic-a" && f.Read(f.a, "new") == "absent");
	});
	test("case_insensitive_duplicate_list_is_rejected_atomically", [] {
		Fixture f;
		auto a = f.Login(f.a);
		f.Cache(f.a);
		Reject([&] { f.List(*a, "[" + f.Encode("DUP", "first") + "," + f.Encode("dup", "second") + "]"); });
		Require(f.Read(f.a) == "synthetic-a" && f.Read(f.a, "dup") == "absent");
	});
	test("invalid_expiration_cannot_replace_valid_snapshot", [] {
		Fixture f;
		auto a = f.Login(f.a);
		f.Cache(f.a);
		auto json = f.Encode("new", "replacement");
		auto pos = json.find("expires_at");
		Require(pos != string::npos);
		auto colon = json.find(':', pos);
		auto quote = json.find('"', colon);
		auto end = json.find('"', quote + 1);
		json.replace(quote + 1, end - quote - 1, "invalid");
		Reject([&] { f.List(*a, "[" + json + "]"); });
		Require(f.Read(f.a) == "synthetic-a");
	});
	test("complete_list_removes_absent_entries_and_empty_list_revokes_all", [] {
		Fixture f;
		auto a = f.Login(f.a);
		f.Cache(f.a);
		f.List(*a, "[" + f.Encode("new", "replacement") + "]");
		Require(f.Read(f.a) == "absent" && f.Read(f.a, "new") == "replacement");
		f.List(*a, "[]");
		Require(f.Read(f.a, "new") == "absent");
	});
	test("late_response_after_logout_cannot_restore_credentials", [] {
		Fixture f;
		auto a = f.Login(f.a);
		f.Cache(f.a);
		auto rev = a->secret_cache->Revision();
		auto json = "[" + f.Encode("owned", "late") + "]";
		f.storage->ClearSession(*f.a.context);
		Reject([&] { BoilstreamSessionPublicationTestAccess::List(*f.storage, *a, json, rev); });
		Require(f.Read(f.a) == "absent" && a->secret_cache->Snapshot().empty());
	});
	test("session_replacement_retires_old_cache_and_preserves_owned_reader", [] {
		Fixture f;
		auto old = f.Login(f.a);
		f.Cache(f.a);
		auto reader = old->secret_cache->Get("owned");
		auto rev = old->secret_cache->Revision();
		auto next = f.Login(f.a, "new-identity");
		f.Cache(f.a, "owned", "new");
		Reject([&] { BoilstreamSessionPublicationTestAccess::List(*f.storage, *old, "[]", rev); });
		Require(ValueOf(*reader) == "synthetic-a" && old->secret_cache->Snapshot().empty() && f.Read(f.a) == "new");
	});
	test("stale_list_cannot_overwrite_newer_individual_update", [] {
		Fixture f;
		auto a = f.Login(f.a);
		f.Cache(f.a);
		auto rev = a->secret_cache->Revision();
		f.Cache(f.a, "owned", "new");
		Reject([&] { BoilstreamSessionPublicationTestAccess::List(*f.storage, *a, "[]", rev); });
		Require(f.Read(f.a) == "new");
	});
	test("local_explicit_secret_store_replace_and_drop_are_private", [] {
		Fixture f;
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*f.a.context);
		auto stored = f.storage->StoreSecret(Secret("manual", "first"), OnCreateConflict::ERROR_ON_CONFLICT, &tx);
		Require(stored && stored->persist_type == SecretPersistType::PERSISTENT &&
		        stored->storage_mode == "boilstream");
		Require(f.Read(f.a, "manual") == "first" && f.Read(f.b, "manual") == "absent");
		Reject([&] { f.storage->StoreSecret(Secret("manual", "wrong"), OnCreateConflict::ERROR_ON_CONFLICT, &tx); });
		Require(!f.storage->StoreSecret(Secret("manual", "wrong"), OnCreateConflict::IGNORE_ON_CONFLICT, &tx));
		f.storage->StoreSecret(Secret("manual", "second"), OnCreateConflict::REPLACE_ON_CONFLICT, &tx);
		Require(f.Read(f.a, "manual", "memory") == "second");
		f.storage->DropSecretByName("manual", OnEntryNotFound::THROW_EXCEPTION, &tx);
		Require(f.Read(f.a, "manual") == "absent");
	});
	test("failed_remote_write_and_delete_preserve_valid_cache", [] {
		Fixture f;
		f.Login(f.a);
		f.Cache(f.a);
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*f.a.context);
		// No endpoint: real production rejection before any network access.
		Reject([&] { f.storage->StoreSecret(Secret("owned", "wrong"), OnCreateConflict::REPLACE_ON_CONFLICT, &tx); });
		Reject([&] { f.storage->DropSecretByName("owned", OnEntryNotFound::RETURN_NULL, &tx); });
		Require(f.Read(f.a) == "synthetic-a");
	});
	test("oversized_list_and_entry_leave_valid_cache_unchanged", [] {
		Fixture f;
		auto a = f.Login(f.a);
		f.Cache(f.a);
		Reject([&] { f.List(*a, string(BoilstreamSecretCache::MAX_BYTES + 1, ' ')); });
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*f.a.context);
		Reject([&] {
			f.storage->StoreSecret(Secret("owned", string(BoilstreamSecretCache::MAX_ENTRY_BYTES, 'x')),
			                       OnCreateConflict::REPLACE_ON_CONFLICT, &tx);
		});
		Require(f.Read(f.a) == "synthetic-a");
	});
	test("competing_complete_publications_have_one_winner", [] {
		Fixture f;
		auto a = f.Login(f.a);
		f.Cache(f.a);
		auto rev = a->secret_cache->Revision();
		auto first = "[" + f.Encode("owned", "first") + "]", second = "[" + f.Encode("owned", "second") + "]";
		std::atomic<int> ready {0}, won {0}, rejected {0};
		std::atomic<bool> go {false};
		auto publish = [&](const string &json) {
			++ready;
			while (!go.load())
				std::this_thread::yield();
			try {
				BoilstreamSessionPublicationTestAccess::List(*f.storage, *a, json, rev);
				++won;
			} catch (const IOException &) {
				++rejected;
			}
		};
		std::thread one(publish, std::cref(first)), two(publish, std::cref(second));
		while (ready.load() != 2)
			std::this_thread::yield();
		go = true;
		one.join();
		two.join();
		Require(won == 1 && rejected == 1);
		auto value = f.Read(f.a);
		Require(value == "first" || value == "second");
	});
	test("parallel_users_with_equal_secret_names_never_cross", [] {
		Fixture f;
		f.Login(f.a);
		f.Login(f.b, "synthetic-b");
		std::atomic<int> errors {0};
		auto loop = [&](Connection &c, const string &value) {
			try {
				for (int i = 0; i < 100; ++i) {
					f.Cache(c, "owned", value);
					if (f.Read(c) != value || f.Match(c) != value)
						++errors;
				}
			} catch (...) {
				++errors;
			}
		};
		std::thread one(loop, std::ref(f.a), "first"), two(loop, std::ref(f.b), "second");
		one.join();
		two.join();
		Require(errors == 0);
	});

	test("local_cache_byte_limit_preserves_entries_and_drop_restores_capacity", [] {
		Fixture f;
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*f.a.context);
		string payload(128 * 1024, 'x');
		int admitted = 0;
		bool full = false;
		for (int i = 0; i < 100; ++i) {
			try {
				f.storage->StoreSecret(Secret("entry_" + std::to_string(i), payload),
				                       OnCreateConflict::ERROR_ON_CONFLICT, &tx);
				++admitted;
			} catch (const IOException &) {
				full = true;
				break;
			}
		}
		Require(full && admitted > 1 && admitted < 100);
		Require(f.Read(f.a, "entry_0") == payload && f.Read(f.a, "entry_" + std::to_string(admitted)) == "absent");
		f.storage->DropSecretByName("entry_0", OnEntryNotFound::THROW_EXCEPTION, &tx);
		f.storage->StoreSecret(Secret("replacement", payload), OnCreateConflict::ERROR_ON_CONFLICT, &tx);
		Require(f.Read(f.a, "replacement") == payload && f.Read(f.b, "replacement") == "absent");
	});
	test("entry_count_limit_rejects_without_eviction_and_allows_same_name_replace", [] {
		Fixture f;
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*f.a.context);
		for (idx_t i = 0; i < BoilstreamSecretCache::MAX_ENTRIES; ++i)
			f.storage->StoreSecret(Secret("entry_" + std::to_string(i), "value"), OnCreateConflict::ERROR_ON_CONFLICT,
			                       &tx);
		Reject([&] { f.storage->StoreSecret(Secret("extra", "value"), OnCreateConflict::ERROR_ON_CONFLICT, &tx); });
		Require(f.storage->GetCachedSecrets(&tx).size() == BoilstreamSecretCache::MAX_ENTRIES);
		f.storage->StoreSecret(Secret("ENTRY_0", "replacement"), OnCreateConflict::REPLACE_ON_CONFLICT, &tx);
		Require(f.Read(f.a, "entry_0") == "replacement" && f.Read(f.a, "extra") == "absent");
	});
	test("scope_specificity_and_case_insensitive_names_are_preserved", [] {
		Fixture f;
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*f.a.context);
		f.storage->StoreSecret(Secret("general", "general", "test://"), OnCreateConflict::ERROR_ON_CONFLICT, &tx);
		f.storage->StoreSecret(Secret("specific", "specific", "test://shared/"), OnCreateConflict::ERROR_ON_CONFLICT,
		                       &tx);
		Require(f.Match(f.a) == "specific" && f.Match(f.a, "test://other/object") == "general");
		Require(f.Read(f.a, "SPECIFIC") == "specific");
	});
	test("connection_teardown_closes_cache_without_invalidating_owned_reader", [] {
		Fixture f;
		shared_ptr<BoilstreamConnectionState> retained;
		shared_ptr<const SecretEntry> reader;
		{
			Connection c(f.db);
			c.BeginTransaction();
			retained = f.Login(c);
			f.Cache(c);
			reader = retained->secret_cache->Get("owned");
		}
		Require(retained->secret_cache->IsClosed() && retained->secret_cache->Snapshot().empty());
		Require(reader && ValueOf(*reader) == "synthetic-a");
	});

	test("owner_resolution_remains_coherent_during_authentication_replacement", [] {
		Fixture f;
		f.Login(f.a);
		std::atomic<int> errors {0}, reads {0};
		std::atomic<bool> done {false};
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*f.a.context);
		std::thread reader([&] {
			while (!done.load()) {
				if (!BoilstreamSessionPublicationTestAccess::Coherent(*f.storage, tx))
					++errors;
				++reads;
			}
		});
		while (reads.load() == 0)
			std::this_thread::yield();
		for (int i = 0; i < 300; ++i) {
			f.Login(f.a, "replacement-" + std::to_string(i));
			const auto observed = reads.load();
			while (reads.load() == observed)
				std::this_thread::yield();
		}
		done = true;
		reader.join();
		Require(errors == 0 && reads.load() >= 301);
	});
	return failed ? 1 : 0;
}
