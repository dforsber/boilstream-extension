//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_session_routing.cpp
//
// Unit tests for per-connection session routing in RestApiSecretStorage.
// Every session access requires a connection context. There is no global
// fallback — system transactions without context get nullptr.
//
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "boilstream_connection_state.hpp"
#include "boilstream_secret_storage.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <thread>
#include <vector>
#include <atomic>

using namespace duckdb;

//===----------------------------------------------------------------------===//
// Fixture: each TEST_CASE gets a fresh DuckDB + storage to avoid cross-test
// pollution from accumulated session maps.
//===----------------------------------------------------------------------===//
struct SessionRoutingFixture {
	DuckDB db;
	unique_ptr<RestApiSecretStorage> storage;

	SessionRoutingFixture() : db(nullptr) {
		storage = make_uniq<RestApiSecretStorage>(*db.instance, "https://test.example.com/secrets");
	}
};

//===----------------------------------------------------------------------===//
// Test: Basic Per-Connection Session Routing
//===----------------------------------------------------------------------===//
TEST_CASE("Per-Connection Session Routing", "[boilstream][session-routing]") {
	SessionRoutingFixture f;
	auto &s = *f.storage;

	SECTION("SetActiveSessionKeyForConnection + GetSessionForConnection round-trip") {
		Connection con1(f.db);
		Connection con2(f.db);
		auto id1 = con1.context->GetConnectionId();
		auto id2 = con2.context->GetConnectionId();

		auto &sess1 = s.GetOrCreateSession("key-alpha");
		auto &sess2 = s.GetOrCreateSession("key-beta");

		s.SetActiveSessionKeyForConnection(id1, "key-alpha");
		s.SetActiveSessionKeyForConnection(id2, "key-beta");

		REQUIRE(s.GetSessionForConnection(id1) == &sess1);
		REQUIRE(s.GetSessionForConnection(id2) == &sess2);
		REQUIRE(s.GetSessionForConnection(id1) != s.GetSessionForConnection(id2));
	}

	SECTION("Unknown connection returns nullptr") {
		REQUIRE(s.GetSessionForConnection(999999) == nullptr);
	}

	SECTION("Multiple connections sharing same session key get same object") {
		Connection con1(f.db);
		Connection con2(f.db);

		s.GetOrCreateSession("shared-key");
		s.SetActiveSessionKeyForConnection(con1.context->GetConnectionId(), "shared-key");
		s.SetActiveSessionKeyForConnection(con2.context->GetConnectionId(), "shared-key");

		auto *r1 = s.GetSessionForConnection(con1.context->GetConnectionId());
		auto *r2 = s.GetSessionForConnection(con2.context->GetConnectionId());
		REQUIRE(r1 != nullptr);
		REQUIRE(r1 == r2);
	}

	SECTION("Mapping to nonexistent session key returns nullptr") {
		Connection con(f.db);
		s.SetActiveSessionKeyForConnection(con.context->GetConnectionId(), "no-such-session");
		REQUIRE(s.GetSessionForConnection(con.context->GetConnectionId()) == nullptr);
	}
}

//===----------------------------------------------------------------------===//
// Test: GetSession via CatalogTransaction
//===----------------------------------------------------------------------===//
TEST_CASE("GetSession Transaction Routing", "[boilstream][session-routing]") {
	SessionRoutingFixture f;
	auto &s = *f.storage;

	SECTION("nullptr transaction returns nullptr (no global fallback)") {
		// Even after creating sessions, nullptr transaction gets nothing
		s.GetOrCreateSession("some-key");
		REQUIRE(s.GetSession(nullptr) == nullptr);
	}

	SECTION("Transaction with context routes to per-connection session") {
		Connection con(f.db);
		auto &sess = s.GetOrCreateSession("tx-key");
		s.SetActiveSessionKeyForConnection(con.context->GetConnectionId(), "tx-key");

		con.Query("BEGIN TRANSACTION");
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
		REQUIRE(tx.HasContext());
		REQUIRE(s.GetSession(&tx) == &sess);
		con.Query("COMMIT");
	}

	SECTION("Transaction with context but no mapping returns nullptr") {
		Connection con(f.db);
		con.Query("BEGIN TRANSACTION");
		auto tx = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
		REQUIRE(s.GetSession(&tx) == nullptr);
		con.Query("COMMIT");
	}
}

//===----------------------------------------------------------------------===//
// Test: ClearSession Isolation
//===----------------------------------------------------------------------===//
TEST_CASE("ClearSession Isolation", "[boilstream][session-routing]") {
	SessionRoutingFixture f;
	auto &s = *f.storage;

	SECTION("ClearSession on conn A does not affect conn B session data") {
		Connection con1(f.db);
		Connection con2(f.db);

		auto &sess1 = s.GetOrCreateSession("ck-1");
		auto &sess2 = s.GetOrCreateSession("ck-2");

		{
			lock_guard<mutex> l(sess1.session_lock);
			sess1.access_token = "token-a-pad0123456789abcdef0123456789abcdef0123456789abcdef01";
		}
		{
			lock_guard<mutex> l(sess2.session_lock);
			sess2.access_token = "token-b-pad0123456789abcdef0123456789abcdef0123456789abcdef01";
		}

		s.SetActiveSessionKeyForConnection(con1.context->GetConnectionId(), "ck-1");
		s.SetActiveSessionKeyForConnection(con2.context->GetConnectionId(), "ck-2");

		s.ClearSession(*con1.context);

		// A cleared
		{
			lock_guard<mutex> l(sess1.session_lock);
			REQUIRE(sess1.access_token.empty());
		}
		// B unaffected
		{
			lock_guard<mutex> l(sess2.session_lock);
			REQUIRE(sess2.access_token == "token-b-pad0123456789abcdef0123456789abcdef0123456789abcdef01");
		}
	}

	SECTION("ClearSession preserves mapping — returns cleared session, not nullptr") {
		Connection con(f.db);
		auto &sess = s.GetOrCreateSession("preserve-key");
		{
			lock_guard<mutex> l(sess.session_lock);
			sess.access_token = "to-be-cleared-pad0123456789abcdef0123456789abcdef0123456789";
		}
		s.SetActiveSessionKeyForConnection(con.context->GetConnectionId(), "preserve-key");

		s.ClearSession(*con.context);

		auto *result = s.GetSessionForConnection(con.context->GetConnectionId());
		REQUIRE(result != nullptr);
		REQUIRE(result == &sess);
		{
			lock_guard<mutex> l(sess.session_lock);
			REQUIRE(sess.access_token.empty());
			REQUIRE(sess.session_key.empty());
		}
	}

	SECTION("ClearSession with shared key clears session for all sharing connections") {
		Connection con1(f.db);
		Connection con2(f.db);

		auto &shared = s.GetOrCreateSession("shared-clear");
		{
			lock_guard<mutex> l(shared.session_lock);
			shared.access_token = "shared-token-pad0123456789abcdef0123456789abcdef012345678901";
		}
		s.SetActiveSessionKeyForConnection(con1.context->GetConnectionId(), "shared-clear");
		s.SetActiveSessionKeyForConnection(con2.context->GetConnectionId(), "shared-clear");

		// Clearing via con1 wipes the shared object
		s.ClearSession(*con1.context);

		auto *via_con2 = s.GetSessionForConnection(con2.context->GetConnectionId());
		REQUIRE(via_con2 != nullptr);
		{
			lock_guard<mutex> l(via_con2->session_lock);
			REQUIRE(via_con2->access_token.empty());
		}
	}

	SECTION("ClearSession for unmapped connection is a no-op") {
		Connection con(f.db);
		s.ClearSession(*con.context); // should not crash
	}
}

//===----------------------------------------------------------------------===//
// Test: ClearConnectionMapping
//===----------------------------------------------------------------------===//
TEST_CASE("ClearConnectionMapping", "[boilstream][session-routing]") {
	SessionRoutingFixture f;
	auto &s = *f.storage;

	SECTION("After clear, GetSessionForConnection returns nullptr") {
		Connection con(f.db);
		auto id = con.context->GetConnectionId();
		s.GetOrCreateSession("m-key");
		s.SetActiveSessionKeyForConnection(id, "m-key");

		REQUIRE(s.GetSessionForConnection(id) != nullptr);
		s.ClearConnectionMapping(id);
		REQUIRE(s.GetSessionForConnection(id) == nullptr);
	}

	SECTION("Does not affect other connections") {
		Connection con1(f.db);
		Connection con2(f.db);
		auto id1 = con1.context->GetConnectionId();
		auto id2 = con2.context->GetConnectionId();

		s.GetOrCreateSession("p-key");
		s.SetActiveSessionKeyForConnection(id1, "p-key");
		s.SetActiveSessionKeyForConnection(id2, "p-key");

		s.ClearConnectionMapping(id1);
		REQUIRE(s.GetSessionForConnection(id1) == nullptr);
		REQUIRE(s.GetSessionForConnection(id2) != nullptr);
	}

	SECTION("Does not destroy the session object") {
		Connection con(f.db);
		auto id = con.context->GetConnectionId();
		auto &sess = s.GetOrCreateSession("surv-key");
		{
			lock_guard<mutex> l(sess.session_lock);
			sess.access_token = "survivor-token-pad0123456789abcdef0123456789abcdef01234567890";
		}
		s.SetActiveSessionKeyForConnection(id, "surv-key");
		s.ClearConnectionMapping(id);

		// Session still accessible by key
		auto *by_key = s.GetSessionByKey("surv-key");
		REQUIRE(by_key != nullptr);
		{
			lock_guard<mutex> l(by_key->session_lock);
			REQUIRE(by_key->access_token == "survivor-token-pad0123456789abcdef0123456789abcdef01234567890");
		}
	}

	SECTION("Unknown connection is a no-op") {
		s.ClearConnectionMapping(999999);
	}
}

//===----------------------------------------------------------------------===//
// Test: Re-bootstrap (ClearSession → new login cycle)
//===----------------------------------------------------------------------===//
TEST_CASE("Re-bootstrap Cycle", "[boilstream][session-routing]") {
	SessionRoutingFixture f;
	auto &s = *f.storage;

	SECTION("Overwriting connection mapping switches to new session") {
		Connection con(f.db);
		auto id = con.context->GetConnectionId();

		auto &old_sess = s.GetOrCreateSession("old-key");
		auto &new_sess = s.GetOrCreateSession("new-key");

		s.SetActiveSessionKeyForConnection(id, "old-key");
		REQUIRE(s.GetSessionForConnection(id) == &old_sess);

		s.SetActiveSessionKeyForConnection(id, "new-key");
		REQUIRE(s.GetSessionForConnection(id) == &new_sess);

		// Old session still exists by key
		REQUIRE(s.GetSessionByKey("old-key") == &old_sess);
	}

	SECTION("ClearSession then re-login with new key") {
		Connection con(f.db);
		auto id = con.context->GetConnectionId();

		auto &sess_v1 = s.GetOrCreateSession("v1-key");
		{
			lock_guard<mutex> l(sess_v1.session_lock);
			sess_v1.access_token = "v1-token-pad0123456789abcdef0123456789abcdef0123456789abcdef";
		}
		s.SetActiveSessionKeyForConnection(id, "v1-key");

		// Mimics what SetRestApiEndpoint does: clear then re-login
		s.ClearSession(*con.context);

		// Mapping still exists but session data is empty
		auto *cleared = s.GetSessionForConnection(id);
		REQUIRE(cleared != nullptr);
		{
			lock_guard<mutex> l(cleared->session_lock);
			REQUIRE(cleared->access_token.empty());
		}

		// Re-login with new key
		auto &sess_v2 = s.GetOrCreateSession("v2-key");
		{
			lock_guard<mutex> l(sess_v2.session_lock);
			sess_v2.access_token = "v2-token-pad0123456789abcdef0123456789abcdef0123456789abcdef";
		}
		s.SetActiveSessionKeyForConnection(id, "v2-key");

		auto *fresh = s.GetSessionForConnection(id);
		REQUIRE(fresh == &sess_v2);
		{
			lock_guard<mutex> l(fresh->session_lock);
			REQUIRE(fresh->access_token == "v2-token-pad0123456789abcdef0123456789abcdef0123456789abcdef");
		}
	}
}

//===----------------------------------------------------------------------===//
// Test: GetOrCreateSession idempotency
//===----------------------------------------------------------------------===//
TEST_CASE("GetOrCreateSession Idempotency", "[boilstream][session-routing]") {
	SessionRoutingFixture f;
	auto &s = *f.storage;

	SECTION("Same key returns same object") {
		auto &a = s.GetOrCreateSession("idem-key");
		auto &b = s.GetOrCreateSession("idem-key");
		REQUIRE(&a == &b);
	}

	SECTION("Different keys return different objects") {
		auto &a = s.GetOrCreateSession("key-a");
		auto &b = s.GetOrCreateSession("key-b");
		REQUIRE(&a != &b);
	}

	SECTION("HasSession / GetSessionByKey consistency") {
		REQUIRE_FALSE(s.HasSession("hs-key"));
		REQUIRE(s.GetSessionByKey("hs-key") == nullptr);

		s.GetOrCreateSession("hs-key");

		REQUIRE(s.HasSession("hs-key"));
		REQUIRE(s.GetSessionByKey("hs-key") != nullptr);
	}
}

//===----------------------------------------------------------------------===//
// Test: Session Pointer Stability (shared_ptr keeps objects alive through rehash)
//===----------------------------------------------------------------------===//
TEST_CASE("Session Pointer Stability", "[boilstream][session-routing]") {
	SessionRoutingFixture f;
	auto &s = *f.storage;

	SECTION("Pointer survives map rehash from bulk inserts") {
		auto &sess = s.GetOrCreateSession("stable-1");
		auto *ptr = &sess;

		for (int i = 0; i < 100; i++) {
			s.GetOrCreateSession("bulk-" + std::to_string(i));
		}

		REQUIRE(s.GetSessionByKey("stable-1") == ptr);
	}

	SECTION("GetSessionForConnection returns same pointer as GetOrCreateSession") {
		Connection con(f.db);
		auto &sess = s.GetOrCreateSession("ptr-key");
		s.SetActiveSessionKeyForConnection(con.context->GetConnectionId(), "ptr-key");
		REQUIRE(s.GetSessionForConnection(con.context->GetConnectionId()) == &sess);
	}
}

//===----------------------------------------------------------------------===//
// Test: Concurrent Session Routing (the 20+ connection scenario)
//===----------------------------------------------------------------------===//
TEST_CASE("Concurrent Session Routing", "[boilstream][session-routing][threading]") {
	SessionRoutingFixture f;
	auto &s = *f.storage;

	SECTION("20 connections concurrently setting and reading session mappings") {
		const int N = 20;
		const int OPS = 200;

		std::vector<std::unique_ptr<Connection>> conns;
		std::vector<idx_t> ids;
		for (int i = 0; i < N; i++) {
			conns.push_back(std::make_unique<Connection>(f.db));
			ids.push_back(conns.back()->context->GetConnectionId());
			s.GetOrCreateSession("ck-" + std::to_string(i));
		}

		std::atomic<bool> go{false};
		std::atomic<int> errors{0};
		std::vector<std::thread> threads;

		for (int i = 0; i < N; i++) {
			threads.emplace_back([&, i]() {
				while (!go.load())
					std::this_thread::yield();

				string key = "ck-" + std::to_string(i);
				for (int j = 0; j < OPS; j++) {
					s.SetActiveSessionKeyForConnection(ids[i], key);
					if (!s.GetSessionForConnection(ids[i]))
						errors++;
				}
			});
		}

		go.store(true);
		for (auto &t : threads)
			t.join();

		REQUIRE(errors == 0);
		for (int i = 0; i < N; i++)
			REQUIRE(s.GetSessionForConnection(ids[i]) != nullptr);
	}

	SECTION("Concurrent connect/disconnect cycling") {
		const int THREADS = 10;
		const int CYCLES = 50;

		std::atomic<bool> go{false};
		std::atomic<int> errors{0};
		std::vector<std::thread> threads;

		for (int t = 0; t < THREADS; t++) {
			threads.emplace_back([&, t]() {
				while (!go.load())
					std::this_thread::yield();

				for (int c = 0; c < CYCLES; c++) {
					Connection con(f.db);
					auto id = con.context->GetConnectionId();
					string key = "cyc-" + std::to_string(t) + "-" + std::to_string(c);

					s.GetOrCreateSession(key);
					s.SetActiveSessionKeyForConnection(id, key);

					if (!s.GetSessionForConnection(id)) {
						errors++;
						continue;
					}

					s.ClearConnectionMapping(id);
					if (s.GetSessionForConnection(id) != nullptr)
						errors++;
				}
			});
		}

		go.store(true);
		for (auto &t : threads)
			t.join();
		REQUIRE(errors == 0);
	}

	SECTION("Concurrent ClearSession on shared session key does not crash") {
		const int N = 10;
		const int OPS = 50;

		s.GetOrCreateSession("shared-conc");
		std::vector<std::unique_ptr<Connection>> conns;
		for (int i = 0; i < N; i++) {
			conns.push_back(std::make_unique<Connection>(f.db));
			s.SetActiveSessionKeyForConnection(conns.back()->context->GetConnectionId(), "shared-conc");
		}

		auto *shared = s.GetSessionByKey("shared-conc");
		REQUIRE(shared != nullptr);
		{
			lock_guard<mutex> l(shared->session_lock);
			shared->access_token = "conc-token-pad0123456789abcdef0123456789abcdef0123456789abcde";
		}

		std::atomic<bool> go{false};
		std::vector<std::thread> threads;

		for (int i = 0; i < N; i++) {
			threads.emplace_back([&, i]() {
				while (!go.load())
					std::this_thread::yield();
				for (int j = 0; j < OPS; j++) {
					s.ClearSession(*conns[i]->context);
					{
						lock_guard<mutex> l(shared->session_lock);
						shared->access_token = "re-" + std::to_string(i) + "-" + std::to_string(j);
					}
				}
			});
		}

		go.store(true);
		for (auto &t : threads)
			t.join();

		// If we get here, no crash — shared_ptr kept the object alive
		REQUIRE(shared != nullptr);
	}
}
