//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_quack_attach_red.cpp
//
// Unit-level guard for the Phase 4 secret-lookup semantics:
//   - `CREATE SECRET ... (TYPE quack)` from a DuckDB CLI session that
//     never called `PRAGMA boilstream_bootstrap_session` must result in
//     `ATTACH 'quack:host' AS r (TYPE quack)` honouring the user's
//     secret (no auto-vend, no exception).
//   - When a boilstream session IS active, a user-supplied scope-matching
//     TYPE quack secret must take priority over the auto-vended one — the
//     server-vended JWT MUST NOT silently clobber the user's secret.
//
// This test stays in the unit lane:
//   - No live boilstream server.
//   - No bootstrap_session called.
//   - We instantiate RestApiSecretStorage directly and inject a
//     KeyValueSecret of TYPE quack, then assert LookupSecret returns it.
//
// Originally written as a RED TDD reproducer for the Phase 4 e2e blocker
// (ingestion-agent-cxum / ingestion-agent-8hnt); turned green by the
// StoreSecret-no-conn_state fix and the named auto-vend helper.
//
// Build (from extension repo root):
//   make            # builds duckdb static libs + extension archive
//   cd test/cpp/build && cmake .. && cmake --build . --target quack_attach_red_test
//   ./quack_attach_red_test
//===----------------------------------------------------------------------===//

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "boilstream_secret_storage.hpp"
#include "boilstream_connection_state.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/catalog/catalog_transaction.hpp"

using namespace duckdb;

struct QuackAttachFixture {
	duckdb::unique_ptr<DuckDB> db;
	duckdb::unique_ptr<RestApiSecretStorage> storage;

	QuackAttachFixture() {
		db = duckdb::make_uniq<DuckDB>(nullptr);
		// Empty endpoint URL == "no bootstrap_session yet". This is the
		// state every fresh duckdb process starts in.
		storage = duckdb::make_uniq<RestApiSecretStorage>(*db->instance, "");
	}
};

//===----------------------------------------------------------------------===//
// RED: a user-created TYPE quack secret MUST be returned by LookupSecret
// when there is no active boilstream session. The auto-vend path requires
// a live conn_state; absent one, LookupQuackSecret must fall through to the
// local CatalogSet path and return the user's secret unchanged.
//===----------------------------------------------------------------------===//
// Green as of the StoreSecret-no-conn_state fix + named auto-vend helper
// (closes ingestion-agent-8hnt). The `[red]` tag stays for cross-reference
// with the Phase 4 incident reports; the test now asserts the expected
// behaviour rather than reproducing the bug.
TEST_CASE("LookupSecret returns user-supplied quack secret without bootstrap_session",
          "[quack][red][phase4]") {
	QuackAttachFixture f;
	auto &s = *f.storage;

	// Build a KeyValueSecret of TYPE quack with scope matching the ATTACH path
	// the user would type. This mirrors what `CREATE SECRET ... (TYPE quack,
	// TOKEN '<jwt>', SCOPE 'quack:127.0.0.1:9494')` produces.
	const string user_path = "quack:127.0.0.1:9494";
	const string user_token = "user-supplied-token";
	vector<string> scope{user_path};
	auto secret = make_uniq<KeyValueSecret>(scope, "quack", "config", "smk");
	secret->secret_map["token"] = Value(user_token);

	// Install through the public StoreSecret API — same path `CREATE SECRET`
	// hits via the secret manager. With no conn_state, StoreSecret stores
	// locally only (no REST persist), matching DuckDB's TEMPORARY semantics.
	s.StoreSecret(std::move(secret), OnCreateConflict::REPLACE_ON_CONFLICT,
	              nullptr /* no transaction */);

	// ─── LookupSecret with no conn_state, type=quack ──────────────────
	auto match = s.LookupSecret(user_path, "quack", nullptr);

	// RED: this currently fails because LookupQuackSecret at line ~3797
	// returns SecretMatch() empty when conn_state is null, then the
	// fallthrough generic /match HTTP call at line ~3157 throws (no
	// connection state) — so we never re-consult the local catalog where
	// the user secret lives.
	REQUIRE(match.HasMatch());

	auto &returned = match.GetSecret();
	REQUIRE(returned.GetName() == "smk");
	REQUIRE(returned.GetType() == "quack");

	// The token field must round-trip — that's the entire contract: the
	// user supplied a token, ATTACH consumes it.
	auto &kv = dynamic_cast<const KeyValueSecret &>(returned);
	auto it = kv.secret_map.find("token");
	REQUIRE(it != kv.secret_map.end());
	REQUIRE(it->second.ToString() == user_token);
}

//===----------------------------------------------------------------------===//
// Companion: even WITH a conn_state present (bootstrap_session called),
// if a user-created TYPE quack secret already exists in the catalog with a
// matching scope, LookupSecret MUST prefer that over re-fetching from the
// boilstream server. Otherwise CREATE SECRET (TYPE quack) is pointless —
// the user's token is silently replaced on every ATTACH.
//===----------------------------------------------------------------------===//
TEST_CASE("LookupSecret prefers user-supplied quack secret over auto-vend",
          "[quack][red][phase4]") {
	QuackAttachFixture f;
	auto &s = *f.storage;

	// Establish a conn_state so the LookupQuackSecret branch runs in full.
	auto &session = s.GetOrCreateSession("test-session");
	Connection con(*f.db);
	s.SetActiveSessionKeyForConnection(con.context->GetConnectionId(), "test-session");

	// Production ATTACH always runs inside an active meta transaction (the
	// secret manager is invoked from query binding, not from raw API calls).
	// CatalogSetSecretStorage::LookupSecret eventually touches
	// `TransactionContext::ActiveTransaction()` so we must open one here.
	con.BeginTransaction();

	// Set up a path with a non-routable endpoint — so if the code DOES
	// take the auto-vend HTTP path, it will fail and we'd see an empty
	// SecretMatch. We want the GREEN path to return the user's secret
	// without touching HTTP at all.
	const string user_path = "quack:non-routable.invalid:1";
	const string user_token = "user-token-must-be-honoured";
	vector<string> scope{user_path};
	auto secret = make_uniq<KeyValueSecret>(scope, "quack", "config", "user-quack");
	secret->secret_map["token"] = Value(user_token);
	s.StoreSecret(std::move(secret), OnCreateConflict::REPLACE_ON_CONFLICT, nullptr);

	// Use a CatalogTransaction wired to our connection so GetSession resolves.
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(*con.context);
	auto match = s.LookupSecret(user_path, "quack", &transaction);

	REQUIRE(match.HasMatch());
	REQUIRE(match.GetSecret().GetName() == "user-quack");

	auto &kv = dynamic_cast<const KeyValueSecret &>(match.GetSecret());
	auto it = kv.secret_map.find("token");
	REQUIRE(it != kv.secret_map.end());
	REQUIRE(it->second.ToString() == user_token);

	// Silence unused warning under -DNDEBUG.
	(void)session;
}
