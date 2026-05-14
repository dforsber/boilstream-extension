//===----------------------------------------------------------------------===//
//                         DuckDB
//
// test_quack_attach_red.cpp
//
// RED TDD test reproducing the Phase 4 e2e blocker:
//   ATTACH 'quack:host' AS r (TYPE quack) silently no-ops when boilstream
//   has been LOAD'ed but no PRAGMA boilstream_bootstrap_session is active.
//
// The user-supplied `CREATE SECRET ... (TYPE quack)` should be honoured.
// Currently the LookupSecret path returns the user's secret correctly when
// conn_state is null (verified by tracing the code), but the integration
// run shows the second secret with name "__quack__<path>" gets installed
// over the top by the bootstrap-session refresh and the resulting ambiguity
// causes the ATTACH to bind to the wrong (or no) secret.
//
// This test stays in the unit lane:
//   - No live boilstream server.
//   - No bootstrap_session called.
//   - We instantiate RestApiSecretStorage directly and inject a
//     KeyValueSecret of TYPE quack, then assert LookupSecret returns it.
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

	// Install through the canonical AddOrUpdateSecretInCatalog path —
	// same one CREATE SECRET ultimately hits via the secret manager.
	s.AddOrUpdateSecretInCatalog(std::move(secret), nullptr /* no transaction */);

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

	// Set up a path with a non-routable endpoint — so if the code DOES
	// take the auto-vend HTTP path, it will fail and we'd see an empty
	// SecretMatch. We want the GREEN path to return the user's secret
	// without touching HTTP at all.
	const string user_path = "quack:non-routable.invalid:1";
	const string user_token = "user-token-must-be-honoured";
	vector<string> scope{user_path};
	auto secret = make_uniq<KeyValueSecret>(scope, "quack", "config", "user-quack");
	secret->secret_map["token"] = Value(user_token);
	s.AddOrUpdateSecretInCatalog(std::move(secret), nullptr);

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
