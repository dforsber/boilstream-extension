//===----------------------------------------------------------------------===//
//                         DuckDB / Boilstream
//
// quack_bridge.hpp
//
// Phase 1 shim that exposes three DuckDB scalar functions:
//   * boilstream_quack_authn        — token check (parity with quack_check_token)
//   * boilstream_quack_authz        — read-only first-keyword policy
//   * boilstream_quack_bind_session — stash (user_id, tenant_id, catalog allowlist)
//                                     for a Quack session_id
//
// Plus an internal test-only helper:
//   * boilstream_quack_debug_session_count — number of entries in the in-memory
//                                            session map (for sqllogictest)
//
// Notes for the next worker (Phase 2):
//   - The session map is *write-only* in Phase 1. The accessor
//     GetQuackSessionCtx() exists so future code (e.g. Quack authz callback
//     that needs to know which tenant/catalogs apply) can read it.
//   - JWT validation is NOT done yet. boilstream_quack_authn must be replaced
//     to verify a server-minted JWT once the mint endpoint lands. See the
//     TODO(quack-jwt) marker in quack_bridge.cpp.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

//===----------------------------------------------------------------------===//
// Host-registered JWT verifier (Phase 1.5 of Quack adoption)
//
// The Quack listener runs inside the BoilStream server process. The bridge
// cannot decode HS256 JWTs on its own (it has no access to cluster_secret),
// so the host (Rust) registers a function pointer at startup. The bridge
// then calls through that pointer in `boilstream_quack_authn`.
//
// When this extension is loaded into a *remote* DuckDB client (which has no
// Quack listener and no cluster_secret), the verifier is never registered;
// the bridge then falls back to literal-token comparison — harmless because
// authentication is always enforced server-side.
//
// IMPORTANT: declared `extern "C"` so the Rust side can resolve the symbol
// at link time without name mangling. `extern "C"` symbols are auto-exported
// from a static library, so no extra DLL/dylib export annotation is needed.
//===----------------------------------------------------------------------===//
extern "C" {

//! JWT verifier signature.
//!
//! Returns 1 on a valid JWT, 0 otherwise. On success the three out buffers
//! are populated with NUL-terminated strings:
//!   * user_id_out      — JWT `sub` claim
//!   * tenant_id_out    — `tenant_id` claim (decimal string)
//!   * catalogs_csv_out — comma-joined `catalogs` claim
//!
//! Truncation (any output that does not fit including the NUL terminator)
//! must be treated as failure by the implementation, returning 0.
typedef int (*boilstream_quack_jwt_verifier_fn)(const char *jwt, size_t jwt_len, char *user_id_out,
                                                size_t user_id_capacity, char *tenant_id_out, size_t tenant_id_capacity,
                                                char *catalogs_csv_out, size_t catalogs_capacity);

//! Register the verifier (or clear it by passing NULL). Intended to be
//! called exactly once during host startup, before the Quack listener
//! accepts connections. Reads of the slot on the hot authn path use an
//! acquire-load against an atomic, so a single late-registration would be
//! observed eventually — but the intended usage is one-shot at boot.
void boilstream_quack_set_jwt_verifier(boilstream_quack_jwt_verifier_fn fn);

//===----------------------------------------------------------------------===//
// Host-registered SQL rewriter (Phase 2 of Quack adoption — write routing)
//
// The patched Quack server fires a pre-execute hook between authz and
// SendQuery. Our bridge wires that hook to a C++ handler that looks up the
// session's SessionCtx, then calls into this Rust-side rewriter to give
// it a chance to substitute the SQL. Used to route INSERT/UPDATE/DELETE
// against DuckLake catalogs through the same Airport-loopback path PGWire
// uses for streaming writes.
//
// Tenant_id and catalogs_csv are pre-resolved by the C++ handler so the
// Rust side doesn't have to make a back-callback to look them up.
//
// Returns:
//    1   — rewrote (sql_out_buf is NUL-terminated rewritten SQL)
//    0   — no rewrite (server executes sql_in verbatim)
//   <0   — rewriter error (treated as no-rewrite; the rewriter logs)
//===----------------------------------------------------------------------===//
typedef int (*boilstream_quack_sql_rewriter_fn)(const char *session_id, const char *tenant_id, const char *catalogs_csv,
                                                const char *sql_in, char *sql_out_buf, size_t sql_out_size);

//! Register the rewriter (or clear with NULL). One-shot at boot, like the
//! JWT verifier above.
void boilstream_quack_set_sql_rewriter(boilstream_quack_sql_rewriter_fn fn);

//===----------------------------------------------------------------------===//
// Host-registered post-success hook (DuckLake catalog durability)
//
// Patched Quack calls the bridge after a PREPARE_REQUEST statement has
// successfully executed. The bridge supplies the bound session context and the
// original/executed SQL to Rust so BoilStream can force a durable catalog
// backup before Quack returns success to the client.
//
// Returns:
//    0   — success / no-op
//   <0   — durability failure; error_out_buf contains a client-visible error
//===----------------------------------------------------------------------===//
typedef int (*boilstream_quack_post_execute_fn)(
    const char *session_id, const char *user_id, const char *tenant_id, const char *catalogs_csv,
    const char *sql_original, const char *sql_executed, char *error_out_buf, size_t error_out_size);

//! Register the post-success hook (or clear with NULL). One-shot at boot.
void boilstream_quack_set_post_execute_hook(boilstream_quack_post_execute_fn fn);

} // extern "C"

namespace duckdb {

//! Per-session context populated by boilstream_quack_bind_session() and (in
//! Phase 2) consumed by the authz callback. Keyed by Quack session_id.
struct SessionCtx {
	std::string user_id;
	std::string tenant_id;
	std::vector<std::string> catalogs; //!< parsed from comma-separated allowlist
};

//! Phase-1 accessor — returns a *copy* of the SessionCtx for the given
//! session id, if any. The bool indicates whether the entry existed.
//! Intentionally non-static so Phase-2 callers in other translation units
//! can use it.
std::pair<SessionCtx, bool> GetQuackSessionCtx(const std::string &session_id);

//! Register the four scalar functions with the DuckDB extension loader.
void RegisterQuackBridge(ExtensionLoader &loader);

} // namespace duckdb
