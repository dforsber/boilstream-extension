//===----------------------------------------------------------------------===//
//                         DuckDB / Boilstream
//
// quack_bridge.cpp
//
// Phase 1 of the BoilStream Quack adoption plan. Implements three scalar
// functions plus one internal test helper. See quack_bridge.hpp for the
// design notes. These functions are referenced from DuckDB's
// quack_authentication_function / quack_authorization_function GLOBAL
// settings so Quack can call into BoilStream policy.
//===----------------------------------------------------------------------===//

#include "quack_bridge.hpp"

#include "duckdb/common/types/string_type.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/vector_operations/binary_executor.hpp"
#include "duckdb/common/vector_operations/ternary_executor.hpp"
#include "duckdb/common/vector_operations/unary_executor.hpp"
#include "duckdb/function/scalar_function.hpp"

#include <atomic>
#include <cctype>
#include <cstring>
#include <iostream>
#include <mutex>
#include <unordered_set>

// Portable runtime symbol lookup. The bridge resolves two `extern "C"`
// symbols that exist only when loaded inside the multi-tenant boilstream
// DuckDB fork (`quack_set_session_init_hook`, `duckdb_set_tenant_id_on_context`).
// On vanilla DuckDB the lookups must return null cleanly so the bridge can
// degrade silently. POSIX uses `dlsym(RTLD_DEFAULT, ...)`; Windows
// (MSVC + MinGW) uses `GetProcAddress(GetModuleHandle(NULL), ...)`.
#ifdef _WIN32
#include <windows.h>
static inline void *boilstream_lookup_runtime_symbol(const char *name) {
	HMODULE h = ::GetModuleHandleA(NULL);
	if (!h) {
		return nullptr;
	}
	return reinterpret_cast<void *>(::GetProcAddress(h, name));
}
#else
#include <dlfcn.h>
static inline void *boilstream_lookup_runtime_symbol(const char *name) {
	return ::dlsym(RTLD_DEFAULT, name);
}
#endif

// Match the BOILSTREAM_LOG convention used by boilstream_secret_storage.cpp:
// build with -DBOILSTREAM_DEBUG to enable; otherwise the macro compiles away.
#ifdef BOILSTREAM_DEBUG
#define BOILSTREAM_LOG(msg) std::cerr << "[BOILSTREAM] " << msg << std::endl
#else
#define BOILSTREAM_LOG(msg) ((void)0)
#endif
#include <string>
#include <unordered_map>
#include <vector>

namespace {

//! Single global slot holding the host-registered JWT verifier (or null).
//! Lives in an anonymous namespace at file scope so it is shared between
//! the extern "C" setter and the (namespaced) authn function below.
//!
//! Initialised to nullptr — when no host registers a verifier (i.e. when
//! the extension is loaded into a remote client DuckDB), authn falls back
//! to literal-token comparison, preserving Phase 1 behaviour.
std::atomic<boilstream_quack_jwt_verifier_fn> &QuackJwtVerifierSlot() {
	static std::atomic<boilstream_quack_jwt_verifier_fn> slot {nullptr};
	return slot;
}

//! Single global slot holding the host-registered SQL rewriter (or null).
//! Same lifecycle as the JWT verifier slot above — set once at boot, read
//! on the hot pre-execute path with acquire/release.
std::atomic<boilstream_quack_sql_rewriter_fn> &QuackSqlRewriterSlot() {
	static std::atomic<boilstream_quack_sql_rewriter_fn> slot {nullptr};
	return slot;
}

//! Single global slot holding the host-registered post-success hook (or
//! null). Called after Quack successfully executes SQL so the host can
//! force durability work before the client sees success.
std::atomic<boilstream_quack_post_execute_fn> &QuackPostExecuteSlot() {
	static std::atomic<boilstream_quack_post_execute_fn> slot {nullptr};
	return slot;
}

} // anonymous namespace

extern "C" void boilstream_quack_set_jwt_verifier(boilstream_quack_jwt_verifier_fn fn) {
	// Release-store so the verifier's internal state (any TLS, statics it
	// closes over on the Rust side) is visible to a thread that later does
	// an acquire-load before calling through the pointer. This is overkill
	// for typical one-shot startup registration but cheap and correct.
	QuackJwtVerifierSlot().store(fn, std::memory_order_release);
}

extern "C" void boilstream_quack_set_sql_rewriter(boilstream_quack_sql_rewriter_fn fn) {
	// Same release-store semantics as the JWT setter above.
	QuackSqlRewriterSlot().store(fn, std::memory_order_release);
}

extern "C" void boilstream_quack_set_post_execute_hook(boilstream_quack_post_execute_fn fn) {
	// Same release-store semantics as the JWT setter above.
	QuackPostExecuteSlot().store(fn, std::memory_order_release);
}

// Forward declarations for the two hook seams between the bridge,
// upstream Quack (with our session-init-hook patch on the server side),
// and the multi-tenant DuckDB fork. All symbols are plain `extern "C"`
// and pass session_id / tenant_id / ClientContext only as primitives
// (const char*, void*). The bridge therefore stays community-extension
// compatible — it never includes multi-tenant headers and never touches
// Quack's internal C++ types.
//
// Bridge-provided (DEFINED at the bottom of this TU, outside namespace duckdb):
//   * `boilstream_quack_session_init` — Quack's session-init hook handler.
//     Looks up tenant_id for the session and forwards to the fork.
//
// Quack-provided (weak: patched-Quack defines, stock-Quack does not):
//   * `quack_set_session_init_hook` — setter for the init hook slot.
//     Called from RegisterQuackBridge below to wire our handler.
//
// Fork-provided (weak: multi-tenant fork defines, vanilla DuckDB does not):
//   * `duckdb_set_tenant_id_on_context` — stamps tenant_id onto a
//     ClientContext (the Quack-spawned Connection's context).
// Forward declaration of the Quack session-init handler defined at the
// bottom of this TU. The handler is reachable from outside this TU via
// its `extern "C"` symbol — Quack's patched server calls into it at
// runtime via `dlsym(RTLD_DEFAULT, ...)` from its hook-registration site.
extern "C" void boilstream_quack_session_init(const char *session_id, void *client_context);

// Forward declaration of the Quack pre-execute hook handler defined at
// the bottom of this TU. Called by patched Quack between authz and
// SendQuery; routes through to the host-registered Rust rewriter.
extern "C" int boilstream_quack_pre_execute(const char *session_id, const char *sql_in, char *sql_out_buf,
                                            size_t sql_out_size);

// Forward declaration of the Quack post-execute hook handler defined at
// the bottom of this TU. Called by patched Quack after successful
// SendQuery so the host can run durability work before success is returned.
extern "C" int boilstream_quack_post_execute(const char *session_id, const char *sql_original,
                                             const char *sql_executed, char *error_out_buf, size_t error_out_size);

// Function-pointer typedefs for the two cross-extension hooks we resolve
// at runtime. We use `dlsym(RTLD_DEFAULT, name)` rather than weak-linked
// `extern` declarations because:
//   (a) macOS's `weak_import` requires the symbol to be in a dynamic
//       library (dylib/framework). Quack's `quack_set_session_init_hook`
//       and the multi-tenant fork's `duckdb_set_tenant_id_on_context` are
//       both exposed only via static archives, so weak_import can't
//       resolve them — link still fails.
//   (b) Plain `weak` on macOS does not leave undefined externals OK at
//       link time without `-undefined dynamic_lookup`, which would mask
//       genuine missing-symbol bugs across the whole build.
//   (c) `dlsym(RTLD_DEFAULT, …)` is fully portable, has zero link-time
//       coupling, and resolves at extension-load time — exactly when we
//       need to know whether the host provides these hooks.
typedef void (*quack_set_session_init_hook_fn_t)(void (*hook)(const char *, void *));

// The patched Quack server (`server-write-routing-hook.patch`) exposes a
// SQL rewrite hook setter with this signature. dlsym'd at runtime — the
// symbol is absent on vanilla Quack builds, in which case we silently
// skip wiring.
typedef void (*quack_set_pre_execute_hook_fn_t)(int (*hook)(const char *session_id, const char *sql_in,
                                                            char *sql_out_buf, size_t sql_out_size));
typedef void (*quack_set_post_execute_hook_fn_t)(int (*hook)(const char *session_id, const char *sql_original,
                                                             const char *sql_executed, char *error_out_buf,
                                                             size_t error_out_size));
typedef bool (*duckdb_set_tenant_id_on_context_fn_t)(void *, const char *);

namespace duckdb {

// Forward declaration of the thread-local sid accessor. Defined at the end
// of this TU, in `namespace duckdb` proper (NOT in the inner anon namespace
// just below) so it has external linkage and the `extern "C"` resolver hook
// at the bottom of the file (sitting outside `namespace duckdb`) can reach
// it as `duckdb::QuackAuthzCurrentSid`. The authz scalar inside the inner
// anon namespace below calls it unqualified — name lookup walks out of the
// anon into the enclosing `namespace duckdb` and finds this declaration.
std::string &QuackAuthzCurrentSid();

namespace {

//! Process-global session map. Populated by boilstream_quack_bind_session();
//! Phase 1 does not yet consume it but Phase 2 will.
std::mutex &SessionMapMutex() {
	static std::mutex m;
	return m;
}

std::unordered_map<std::string, SessionCtx> &SessionMap() {
	static std::unordered_map<std::string, SessionCtx> m;
	return m;
}

//! Convert a string_t to std::string defensively (no exceptions thrown
//! for sane inputs, but wrap in try/catch at call sites anyway).
inline std::string ToStd(const string_t &s) {
	return std::string(s.GetData(), s.GetSize());
}

//! Split a CSV-style allowlist into a vector. Empty entries are skipped.
//! Whitespace around each token is trimmed.
std::vector<std::string> SplitCsv(const std::string &csv) {
	std::vector<std::string> out;
	std::string cur;
	cur.reserve(32);
	auto flush = [&]() {
		auto begin = cur.find_first_not_of(" \t\r\n");
		auto end = cur.find_last_not_of(" \t\r\n");
		if (begin != std::string::npos) {
			out.emplace_back(cur.substr(begin, end - begin + 1));
		}
		cur.clear();
	};
	for (char c : csv) {
		if (c == ',') {
			flush();
		} else {
			cur.push_back(c);
		}
	}
	flush();
	return out;
}

//! Extract the first SQL keyword from `q` (skipping leading whitespace),
//! upper-cased. Returns empty string if no keyword is found.
std::string FirstKeywordUpper(const std::string &q) {
	size_t i = 0;
	while (i < q.size() && std::isspace(static_cast<unsigned char>(q[i]))) {
		i++;
	}
	std::string kw;
	while (i < q.size()) {
		unsigned char c = static_cast<unsigned char>(q[i]);
		// First word ends at the first non-alpha (DuckDB SQL keywords are alpha-only).
		if (!std::isalpha(c)) {
			break;
		}
		kw.push_back(static_cast<char>(std::toupper(c)));
		i++;
	}
	return kw;
}

bool IsReadOnlyKeyword(const std::string &kw) {
	// SELECT / PRAGMA / EXPLAIN / DESCRIBE / SHOW / WITH / CALL
	// (CALL is needed for things like CALL quack_stop.)
	return kw == "SELECT" || kw == "PRAGMA" || kw == "EXPLAIN" || kw == "DESCRIBE" || kw == "SHOW" || kw == "WITH" ||
	       kw == "CALL";
}

//! Phase-2 admit-list: keywords this server is willing to execute.
//! Adds INSERT / UPDATE / DELETE / MERGE on top of the read-only set.
//! Writes are safe because:
//!   1. The pre-execute SQL rewriter routes INSERTs against DuckLake
//!      catalogs through the Airport loopback (central ingestion path).
//!   2. The catalog allow-list rejects writes against catalogs outside
//!      the session's claims.
//!   3. The multi-tenant fork's ActiveTenantRegistry isolates by tenant.
//!   4. Writes against the user's own non-DuckLake attached catalogs
//!      (local memory:, etc.) execute directly — that's the documented
//!      behaviour. Transaction control (BEGIN/COMMIT/ROLLBACK) is also
//!      admitted so multi-statement writes work.
//!
//! DDL (CREATE / DROP / ALTER / TRUNCATE / GRANT / REVOKE / COPY FROM)
//! is still rejected — DuckLake DDL must go through the catalog-master
//! leader RPC (via PGWire) for cluster-wide visibility.
bool IsAllowedKeyword(const std::string &kw) {
	if (IsReadOnlyKeyword(kw)) {
		return true;
	}
	return kw == "INSERT" || kw == "UPDATE" || kw == "DELETE" || kw == "MERGE" || kw == "BEGIN" ||
	       kw == "START" /* START TRANSACTION */ || kw == "COMMIT" || kw == "ROLLBACK" || kw == "END";
}

//! "System" catalog names that are always allowed even when not in the
//! JWT's `catalogs` claim. These are either:
//!   - DuckDB built-ins (memory, system, temp)
//!   - SQL standard discovery views (information_schema)
//!   - Postgres-compat helpers (pg_catalog)
//! The Quack-spawned `Connection` legitimately needs to query these
//! during ATTACH discovery and the user's regular session work.
bool IsSystemCatalog(const std::string &lower) {
	return lower == "memory" || lower == "system" || lower == "temp" || lower == "information_schema" ||
	       lower == "pg_catalog";
}

//! Lower-case ASCII helper. DuckDB folds unquoted identifiers to lower
//! case during parsing; we mirror that for the comparison.
std::string LowerAscii(const std::string &s) {
	std::string out;
	out.reserve(s.size());
	for (unsigned char c : s) {
		out.push_back(static_cast<char>(std::tolower(c)));
	}
	return out;
}

//! Heuristic catalog extraction for the authz allow-list check.
//!
//! Scans `q` for `<ident>.<ident>.<ident>` 3-part references and returns
//! the lowercased catalog identifier (the first part) for each one. Both
//! bare (`cat.schema.t`) and quoted (`"cat".schema.t`) first-parts are
//! recognised. Single-quoted string literals are skipped so e.g.
//! `SELECT '"a"."b"."c"'` is treated as a literal, not a 3-part ref.
//!
//! This is intentionally NOT a full SQL parser. It exists purely to add
//! defense-in-depth on top of the multi-tenant DuckDB fork's catalog
//! isolation. False positives (catalog refs found in places where DuckDB
//! wouldn't actually resolve them) are acceptable — they just fail the
//! query, which the caller can fix by quoting the literal. False
//! negatives (missed catalog refs) fall through to the tenant-isolation
//! layer, which is the authoritative check.
//!
//! Returns the set of *unique* candidate catalog names (lowercase). An
//! empty set means the query has no qualified catalog references; it's
//! safe to allow (subject only to the read-only keyword gate).
std::unordered_set<std::string> ExtractCatalogRefs(const std::string &q) {
	std::unordered_set<std::string> out;
	auto is_ident_start = [](char c) {
		return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
	};
	auto is_ident_cont = [](char c) {
		return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
	};

	// Parse an identifier starting at `i`. Returns (parsed_value, success).
	// Advances `i` past the identifier (including closing quote when quoted).
	// `out_ident` is filled with the inner text (without surrounding quotes).
	auto parse_ident = [&](size_t &i, std::string &out_ident) -> bool {
		const size_t n = q.size();
		if (i >= n) {
			return false;
		}
		if (q[i] == '"') {
			i++;
			std::string buf;
			while (i < n) {
				if (q[i] == '"') {
					if (i + 1 < n && q[i + 1] == '"') {
						buf.push_back('"');
						i += 2;
						continue;
					}
					i++;
					out_ident = std::move(buf);
					return true;
				}
				buf.push_back(q[i]);
				i++;
			}
			// Unterminated quoted ident
			return false;
		}
		if (!is_ident_start(q[i])) {
			return false;
		}
		size_t start = i;
		while (i < n && is_ident_cont(q[i])) {
			i++;
		}
		out_ident = q.substr(start, i - start);
		return true;
	};

	size_t i = 0;
	const size_t n = q.size();
	while (i < n) {
		char c = q[i];
		// Skip single-quoted string literals so we don't mis-parse a `.` inside one.
		if (c == '\'') {
			i++;
			while (i < n) {
				if (q[i] == '\'') {
					if (i + 1 < n && q[i + 1] == '\'') {
						i += 2;
						continue;
					}
					i++;
					break;
				}
				i++;
			}
			continue;
		}
		// Look for a 3-part identifier ref starting here. Try bare-or-quoted.
		size_t save = i;
		std::string ident1;
		if (!parse_ident(i, ident1)) {
			i = save + 1;
			continue;
		}
		// Must be followed by `.<ident>.<ident>` (bare or quoted), no
		// intervening whitespace, to count as a catalog-qualified ref.
		if (i >= n || q[i] != '.') {
			continue;
		}
		i++;
		std::string ident2;
		if (!parse_ident(i, ident2)) {
			continue;
		}
		if (i >= n || q[i] != '.') {
			continue;
		}
		i++;
		std::string ident3;
		if (!parse_ident(i, ident3)) {
			continue;
		}
		// 3-part confirmed. Record the catalog (first) part.
		out.insert(LowerAscii(ident1));
	}
	return out;
}

//! Decide whether the query's catalog references are all within the
//! session's allow-list (claims.catalogs) or the system-catalog list.
//! Returns true if every parsed catalog ref is allowed; false if any
//! ref names a catalog the session has no claim to.
//!
//! An empty ref set (no qualified catalog refs in the query) is allowed.
//! Schema-qualified or unqualified refs (`SELECT * FROM t`, `SELECT *
//! FROM schema.t`) skip this gate and rely on DuckDB's catalog resolver
//! which is gated by the multi-tenant fork's ActiveTenantRegistry.
bool CatalogRefsAreAllowed(const std::vector<std::string> &claims_catalogs, const std::string &query) {
	auto refs = ExtractCatalogRefs(query);
	if (refs.empty()) {
		return true;
	}
	std::unordered_set<std::string> allowed;
	allowed.reserve(claims_catalogs.size());
	for (const auto &c : claims_catalogs) {
		allowed.insert(LowerAscii(c));
	}
	for (const auto &r : refs) {
		if (IsSystemCatalog(r)) {
			continue;
		}
		if (allowed.find(r) == allowed.end()) {
			return false;
		}
	}
	return true;
}

//! Phase-1.5 authn:
//!   * If the host (Rust) has registered a JWT verifier, dispatch to it,
//!     treat `client_auth` as a signed JWT, and on success bind the
//!     session via the same code path as `boilstream_quack_bind_session`.
//!   * If no verifier is registered (e.g. extension loaded into a remote
//!     client DuckDB), fall back to the Phase-1 literal-token comparison
//!     so existing tests and embedded scenarios keep working.
//!
//! Signature (per Quack):
//!   (VARCHAR session_id, VARCHAR client_auth_string, VARCHAR server_token) -> BOOLEAN
//!
//! Defense in depth: Quack fails closed on exceptions, but we ALSO wrap our
//! body in try/catch and return FALSE on any throw. We must never let an
//! exception unwind across the FFI boundary into the Rust verifier — but
//! the Rust side itself wraps the body in `catch_unwind`, so the contract
//! is symmetric.
void BoilstreamQuackAuthnFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &sid_vec = args.data[0];
	auto &client_vec = args.data[1];
	auto &server_vec = args.data[2];

	// Acquire-load matches the release-store in the setter so any state
	// the Rust verifier closes over is visible to this thread.
	auto verifier = QuackJwtVerifierSlot().load(std::memory_order_acquire);

	TernaryExecutor::Execute<string_t, string_t, string_t, bool>(
	    sid_vec, client_vec, server_vec, result, args.size(),
	    [verifier](string_t sid, string_t client_auth, string_t server_tok) -> bool {
		    try {
			    if (verifier != nullptr) {
				    // Stack-allocate the out buffers. 128/128/4096 is comfortable
				    // for our claim sizes (user_id is a UUID-ish string, tenant_id
				    // is a u32 in decimal, catalogs are slug-style names).
				    char user_id_buf[128];
				    char tenant_id_buf[128];
				    char catalogs_buf[4096];
				    user_id_buf[0] = '\0';
				    tenant_id_buf[0] = '\0';
				    catalogs_buf[0] = '\0';

				    int rc = verifier(client_auth.GetData(), client_auth.GetSize(), user_id_buf, sizeof(user_id_buf),
				                      tenant_id_buf, sizeof(tenant_id_buf), catalogs_buf, sizeof(catalogs_buf));
				    BOILSTREAM_LOG("quack-bridge authn verifier rc="
				                   << rc << " sid='" << std::string(sid.GetData(), sid.GetSize()) << "' user='"
				                   << user_id_buf << "' tenant='" << tenant_id_buf << "' catalogs='" << catalogs_buf
				                   << "'");
				    if (rc != 1) {
					    return false;
				    }

				    // Defence-in-depth: ensure NUL termination even if the verifier
				    // misbehaved. (A well-behaved verifier already wrote NULs and
				    // returned 0 on overflow; this is a belt-and-braces guard.)
				    user_id_buf[sizeof(user_id_buf) - 1] = '\0';
				    tenant_id_buf[sizeof(tenant_id_buf) - 1] = '\0';
				    catalogs_buf[sizeof(catalogs_buf) - 1] = '\0';

				    std::string sid_str(sid.GetData(), sid.GetSize());
				    if (sid_str.empty()) {
					    // Empty session id is rejected by bind_session; reject here too.
					    return false;
				    }

				    // Drive the existing session-bind path so authn and the
				    // SQL-level `boilstream_quack_bind_session` write into the
				    // same in-memory map. We construct a SessionCtx directly
				    // rather than re-entering the scalar function.
				    duckdb::SessionCtx ctx;
				    ctx.user_id.assign(user_id_buf);
				    ctx.tenant_id.assign(tenant_id_buf);
				    {
					    // Same split logic the bind scalar function uses.
					    std::string csv(catalogs_buf);
					    std::string cur;
					    cur.reserve(32);
					    auto flush = [&]() {
						    auto begin = cur.find_first_not_of(" \t\r\n");
						    auto end = cur.find_last_not_of(" \t\r\n");
						    if (begin != std::string::npos) {
							    ctx.catalogs.emplace_back(cur.substr(begin, end - begin + 1));
						    }
						    cur.clear();
					    };
					    for (char c : csv) {
						    if (c == ',') {
							    flush();
						    } else {
							    cur.push_back(c);
						    }
					    }
					    flush();
				    }
				    {
					    std::lock_guard<std::mutex> lock(SessionMapMutex());
					    SessionMap()[sid_str] = std::move(ctx);
				    }
				    return true;
			    }

			    // No verifier registered — Phase-1 literal-token fallback.
			    if (client_auth.GetSize() != server_tok.GetSize()) {
				    return false;
			    }
			    if (client_auth.GetSize() == 0) {
				    // Disallow empty tokens — Quack's own ValidateToken requires >=4
				    // chars, but we conservatively reject empty here too.
				    return false;
			    }
			    return memcmp(client_auth.GetData(), server_tok.GetData(), client_auth.GetSize()) == 0;
		    } catch (...) {
			    // Fail closed — never let an exception unwind across FFI or into
			    // DuckDB's scalar function dispatch.
			    return false;
		    }
	    });
}

//! Phase-1 authz: read-only first-keyword policy.
//!
//! Signature (per Quack):
//!   (VARCHAR session_id, VARCHAR query) -> BOOLEAN
void BoilstreamQuackAuthzFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &sid_vec = args.data[0];
	auto &query_vec = args.data[1];
	(void)state;
	BinaryExecutor::Execute<string_t, string_t, bool>(
	    sid_vec, query_vec, result, args.size(), [](string_t sid, string_t query) -> bool {
		    try {
			    std::string q = ToStd(query);
			    std::string kw = FirstKeywordUpper(q);
			    bool kw_allow = IsAllowedKeyword(kw);

			    // Stamp the per-thread sid so the host's tenant-resolver hook
			    // (a weak extern "C" symbol, defined below in this TU) can
			    // map sid → tenant_id when the Quack-spawned Connection's
			    // BeginQueryInternal fires on the same thread microseconds
			    // later. Even when authz `allow==false` we set this — the
			    // upcoming SendQuery is skipped on rejection anyway, and a
			    // stale value here is harmless.
			    QuackAuthzCurrentSid().assign(sid.GetData(), sid.GetSize());

			    if (!kw_allow) {
				    BOILSTREAM_LOG("quack-bridge authz REJECT(keyword) kw='"
				                   << kw << "' sid='" << QuackAuthzCurrentSid() << "' query=" << q.substr(0, 200));
				    return false;
			    }

			    // Defense-in-depth: even though the multi-tenant DuckDB fork
			    // gates catalog visibility via ActiveTenantRegistry, also
			    // reject queries that name a 3-part catalog reference
			    // outside the session's claims allowlist. Catches regressions
			    // in tenant isolation and any future code path that bypasses
			    // it. Missing session ctx => fall through to the keyword
			    // gate only (Phase-1 literal-token authn flow).
			    std::string sid_str(sid.GetData(), sid.GetSize());
			    auto sess = duckdb::GetQuackSessionCtx(sid_str);
			    if (sess.second) {
				    bool cat_allow = CatalogRefsAreAllowed(sess.first.catalogs, q);
				    if (!cat_allow) {
					    BOILSTREAM_LOG("quack-bridge authz REJECT(catalog-allowlist) sid='"
					                   << sid_str << "' user='" << sess.first.user_id << "' tenant='"
					                   << sess.first.tenant_id << "' query=" << q.substr(0, 200));
					    return false;
				    }
			    }

			    BOILSTREAM_LOG("quack-bridge authz ALLOW kw='" << kw << "' sid='" << QuackAuthzCurrentSid()
			                                                   << "' query=" << q.substr(0, 200));
			    return true;
		    } catch (...) {
			    return false;
		    }
	    });
}

//! Phase-1 bind: stash (user_id, tenant_id, catalogs) under session_id.
//!
//! Signature:
//!   (VARCHAR session_id, VARCHAR user_id, VARCHAR tenant_id,
//!    VARCHAR catalog_allowlist_csv) -> BOOLEAN
//!
//! Returns TRUE on success, FALSE on any failure.
void BoilstreamQuackBindSessionFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	// 4-arg scalar — no canned executor, do it row-by-row.
	D_ASSERT(args.ColumnCount() == 4);
	for (idx_t i = 0; i < args.ColumnCount(); i++) {
		args.data[i].Flatten(args.size());
	}
	result.SetVectorType(VectorType::FLAT_VECTOR);
	auto sid_data = FlatVector::GetData<string_t>(args.data[0]);
	auto user_data = FlatVector::GetData<string_t>(args.data[1]);
	auto tenant_data = FlatVector::GetData<string_t>(args.data[2]);
	auto cat_data = FlatVector::GetData<string_t>(args.data[3]);
	auto out_data = FlatVector::GetData<bool>(result);

	auto &sid_validity = FlatVector::Validity(args.data[0]);
	auto &user_validity = FlatVector::Validity(args.data[1]);
	auto &tenant_validity = FlatVector::Validity(args.data[2]);
	auto &cat_validity = FlatVector::Validity(args.data[3]);

	for (idx_t i = 0; i < args.size(); i++) {
		bool ok = false;
		try {
			if (sid_validity.RowIsValid(i) && user_validity.RowIsValid(i) && tenant_validity.RowIsValid(i) &&
			    cat_validity.RowIsValid(i)) {
				SessionCtx ctx;
				ctx.user_id = ToStd(user_data[i]);
				ctx.tenant_id = ToStd(tenant_data[i]);
				ctx.catalogs = SplitCsv(ToStd(cat_data[i]));
				std::string sid_str = ToStd(sid_data[i]);
				if (!sid_str.empty()) {
					std::lock_guard<std::mutex> lock(SessionMapMutex());
					SessionMap()[sid_str] = std::move(ctx);
					ok = true;
				}
			}
		} catch (...) {
			ok = false;
		}
		out_data[i] = ok;
	}
}

//! Test-only debug helper: drives the Quack session-init hook handler
//! against THIS connection's ClientContext, so the SQL test can then
//! assert `current_setting('boilstream.tenant_id')` reflects the bound
//! tenant. The real production firing site is QuackServer::CreateNew-
//! Connection inside the listen thread — unreachable from sqllogictest.
//! This shim lets the test exercise the exact same handler with the
//! same inputs.
//!
//! Returns the tenant_id stamped on the context (empty string if no
//! stamping happened — unbound sid, empty tenant, fork symbol absent).
void BoilstreamQuackDebugInvokeSessionInitFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	D_ASSERT(args.ColumnCount() == 1);
	args.data[0].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	auto sid_data = FlatVector::GetData<string_t>(args.data[0]);
	auto &sid_validity = FlatVector::Validity(args.data[0]);
	auto &out_validity = FlatVector::Validity(result);

	auto &context = state.GetContext();
	for (idx_t i = 0; i < args.size(); i++) {
		if (!sid_validity.RowIsValid(i)) {
			out_validity.SetInvalid(i);
			continue;
		}
		std::string sid = ToStd(sid_data[i]);
		// Drive the production handler directly. The handler internally
		// dlsym's `duckdb_set_tenant_id_on_context` — present in the
		// boilstream fork, absent in vanilla DuckDB (in which case the
		// stamping is a silent no-op and the returned tenant_id stays
		// empty for that environment).
		boilstream_quack_session_init(sid.c_str(), &context);
		// Read back what's currently stamped on the context.
		std::string stamped;
		Value setting_val;
		if (context.TryGetCurrentSetting("boilstream.tenant_id", setting_val) && !setting_val.IsNull()) {
			stamped = setting_val.ToString();
		}
		result.SetValue(i, Value(stamped));
	}
}

//! Test-only debug helper: returns the size of the session map as INTEGER.
//! Marked "test-only" by comment — DuckDB scalar functions do not expose a
//! hidden flag in this API surface. The name carries the convention.
void BoilstreamQuackDebugSessionCountFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	// 0-arg scalar.
	D_ASSERT(args.ColumnCount() == 0);
	int32_t n = 0;
	try {
		std::lock_guard<std::mutex> lock(SessionMapMutex());
		n = static_cast<int32_t>(SessionMap().size());
	} catch (...) {
		n = -1; // sentinel; should be unreachable
	}
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
	auto out = ConstantVector::GetData<int32_t>(result);
	out[0] = n;
}

} // namespace

std::pair<SessionCtx, bool> GetQuackSessionCtx(const std::string &session_id) {
	std::lock_guard<std::mutex> lock(SessionMapMutex());
	auto &m = SessionMap();
	auto it = m.find(session_id);
	if (it == m.end()) {
		return {SessionCtx {}, false};
	}
	return {it->second, true};
}

void RegisterQuackBridge(ExtensionLoader &loader) {
	// boilstream_quack_authn(VARCHAR, VARCHAR, VARCHAR) -> BOOLEAN
	{
		ScalarFunction fn("boilstream_quack_authn", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
		                  LogicalType::BOOLEAN, BoilstreamQuackAuthnFunction);
		loader.RegisterFunction(fn);
	}

	// boilstream_quack_authz(VARCHAR, VARCHAR) -> BOOLEAN
	{
		ScalarFunction fn("boilstream_quack_authz", {LogicalType::VARCHAR, LogicalType::VARCHAR}, LogicalType::BOOLEAN,
		                  BoilstreamQuackAuthzFunction);
		loader.RegisterFunction(fn);
	}

	// boilstream_quack_bind_session(VARCHAR sid, VARCHAR user, VARCHAR tenant,
	//                               VARCHAR catalog_csv) -> BOOLEAN
	{
		ScalarFunction fn("boilstream_quack_bind_session",
		                  {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
		                  LogicalType::BOOLEAN, BoilstreamQuackBindSessionFunction);
		loader.RegisterFunction(fn);
	}

	// boilstream_quack_debug_session_count() -> INTEGER   [test-only]
	{
		ScalarFunction fn("boilstream_quack_debug_session_count", {}, LogicalType::INTEGER,
		                  BoilstreamQuackDebugSessionCountFunction);
		loader.RegisterFunction(fn);
	}

	// boilstream_quack_debug_invoke_session_init(VARCHAR sid) -> VARCHAR  [test-only]
	{
		ScalarFunction fn("boilstream_quack_debug_invoke_session_init", {LogicalType::VARCHAR}, LogicalType::VARCHAR,
		                  BoilstreamQuackDebugInvokeSessionInitFunction);
		loader.RegisterFunction(fn);
	}

	// Register the Quack session-init hook with patched Quack (if present
	// in the host process). On vanilla DuckDB / stock Quack the symbol is
	// not present and dlsym returns null — the bridge still loads fine as
	// a community extension and the hook is simply never wired up. On the
	// boilstream fork with our `server-session-init-hook.patch`, the
	// setter routes new-Quack-Connection notifications through our
	// handler, which forwards the tenant_id to the fork via the matching
	// `duckdb_set_tenant_id_on_context` symbol (also looked up via dlsym
	// inside the handler). This is the only path through which the
	// per-Quack-session tenant context reaches the per-session Connection
	// in time for its first query — and therefore the only path through
	// which `TenantIsolation::FilterSchemas` correctly scopes discovery
	// output to the calling tenant.
	{
		auto quack_setter = reinterpret_cast<quack_set_session_init_hook_fn_t>(
		    boilstream_lookup_runtime_symbol("quack_set_session_init_hook"));
		if (quack_setter) {
			quack_setter(&boilstream_quack_session_init);
		}
	}

	// Wire the pre-execute SQL rewriter hook (Phase 2 write routing). Same
	// dlsym pattern as the session-init hook — symbol is absent on vanilla
	// Quack builds, in which case writes simply fall through to the keyword
	// authz gate (which rejects them in Phase 1) or to direct execution.
	{
		auto quack_setter = reinterpret_cast<quack_set_pre_execute_hook_fn_t>(
		    boilstream_lookup_runtime_symbol("quack_set_pre_execute_hook"));
		if (quack_setter) {
			quack_setter(&boilstream_quack_pre_execute);
		}
	}

	// Wire the post-success hook used for DuckLake catalog durability.
	// Absent on vanilla Quack builds; present in the boilstream-patched
	// Quack server.
	{
		auto quack_setter = reinterpret_cast<quack_set_post_execute_hook_fn_t>(
		    boilstream_lookup_runtime_symbol("quack_set_post_execute_hook"));
		if (quack_setter) {
			quack_setter(&boilstream_quack_post_execute);
		}
	}
}

// Thread-local backing storage for the active Quack authz `session_id`.
// File scope (not anonymous namespace) so the `extern "C"` resolver below,
// which sits outside `namespace duckdb`, can reach it via the
// `QuackAuthzCurrentSid()` accessor declared at the top of this TU.
std::string &QuackAuthzCurrentSid() {
	static thread_local std::string sid;
	return sid;
}

} // namespace duckdb

//===----------------------------------------------------------------------===//
// Tenant-resolver hook: tenant-AGNOSTIC `extern "C"` symbol the multi-tenant
// fork's `ClientContext::BeginQueryInternal` calls via a weak link. The
// bridge stays community-extension-compatible — vanilla DuckDB never calls
// this symbol, so the bridge can be loaded as a stock community extension
// against unmodified DuckDB. Only the boilstream fork's `BeginQueryInternal`
// calls it; on call, we look up the thread-local sid stashed by
// `BoilstreamQuackAuthzFunction` and resolve it to a tenant_id via the
// existing SessionMap. The fork then SETs that tenant_id on the per-Quack
// Connection's TenantContext for the duration of the query, so all
// `TenantIsolation::Filter*` paths see the correct tenant and information
// schema discovery returns only the user's catalogs.
//
// Contract:
//   out_buf, cap: caller-owned NUL-terminated output buffer + capacity.
//   Returns true on success (out_buf populated with tenant_id, NUL-term'd),
//   false otherwise (out_buf may have been touched — caller must treat
//   false as "no override, fall through to context.tenant").
// Quack session-init handler (declared at file top). Quack invokes this
// inside `QuackServer::CreateNewConnection`, after the per-session
// Connection's ClientContext is fully constructed but before any user
// query runs on it. We look up the tenant_id associated with the session
// (populated by the authn callback / `boilstream_quack_bind_session`) and
// hand it to the multi-tenant fork's setter, which stamps it onto the
// ClientContext's TenantContext. Subsequent queries on this Connection
// observe tenant isolation in `TenantIsolation::FilterSchemas` etc.
//
// Failure modes (silent, fail-closed):
//   * No SessionMap entry for the sid → no tenant set, Connection runs
//     in admin mode. In practice this shouldn't happen because authn
//     fired first and bound the session.
//   * Fork-setter weak symbol absent (vanilla DuckDB) → no tenant set;
//     bridge is community-compatible and gracefully degrades.
//   * SetTenantId throws (e.g. invalid chars) → caught by fork's setter,
//     returns false; we ignore and proceed without tenant.
// Quack-provided pre-execute SQL rewriter hook handler. Patched Quack calls
// this between authz and SendQuery, giving us a chance to substitute the
// SQL string. We:
//   1. Look up the SessionCtx by session_id (populated at authn time).
//   2. Build a comma-joined catalog list.
//   3. Hand off to the host-registered Rust rewriter (atomic slot).
//
// If no rewriter is registered (vanilla DuckDB load), or the session has
// no bound ctx, we return 0 — the server then executes sql_in verbatim,
// preserving Phase 1 semantics. Catches any exception and returns 0.
extern "C" int boilstream_quack_pre_execute(const char *session_id_cstr, const char *sql_in, char *sql_out_buf,
                                            size_t sql_out_size) {
	try {
		if (session_id_cstr == nullptr || sql_in == nullptr || sql_out_buf == nullptr || sql_out_size == 0) {
			return 0;
		}
		auto rewriter = QuackSqlRewriterSlot().load(std::memory_order_acquire);
		if (rewriter == nullptr) {
			return 0;
		}
		std::string sid(session_id_cstr);
		auto found = duckdb::GetQuackSessionCtx(sid);
		if (!found.second) {
			return 0;
		}
		// Build comma-joined catalog CSV. The Rust rewriter uses this to
		// gate which catalogs the rewriter is willing to route through the
		// Airport loopback (only DuckLake-registered catalogs).
		std::string catalogs_csv;
		for (size_t i = 0; i < found.first.catalogs.size(); ++i) {
			if (i > 0) {
				catalogs_csv.push_back(',');
			}
			catalogs_csv.append(found.first.catalogs[i]);
		}
		return rewriter(session_id_cstr, found.first.tenant_id.c_str(), catalogs_csv.c_str(), sql_in, sql_out_buf,
		                sql_out_size);
	} catch (...) {
		// Never throw across the Quack hook boundary.
		return 0;
	}
}

extern "C" int boilstream_quack_post_execute(const char *session_id_cstr, const char *sql_original,
                                             const char *sql_executed, char *error_out_buf, size_t error_out_size) {
	try {
		if (session_id_cstr == nullptr || sql_original == nullptr || sql_executed == nullptr || error_out_buf == nullptr ||
		    error_out_size == 0) {
			return 0;
		}
		auto hook = QuackPostExecuteSlot().load(std::memory_order_acquire);
		if (hook == nullptr) {
			return 0;
		}
		std::string sid(session_id_cstr);
		auto found = duckdb::GetQuackSessionCtx(sid);
		if (!found.second) {
			return 0;
		}
		std::string catalogs_csv;
		for (size_t i = 0; i < found.first.catalogs.size(); ++i) {
			if (i > 0) {
				catalogs_csv.push_back(',');
			}
			catalogs_csv.append(found.first.catalogs[i]);
		}
		return hook(session_id_cstr, found.first.user_id.c_str(), found.first.tenant_id.c_str(), catalogs_csv.c_str(),
		            sql_original, sql_executed, error_out_buf, error_out_size);
	} catch (...) {
		if (error_out_buf != nullptr && error_out_size > 0) {
			const char *msg = "Quack post-execute hook failed";
			std::strncpy(error_out_buf, msg, error_out_size - 1);
			error_out_buf[error_out_size - 1] = '\0';
		}
		return -1;
	}
}

extern "C" void boilstream_quack_session_init(const char *session_id_cstr, void *client_context_ptr) {
	try {
		if (session_id_cstr == nullptr || client_context_ptr == nullptr) {
			return;
		}
		std::string sid(session_id_cstr);
		auto found = duckdb::GetQuackSessionCtx(sid);
		if (!found.second) {
			return;
		}
		const std::string &tid = found.first.tenant_id;
		if (tid.empty()) {
			return;
		}
		// Forward to the multi-tenant fork. The fork's setter casts
		// `client_context_ptr` back to `ClientContext*` and calls
		// `tenant.SetTenantId(...)`. On vanilla DuckDB the symbol is
		// absent (dlsym returns null) and we skip silently — Quack will
		// still serve the session, just without tenant isolation.
		// Cache the dlsym lookup in a function-static for amortised cost:
		// the symbol is process-stable, so one lookup per process is fine.
		static duckdb_set_tenant_id_on_context_fn_t fork_setter =
		    reinterpret_cast<duckdb_set_tenant_id_on_context_fn_t>(
		        boilstream_lookup_runtime_symbol("duckdb_set_tenant_id_on_context"));
		if (fork_setter) {
			fork_setter(client_context_ptr, tid.c_str());
		}
	} catch (...) {
		// Never throw across the Quack hook boundary.
	}
}
