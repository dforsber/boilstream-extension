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
	static std::atomic<boilstream_quack_jwt_verifier_fn> slot{nullptr};
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
				                   << user_id_buf << "' tenant='" << tenant_id_buf << "' catalogs='"
				                   << catalogs_buf << "'");
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
			    bool allow = IsReadOnlyKeyword(kw);

			    // Stamp the per-thread sid so the host's tenant-resolver hook
			    // (a weak extern "C" symbol, defined below in this TU) can
			    // map sid → tenant_id when the Quack-spawned Connection's
			    // BeginQueryInternal fires on the same thread microseconds
			    // later. Even when authz `allow==false` we set this — the
			    // upcoming SendQuery is skipped on rejection anyway, and a
			    // stale value here is harmless.
			    QuackAuthzCurrentSid().assign(sid.GetData(), sid.GetSize());

			    BOILSTREAM_LOG("quack-bridge authz kw='" << kw << "' allow=" << (allow ? 1 : 0)
			                                             << " sid='" << QuackAuthzCurrentSid()
			                                             << "' query=" << q.substr(0, 200));
			    return allow;
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
		return {SessionCtx{}, false};
	}
	return {it->second, true};
}

void RegisterQuackBridge(ExtensionLoader &loader) {
	// boilstream_quack_authn(VARCHAR, VARCHAR, VARCHAR) -> BOOLEAN
	{
		ScalarFunction fn("boilstream_quack_authn",
		                  {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR}, LogicalType::BOOLEAN,
		                  BoilstreamQuackAuthnFunction);
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
		ScalarFunction fn(
		    "boilstream_quack_bind_session",
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
