# Application protocol client integration

Owner: root; branch `codex/client-protocol-v2-integration`, based on the tested
client-only protocol candidate62ca20d. Active goal: finish production client
integration, validate native DuckDB and baseline2.0 WASM including pthreads against
the private server candidate, preserve SPA/direct server APIs, run release gates,
three final reviews and prepare coordinated release. Not released or ready yet.

Implemented in this candidate:
- Pure single-flight session lifecycle: pinned handshake before credentials,
  sequence advance only after a verified reply, poison/erase after failed or
  abandoned exchange, no retry or channel reset with retained keys.
- OPAQUE client static library exposes client-only protocol C ABI with fallible
  entropy/time inputs from the OS and bounded input decoding; opaque handles and
  buffers have explicit ownership contracts.
- C++ transport owns each channel, serializes the full request/response exchange,
  disables HTTP retries/redirects and ignores outer response security headers.
  Requests/responses, cookies, errors and resumption metadata use body envelopes.
- `PRAGMA boilstream_server_key(authority, public_key_hex)` provisions trusted pins
  per DuckDB connection. Active channels retain their original pin; new login uses
  configured pins, resumption uses a fresh channel with its prior trusted pin.
- Registration/MFA flow owns one channel across commands; email login owns its own
  channel; OPAQUE sessions own independent channels. GET/POST/DELETE callers route
  through the common transport. Failed session requests invalidate cached authority.

Evidence so far:
- Protocol core:28 native unit tests and5 compile-fail checks pass, including6 new
  lifecycle tests. Strict Clippy passes after boxing pending handshake state.
- Client Rust package:18 unit +10 crypto +3 interop +4 peer +2 registration tests
  pass. New FFI invalid configuration/ownership tests included. Warning-fatal
  Cargo audit of the updated102-package client lockfile and48-package protocol lockfile passes.
- Syntax checking all3 changed C++ translation units against baseline headers passes.
- Full standalone native build PASS with standard community make release,
  DuckDB d54cbbe3df17e8e5ce68312f483b4155836112aa and extension-ci-tools
  ae971e03c1840a1c6c2d81b91d1ec851f297f720 in independent source worktrees.
  Controller14324/group14442 exited0; log ../logs/native-build.log.
- Strict Clippy of the complete opaque-client now PASS. Raw-pointer and allocator
  ownership APIs are explicitly unsafe for Rust callers with Safety contracts;
  C ABI is unchanged. All37 Rust client tests pass after callsite updates.

Remaining:
1. Finish native build, resolve integration defects, test actual protocol C ABI
   against private peer and actual server handlers with autonomous fixtures.
2. Replace legacy signature/header-dependent harness assumptions with new protocol
   coverage; remove obsolete client wire helpers once replacement tests exist.
   C++ test target linkage now includes the protocol wrapper; execution remains pending.
3. Qualify loaded native client and actual baseline2.0 browser/pthread clients:
   login/registration/MFA, tenant isolation, revocation, replay/races, forged/missing
   headers, plaintext loopback, wrong pins, errors/cancellation/unknown outcomes.
4. Complete C ABI safety/strict lint checks, formatting, Rust/C++ dependency audits,
   release CI/build gates; use real coverage and no success-shaped skips.
5. Three final reviews, documentation/version/release compatibility decisions,
   commit/push clean public/private candidate branches. No release/main merge until
   complete evidence supports coordinated promotion.

All builds use local macOS. Artifacts/temp/cache are on Development with guard
floors8GiB internal and50GiB external. No unrelated cleanup or process termination.
- Three CMake Rust target-selection checks PASS (standalone/external/invalid),
  preserving the community build's Rust archive selection.
- WASM core tests PASS:28 cases on each variant, run sequentially with Emscripten6.0.9, pinned Rust1.94.1 and
  nightly-2026-08-06; log ../logs/core-wasm.log, functions session33120 (completed).
  This is core execution under Node, not loaded-browser extension qualification.

Initial free24GiB internal, about1.2TiB external. The worktree parent run-local.sh
contains environment and reserve-controller invocation. Do not use subagents.

2026-11-08 follow-up evidence:
- Loaded native DuckDB2.0 + public extension + compatible httpfs against the actual
  private LandingServer/OPAQUE/UsersStore over plaintext loopback PASS. Autonomous
  fixture tests missing/wrong installation pins, bootstrap login, secret create/list/
  delete, tenant isolation and consumed-bootstrap rejection. Private source/log:
  src/auth/application_protocol_tests.rs and ../logs/loaded-native.log in server candidate.
- That test caught a production bug: a verified optional catalog503 erased the
  authenticated session, then bootstrap formatted its cleared expiry. Fixed with a
  verifier-only typed application error.401/403 and transport/crypto failures clear
  identity; other verified refusals retain sequence state without retrying. Both login
  entry points reject a session invalidated during optional initial fetches.
- Exact production WASM EH Rust archive:34 C ABI assertions PASS, including new
  protocol clock/entropy/randomization, pre-proof credential refusal and poisoning
  after forged handshake/response. No private key or server implementation added.
- Full WASM EH build PASS; incremental rebuild includes the application-error repair.
  Pthread community make running (session14279, ../logs/wasm-threads-build.log).
  EH incremental session81365, ../logs/wasm-eh-incremental.log. Inspect terminal state
  before reusing either. Loaded browser coverage remains unfinished.
- WASM setup now provisions the pinned compiler with --no-self-update: rustup must
  not try to update itself in a separately configured Cargo cache. Native strict
  Clippy/test logs: ../logs/ffi-clippy.log and ../logs/ffi-tests.log.
- Scope review: pointer ownership contracts match actual consuming/free operations;
  verified application failures cannot be constructed by the HTTP transport; actual
  native failure then passing rerun demonstrates the catalog503 regression oracle.
  These are incremental reviews, not the required final three release reviews.

2026-11-08 build/harness checkpoint (continues the same goal):
- Both full WASM variants and EH incremental repair build PASS. Their build
  controllers are terminal; no live WASM build remains. Production C ABI tests:
  34 EH assertions,35 pthread assertions PASS, including actual worker execution.
  Logs ../logs/ffi-wasm-eh.log and ffi-wasm-threads.log. Pinned Rust1.94.1
  wasm32-unknown-unknown check PASS after installing the missing target; existing
  wasm-bindgen dead-state/unused warnings remain visible, not suppressed.
- C++ harness build PASS. Found that selecting exact archive paths alone allowed
  stale native static/shared objects when only a loadable extension was rebuilt.
  Every test executable now depends on the selected native tree's ordinary
  incremental CMake build. Native artifacts are declared byproducts so Ninja
  relinks against updates. No fingerprint records, clean rebuild, alternate
  archive substitution or community release-build changes. Log cpp-refresh-build.log
  shows current static extension sources rebuilt before the test relinks; the next
  focused build reused Cargo in0.13s and compiled only the two changed test sources.
- Full CTest:16/24 suites PASS,8 FAIL (../logs/cpp-tests.log). Two pure registration
  ownership/output suites were missing configured pins; fixtures now provision
  public test keys without network I/O, and a new case confirms a fresh connection
  cannot inherit another connection's pin. Both affected suites now PASS
  (../logs/cpp-registration-tests.log); do not rerun unchanged passing suites.
- Six remaining failures: BoilstreamCatalogVersionTests, SessionMemoryOnly,
  AuthDiagnostics_debug, AuthDiagnostics_release, RegistrationHttp and
  RequiredResponseSignature. These still assume old header/signature transport
  or fixtures; replace their protocol setup/oracles with meaningful body-protocol
  coverage, preserving policy/lifecycle/diagnostic assertions. Do not skip them.
- Private candidate b15a64d36 pushed clean, selecting public production client701e8fc.
  Its16 transport/OPAQUE cases, strict Clippy and26-lockfile audit PASS. Loaded
  actual native test and real-router revocation test PASS as recorded above.
- Disk free23GiB internal,1.2TiB external. All commands in this checkpoint terminal.
  No full browser/release-green claim; remaining work and final reviews unchanged.
