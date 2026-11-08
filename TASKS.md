# Application protocol client integration

## APPSEC2-DIAGNOSTICS — Encrypted failure coverage and incremental Quack builds

Owner: codex-root, 2026-11-08. Continues the full encrypted client/server release
objective; no subagents, merge, publication or release signoff.

- AuthDiagnostics debug/release now exercise the actual encrypted handshake
  boundary with adversarial HTTP status/body/headers and exact request counts.
  Real SQL login/register errors and JSON error output must omit private markers;
  trusted structured status and concurrent exception/credential erasure checks
  remain. Both CTest modes PASS (../logs/diagnostic-migration-tests.log).
- Removed the unused legacy diagnostics Python server. Malformed authenticated
  application bodies still need parser/real-server coverage; handshake refusal
  is explicitly not counted as proof of those later stages.
- Quack build refresh now uses persistent OpenSSL Make and CMake/Ninja trees.
  Both browser drivers refresh the threaded dependency before loading it; failed
  builds stop the harness. Removed source inventories, receipts and forced cleans.
  Pinned archive/upstream artifact SHA verification, SDK/Git selection, actual
  shared-memory import and exported entrypoint checks remain. The community
  extension build/sign/publish entry points remain unchanged.
- Harness unit tests PASS14/14; threaded browser PASS74 checks with the rebuilt
  dependency (../logs/quack-incremental-browser.log). Incremental installation
  efficiency is verified by a warm Ninja 'no work to do' result. Private
  coordinated router/registration/native/EH/pthread gate PASS5/5 (229.88s),
 0 ignored; all keys and server implementation stayed private.
- GitHub's asset API returned the exact pinned OpenSSL archive in a local download
  check. Added that API as a fallback for release-redirect HTTP504 failures;
  the existing pinned SHA256 is mandatory for either download path.
- GitHub6df7549: Rust audit/client protocol PASS; native20/24 (the four known
  legacy suites); WASM failed fetching OpenSSL with HTTP504; ARM64 distribution
  failed downloading CMake. No claim that all remote CI is green.

Remaining: SessionMemoryOnly and RegistrationHttp migrations; authenticated
malformed-body, loaded registration/MFA, resume/account replacement and managed
catalog/live remote Quack coverage; old wire cleanup, C++ dependency review,
release enforcement/gates, three final reviews and clean coordinated promotion.

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

2026-11-08 loaded-browser and CI harness checkpoint (owner codex-root):
- Actual private-server qualification now PASS on native, WASM EH and pthread.
  Both browser variants use the exact2.0 baseline plus compatible Quack. Their
  proxy uses plaintext loopback, strips all security response headers and checks
  that application traffic is encrypted. Missing/wrong pins, one-use bootstrap,
  secret create/list/delete, other-tenant exclusion, concurrent connection ownership,
  tamper rejection/no retry, unknown mutation outcome reconciliation via a healthy
  sibling, and actual database revocation all pass.
- Fixed a production bug found by these tests: explicit boilstream_secrets() used
  the WASM cache, which omits credentials without known expiry. It now fetches an
  authenticated remote snapshot using the captured connection owner on native and
  WASM. Generic WASM SecretManager callbacks remain cache-only to avoid recursion.
  Native/EH/pthread rebuilds and real-server regressions PASS. Private combined
  make test-application-protocol-clients:4 passed,0 failed,0 ignored (99.13s), log
  ../logs/loaded-client-gate.log under the private candidate parent. No server key
  or server implementation added to the public repository.
- Public browser CI migrated off the obsolete expected POST-header failure.
  Public tests verify missing pins cause no traffic, exactly one forged proof
  reaches the verifier, and no application request or identity is published.
  Real-browser EH73 /pthread74 compatibility checks PASS; native adversarial
  check PASS. Logs browser-public-eh-migration.log, browser-public-threads-migration.log
  and native-untrusted-peer.log. Positive auth remains a mandatory private release
  gate, not an assertion inferred from these public rejection checks.
- Removed obsolete header-protocol browser fixture and its unused Rust peer.
  Prior account replacement/catalog-resumption oracles that never passed on WASM
  remain explicit gaps requiring actual-server coverage; removing obsolete code
  does not close those requirements. Six legacy C++ suites remain to migrate.
- Browser runners now invoke ordinary incremental CMake/Cargo before loading
  artifacts, including the private-driver path. Removed BoilStream source hash
  inventories/receipts and forced cleans. Existing Ninja/Make trees are supported;
  wrong-source and wrong-platform cache controls reject before compilation (log
  wasm-build-selection.log). Community make targets unchanged. Quack's older
  source-build receipt machinery is separate remaining harness debt.
- Harness14 tests PASS after removing the obsolete receipt test; shell/JS syntax
  and Git whitespace checks PASS. Driver cleanup now unwinds browser/server rather
  than process.exit from a whole-run timer; per-operation deadlines remain.
- Incremental reviews (not final release reviews): security—private fixture keys
  stay private, no forged HTTP metadata grants identity, real401 closes sessions;
  test quality—actual encrypted mutation commits once despite rejected reply,
  sibling verifies the effect, negative cases check wire counts; compatibility—
  actual2.0 EH/pthread/native, compatible Quack, normal CMake/Cargo dependency
  tracking and unchanged community entry points. Old gaps are not relabeled passes.
- Still required: six C++ suite migrations, registration/MFA/resumption/account
  replacement and catalog/remote Quack coverage, obsolete production wire cleanup,
  C++ dependency review, release gates, remote CI verification and final3 reviews.
  No main merge/publication/full-GitHub-green claim. Disk remains23GiB internal,
  1.2TiB external with8/50GiB reserve guards. No subagents used.
- Native harness follow-up: both private preflight and public adversarial entrypoint
  update the full selected native CMake tree so host/static objects cannot remain
  stale after a loadable-only build. Private preflight requires the selected CLI
  to belong to that same tree. The new run rebuilt the changed static extension
  object; actual-server native and public adversarial cases both PASS afterwards.
  Logs private loaded-native-host-refresh.log and public native-untrusted-peer-refresh.log.
  Private checkpoint pushed at18fb89cdb, clean; production Rust pins unchanged.

2026-11-08 catalog/application-boundary migration (owner codex-root):
- Replaced the catalog suite's fabricated legacy response signatures with pure
  client parsing/reconciliation and actual production channel rejection. Extracted
  CatalogVersionsURL, ParseCatalogVersions and ReconcileCatalogVersions; production
  applies the returned plan under the connection lock, then expires credentials.
  Existing version comparison/merge semantics preserved, including lower versions.
- Catalog suite PASS1120 assertions/9 cases: malformed types and unsigned bounds,
  embedded-NUL preservation, immutable input maps, retained unrelated catalog IDs,
  exact expiration in both metadata and actual secret cache, sibling ownership,
  atomic single polling admission under16 concurrent callers, exact60s boundary,
  clock rollback, initial sentinel, and forged proof refusal before inner traffic.
- Migrated RequiredResponseSignature to RequiredApplicationProtocol (same C++
  executable, now no Python signed-reply server). PASS28 cases: GET/POST/DELETE and
  OPAQUE start/finish reject forged/empty/oversized/status/exception replies; no
  request retry; inherited auth/cookie headers erased; redirects disabled; no
  credential disclosure; failed owner cannot retire replacement; closed channels
  need explicit fresh authentication; authority mismatch sends no network request.
  Final combined log ../logs/catalog-boundary-final-tests.log PASS2/2 suites.
  The old Python signing helper remains only for the other legacy suites and must
  be removed with their migration. Positive crypto/tamper/time/replay oracles are
  in the Rust/private actual-server gates, not falsely claimed by public negatives.
- Actual private gate rerun after production refactor and native/EH/pthread rebuild:
  PASS4/4,0 ignored in65.27s, private ../logs/catalog-client-regression.log. SPA,
  server production and direct native integration unchanged; no Rust dependency
  or public/private protocol-pin change needed for this C++ refactor.
- GitHub9c44b73 evidence: Rust audit/client protocol/wasm-bindgen PASS; browser EH
  PASS, threaded still running at inspection. Main code quality failed format and
  a namespace using-directive in the protocol wrapper. Applied the required11.0.1
  formatter/CMake formatter, and qualified yyjson calls rather than suppressing
  the tidy finding. Local make format-check PASS. Full5-TU/10-command clang-tidy22
  PASS with matching macOS SDK flags; no warning suppression. Earlier native
  clang-tidy attempts failed to locate Apple SDK headers; those logs are retained.
  check-tidy.py now supplies the selected CMake/xcrun SDK on macOS automatically,
  respecting explicit overrides and leaving Linux/community behavior unchanged.
- Incremental reviews (final release reviews still pending): security—pure parsers
  cannot grant identity, all production input still passes protocol verification;
  correctness—version/expiry behavior retained, malformed input and UINT64_MAX
  tested, no new public server implementation; build/release—current native/WASM
  artifacts exercised, all production TUs checked, no forced clean/source records,
  community build entry points unchanged. Formatting-only edits need no repeated
  tests of unchanged registration behavior.
- Four legacy failures remain: SessionMemoryOnly, RegistrationHttp,
  AuthDiagnostics_debug and AuthDiagnostics_release. Next migrate actual
  registration/MFA/resumption plus error privacy with private-server positives,
  preserving ownership/persistence tripwires. Then obsolete wire cleanup, catalog/
  remote Quack coverage, C++ dependency audit, remaining CI/release gates and the
  final three reviews. No full CI-green, main merge or release claim.
- Final checkpoint verification: automatic macOS SDK selection in check-tidy.py
  passes the complete5-TU/10-command scan without caller SDK flags (log
  catalog-tidy-automatic-sdk.log, controller27919 exited0). Final format-check PASS.
  GitHub run42463401232 for9c44b73 is now SUCCESS: EH, threaded and wasm-bindgen all
  green. That is prior-checkpoint browser evidence, not full release qualification.
  All owned test/lint processes terminal; disk23GiB internal/1.2TiB external.
