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
- Full standalone native build running with standard community make release,
  DuckDB d54cbbe3df17e8e5ce68312f483b4155836112aa and extension-ci-tools
  ae971e03c1840a1c6c2d81b91d1ec851f297f720 in independent source worktrees.
  Controller14324/group14442; log ../logs/native-build.log. Do not restart unless
  process/session observation proves it terminal. Functions session61694.
- Strict Clippy of the whole old opaque-client exposes pre-existing unsafe public
  FFI signatures and missing safety documentation; not suppressed or claimed green.

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
