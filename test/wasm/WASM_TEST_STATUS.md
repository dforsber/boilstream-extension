# Encrypted client candidate qualification — 2026-11-08

The candidate uses the exact DuckDB **v2.0.0** baseline in
[baseline.json](baseline.json), including both WASM EH and pthread builds.
It is not yet release-ready. The public and private test lanes have different
responsibilities; a public green check alone does not qualify authentication.

## Verified locally

- The actual private server accepts the loaded native, EH and threaded clients
  over plaintext loopback. Browser tests strip all response security headers.
- Missing/wrong installation pins fail; one-use bootstrap login succeeds with the
  trusted key; consumed bootstrap credentials cannot be reused.
- Browser secret create/list/delete uses the real compatible Quack secret type.
  An unrelated tenant's fixture secret is excluded. Multiple connections coexist
  without sharing channel ownership.
- A modified encrypted mutation reply is rejected without retry. That channel
  becomes unusable; a healthy sibling sees the single committed mutation and can
  reconcile its unknown outcome. Actual database session revocation produces a
  verified401 and retires the sibling's credentials.
- These tests exposed and fixed an explicit secret-listing bug: WASM used a cache
  that omits secrets without a known expiry. Explicit SQL now fetches an
  authenticated server snapshot on both platforms; the generic WASM secret
  callback remains cache-only to avoid recursive HTTP.
- Native and both browsers execute one shared scenario for email registration, cached enrollment and
  account replacement. Failed signup clears the prior enrollment; wrong MFA codes
  can be retried, completed enrollment cannot be reused, and ten unique recovery
  codes are returned. Replayed TOTP is refused; a fresh code permits email login.
  Email tenant secrets remain isolated and survive another tenant's revocation.
- Production Rust WASM C ABI checks pass36 EH /37 threaded assertions. Protocol
  core tests pass28 cases per variant. Native Rust strict Clippy passes.

The missing POST response headers in the pinned host are no longer an
application-protocol blocker. Status, cookies and resumption metadata are inside
verified encrypted bodies. No DuckDB host changes or verification bypass are used.

## Gates

`WasmTests.yml` runs public shared SQL, real-worker baseline/artifact negative
controls, compatible Quack loading and rejection of an untrusted peer. It proves
that missing pins cause no network I/O and forged server proof cannot release an
application request or publish identity. It does **not** claim successful login.

The private server's `make test-application-protocol-clients` explicitly includes
all six real-router/registration/native/EH/pthread/resumption cases, including tests normally excluded
from artifact-free unit runs. Missing artifacts fail. The private release target
`test-application-protocol-release` first audits dependencies, then runs standalone
transport tests and the loaded-client gate. It must pass for coordinated release.
The private server implementation and installation private keys stay private;
[real-server.js](real-server.js) and [real-server-native.js](real-server-native.js)
receive only public pins and synthetic credentials. Their SQL adapters share
[authenticated-scenario.js](authenticated-scenario.js); native transport observation
and fault injection remain private.

The runners invoke ordinary CMake/Cargo incremental builds before loading WASM
artifacts. Selected CMake source paths and platform are checked. No source hash
inventory, forced clean or BoilStream build receipt is used. Community extension
make targets remain unchanged.

## Outstanding coverage and release work

All21 native C++ suites pass. The lower count follows removal of three suites
exclusively for the retired signing/encryption protocol; active parser, memory,
credential cleanup and lifecycle regressions remain. Successful resumption now
runs on native, EH and pthread clients: fresh channel, one-use rotation, preserved
original expiry, live revocation and atomic publication checks pass.

Managed catalog credential vending and live remote Quack queries still require
the receiving server owner's backend/full-product qualification. Catalog polling
parser/planner and failure tests do not substitute for those successful paths.
Obsolete production wire and unused JS wrapper cleanup are complete. Dependency
repair, coordinated release-gate enforcement and final combined release approval
remain open. GitHub status must be checked for the exact candidate being released;
local passing tests are not a publication claim.

## Threaded runtime and Quack

Open with `maximumThreads: 1`, load BoilStream, then execute `SET threads = 2`.
Loading a dynamic extension after starting the worker pool can stall in the
pinned runtime. The tests qualify this startup order and two-thread operation.
The Rust FFI tests separately execute on a pthread.

The pinned public threaded Quack artifact imports non-shared memory. Tests use
an actual source-built shared-memory Quack module. A passing paired build does
not fix public repository distribution of Quack. See
[QUACK_COMPATIBILITY.md](QUACK_COMPATIBILITY.md) for deployment requirements.
