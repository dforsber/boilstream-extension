# Client-only candidate qualification — 2026-11-07

The 0.8.3 candidate uses the DuckDB **2.0.0** baseline in
[baseline.json](baseline.json). It removes server hosting APIs while retaining
remote authentication, secret access and Quack client attachment.

Local native qualification passed 24 CTest executables, including registration
ownership, actual registration/MFA handlers, diagnostic redaction in debug and
release builds, independently signed HTTP responses, credential cleanup,
connection isolation and stale-session publication. The newly enabled tests use
stock DuckDB APIs and the exact matching HTTPFS artifact. These native results
do not qualify successful browser authentication. All five native SQL files also
pass with zero skips; CI now requires every terminal test event to be successful with zero skips.
The pinned upstream `--fail-require-skip` flag misses skips printed on stderr;
`scripts/test-native-sql.py` checks structured events from both streams instead.

The harness has 15 passing tests and rejects changed build inputs, stale receipts
and replaced artifacts. npm audit reports zero vulnerabilities; the production
Cargo lockfile audit passes. Server hosting tests are no longer part of this
client distribution. `client_boundary.test` instead verifies the retained client
API and absence of the removed server SQL functions, in native and browser runs.

Local results after this cleanup: 24 CTest executables, 35 Rust tests, 15 harness
tests, 72 EH / 73 threaded compatibility checks (including the explicitly labeled
failure probe), and 26 / 27 Rust WASM FFI assertions passed. The strict native
SQL gate also fails as intended when required dependency artifacts are withheld.
The native OPAQUE fixture positive control passes. Strict authenticated browser
qualification fails on both variants as described below.

An additional `cargo clippy --example browser_peer -- -D warnings` check fails on
pre-existing raw-pointer API and missing safety documentation diagnostics in the
unchanged `opaque-client/src` code. Clippy is not included among the passing gates;
`cargo audit --deny warnings` and the Rust tests do pass.

## Required browser qualification

`WasmTests.yml` builds and executes both variants for every candidate push.
Use the workflow result for the exact candidate commit as remote qualification;
results from the earlier 0.8.x hosting builds do not qualify this candidate.

| Gate | Required behavior |
|---|---|
| Engine / ABI | Query actual v2.0.0 and matching platform before loading |
| Both variants | Build fresh BoilStream objects and verify source/artifact receipts |
| Shared SQL | Run every case in `boilstream_pragmas.test`, `boilstream_grammar.test`, `client_boundary.test` |
| Client isolation | Reject unowned result IDs; preserve empty unauthenticated stores on two connections |
| Optional dependency | Local 404 fixture for Quack; BoilStream remains usable |
| Mandatory Quack | Load compatible Quack and verify secret registration and creation |
| Rust WASM FFI | Run the production archive through 26 base / 27 threaded assertions |
| Negative controls | Wrong engine, missing/corrupt artifact, wrong SQL result and unsupported directives must fail |

The SQL inventory check requires an explicit browser coverage decision for every
file. Native managed attachment tests remain native-only.

## Authenticated browser qualification is BLOCKED

Local execution of the new real OPAQUE fixture completes both handshake messages
in the browser, then login fails with `IO Error: Token exchange failed`. The same
fixture succeeds through the native public SQL client, including signed AES-GCM
responses and three account replacements/catalog fetches.

The pinned host's [`HTTPWasmClient::Post`](https://github.com/duckdb/duckdb-wasm/blob/deb938860faf52dec5e8b5dbcc7371858c15e9e4/lib/src/http_wasm.cc#L541)
copies body and status but never response headers into `HTTPResponse`. The
required response signature and timestamp are therefore unavailable to the
extension. DELETE has the same header loss. GET already returns headers.
Disabling verification would accept unauthenticated responses and is not a fix.

`npm test` now runs a mandatory **failure regression**, completing real OPAQUE
and verifying that the rejected reply publishes no usable session. It explicitly
prints the blocker. `npm run test:authenticated` is the strict qualification and
must fail on this baseline. Its later success/isolation/tampering cases remain
unqualified. Both commands use the same fresh extension artifacts and real
browser workers; neither injects session state nor replaces SQL query results.

Before claiming working authenticated WASM or publishing a release qualified for
it, the host must preserve POST/DELETE response headers (and error bodies), a
corrected DuckDB 2.0 baseline must be pinned, and the strict suite must pass and
become mandatory in CI. No DuckDB library or community build entrypoint was
changed here. Email/password/MFA, refresh resumption, managed catalog credential
vending and live remote Quack queries remain separate browser coverage gaps.

## Threaded runtime and Quack

Open with `maximumThreads: 1`, load BoilStream, then execute `SET threads = 2`.
Loading a dynamic extension after starting the worker pool can stall in the
pinned runtime. The suite qualifies the documented startup order. The dedicated
Rust FFI test executes on a pthread; ordinary SQL checks run after two query
threads are enabled.

The pinned public threaded Quack artifact imports non-shared memory and cannot
load in this runtime. Strict compatibility uses the source-built shared-memory
Quack module, with verified inputs and bytes. The public artifact is not patched
or relabeled, and its failure is not accepted as strict compatibility success.
A passing paired build does not fix public repository distribution of Quack.
See [QUACK_COMPATIBILITY.md](QUACK_COMPATIBILITY.md) for deployment requirements.

Commands: [README.md](README.md). Remaining security boundaries:
[SECURITY_AUDIT.txt](../../SECURITY_AUDIT.txt).
