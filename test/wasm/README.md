# DuckDB 2.0 WASM regression tests

`npm test` runs real Chromium workers against the built BoilStream WASM extension.
It does not run native DuckDB, use a CDN, or accept missing extensions as success.

## Baseline

`baseline.json` records the exact package, DuckDB source revision, engine version,
Emscripten version, and supported platforms. The npm package version is **not** the
DuckDB engine version: `@duckdb/duckdb-wasm@1.33.1-dev114.0` contains DuckDB **v2.0.0**.
The test asserts `SELECT version()` and `PRAGMA platform` before loading BoilStream.
Use the single-threaded `base` bundle for `wasm_eh`, and the `threads` bundle for
`wasm_threads`. The old MVP bundle is not part of this DuckDB 2.0 baseline.

## Run

From the repository root:

```sh
npm ci --prefix test/wasm
(cd test/wasm && npx playwright install chromium)
rustup toolchain install 1.94.1 --profile minimal --target wasm32-unknown-emscripten
rustup toolchain install nightly-2026-08-06 --profile minimal --component rust-src
./build-wasm-fixed.sh wasm_eh
scripts/build-quack-wasm.sh
./build-wasm-fixed.sh wasm_threads
npm test --prefix test/wasm
npm run test:compatibility --prefix test/wasm
```

The build requires the Emscripten and Rust versions in `baseline.json`, plus
the `wasm32-unknown-emscripten` target. It rejects source/toolchain mismatches and
propagates build failures. The helper and browser runners update the selected CMake tree incrementally before loading its output. CMake checks C++ dependencies and Cargo checks Rust inputs, including the protocol client. Existing Ninja and Makefile trees are supported; source paths and WASM platform must match. No forced clean or source-hash receipt is required. Direct community make targets remain available and unchanged in purpose. It never restores old artifacts or changes metadata to
make an incompatible binary appear compatible.

For one platform, use `WASM_VARIANTS=wasm_eh npm test --prefix test/wasm` (or
`wasm_threads`). `BOILSTREAM_WASM_BUILD_DIR` can point to another build root with
`<variant>/extension/boilstream/boilstream.duckdb_extension.wasm` beneath it.
CI runs both platforms independently in `WasmTests.yml`.
The threaded variant rebuilds Rust's standard library with atomics using the
pinned `rustThreadsToolchain`; rustup's prebuilt standard library cannot be
linked safely into a shared-memory module.

For the threaded bundle, open with `maximumThreads: 1`, load the extension, then
`SET threads = 2`. Loading after starting the query worker pool can stall in the
pinned runtime; see [WASM_TEST_STATUS.md](WASM_TEST_STATUS.md). The tests exercise
two-thread operation after the extension has loaded.

For interactive inspection, run `npm run serve --prefix test/wasm` and open the
printed loopback URL. The page runs the core suite; Node adds harness, compatibility and authenticated-transport checks. No authentication token
or real account is needed. The server exposes only declared assets and does not
proxy authentication traffic.

## Coverage and boundaries

- Actual DuckDB 2.0 engine and matching WASM platform; extension load and registration.
- Shared `test/sql/boilstream_pragmas.test` and `boilstream_grammar.test`, including
  exact query results, expected error messages, grammar/PRAGMA equivalence,
  new-connection grammar activation, argument validation, and no-session behavior.
- Shared `client_boundary.test`: client APIs remain registered and server-only
  authentication functions are absent.
- Unowned authentication result IDs, empty unauthenticated secret stores on two
  connections, recovery after rejected operations, and malformed extension rejection.
- Real-worker negative tests prove wrong engine baselines and missing artifacts fail.
- Optional Quack absence is tested with a local 404 fixture. A separate mandatory run requires successful loading and client secret registration: EH uses the pinned public artifact; threads uses a fresh source build with verified shared-memory imports. No incompatibility is accepted as success. See [QUACK_COMPATIBILITY.md](QUACK_COMPATIBILITY.md) for artifact provenance and deployment requirements.
- Test-harness regressions ensure failures cannot become warnings or false passes.
- Both single-threaded and threaded workers, with deadlines and worker cleanup.
- Server path traversal rejection, byte ranges, and cross-origin isolation headers.

CI also executes 34 base / 35 threaded Rust WASM FFI assertions using the same archive linked into
each extension, including RFC 4231 HMAC and malformed OPAQUE response checks.
See [`../../opaque-client/test-wasm/README.md`](../../opaque-client/test-wasm/README.md).

Browser execution is hermetic: unrecognized external requests fail. Preparation
verifies the pinned EH Quack download and the source-built threaded Quack's shared
memory compatibility. The public lane rejects missing pins and a forged server
proof before any application credentials can be sent. It does not contain server
crypto or imply successful authentication coverage.

## Actual-server qualification

The private server coordinator starts the real router, database, OPAQUE handlers
and autonomous fixtures, then invokes:

```sh
node test/wasm/real-server.js wasm_eh
node test/wasm/real-server.js wasm_threads
```

These commands are drivers, not standalone fixture servers. Activate the pinned
Emscripten SDK first; each driver incrementally updates the selected client build.
The first stdin line must be JSON containing `authority` (plaintext loopback
origin), `pin`, `wrongPin` (64 hex characters), `password` and `siblingPassword`
(synthetic one-use bootstraps for the same fixture identity). No installation
private key is sent to this public driver. When stdout emits
`{"control":"revoke"}`, the private coordinator revokes that user's actual database
sessions and replies on stdin with `{"revoked":true}`. The final stdout JSON
contains `result`; all compilation and diagnostic output goes to stderr.

The browser proxy strips response security headers and verifies application
traffic is encrypted. Tests exercise authentication, secret CRUD, tenant
exclusion, concurrent connections, tamper rejection without retry, unknown
mutation outcome reconciliation and live revocation. The private Make target
`test-application-protocol-clients` requires native and both browser variants;
`test-application-protocol-release` adds dependency audit and standalone transport
checks. Missing inputs fail rather than silently skipping coverage.

The public native adversarial test is
`node test/wasm/check-native-untrusted-peer.js`, requiring a current native build
and matching installed HTTPFS. Successful native authentication is tested by the
private coordinator, against the actual server.

See [WASM_TEST_STATUS.md](WASM_TEST_STATUS.md) for current evidence and remaining
coverage gaps. Public CI alone does not qualify a coordinated client/server release.
