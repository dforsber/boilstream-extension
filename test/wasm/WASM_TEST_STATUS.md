# Follow-up qualification — 2026-11-07

The pinned upstream OPAQUE upgrade removes the production audit failure. The
source-built shared-memory Quack module passes all 70 strict threaded checks.
The harness now has 15 tests and rejects stale receipts or replaced artifacts.
All 35 native Rust tests pass, including four cross-version OPAQUE 3 peer tests.
The standalone wasm-bindgen target also compiles. See
[QUACK_COMPATIBILITY.md](QUACK_COMPATIBILITY.md) for the fresh-build procedure and
the unchanged public-artifact deployment boundary. GitHub runs remain authoritative for remote platform qualification.

The following records the original 0.8.1 qualification, before these fixes.

# DuckDB 2.0 WASM qualification

Last executed: **2026-11-06**, macOS ARM64, Node 24.18.0, Playwright 1.65.0 Chromium.

The exact engine, npm package, source revisions, Emscripten and Rust toolchains
are recorded in [baseline.json](baseline.json). Both workers queried **v2.0.0**.
This supersedes the old DuckDB 1.4.1/CDN smoke-test status.

| Validation | Result |
|---|---|
| `./build-wasm-fixed.sh wasm_eh` | Passed, Emscripten 6.0.9 |
| `./build-wasm-fixed.sh wasm_threads` | Passed, including Rust std rebuilt with atomics |
| `npm test --prefix test/wasm`: harness | 12 passed |
| Chromium `wasm_eh` | 68 checks passed |
| Chromium `wasm_threads` | 70 checks passed, two query threads enabled after loading |
| Core Quack EH | 68 checks passed, including load, secret type ownership and client secret creation |
| Core Quack threads | **Unsupported**: pinned artifact imports non-shared memory; 67 recovery/regression checks pass |
| `npm run test:compatibility` | **Fails** for threaded Quack; EH passes. This is a release gate, not an allowed failure |
| Rust WASM C FFI, archive from each variant | 26 base / 27 threaded assertions; threaded suite executes on a pthread |
| `cargo test --locked --manifest-path opaque-client/Cargo.toml` | 31 tests passed, including complete C-ABI OPAQUE exchanges |
| `npm audit --prefix test/wasm` | 0 vulnerabilities |
| `cargo audit --file opaque-client/Cargo.lock` | **Fails:** RUSTSEC-2026-0387; see security audit |

The browser runs use a clean lockfile installation with no runtime patches.
Both extension artifacts are compiled from the pinned DuckDB source. There is
no metadata relabeling, stale artifact fallback, or missing-artifact skip.
GitHub Actions now builds/tests/uploads both variants; the workflow itself has
not yet been executed on GitHub during this local review.

## Required threaded startup order

Instantiate the threaded bundle, open with `maximumThreads: 1`, load BoilStream,
then execute `SET threads = 2`. All threaded SQL regressions run after enabling
two query threads, including one million per-row authorization denials from a materialized table
(the range generator is single-threaded). The table offers multiple row groups
to the worker pool; individual browser operator threads are not instrumented.

Opening with two threads **before** `LOAD` repeatedly stalled at dynamic-library
loading and hit the 90-second deadline. A diagnostic build passed once, which
was not accepted as qualification. The qualified startup order avoids that
observed synchronization problem. Loading into an already active worker pool
remains an open runtime compatibility issue; this suite does not claim it works.

## Coverage decisions

| Area | Executed coverage / remaining boundary |
|---|---|
| Engine / ABI | Actual version and platform, extension load and registration, corrupted artifact rejection |
| Harness guards | Wrong engine baseline, missing artifact, wrong query/error results, unsupported directives, cleanup |
| Shared SQL | Every case in `boilstream_pragmas.test`, `boilstream_grammar.test`, `quack_bridge.test` |
| Platform differences | Explicit `# wasm-error:` assertions for native-only managed attachment; no skipped statements |
| Unauthenticated isolation | Two connections expose no BoilStream secrets or guessed authentication results; queries recover after rejection |
| Quack bridge | No host verifier means no authentication, authorization or sessions; threaded scan also denies every row |
| Optional dependency | Local repository fixture returns 404 for Quack; BoilStream remains usable |
| Rust WASM FFI | Production C header, OPAQUE request sizes/randomness, invalid pointers/messages, no key output on failure, RFC 4231 HMAC and canonical SHA256 vector |
| Test server | Loopback binding, exact asset routes, traversal rejection, range handling, isolation headers, no credential proxy |
| Quack integration SQL | Both files pass natively with core Quack. Browser suite explicitly excludes native attachment SQL; EH tests Quack loading/secret creation separately, threads compatibility fails |
| Full authentication | Successful server-backed OPAQUE login, encrypted response/signature verification, refresh/rotation, authenticated connection isolation and remote catalogs still require a protocol/integration fixture |
| Native C++ suite | 19 executables and all five SQL files pass against stock DuckDB 2.0 on macOS ARM64 and Linux ARM64, with zero SQL skips. These do not substitute for browser authentication qualification |

The inventory check fails when a new SQL test file appears without a browser
coverage decision. These checks close the identified smoke-test gaps, but do
not establish gap-free authentication coverage or absence of security flaws.

See [README.md](README.md) for commands and
[../../SECURITY_AUDIT.txt](../../SECURITY_AUDIT.txt) for open production findings.

## Core Quack repository and artifact evidence

`INSTALL quack` uses the core repository. An earlier community-repository 404
was a repository-selection error, not absence of the native artifact.
Native v2.0.0 artifacts report Quack revision `f96420ed46`. Browser URLs and
SHA256 digests are pinned in `baseline.json`. Both official WASM files exist.
The threaded artifact fails with:

```
LinkError: WebAssembly.Instance(): Import #0 "env" "memory": mismatch in shared state of memory, declared = 0, imported = 1
```

Regression acceptance requires the exact artifact hash, this worker diagnostic,
the expected SQL loader error, unloaded Quack metadata, and successful subsequent
BoilStream/SQL checks. The strict command never accepts this exception. We have
not patched the artifact, changed its metadata, or changed DuckDB libraries.
