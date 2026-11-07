# Client-only candidate qualification — 2026-11-07

The 0.8.3 candidate uses the DuckDB **2.0.0** baseline in
[baseline.json](baseline.json). It removes server hosting APIs while retaining
remote authentication, secret access and Quack client attachment.

Local native qualification passed 24 CTest executables, including registration
ownership, actual registration/MFA handlers, diagnostic redaction in debug and
release builds, independently signed HTTP responses, credential cleanup,
connection isolation and stale-session publication. The newly enabled tests use
stock DuckDB APIs and the exact matching HTTPFS artifact. These native results
do not qualify successful browser authentication.

The harness has 15 passing tests and rejects changed build inputs, stale receipts
and replaced artifacts. npm audit reports zero vulnerabilities; the production
Cargo lockfile audit passes. Server hosting tests are no longer part of this
client distribution. `client_boundary.test` instead verifies the retained client
API and absence of the removed server SQL functions, in native and browser runs.

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
file. Native managed attachment tests remain native-only. Successful browser
OPAQUE login, encrypted signed responses, credential rotation, authenticated
cross-connection isolation and remote catalogs still require protocol fixtures or
a separately provisioned integration environment. No gap-free browser coverage
is claimed.

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
