# C++ Unit Tests for the Boilstream Extension

Standalone Catch2 executables built with the CMake project in this directory against a DuckDB 2.0
build. Build, run and per-executable coverage are documented in [`../README_TESTS.md`](../README_TESTS.md).

## Authentication diagnostic regression tests

`AuthDiagnostics_debug` and `AuthDiagnostics_release` compile the actual storage
and SQL authentication entrypoints against the selected stock DuckDB 2.0 shared
library and matching HTTPFS artifact. The mode selects whether `BOILSTREAM_DEBUG` diagnostics are enabled. This does not
qualify an entire product Release build.

Run the registered CTest cases with `ctest -R '^AuthDiagnostics_' --output-on-failure`.
The Python runner starts only a loopback synthetic HTTP server and has a 30-second
child deadline. It needs no account, password, external service or persistent
credential file. It asserts request counts as well as native case outcomes.

The cases cover secret markers in logs and errors, structured exception metadata,
exact status preservation, malformed cipher headers, real SQL login/registration
failure stages, malformed cookies, successful response delivery, request reuse
after errors, and simultaneous exception handling. Captured diagnostics are never
printed. A passing case must reach its intended failure stage; merely throwing is
insufficient. Full OPAQUE success, browser/WASM behavior, registration ownership
and mandatory response-signature enforcement remain separate qualification work.

## Registration ownership

`RegistrationOwnership` uses real ClientContexts, client routing settings and concurrent
workers to verify connection ownership, identity changes, cancellation, stale or
foreign operation IDs, field limits and destruction. The legacy adapter used for
causal evidence invokes the old contextless API; it is never production code.

`RegistrationHttp` invokes the actual registration/MFA PRAGMA handlers with real
HTTPFS and Rust helpers against a synthetic loopback server. It verifies separate
cookies for simultaneous connections, cached-account reuse, switching accounts,
failed-code retry, successful MFA consumption and retry after failed signup.
It checks request counts and cookie ownership without printing credentials.
It examines the returned QR SQL without executing optional textplot installation.
Live authentication, browser runtime and full product qualification remain separate.

## Concurrent remote secret lookups

`SecretLookupConcurrency` holds a real signed loopback response while a second
uncached lookup waits on the same session. It verifies ordered requests, both
results, unknown-expiry cache behavior, queued expiry/replacement/cancellation,
and unchanged nonblocking local recursion handling. Run the registered CTest
case; it starts and drains its own synthetic authority without real credentials.

### Client-only migration regressions

`SecretLookupConcurrency` uses the real public storage and independently signed
loopback responses for six scenarios: normal, expired, replaced, generation,
cancelled and cancelled_cached. Two ordinary concurrent file workers must queue
within one session; true same-thread recursion must refuse. Normal HTTP sequence
is exactly0,1 with maximum concurrency1. Invalidated held requests must not
expose credentials, including a newly populated cache during cancellation. The
obsolete local-host cross-thread guard is intentionally absent from this public
client; that interface is owned by the private server integration suite.

`ManagedVendingLifetime` exercises actual direct managed vending and the
`__quack__` named-secret lookup. For each lane an independently signed GET is held
while the session is unchanged, changes generation, is replaced, is cancelled, expires, or logs out. Only the unchanged owner may return/cache that response. A separate live
connection then receives a distinct signed token for the same scope, proving
owner isolation and a working transport after every refusal. Exact HTTP counts
and independent sequence0,0 reject a hidden extra request or global cache reuse.
The fixture supplies synthetic session material; actual OPAQUE proof/login is
qualified by the separate production-client/v3-peer and stock-suite tests.

Both tests require the explicit stock-compatible `BOILSTREAM_HTTPFS_EXTENSION_PATH`
selected at CMake configuration; no fork static-provider fallback is used.

The cancelled_cached concurrency mode also checks the same cached credential
through match, named, recent-list and direct cached-list APIs before and after
interruption: four live positive controls and four cancelled negative controls.
Authenticated cache reads revalidate after materializing their return snapshot;
standalone no-session cache behavior is unchanged.

Managed cache retirement is permanent for an old session object. The existing
`QuackAttachRedTests` includes a deterministic completed-logout then late-store
ordering test, plus reusable ordinary invalidation and fresh-session controls.
`ManagedVendingLifetime` includes actual held HTTP logout in both lanes (12 total
held-response cases). Closing the cache never waits on the remote HTTP mutex.
