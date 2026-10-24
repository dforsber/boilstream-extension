# C++ Unit Tests for the Boilstream Extension

Standalone Catch2 executables built with the CMake project in this directory against a DuckDB 2.0
build. Build, run and per-executable coverage are documented in [`../README_TESTS.md`](../README_TESTS.md).

## Authentication diagnostic regression tests

`AuthDiagnostics_debug` and `AuthDiagnostics_release` compile the actual storage
and SQL authentication entrypoints against the selected BoilStream fork shared
library and its statically built HTTPFS provider. Both use optimized C++; the
mode selects whether `BOILSTREAM_DEBUG` diagnostics are enabled. This does not
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

`RegistrationOwnership` uses real ClientContexts, the tenant registry and concurrent
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
