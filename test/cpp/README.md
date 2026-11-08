# C++ Unit Tests for the Boilstream Extension

Standalone Catch2 executables built with the CMake project in this directory against a DuckDB 2.0
build. Build, run and per-executable coverage are documented in [`../README_TESTS.md`](../README_TESTS.md).

## Authentication diagnostic regression tests

`AuthDiagnostics_debug` and `AuthDiagnostics_release` compile the actual storage
and SQL authentication entrypoints against the selected stock DuckDB 2.0 shared
library and matching HTTPFS artifact. The mode selects whether `BOILSTREAM_DEBUG` diagnostics are enabled. This does not
qualify an entire product Release build.

Run the registered CTest cases with `ctest -R '^AuthDiagnostics_' --output-on-failure`.
The executables inject adversarial responses at the actual HTTP transport boundary,
assert exact handshake request counts, and need no account or external service.

Cases cover secret markers in logs and errors, structured exception metadata,
trusted status preservation, untrusted status rejection, real SQL login/registration
failures, fresh channel attempts after failures, and simultaneous exception handling.
Captured diagnostics are never printed. Secret serialization and Rust ownership
checks remain real calls. Positive authentication and malformed *authenticated*
application response coverage belong to the private real-server gate and parser
suites; handshake rejection does not prove those later stages were reached.

## Registration ownership

`RegistrationOwnership` uses real ClientContexts, client routing settings and concurrent
workers to verify connection ownership, identity changes, cancellation, stale or
foreign operation IDs, field limits and destruction. The legacy adapter used for
causal evidence invokes the old contextless API; it is never production code.

`RegistrationResponses` exercises the production parsers for already authenticated
bodies and the actual connection-owned result table. It rejects malformed types,
duplicate fields, control bytes and excessive sizes; checks exact cookie names;
preserves pending enrollment after malformed recovery responses; and verifies
one-use recovery output, sibling isolation and manual setup without `textplot`.
These parser tests cannot authenticate a peer. Actual encrypted registration/MFA
and account replacement are exercised by the private server with loaded clients.
