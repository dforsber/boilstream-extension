# Boilstream Extension Test Suite

Native SQL logic tests under `test/sql/` run inside DuckDB's `unittest` binary, and C++ Catch2 tests
under `test/cpp/` build as standalone executables against the same DuckDB build. Both need DuckDB
**v2.0.0** for this qualified baseline; later hosts require requalification.

The [WASM lane](wasm/README.md) runs a pinned DuckDB **v2.0.0** in real Chromium
workers for both `wasm_eh` and `wasm_threads`. It also runs the compatible shared
SQL corpus. `session_lifecycle_test` below is a native executable and does not
replace browser testing. Rust WASM FFI vectors run separately against the same
archive linked into each extension.

## SQL tests (`test/sql/`)

| File | What it checks |
|------|----------------|
| `boilstream_grammar.test` | `BOILSTREAM ...`, `CREATE DUCKLAKE`, `ATTACH DUCKLAKE` statements: registration in `duckdb_grammar_extensions()`, automatic activation on new connections, equivalence with the PRAGMA output, routing of arguments into the PRAGMA validation, parse-time arity errors, built-in `ATTACH`/`CREATE` still parsing, deactivation via `SET active_grammar_extensions`. |
| `boilstream_pragmas.test` | Every PRAGMA and table function is registered; URL/email/token/TOTP validation errors; no-session failure paths (`No endpoint configured`, `requires an active Boilstream session`); `duckdb_secrets()` without a session; dotted setting names must be quoted in 2.0. |
| `client_boundary.test` | Client API registration and absence of server authentication functions. |
| `quack_secret_autovend.test` | `quack` secret type stays owned by the quack extension (`require quack`). |
| `quack_attach_with_manual_secret.test` | A user-created `TYPE quack` secret is honoured by `ATTACH` (`require quack`). |

The tests are registered into `unittest` through `LOAD_TESTS` in the extension config. Run them with
an absolute path glob:

```bash
<duckdb-build>/test/unittest "<extension-checkout>/test/sql/*"
```

For complete local SQL coverage, copy the matching signed HTTPFS and Quack artifacts
into `<duckdb-build>/repository/v2.0.0/<platform>/` before running. A skipped
`require` case is not a qualified pass.

## C++ tests (`test/cpp/`)

Standalone CMake project. It links the extension archive, `libduckdb_static.a` and the third-party
archives from a DuckDB build directory and registers the linked extensions through
`static_extension_loader.c` (DuckDB 2.0 removed the dummy loader archive; programs register their
statically linked extensions themselves).

```bash
export DUCKDB_BUILD_DIR=<duckdb-build>        # dir containing src/libduckdb_static.a, extension/boilstream/...
export DUCKDB_SOURCE_DIR=<duckdb-source>      # matching DuckDB 2.0 checkout
# Install matching core artifacts: INSTALL httpfs; INSTALL quack;
cmake -G Ninja -DBOILSTREAM_INTEGRATION_TESTS=ON \
  -DBOILSTREAM_HTTPFS_EXTENSION_PATH=<version/platform/httpfs.duckdb_extension> \
  -DBOILSTREAM_QUACK_EXTENSION_PATH=<version/platform/quack.duckdb_extension> \
  -S test/cpp -B build/cpp-tests
ninja -C build/cpp-tests
ctest --test-dir build/cpp-tests --output-on-failure
```

Without the environment variables the project falls back to `../../build/release` and the `duckdb`
submodule. Exactly one `libopaque_client.a` must exist under the selected
`<build>/cargo/build/*/release/`; ambiguous or missing archives fail configuration.
The harness never substitutes another build tree or a separate server library.

| Executable | Tags | Covers |
|------------|------|--------|
| `boilstream_test` | `[security]` | Token format validation, session state, connection user mapping, bootstrap hash, thread safety (`[.]`, hidden). |
| `boilstream_crypto_test` | `[crypto]` | Production Rust C ABI SHA-256 and OPAQUE refresh-credential known-answer vectors, binary input, invalid pointers and unchanged output on failure. |
| `boilstream_catalog_version_test` | `[catalog_versions]` | Catalog version polling route, rate limiting, per-connection tracking. |
| `boilstream_connection_state_test` | `[connection]` | Per-connection state isolation, expiration sentinels and concurrent owner-local updates. |
| `session_routing_test` | `[session-routing]` | Connection-id to session routing, re-bootstrap, concurrency. |
| `input_validation_test` | `[input_validation]` | Malformed JSON, size limits, SQL injection in values, error-message hygiene. |
| `quack_attach_red_test` | `[quack]` | Managed catalog credential vending, user secret precedence, RFC 3339 expiry. |
| `registration_ffi_test` | `[registration]` | Rust FFI registration validation and TOTP URI. |
| `session_lifecycle_test` | `[session]` | Concurrent logout, exact authentication-generation invalidation, owner isolation and retired-cache rejection, executed natively. |

### Integration lane (enabled above and in CI)

`boilstream_integration_test` (`-DBOILSTREAM_INTEGRATION_TESTS=ON`, the default) loads the *loadable*
`boilstream.duckdb_extension` into DuckDB together with stock `httpfs` and `quack` artifacts from one
extension directory (`BOILSTREAM_HTTPFS_EXTENSION_PATH`, `BOILSTREAM_QUACK_EXTENSION_PATH`). The
`[local]` cases run in CTest; the `[server]` cases need a running boilstream server and single-use
bootstrap tokens (`BOILSTREAM_TEST_ENDPOINT`). It needs 2.0-compatible httpfs and quack artifacts.

The standalone Rust tests include successful registration/login through the production
C ABI against an in-process OPAQUE server, plus wrong-password and modified-proof
rejection. Run `cargo test --locked --manifest-path opaque-client/Cargo.toml`.
The dependency-free `transport_security_test` exercises the production URL policy,
bounded append and exceptional secret erasure. Native tests have subprocess deadlines. `CredentialCleanup` observes actual JSON allocation/reallocation erasure before free, checks binary serializer contents and erasure, and verifies HTTP cleanup preserves borrowed provider headers.

The stock baseline also runs `AuthDiagnostics_debug`, `AuthDiagnostics_release`,
`RegistrationOwnership`, `RegistrationOutput`, `RegistrationResponses` and
`RequiredApplicationProtocol`. Diagnostics and application-boundary cases inject
untrusted replies into the actual transport; ownership/output cases exercise real
ClientContexts. `RegistrationResponses` tests production authenticated-body parsers
and one-use result publication. `SessionMemoryOnly` verifies two failed fresh-channel
handshakes preserve connection-owned resume credentials without filesystem access.
Neither suite claims successful authentication with its untrusted wire fixtures.

## Not covered without a server

The private real-server gate covers successful encrypted authentication on native
and both WASM runtimes. Registration/MFA, resume, credential rotation and remote
catalog coverage must also be qualified there; public adversarial fixtures only
prove rejection, not successful server interoperability. Browser authentication has its own
remaining boundaries documented in `wasm/WASM_TEST_STATUS.md`.

## Adding tests

- SQL: add a `.test` file under `test/sql/`; start with `require boilstream` (and `require quack` when
  the quack extension is needed). Assert behaviour (results or error text), not just `statement ok`.
- C++: add a `TEST_CASE` to the matching file, or a new executable in `test/cpp/CMakeLists.txt` linked
  through `link_duckdb_static(<target>)` when it needs DuckDB.

The retired header-signing/cipher-negotiation protocol has no production path or
FFI exports. Its old tests have been removed; authenticated wire cryptography is
covered by `protocol-client` and the real native/EH/pthread server gate. Credential
erasure is covered by `CredentialCleanup`, and response schema validation by
`RegistrationResponses`. These suites do not claim legacy protocol compatibility.
