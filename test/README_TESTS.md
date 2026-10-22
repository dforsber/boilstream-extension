# Boilstream Extension Test Suite

Two lanes: SQL logic tests under `test/sql/` run inside DuckDB's `unittest` binary, and C++ Catch2 tests
under `test/cpp/` build as standalone executables against the same DuckDB build. Both need DuckDB
**v2.0.0 or newer**.

## SQL tests (`test/sql/`)

| File | What it checks |
|------|----------------|
| `boilstream_grammar.test` | `BOILSTREAM ...`, `CREATE DUCKLAKE`, `ATTACH DUCKLAKE` statements: registration in `duckdb_grammar_extensions()`, automatic activation on new connections, equivalence with the PRAGMA output, routing of arguments into the PRAGMA validation, parse-time arity errors, built-in `ATTACH`/`CREATE` still parsing, deactivation via `SET active_grammar_extensions`. |
| `boilstream_pragmas.test` | Every PRAGMA and table function is registered; URL/email/token/TOTP validation errors; no-session failure paths (`No endpoint configured`, `requires an active Boilstream session`); `duckdb_secrets()` without a session; dotted setting names must be quoted in 2.0. |
| `quack_bridge.test` | Quack bridge scalar functions fail closed without a Rust host. |
| `quack_secret_autovend.test` | `quack` secret type stays owned by the quack extension (`require quack`). |
| `quack_attach_with_manual_secret.test` | A user-created `TYPE quack` secret is honoured by `ATTACH` (`require quack`). |

The tests are registered into `unittest` through `LOAD_TESTS` in the extension config. Run them with
an absolute path glob:

```bash
<duckdb-build>/test/unittest "<extension-checkout>/test/sql/*"
```

Tests with `require quack` are skipped when the quack extension is not linked into the build.

## C++ tests (`test/cpp/`)

Standalone CMake project. It links the extension archive, `libduckdb_static.a` and the third-party
archives from a DuckDB build directory and registers the linked extensions through
`static_extension_loader.c` (DuckDB 2.0 removed the dummy loader archive; programs register their
statically linked extensions themselves).

```bash
export DUCKDB_BUILD_DIR=<duckdb-build>        # dir containing src/libduckdb_static.a, extension/boilstream/...
export DUCKDB_SOURCE_DIR=<duckdb-source>      # fork checkout, for headers and extension/loader/*.cpp
cmake -G Ninja -DBOILSTREAM_INTEGRATION_TESTS=OFF -S test/cpp -B build/cpp-tests
ninja -C build/cpp-tests
ctest --test-dir build/cpp-tests --output-on-failure
```

Without the environment variables the project falls back to `../../build/release` and the `duckdb`
submodule. The Rust library is found under `<build>/cargo/build/*/release/` as either
`libopaque_client.a` (standalone build) or `librust_bridge.a` (shared staticlib in the BoilStream fork).

| Executable | Tags | Covers |
|------------|------|--------|
| `boilstream_test` | `[security]` | Token format validation, session state, connection user mapping, bootstrap hash, thread safety (`[.]`, hidden). |
| `boilstream_crypto_test` | `[crypto]` | HKDF key derivation, response signature verification, header extraction, secure zeroization, constant-time HMAC compare, canonical response format, refresh-token derivation and storage round-trip. |
| `boilstream_conformance_test` | `[conformance]` | RFC 4231 / RFC 5869 / SHA-256 vectors, SECURITY_SPECIFICATION.md key derivation, canonical formats, request signing, response verification, AES-256-GCM. |
| `boilstream_encryption_test` | `[encryption]` | Response decryption and HMAC ordering. |
| `boilstream_catalog_version_test` | `[catalog_versions]` | Catalog version polling route, rate limiting, per-connection tracking. |
| `boilstream_connection_state_test` | `[connection]` | Per-connection state isolation, expiration sentinels, snapshot thread safety. |
| `session_routing_test` | `[session-routing]` | Connection-id to session routing, re-bootstrap, concurrency. |
| `input_validation_test` | `[input_validation]` | Malformed JSON, size limits, SQL injection in values, error-message hygiene. |
| `quack_attach_red_test` | `[quack]` | Managed catalog credential vending, user secret precedence, RFC 3339 expiry. |
| `quack_bridge_test` | `[quack_bridge]` | Planner/authorizer bridge ABI, fail-closed behaviour, session registry lifetime. |
| `aws_signing_test`, `registration_ffi_test` | `[aws]`, `[registration]` | Rust FFI: SigV4 signing, registration validation, TOTP URI. |
| `wasm_lock_ordering_test` | `[wasm]` | Lock ordering patterns, no DuckDB dependency. |

### Integration lane (off in the commands above)

`boilstream_integration_test` (`-DBOILSTREAM_INTEGRATION_TESTS=ON`, the default) loads the *loadable*
`boilstream.duckdb_extension` into DuckDB together with stock `httpfs` and `quack` artifacts from one
extension directory (`BOILSTREAM_HTTPFS_EXTENSION_PATH`, `BOILSTREAM_QUACK_EXTENSION_PATH`). The
`[local]` cases run in CTest; the `[server]` cases need a running boilstream server and single-use
bootstrap tokens (`BOILSTREAM_TEST_ENDPOINT`). It needs 2.0-compatible httpfs and quack artifacts.

## Not covered without a server

Token exchange and rotation, server response parsing, network error handling and concurrent rotation
need a boilstream server; they belong to the product and staging gates.

## Adding tests

- SQL: add a `.test` file under `test/sql/`; start with `require boilstream` (and `require quack` when
  the quack extension is needed). Assert behaviour (results or error text), not just `statement ok`.
- C++: add a `TEST_CASE` to the matching file, or a new executable in `test/cpp/CMakeLists.txt` linked
  through `link_duckdb_static(<target>)` when it needs DuckDB.
