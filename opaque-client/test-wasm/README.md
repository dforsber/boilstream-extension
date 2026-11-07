# OPAQUE Client WASM tests

`npm test` (or `bash test-ffi.sh`) compiles and executes the production Rust C FFI
as WebAssembly under Node. It requires the Emscripten version pinned in
[`../../test/wasm/baseline.json`](../../test/wasm/baseline.json) and the Rust
`wasm32-unknown-emscripten` target. Archive existence alone never counts as a pass.

The test uses the production C header and checks registration/login request
sizes and randomization, null arguments, explicit empty-password behavior,
malformed server-message rejection with no key outputs, RFC 4231 HMAC-SHA256,
and a canonical request containing the known SHA256 empty-payload digest.
Failures exit nonzero. Generated executables live in a temporary directory.

By default the script rebuilds the locked Rust dependencies. To test the exact
Rust archive linked into a DuckDB extension, set `BOILSTREAM_RUST_WASM_LIB` to
its absolute path. The DuckDB WASM CI matrix does this for both variants.

For the actual DuckDB 2.0 Chromium worker tests, see
[`../../test/wasm/README.md`](../../test/wasm/README.md). Standalone FFI checks do
not establish browser transport behavior or successful end-to-end authentication.
The older interactive integration scripts in this directory are separate manual
tools and are not part of the qualified CI suite.

The fallback base FFI build uses a fresh temporary Cargo target directory; inherited
Cargo cache paths cannot select a stale archive. Threaded tests require the exact
archive from the extension build. They use `PROXY_TO_PTHREAD` and assert that the
Rust calls run on a real pthread (27 assertions, versus 26 for base).
