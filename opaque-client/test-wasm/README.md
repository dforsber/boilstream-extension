# OPAQUE client WASM C ABI tests

Activate the Emscripten SDK pinned in
[baseline.json](../../test/wasm/baseline.json), then run from the repository root:

```sh
bash scripts/prepare-wasm-toolchain.sh wasm_eh
npm test --prefix opaque-client/test-wasm
```

The runner builds the locked Rust client with the pinned base compiler and
executes its production C ABI as WebAssembly under Node. Cargo incrementally
updates `build/wasm-ffi-rust`; only the small generated test executable uses a
temporary directory. A failed build or test fails the command. Archive existence
is never reported as a successful test.

The suite uses the production C header. It checks registration/login request
sizes and randomization, invalid/null inputs, empty-password behavior, malformed
peer messages without key publication, SHA-256 and refresh-credential known-answer
vectors. EH runs36 assertions; the threaded variant adds a pthread check.

To test the exact archive linked into an already-updated DuckDB extension, set
`BOILSTREAM_RUST_WASM_LIB` to its absolute path. Threaded tests also require
`WASM_BUILD_TYPE=wasm_threads` and that explicit shared-memory archive. The public
CI matrix builds each variant immediately before invoking this suite.

These FFI checks do not establish successful authentication or browser transport
behavior. Use the [DuckDB browser harness](../../test/wasm/README.md) and the
[private real-server gate](../../test/wasm/WASM_TEST_STATUS.md) for those claims.
The old interactive server runners and their file-existence build shortcuts are
retired. Current authentication fixtures require no personal token or account.
