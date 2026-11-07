# Rebuilding the DuckDB 2.0 WASM tests

Use the commands and exact baseline in [README.md](README.md) and
[baseline.json](baseline.json). Run both `wasm_eh` and `wasm_threads`.

When updating the baseline:

1. Select an exact DuckDB-Wasm package and record its Git revision and embedded
   DuckDB submodule revision. Update the package lockfile with npm.
2. Align the extension's DuckDB source and Emscripten toolchain with that runtime.
   Qualify the pinned Rust nightly used to rebuild the threaded standard library.
3. Rebuild both extension variants; never append a new version to an old binary.
4. Run `npm test` and verify the queried engine version, platform, and all SQL
   assertions on each variant. Missing artifacts and runtime/link failures fail.
5. Update the CI toolchain and `WASM_TEST_STATUS.md` with actual execution results.

DuckDB's build helper owns WASM exports and the single metadata footer. The Rust
archive must participate in the final side-module link, using the same i64 ABI as
DuckDB-Wasm (`WASM_BIGINT=1`).

Upstream ABI requirements: [Rust Emscripten target documentation](https://doc.rust-lang.org/rustc/platform-support/wasm32-unknown-emscripten.html#emscripten-abi-compatibility).
