# DuckDB 2.0 WASM build findings

The previous DuckDB 1.x build notes are superseded by [README.md](README.md).
The current executable baseline is [baseline.json](baseline.json).

Browser qualification found build issues that a native smoke test missed:

- The pinned DuckDB 2.0 package uses Emscripten 6.0.9. The old 3.1.71 SDK
  emits exception-handling imports absent from the 2.0 runtime. The test build
  and CI now require the package's SDK version.
- Emscripten's legalized i64 imports did not match DuckDB 2.0's native i64 imports.
  The final WASM link needs `WASM_BIGINT=1`.
- `target_link_libraries` on DuckDB's intermediate static archive did not pass the
  Rust library into DuckDB's later `emcc` side-module link. The WASM linked-library
  list must explicitly include the Rust archive.
- The threaded variant requires `-pthread` at the final side-module link and a
  Rust standard library rebuilt with atomics/bulk memory. CI uses the pinned
  nightly in `baseline.json` and `-Zbuild-std=std,panic_abort`; it does not suppress
  the linker's shared-memory compatibility checks.

DuckDB 2.0's helper exports the C++ entry point and appends metadata. A second
export/metadata pass on the intermediate archive is unnecessary and misleading.
