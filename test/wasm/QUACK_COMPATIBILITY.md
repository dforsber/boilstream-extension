# Threaded Quack compatibility

The DuckDB 2.0 public `wasm_threads/quack.duckdb_extension.wasm` pinned in
`baseline.json` imports **non-shared** memory. It fails to load into the threaded
runtime. Changing its filename or footer cannot repair it.

The pinned DuckDB build helper creates the final side module in a post-build
`emcc` command. That command reads `WASM_THREAD_FLAGS`, set by
`USE_WASM_THREADS=ON`; merely passing `-pthread` in `CMAKE_CXX_FLAGS` does not
set the final link mode. The root Makefile now passes this option for our threaded
community build too, retaining the normal `make wasm_threads` entry point.

## Build and test

```sh
# Activate Emscripten 6.0.9 first (or set EMSDK).
npm ci --prefix test/wasm
scripts/build-quack-wasm.sh
./build-wasm-fixed.sh wasm_threads
WASM_VARIANTS=wasm_threads npm test --prefix test/wasm
```

The dependency builder uses unmodified Quack revision
`f96420ed46aee9c42064bdb99ddfd1230d6c0086`, the existing pinned DuckDB host, and
OpenSSL 3.5.9 with a verified source archive SHA256. **Every invocation creates a
fresh temporary source/build/install tree for OpenSSL and a fresh CMake build tree
for Quack.** Neither stale objects nor a previous SDK's libraries are reused.
A failed build exits nonzero and cannot produce a new receipt. DuckDB source and
its installed libraries are not modified.

The completed module and `quack.build.json` receipt are placed under
`build/compatibility/v2.0.0/wasm_threads/`. Before running a browser, the harness
checks the source/SDK/recipe identity, artifact SHA256, actual shared-memory import,
and exported Quack entrypoint. Replacing the artifact or changing the build inputs
requires a rebuild. The receipt records a local build; it is not an upstream
signature or independent attestation.

`npm test` has one mandatory compatibility path: Quack must autoload, own its
secret type, create/drop a client secret, and leave the regression suite working.
There is no accepted-incompatibility fallback. `test:compatibility` remains an
alias for the same strict browser runner. The unavailable-optional-dependency
regression is tested separately. The CI workflow uploads the rebuilt dependency
and its receipt alongside BoilStream.

## Distribution boundary

This fixes our paired artifact and CI; it does **not** overwrite DuckDB's public
Quack repository. Browser deployments must serve the rebuilt module from their
own trusted extension repository (under `v2.0.0/wasm_threads/`) and configure
`custom_extension_repository` before loading BoilStream, or explicitly load the
compatible Quack module first. Unsigned development artifacts require the same
explicit opt-in as the tests; production distribution needs appropriate signing
and trust configuration. Do not advertise the old public artifact as repaired.

The community descriptor continues to reference BoilStream source and exclude
only MVP. The extra Quack source build is confined to our regression workflow;
it does not replace DuckDB's central build/sign/deploy pipeline or add OpenSSL
to BoilStream's native library dependencies. No existing release tag is moved.
