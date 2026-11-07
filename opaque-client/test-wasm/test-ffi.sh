#!/usr/bin/env bash
# Execute the production Rust FFI as WebAssembly, with the qualified DuckDB SDK.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
expected="$(node -e 'console.log(require(process.argv[1]).emscriptenVersion)' "$repo/test/wasm/baseline.json")"
actual="$(emcc --version | sed -n '1s/.*) \([0-9][0-9.]*\).*/\1/p')"
[[ "$actual" == "$expected" ]] || { echo "Expected Emscripten $expected, got $actual" >&2; exit 1; }
output="$(mktemp -d "${TMPDIR:-/tmp}/boilstream-ffi.XXXXXX")"
trap 'rm -rf "$output"' EXIT
if [[ -n "${BOILSTREAM_RUST_WASM_LIB:-}" ]]; then
  rust_library="$BOILSTREAM_RUST_WASM_LIB"
else
  if [[ "${WASM_BUILD_TYPE:-wasm_eh}" != "wasm_eh" ]]; then
    echo 'Threaded FFI requires BOILSTREAM_RUST_WASM_LIB from ./build-wasm-fixed.sh wasm_threads' >&2
    exit 1
  fi
  rust_toolchain="$(node -e 'console.log(require(process.argv[1]).rustToolchain)' "$repo/test/wasm/baseline.json")"
  (cd "$repo/opaque-client" && CARGO_BUILD_BUILD_DIR="$output/rust-build" cargo "+$rust_toolchain" build --locked --release --target wasm32-unknown-emscripten --target-dir "$output/rust")
  rust_library="$output/rust/wasm32-unknown-emscripten/release/libopaque_client.a"
fi
test -s "$rust_library"
thread_flags=()
if [[ "${WASM_BUILD_TYPE:-wasm_eh}" == "wasm_threads" ]]; then
  thread_flags=(-pthread -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=1)
fi
emcc "$here/test-ffi.c" "$rust_library" -I"$repo/src/include" -o "$output/test-ffi.cjs" \
  -fwasm-exceptions -sWASM_BIGINT=1 -sALLOW_MEMORY_GROWTH=1 -sEXIT_RUNTIME=1 -sENVIRONMENT=node "${thread_flags[@]}"
node "$output/test-ffi.cjs"
