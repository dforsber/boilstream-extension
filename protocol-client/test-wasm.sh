#!/usr/bin/env bash
# Execute the client-only core with the extension's pinned Emscripten baseline.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
variant="${1:-wasm_eh}"
baseline="$here/../test/wasm/baseline.json"
expected="$(node -e 'console.log(require(process.argv[1]).emscriptenVersion)' "$baseline")"
actual="$(emcc --version | sed -n '1s/.*) \([0-9][0-9.]*\).*/\1/p')"
[[ "$actual" == "$expected" ]] || { echo "Expected Emscripten $expected, got $actual" >&2; exit 1; }
toolchain="$(node -e 'console.log(require(process.argv[1]).rustToolchain)' "$baseline")"
flags='-C link-arg=-sALLOW_MEMORY_GROWTH=1 -C link-arg=-sENVIRONMENT=node -C link-arg=-sEXIT_RUNTIME=1 -C link-arg=-sSTACK_SIZE=2097152'
args=()
case "$variant" in
  wasm_eh) ;;
  wasm_threads)
    toolchain="$(node -e 'console.log(require(process.argv[1]).rustThreadsToolchain)' "$baseline")"
    flags="$flags -C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=-pthread -C link-arg=-sPROXY_TO_PTHREAD=1 -C link-arg=-sPTHREAD_POOL_SIZE=1"
    args=(-Z build-std=std,panic_abort)
    ;;
  *) echo "Expected wasm_eh or wasm_threads" >&2; exit 1 ;;
esac
CARGO_TARGET_WASM32_UNKNOWN_EMSCRIPTEN_RUNNER=node RUSTFLAGS="$flags" \
  cargo "+$toolchain" test --locked --manifest-path "$here/Cargo.toml" \
    --target wasm32-unknown-emscripten "${args[@]}" --lib -- --test-threads=1
