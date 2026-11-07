#!/usr/bin/env bash
# Used by both local builds and DuckDB's community make targets.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
variant="${1:?WASM platform required}"
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$repo/test/wasm/baseline.json" "$1"; }
case "$variant" in
  wasm_eh) toolchain="$(field rustToolchain)"; extra=(--target wasm32-unknown-emscripten) ;;
  wasm_threads) toolchain="$(field rustThreadsToolchain)"; extra=(--component rust-src) ;;
  *) echo "Unsupported DuckDB 2.0 WASM platform: $variant" >&2; exit 1 ;;
esac
expected="$(field emscriptenVersion)"
actual="$(emcc --version | sed -n '1s/.*) \([0-9][0-9.]*\).*/\1/p')"
[[ "$actual" == "$expected" ]] || { echo "Expected Emscripten $expected; got $actual" >&2; exit 1; }
rustup toolchain install "$toolchain" --profile minimal "${extra[@]}"
