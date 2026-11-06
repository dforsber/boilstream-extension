#!/usr/bin/env bash
# Build only from the source/toolchain qualified by the browser test baseline.
set -euo pipefail
PROJ_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJ_DIR"
variant="${1:-wasm_eh}"
case "$variant" in wasm_eh|wasm_threads) ;; *) echo 'Usage: ./build-wasm-fixed.sh [wasm_eh|wasm_threads]' >&2; exit 1 ;; esac
baseline_field() { node -e 'console.log(require(process.argv[1])[process.argv[2]])' "$PROJ_DIR/test/wasm/baseline.json" "$1"; }
expected_revision="$(baseline_field duckdbRevision)"
if [[ "$(git -C duckdb rev-parse HEAD)" != "$expected_revision" ]]; then
  echo "DuckDB source differs from the qualified WASM baseline ($expected_revision). Update and qualify baseline.json first." >&2
  exit 1
fi
if ! command -v emcc >/dev/null; then
  emsdk_environment="${EMSDK:-$HOME/emsdk}/emsdk_env.sh"
  if [[ ! -f "$emsdk_environment" ]]; then
    echo 'Activate the Emscripten version in test/wasm/baseline.json first.' >&2; exit 1
  fi
  set +u
  source "$emsdk_environment"
  set -u
fi
expected_emcc="$(baseline_field emscriptenVersion)"
actual_emcc="$(emcc --version | sed -n '1s/.*) \([0-9][0-9.]*\).*/\1/p')"
if [[ "$actual_emcc" != "$expected_emcc" ]]; then
  echo "Expected Emscripten $expected_emcc, got $actual_emcc. Activate the qualified SDK first." >&2; exit 1
fi
export WASM_BUILD_TYPE="$variant"
make "$variant" OVERRIDE_GIT_DESCRIBE="$(baseline_field engineVersion)" EXTENSION_STATIC_BUILD=0
artifact="$PROJ_DIR/build/$variant/extension/boilstream/boilstream.duckdb_extension.wasm"
test -s "$artifact"
echo "Built $artifact"
echo "Test with: WASM_VARIANTS=$variant npm test --prefix test/wasm"
