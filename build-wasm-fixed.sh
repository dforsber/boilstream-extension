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
# Reuse ordinary compiler dependency tracking. Validate the selected CMake tree
# so a copied cache cannot silently build a different checkout or WASM platform.
export WASM_BUILD_TYPE="$variant"
build_root="${BOILSTREAM_WASM_BUILD_DIR:-$PROJ_DIR/build}"
build_dir="$build_root/$variant"
if [[ -f "$build_dir/CMakeCache.txt" ]]; then
  python3 - "$build_dir/CMakeCache.txt" "$PROJ_DIR" "$variant" <<'PY_CACHE'
import pathlib, sys
cache = {}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if '=' in line and ':' in line.split('=', 1)[0]:
        name, value = line.split('=', 1)
        cache[name.split(':', 1)[0]] = value
root = pathlib.Path(sys.argv[2]).resolve()
for name, expected in [('CMAKE_HOME_DIRECTORY', root / 'duckdb'), ('boilstream_SOURCE_DIR', root)]:
    if name not in cache or pathlib.Path(cache[name]).resolve() != expected:
        raise SystemExit(f'{name} selects another source tree; configure the intended build directory')
if cache.get('DUCKDB_CUSTOM_PLATFORM') != sys.argv[3] or cache.get('EMSCRIPTEN') != '1':
    raise SystemExit('CMake cache does not select the requested WASM platform')
PY_CACHE
  bash scripts/prepare-wasm-toolchain.sh "$variant"
  cmake --build "$build_dir" --target boilstream_loadable_extension --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
else
  if [[ "$build_root" != "$PROJ_DIR/build" ]]; then
    echo 'Configure the selected BOILSTREAM_WASM_BUILD_DIR before using it.' >&2; exit 1
  fi
  # First configuration uses the unchanged DuckDB community extension recipe.
  make "$variant" OVERRIDE_GIT_DESCRIBE="$(baseline_field engineVersion)" EXTENSION_STATIC_BUILD=0
fi
artifact="$build_dir/extension/boilstream/boilstream.duckdb_extension.wasm"
test -s "$artifact"
echo "Built $artifact"
echo "Test with: WASM_VARIANTS=$variant npm test --prefix test/wasm"
