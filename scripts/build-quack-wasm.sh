#!/usr/bin/env bash
# Build the real pinned Quack dependency with shared memory. Never relabel a binary.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"
variant="${1:-wasm_threads}"
[[ "$variant" == wasm_threads ]] || { echo 'Only wasm_threads needs this source build' >&2; exit 1; }
field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d[sys.argv[2]])' "$repo/test/wasm/baseline.json" "$1"; }
source_field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["quackArtifacts"]["wasm_threads"]["sourceBuild"][sys.argv[2]])' "$repo/test/wasm/baseline.json" "$1"; }
if ! command -v emcc >/dev/null; then
  set +u
  source "${EMSDK:-$HOME/emsdk}/emsdk_env.sh"
  set -u
fi
actual="$(emcc --version | sed -n '1s/.*) \([0-9][0-9.]*\).*/\1/p')"
[[ "$actual" == "$(field emscriptenVersion)" ]] || { echo 'Activate the baseline Emscripten SDK' >&2; exit 1; }
[[ "$(git -C duckdb rev-parse HEAD)" == "$(field duckdbRevision)" ]] || { echo 'DuckDB source differs from baseline' >&2; exit 1; }
[[ -z "$(git -C duckdb status --porcelain )" ]] || { echo 'DuckDB source must be unmodified' >&2; exit 1; }
source_dir="$repo/build/quack-source"
revision="$(source_field revision)"
if [[ ! -d "$source_dir/.git" ]]; then
  git clone --filter=blob:none --no-checkout "$(source_field repository)" "$source_dir"
  git -C "$source_dir" checkout --detach "$revision"
fi
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$revision" && -z "$(git -C "$source_dir" status --porcelain )" ]] || {
  echo 'Quack checkout differs from pinned source; use a clean build/quack-source' >&2; exit 1;
}
openssl_version="$(source_field opensslVersion)"
archive="$repo/build/openssl-$openssl_version.tar.gz"
if [[ ! -f "$archive" ]]; then
  curl --fail --location --retry 3 "$(source_field opensslURL)" -o "$archive.tmp"
  mv "$archive.tmp" "$archive"
fi
python3 - "$archive" "$(source_field opensslSHA256)" <<'PY'
import hashlib,sys
from pathlib import Path
if hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit('OpenSSL archive differs from pinned SHA256')
PY
# Fresh source and objects on every invocation: archive mtimes must never let
# modified/stale objects survive and receive a receipt for different inputs.
staging="$(mktemp -d "$repo/build/quack-openssl.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
tar -xzf "$archive" -C "$staging"
openssl_build="$staging/output"
openssl_install="$staging/install"
quack_build="$staging/quack-build"
mkdir -p "$openssl_build"
(
  cd "$openssl_build"
  CC=emcc AR=emar RANLIB=emranlib "$staging/openssl-$openssl_version/Configure" \
    linux-generic32 --cross-compile-prefix= no-shared no-asm no-tests no-module \
    no-engine no-dso no-ui-console --prefix="$openssl_install" --libdir=lib -pthread -fPIC
  make -j"${CMAKE_BUILD_PARALLEL_LEVEL:-4}" build_libs
  make install_dev
)
emcmake cmake -S duckdb -B "$quack_build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DUSE_WASM_THREADS=ON -DWASM_LOADABLE_EXTENSIONS=1 \
  -DBUILD_EXTENSIONS_ONLY=ON -DBUILD_SHELL=OFF -DBUILD_UNITTESTS=OFF -DEXTENSION_STATIC_BUILD=OFF \
  -DDUCKDB_EXTENSION_CONFIGS="$repo/scripts/quack-wasm.cmake" \
  -DBOILSTREAM_QUACK_SOURCE="$source_dir" -DBOILSTREAM_QUACK_OPENSSL="$openssl_install" \
  -DDUCKDB_EXPLICIT_PLATFORM=wasm_threads -DOVERRIDE_GIT_DESCRIBE="$(field engineVersion)" \
  -DOPENSSL_USE_STATIC_LIBS=TRUE -DOPENSSL_INCLUDE_DIR="$openssl_install/include" \
  -DOPENSSL_SSL_LIBRARY="$openssl_install/lib/libssl.a" \
  -DOPENSSL_CRYPTO_LIBRARY="$openssl_install/lib/libcrypto.a"
cmake --build "$quack_build" --target quack_loadable_extension --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-4}"
node scripts/record-quack-build.mjs "$quack_build/extension/quack/quack.duckdb_extension.wasm"
