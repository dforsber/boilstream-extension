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
  if ! curl --fail --location --connect-timeout 15 --max-time 120 --retry 3 "$(source_field opensslURL)" -o "$archive.tmp"; then
    # GitHub's release redirect can fail independently of the asset API. Both
    # paths must return the same pinned archive; neither bypasses SHA verification.
    curl --fail --location --connect-timeout 15 --max-time 120 --retry 3 \
      -H 'Accept: application/octet-stream' "$(source_field opensslAssetURL)" -o "$archive.tmp"
  fi
  mv "$archive.tmp" "$archive"
fi
python3 - "$archive" "$(source_field opensslSHA256)" <<'PY'
import hashlib,sys
from pathlib import Path
if hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit('OpenSSL archive differs from pinned SHA256')
PY
# Ordinary persistent build trees. OpenSSL's generated Makefile and CMake/Ninja
# track inputs; the harness invokes this builder before loading its output.
openssl_source="$repo/build/openssl-$openssl_version"
if [[ ! -d "$openssl_source" ]]; then
  tar -xzf "$archive" -C "$repo/build"
fi
openssl_build="$repo/build/openssl-$openssl_version-wasm_threads-$(field emscriptenVersion)"
openssl_install="$openssl_build/install"
quack_build="$repo/build/quack-wasm_threads"
mkdir -p "$openssl_build"
(
  cd "$openssl_build"
  # Configure rewrites generated headers, so only rerun it when this recipe
  # changes or the tree is new. OpenSSL Make tracks its own source dependencies.
  if [[ ! -f Makefile || "$repo/scripts/build-quack-wasm.sh" -nt configdata.pm ]]; then
    CC=emcc AR=emar RANLIB=emranlib "$openssl_source/Configure" \
      linux-generic32 --cross-compile-prefix= no-shared no-asm no-tests no-module \
      no-engine no-dso no-ui-console --prefix="$openssl_install" --libdir=lib -pthread -fPIC
  fi
  make -j"${CMAKE_BUILD_PARALLEL_LEVEL:-4}" build_libs
  # Upstream install_dev copies every header unconditionally. Stage it, then
  # install only changed contents so Ninja can retain unaffected Quack objects.
  make install_dev DESTDIR="$openssl_build/staging"
  mkdir -p "$openssl_install"
  rsync -r --checksum --delete "$openssl_build/staging$openssl_install/" "$openssl_install/"
)
emcmake cmake -S duckdb -B "$quack_build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DUSE_WASM_THREADS=ON -DWASM_LOADABLE_EXTENSIONS=1 \
  -DBUILD_EXTENSIONS_ONLY=ON -DBUILD_SHELL=OFF -DBUILD_UNITTESTS=OFF -DEXTENSION_STATIC_BUILD=OFF \
  -DDUCKDB_EXTENSION_CONFIGS="$repo/scripts/quack-wasm.cmake" \
  -DBOILSTREAM_QUACK_SOURCE="$source_dir" -DBOILSTREAM_QUACK_REVISION="$revision" \
  -DBOILSTREAM_QUACK_OPENSSL="$openssl_install" \
  -DDUCKDB_EXPLICIT_PLATFORM=wasm_threads -DOVERRIDE_GIT_DESCRIBE="$(field engineVersion)" \
  -DOPENSSL_USE_STATIC_LIBS=TRUE -DOPENSSL_INCLUDE_DIR="$openssl_install/include" \
  -DOPENSSL_SSL_LIBRARY="$openssl_install/lib/libssl.a" \
  -DOPENSSL_CRYPTO_LIBRARY="$openssl_install/lib/libcrypto.a"
cmake --build "$quack_build" --target quack_loadable_extension --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-4}"
[[ "$(git -C duckdb rev-parse HEAD)" == "$(field duckdbRevision)" ]] || { echo 'DuckDB revision changed during Quack build' >&2; exit 1; }
[[ -z "$(git -C duckdb status --porcelain)" ]] || { echo 'DuckDB changed during Quack build' >&2; exit 1; }
node --input-type=module - "$quack_build/extension/quack/quack.duckdb_extension.wasm" "$(field engineVersion)" <<'JS'
import { readFile, mkdir, copyFile } from 'node:fs/promises';
import { assertThreadedQuack } from './test/wasm/quack-build.js';
const source = process.argv[2];
assertThreadedQuack(await readFile(source));
const directory = `build/compatibility/${process.argv[3]}/wasm_threads`;
await mkdir(directory, { recursive: true });
await copyFile(source, `${directory}/quack.duckdb_extension.wasm`);
console.log(`Built shared-memory Quack: ${directory}`);
JS
