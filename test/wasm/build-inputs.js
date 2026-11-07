import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { sha256 } from './quack-build.js';
const root = fileURLToPath(new URL('../../', import.meta.url));
async function filesIn(directory) {
  const result = [];
  for (const entry of await readdir(resolve(root, directory), { withFileTypes: true })) {
    const path = directory + '/' + entry.name;
    if (entry.isDirectory()) result.push(...await filesIn(path));
    else { assert(entry.isFile(), `Unsupported build-input symlink: ${path}`); result.push(path); }
  }
  return result;
}
export async function wasmBuildInputs(baseline, variant) {
  assert(baseline.variants.includes(variant), 'Unknown WASM variant');
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
  assert.equal(git('-C', 'duckdb', 'rev-parse', 'HEAD'), baseline.duckdbRevision, 'DuckDB differs from baseline');
  assert.equal(git('-C', 'duckdb', 'status', '--porcelain'), '', 'DuckDB source must be clean');
  assert.equal(git('-C', 'extension-ci-tools', 'status', '--porcelain'), '', 'CI tool sources must be clean');
  const files = [
    'CMakeLists.txt', 'Makefile', 'extension_config.cmake', 'build-wasm-fixed.sh',
    'opaque-client/Cargo.toml', 'opaque-client/Cargo.lock', 'opaque-client/.cargo/config.toml',
    'scripts/prepare-wasm-toolchain.sh', 'scripts/record-wasm-build.mjs',
    'test/wasm/baseline.json', 'test/wasm/build-inputs.js',
    ...await filesIn('src'), ...await filesIn('opaque-client/src'),
  ].sort();
  const source = {};
  for (const file of files) source[file] = sha256(await readFile(resolve(root, file)));
  return { variant, duckdbRevision: baseline.duckdbRevision,
    ciToolsRevision: git('-C', 'extension-ci-tools', 'rev-parse', 'HEAD'), source };
}
export function verifyWasmBuild(bytes, receipt, expected) {
  assert.deepEqual(receipt.inputs, expected, 'BoilStream build inputs changed; rerun build-wasm-fixed.sh');
  assert.equal(receipt.sha256, sha256(bytes), 'BoilStream artifact differs from its build receipt');
}
