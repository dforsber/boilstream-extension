import { readFile, writeFile, mkdir } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { wasmBuildInputs } from '../test/wasm/build-inputs.js';
import { sha256 } from '../test/wasm/quack-build.js';
const root = new URL('../', import.meta.url);
const baseline = JSON.parse(await readFile(new URL('test/wasm/baseline.json', root), 'utf8'));
const variant = process.argv[2];
assert(baseline.variants.includes(variant), 'Unknown WASM variant');
const inputsFile = new URL(`build/${variant}/boilstream.inputs.json`, root);
const currentInputs = await wasmBuildInputs(baseline, variant);
if (process.argv[3] === '--snapshot') {
  await mkdir(new URL(`build/${variant}/`, root), { recursive: true });
  await writeFile(inputsFile, JSON.stringify(currentInputs));
} else {
  const before = JSON.parse(await readFile(inputsFile, 'utf8'));
  assert.deepEqual(currentInputs, before, 'Build inputs changed during compilation; rebuild before testing');
  const artifact = new URL(`build/${variant}/extension/boilstream/boilstream.duckdb_extension.wasm`, root);
  const bytes = await readFile(artifact);
  await writeFile(new URL('./boilstream.build.json', artifact), JSON.stringify({
    inputs: before, sha256: sha256(bytes),
  }, null, 2) + '\n');
}
