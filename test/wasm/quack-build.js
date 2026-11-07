import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export async function quackBuildInputs(baseline) {
  return {
    source: baseline.quackArtifacts.wasm_threads.sourceBuild,
    duckdbRevision: baseline.duckdbRevision,
    engineVersion: baseline.engineVersion,
    emscriptenVersion: baseline.emscriptenVersion,
    recipe: sha256(await readFile(new URL('../../scripts/build-quack-wasm.sh', import.meta.url))),
    cmake: sha256(await readFile(new URL('../../scripts/quack-wasm.cmake', import.meta.url))),
    recorder: sha256(await readFile(new URL('../../scripts/record-quack-build.mjs', import.meta.url))),
    verifier: sha256(await readFile(new URL('./quack-build.js', import.meta.url))),
    sharedMemory: true,
  };
}

// Read the actual memory import type. A wasm_threads filename/footer is insufficient.
export function memoryImports(bytes) {
  let offset = 0;
  const byte = () => { assert(offset < bytes.length, 'Truncated WASM'); return bytes[offset++]; };
  const uint = () => {
    let n = 0, shift = 0, b;
    do { b = byte(); assert(shift < 35, 'Invalid WASM integer'); n += (b & 127) * 2 ** shift; shift += 7; } while (b & 128);
    return n;
  };
  const name = () => { const size = uint(); assert(offset + size <= bytes.length, 'Truncated WASM name'); const s = new TextDecoder().decode(bytes.subarray(offset, offset + size)); offset += size; return s; };
  const limits = () => { const flags = uint(); assert((flags & ~3) === 0, 'Unsupported WASM memory/table limits'); uint(); if (flags & 1) uint(); return flags; };
  assert.deepEqual([...bytes.subarray(0, 8)], [0, 97, 115, 109, 1, 0, 0, 0], 'Invalid WASM header');
  offset = 8;
  const memories = [];
  while (offset < bytes.length) {
    const section = byte(), size = uint(), end = offset + size;
    assert(end <= bytes.length, 'Truncated WASM section');
    if (section === 2) {
      const count = uint();
      for (let i = 0; i < count; i++) {
        const module = name(), field = name(), kind = byte();
        if (kind === 0) uint();
        else if (kind === 1) { byte(); limits(); }
        else if (kind === 2) memories.push({ module, field, shared: Boolean(limits() & 2) });
        else if (kind === 3) { byte(); byte(); }
        else if (kind === 4) { byte(); uint(); }
        else throw new Error('Unknown WASM import kind');
      }
      assert.equal(offset, end, 'Malformed WASM import section');
    }
    offset = end;
  }
  return memories;
}
export function assertThreadedQuack(bytes) {
  assert.deepEqual(memoryImports(bytes), [{ module: 'env', field: 'memory', shared: true }],
    'Threaded Quack must import shared memory; rebuild with USE_WASM_THREADS=ON');
  assert(WebAssembly.Module.exports(new WebAssembly.Module(bytes)).some(e => e.name === 'quack_duckdb_cpp_init' && e.kind === 'function'),
    'Missing real Quack entrypoint');
}
export function verifyQuackBuild(bytes, manifest, expectedInputs) {
  assert.deepEqual(manifest.inputs, expectedInputs, 'Quack build inputs changed; rebuild with scripts/build-quack-wasm.sh');
  assert.equal(sha256(bytes), manifest.sha256, 'Quack artifact differs from its build receipt');
  assertThreadedQuack(bytes);
}
