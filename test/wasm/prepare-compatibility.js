// Fetch once, then verify the exact core artifacts used by compatibility tests.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { baseline, quackArtifactPath } from './server.js';
for (const variant of (process.env.WASM_VARIANTS?.split(',') || baseline.variants)) {
  assert(baseline.variants.includes(variant), 'Unknown compatibility platform');
  const expected = baseline.quackArtifacts[variant];
  const path = quackArtifactPath(variant);
  let bytes;
  try { bytes = await readFile(path); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const response = await fetch(expected.url, { signal: AbortSignal.timeout(60_000) });
    assert(response.ok, `Missing core Quack artifact for ${variant}: HTTP ${response.status}`);
    bytes = Buffer.from(await response.arrayBuffer());
    assert.equal(createHash('sha256').update(bytes).digest('hex'), expected.sha256, 'Core Quack artifact changed; requalify it');
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes);
  }
  assert.equal(createHash('sha256').update(bytes).digest('hex'), expected.sha256, 'Cached Quack artifact differs from baseline');
}
