#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile, access, appendFile } from 'node:fs/promises';
import { createUntrustedPeer } from './untrusted-peer.js';
import { chromium } from 'playwright';
import { ensureWasmBuild } from './ensure-build.js';
import { startServer, baseline, artifactPath } from './server.js';

assert(!process.argv.includes('--authenticated'), 'Use the private real-server coordinator with real-server.js for authenticated qualification');
async function summary(message) {
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, message + '\n');
}
const variants = process.env.WASM_VARIANTS ? process.env.WASM_VARIANTS.split(',') : baseline.variants;
assert(variants.length > 0 && variants.every(v => baseline.variants.includes(v)), 'Invalid WASM_VARIANTS');
const pkg = JSON.parse(await readFile(new URL('./node_modules/@duckdb/duckdb-wasm/package.json', import.meta.url), 'utf8'));
assert.equal(pkg.version, baseline.packageVersion, 'Run npm ci to install the exact baseline');
for (const variant of variants) {
  ensureWasmBuild(variant);
  try { await access(artifactPath(variant)); }
  catch { throw new Error(`Missing ${artifactPath(variant)}; run ./build-wasm-fixed.sh ${variant} from the repository root`); }
}
await import('./prepare-compatibility.js');
const auth = createUntrustedPeer();
let server, url, browser;
try {
  ({ server, url } = await startServer(0, auth));
  browser = await chromium.launch({ headless: true });
  for (const variant of variants) {
    const context = await browser.newContext();
    await context.exposeFunction('untrustedHandshakeCount', () => auth.counts.handshake);
    if (process.env.WASM_TRACE) context.on('request', request => console.log(request.url()));
    const unexpected = [];
    let absentQuack = 0;
    const optionalQuack = `${url}/fixtures/extensions/${baseline.engineVersion}/${variant}/quack.duckdb_extension.wasm`;
    await context.route('**/*', async route => {
      if (route.request().url() === optionalQuack) {
        // LOAD attempts the optional Quack dependency even without autoinstall.
        // Model an unavailable artifact locally; never fetch a moving binary.
        absentQuack++;
        await route.fulfill({ status: 404, body: 'Optional Quack fixture: unavailable',
          headers: { 'Access-Control-Allow-Origin': url } });
      }
      else if (route.request().url().startsWith(url + '/')) await route.continue();
      else { unexpected.push(route.request().url()); await route.abort(); }
    });
    const page = await context.newPage();
    page.setDefaultTimeout(90_000);
    await page.exposeFunction('reportTest', message => console.log(`[${variant}] ${message}`));
    page.on('pageerror', error => { unexpected.push(error.message); console.error(error.message); });
    page.on('console', message => { if (message.type() === 'error' || process.env.WASM_TRACE) console.error(message.text().slice(0, 3000)); });
    await page.goto(url);
    await page.waitForFunction(() => typeof window.runSuite === 'function');
    let timer;
    const result = await Promise.race([
      page.evaluate(v => window.runSuite(v, message => window.reportTest(message)), variant),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${variant} exceeded 90s`)), 90_000); timer.unref(); }),
    ]).finally(() => clearTimeout(timer));
    assert.deepEqual(unexpected, [], 'Unexpected network access or uncaught browser errors');
    assert.equal(absentQuack, 1, 'Optional Quack dependency must be tested as unavailable');
    console.log(`[${variant}] PASS extension remains usable without optional Quack`);
    // Exercise the baseline/artifact guards in real workers, not only parser mocks.
    await context.route(url + '/baseline.json', route => route.fulfill({ json: { ...baseline, engineVersion: 'v1.4.4' } }));
    await assert.rejects(page.evaluate(v => window.runSuite(v), variant), /Expected v1\.4\.4, got v2\.0\.0/);
    await context.unroute(url + '/baseline.json');
    const artifactURL = `${url}/extension/${variant}/boilstream.duckdb_extension.wasm`;
    await context.route(artifactURL, route => route.fulfill({ status: 404, body: 'Missing artifact fixture' }));
    await assert.rejects(page.evaluate(v => window.runSuite(v), variant), /Missing .* extension; run/);
    await context.unroute(artifactURL);
    assert.deepEqual(unexpected, [], 'Guard tests caused unexpected network access or browser errors');
    console.log(`[${variant}] PASS wrong engine baseline and missing artifact fail the suite`);
    result.passed += 3; // optional dependency and two guard tests above
    console.log(JSON.stringify(result));
    const before = { ...auth.counts };
    let compatibilityTimer;
    const compatibility = await Promise.race([
      page.evaluate(variant => window.runSuite(variant, message => window.reportTest(message),
        { quack: true, untrustedPeer: true }), variant),
      new Promise((_, reject) => { compatibilityTimer = setTimeout(() => reject(new Error(`${variant} Quack compatibility exceeded 90s`)), 90_000); compatibilityTimer.unref(); }),
    ]).finally(() => clearTimeout(compatibilityTimer));
    assert.deepEqual(unexpected, [], 'Quack compatibility caused unexpected network access or browser errors');
    assert.equal(compatibility.quackCompatibility, 'supported', 'Quack compatibility is mandatory');
    console.log(JSON.stringify({ ...compatibility, protocol: auth.counts, mode: 'core-quack' }));
    auth.assertHealthy();
    assert.equal(auth.counts.handshake - before.handshake, 1, 'Forged peer must receive exactly one handshake');
    assert.equal(auth.counts.application - before.application, 0, 'No application message may precede server proof');
    await summary(`- ${variant}: public client rejection and Quack compatibility passed. Full authenticated qualification requires the private real-server gate.`);
    await context.close();
  }
} catch (error) {
  console.error("Untrusted-peer fixture progress:", auth.counts);
  auth.assertHealthy();
  throw error;
} finally {
  await browser?.close();
  if (server) {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}
