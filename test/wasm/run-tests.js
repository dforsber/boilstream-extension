#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile, access, appendFile } from 'node:fs/promises';
import { startAuthFixture } from './auth-fixture.js';
import { chromium } from 'playwright';
import { dirname, join } from 'node:path';
import { wasmBuildInputs, verifyWasmBuild } from './build-inputs.js';
import { startServer, baseline, artifactPath } from './server.js';

const authenticated = process.argv.includes('--authenticated');
async function summary(message) {
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, message + '\n');
}
const variants = process.env.WASM_VARIANTS ? process.env.WASM_VARIANTS.split(',') : baseline.variants;
assert(variants.length > 0 && variants.every(v => baseline.variants.includes(v)), 'Invalid WASM_VARIANTS');
const pkg = JSON.parse(await readFile(new URL('./node_modules/@duckdb/duckdb-wasm/package.json', import.meta.url), 'utf8'));
assert.equal(pkg.version, baseline.packageVersion, 'Run npm ci to install the exact baseline');
for (const variant of variants) {
  try { await access(artifactPath(variant)); }
  catch { throw new Error(`Missing ${artifactPath(variant)}; run ./build-wasm-fixed.sh ${variant} from the repository root`); }
  let receipt;
  try { receipt = JSON.parse(await readFile(join(dirname(artifactPath(variant)), 'boilstream.build.json'), 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') throw new Error(`Missing ${variant} build receipt; run ./build-wasm-fixed.sh ${variant}`);
    throw error;
  }
  verifyWasmBuild(await readFile(artifactPath(variant)), receipt, await wasmBuildInputs(baseline, variant));
}
await import('./prepare-compatibility.js');
const auth = await startAuthFixture();
let server, url, browser;
try {
  ({ server, url } = await startServer(0, auth));
  browser = await chromium.launch({ headless: true });
  const hardDeadline = setTimeout(() => { console.error('Browser test process exceeded its cleanup deadline'); process.exit(1); }, 250_000 * variants.length);
  hardDeadline.unref();
  for (const variant of variants) {
    const context = await browser.newContext();
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
      page.evaluate(({ variant, authenticated }) => window.runSuite(variant, message => window.reportTest(message),
        { quack: true, authenticated, authTransportProbe: !authenticated }), { variant, authenticated }),
      new Promise((_, reject) => { compatibilityTimer = setTimeout(() => reject(new Error(`${variant} Quack compatibility exceeded 90s`)), 90_000); compatibilityTimer.unref(); }),
    ]).finally(() => clearTimeout(compatibilityTimer));
    assert.deepEqual(unexpected, [], 'Quack compatibility caused unexpected network access or browser errors');
    assert.equal(compatibility.quackCompatibility, 'supported', 'Quack compatibility is mandatory');
    console.log(JSON.stringify({ ...compatibility, protocol: auth.counts, mode: 'core-quack' }));
    auth.assertHealthy();
    if (authenticated) {
      assert.equal(auth.counts.faults - before.faults, 5, 'Every forged response must reach the browser');
      assert(auth.counts.finish - before.finish >= 8, 'Real authentication and recovery must complete');
      assert(auth.counts.secrets - before.secrets >= 8, 'Bootstrap must fetch authenticated secrets');
      assert(auth.counts.catalogs - before.catalogs >= 20, 'Catalog and isolation checks must reach the authority');
      await summary(`- ${variant}: strict authenticated browser qualification passed.`);
    } else {
      assert.equal(auth.counts.login - before.login, 1, 'Transport probe must send OPAQUE start');
      assert.equal(auth.counts.finish - before.finish, 1, 'Transport probe must complete real OPAQUE');
      assert.equal(auth.counts.encrypted - before.encrypted, 1, 'Transport probe must receive a signed encrypted reply');
      assert.equal(auth.counts.requests - before.requests, 0, 'Failed authentication must publish no usable session');
      const blocker = `${variant}: **Successful authenticated browser coverage is BLOCKED.** The pinned host drops POST response headers. The passing test proves rejection without publishing a session, not successful login.`;
      console.log(`[${variant}] BLOCKED successful authenticated coverage: baseline POST discards response headers; run npm run test:authenticated`);
      await summary(`- ${blocker} Run npm run test:authenticated after correcting the host. See test/wasm/WASM_TEST_STATUS.md.`);
    }
    await context.close();
  }
} catch (error) {
  console.error("Authenticated fixture progress:", auth.counts);
  auth.assertHealthy();
  throw error;
} finally {
  await browser?.close();
  await auth.close();
  if (server) await new Promise(resolve => server.close(resolve));
}
