#!/usr/bin/env node
// Invoked by the private real-server fixture. No server crypto or private keys.
import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { chromium } from 'playwright';
import { ensureWasmBuild } from './ensure-build.js';
import { startServer, baseline, artifactPath } from './server.js';

const variant = process.argv[2];
assert(baseline.variants.includes(variant), 'Explicit baseline variant is required');
ensureWasmBuild(variant);
await access(artifactPath(variant));
process.env.WASM_VARIANTS = variant;
await import('./prepare-compatibility.js');
const input = createInterface({ input: process.stdin });
const lines = input[Symbol.asyncIterator]();
const configuration = await lines.next();
assert(!configuration.done && configuration.value.length <= 8192, 'Missing or oversized fixture configuration');
const fixture = JSON.parse(configuration.value);
const authority = new URL(fixture.authority);
assert.equal(authority.protocol, 'http:');
assert.equal(authority.hostname, '127.0.0.1', 'Real-server tests only contact loopback');
assert.equal(authority.origin, fixture.authority);
assert.match(fixture.pin, /^[a-f0-9]{64}$/);
assert.match(fixture.wrongPin, /^[a-f0-9]{64}$/);
const { server, url } = await startServer();
let browser;
const counts = { handshake: 0, request: 0, tampered: 0 };
const errors = [];
let fault = false, deadline;
const timeout = new Promise((_, reject) => {
  deadline = setTimeout(() => reject(new Error('Real-server browser test deadline exceeded')), 120_000);
  deadline.unref();
});
async function runBrowser() {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  await context.exposeFunction('armProtocolFault', () => { assert(!fault); fault = true; });
  await context.exposeFunction('protocolRequestCount', () => counts.request);
  await context.exposeFunction('revokeFixtureIdentity', async () => {
    // Only the private parent can change fixture identity state. No test control
    // route or credential is exposed over HTTP or added to the production server.
    console.log(JSON.stringify({ control: 'revoke' }));
    const reply = await lines.next();
    assert(!reply.done && reply.value.length <= 8192, 'Missing revocation acknowledgement');
    assert.equal(JSON.parse(reply.value).revoked, true);
  });
  await context.route('**/*', async route => {
    try {
      const request = route.request(), target = new URL(request.url());
      if (target.origin === url) return await route.continue();
      assert.equal(target.origin, fixture.authority, 'Unexpected non-fixture traffic');
      assert(['/auth/api/protocol/v2/handshake', '/auth/api/protocol/v2/request'].includes(target.pathname));
      const cors = { 'access-control-allow-origin': url, 'access-control-allow-methods': 'POST, OPTIONS',
        'access-control-allow-headers': '*', 'content-type': 'text/plain' };
      if (request.method() === 'OPTIONS') return await route.fulfill({ status: 204, headers: cors });
      assert.equal(request.method(), 'POST');
      const body = request.postDataBuffer();
      assert(body && ![fixture.password, fixture.siblingPassword].some(password => body.includes(password)), 'Credential exposed on plaintext wire');
      const handshake = target.pathname.endsWith('/handshake');
      assert(body.toString().startsWith(handshake ? 'BH2.c.' : 'BS2.'), 'Unprotected application request');
      counts[handshake ? 'handshake' : 'request']++;
      const reply = await fetch(request.url(), { method: 'POST', redirect: 'manual', body, headers: { 'content-type': 'text/plain' }, signal: AbortSignal.timeout(15_000) });
      let bytes = Buffer.from(await reply.arrayBuffer());
      // No response security metadata survives this proxy, even if the host
      // starts exposing POST headers in a future runtime.
      if (!handshake && fault) {
        assert.equal(reply.status, 200, 'Fault must alter an actual encrypted server response');
        assert(bytes.length > 32);
        bytes[32] = bytes[32] === 65 ? 66 : 65;
        fault = false;
        counts.tampered++;
      }
      await route.fulfill({ status: reply.status, headers: cors, body: bytes });
    } catch (error) { errors.push(error); await route.abort(); }
  });
  const page = await context.newPage();
  page.on('pageerror', error => errors.push(error));
  await page.goto(url);
  await page.waitForFunction(() => typeof window.runProtocolScenario === 'function');
  const result = await page.evaluate(({ variant, fixture }) => window.runProtocolScenario(variant, fixture), { variant, fixture });
  assert.deepEqual(errors, [], 'Browser protocol proxy failed');
  assert.equal(counts.tampered, 1, 'Tampered reply did not reach the loaded client');
  assert(counts.request >= 6 && counts.handshake >= 3, 'Scenario did not reach the actual server');
  console.log(JSON.stringify({ result: { ...result, counts } }));
}
try {
  await Promise.race([runBrowser(), timeout]);
} catch (error) {
  console.error('Real-server browser failure:', error, errors, counts);
  throw error;
} finally {
  clearTimeout(deadline);
  input.close();
  process.stdin.destroy();
  await browser?.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
