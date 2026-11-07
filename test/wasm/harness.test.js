import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { readFile, readdir } from 'node:fs/promises';
import { parseTests, runSqlTests } from './sql-runner.js';
import { startServer, baseline } from './server.js';

const table = values => ({ schema: { fields: [{ name: 'value' }] }, toArray: () => values.map(value => ({ value })) });
const queryTest = 'query I\nSELECT 42\n----\n42\n';
const failureTest = 'statement error\nREJECT\n----\nexpected rejection\n';

test('query result mismatches fail the suite', async () => {
  await assert.rejects(runSqlTests(queryTest, { query: async () => table([41]) }), /expected.*42.*got.*41/);
});
test('an expected error succeeding fails the suite', async () => {
  await assert.rejects(runSqlTests(failureTest, { query: async () => table([]) }), /expected rejection, succeeded/);
});
test('unrelated failures cannot satisfy a negative test', async () => {
  await assert.rejects(runSqlTests(failureTest, { query: async () => { throw Error('network unavailable'); } }), /expected error containing/);
});
test('unexpected query failures propagate', async () => {
  await assert.rejects(runSqlTests(queryTest, { query: async () => { throw Error('worker crashed'); } }), /worker crashed/);
});
test('label comparisons catch grammar/PRAGMA divergence and reject empty help', async () => {
  const source = 'query I nosort help\nHELP\n----\n\nquery I nosort help\nOTHER HELP\n----\n';
  let calls = 0;
  await assert.rejects(runSqlTests(source, { query: async () => table([++calls]) }), /expected.*1.*got.*2/);
  await assert.rejects(runSqlTests(source, { query: async () => table([]) }), /must not be empty/);
});
test('named connections are distinct and closed even on assertion failure', async () => {
  let closed = 0;
  const primary = { query: async () => { throw Error('wrong connection'); } };
  const named = { query: async () => table([41]), close: async () => { closed++; } };
  await assert.rejects(runSqlTests(queryTest.replace('query I', 'query I second'), primary, async () => named), /expected.*42/);
  assert.equal(closed, 1);
});
test('unknown directives and empty files cannot silently skip coverage', () => {
  for (const source of ['', 'require imaginary', 'skipif wasm', 'halt']) assert.throws(() => parseTests(source));
});
test('platform-specific errors remain explicit assertions and cannot skip tests', async () => {
  const source = '# wasm-error: unsupported on wasm\n' + failureTest;
  await assert.rejects(runSqlTests(source, { query: async () => { throw Error('expected rejection'); } }), /expected error containing/);
  assert.equal(await runSqlTests(source, { query: async () => { throw Error('unsupported on wasm'); } }), 1);
  for (const source of ['# wasm-error: orphan', '# wasm-error: x\n' + queryTest,
    'statement error\nREJECT\n----\n']) assert.throws(() => parseTests(source));
});
test('the real shared regression corpus is parsed without omissions', async () => {
  for (const name of ['boilstream_pragmas.test', 'boilstream_grammar.test', 'quack_bridge.test']) {
    const source = await readFile(new URL('../sql/' + name, import.meta.url), 'utf8');
    const tests = parseTests(source);
    assert.equal(tests.length, source.split('\n').filter(line => /^(query|statement) /.test(line)).length);
    assert(tests.length >= (name === 'quack_bridge.test' ? 5 : 20), `Unexpectedly small regression corpus: ${name}`);
    assert(tests.some(t => t.kind === 'query'));
    if (name !== 'quack_bridge.test') assert(tests.some(t => t.mode === 'error'));
  }
});
test('new SQL files require an explicit browser coverage decision', async () => {
  const files = (await readdir(new URL('../sql/', import.meta.url))).filter(name => name.endsWith('.test')).sort();
  assert.deepEqual(files, ['boilstream_grammar.test', 'boilstream_pragmas.test',
    'quack_attach_with_manual_secret.test', 'quack_bridge.test', 'quack_secret_autovend.test']);
  // These two require a real Quack artifact and are tracked in the integration
  // coverage table; they must not silently become no-dependency tests we omit.
  for (const name of ['quack_attach_with_manual_secret.test', 'quack_secret_autovend.test']) {
    const source = await readFile(new URL('../sql/' + name, import.meta.url), 'utf8');
    assert.match(source, /^require quack$/m);
  }
});
test('the installed WASM package matches the explicit 2.0 baseline', async () => {
  const pkg = JSON.parse(await readFile(new URL('./node_modules/@duckdb/duckdb-wasm/package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.version, baseline.packageVersion);
  assert.equal(baseline.engineVersion, 'v2.0.0');
  assert.deepEqual(baseline.variants, ['wasm_eh', 'wasm_threads']);
});
function get(url, path, headers = {}) {
  return new Promise((resolve, reject) => {
    request(url + '/', { path, headers }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks) }));
    }).on('error', reject).end();
  });
}
test('test server isolates assets, rejects traversal and never proxies credentials', async () => {
  const { server, url } = await startServer();
  try {
    for (const path of ['/build/../../.git/config', '/build/%2e%2e/%2e%2e/.git/config',
      '/runtime/../package.json', '/auth/email/login', '/secrets', '/sql/../README.md']) {
      assert.equal((await get(url, path)).status, 404, path);
    }
    assert.equal((await get(url, '/%ZZ')).status, 400);
    const response = await get(url, '/baseline.json');
    assert.equal(response.status, 200);
    assert.equal(response.headers['cross-origin-opener-policy'], 'same-origin');
    assert.equal(response.headers['cross-origin-embedder-policy'], 'require-corp');
    assert.equal(response.headers['access-control-allow-origin'], undefined);
    const partial = await get(url, '/baseline.json', { Range: 'bytes=0-9' });
    assert.equal(partial.status, 206);
    assert.deepEqual(partial.body, response.body.subarray(0, 10));
    assert.equal((await get(url, '/baseline.json', { Range: 'bytes=999999-' })).status, 416);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('threaded Quack checks the actual shared-memory import, not the filename', async () => {
  const { memoryImports } = await import('./quack-build.js');
  const module = shared => new Uint8Array([
    0, 97, 115, 109, 1, 0, 0, 0, // WASM v1
    2, 16, 1, 3, 101, 110, 118, 6, 109, 101, 109, 111, 114, 121,
    2, shared ? 3 : 1, 0, 1,
  ]);
  assert.deepEqual(memoryImports(module(true)), [{ module: 'env', field: 'memory', shared: true }]);
  assert.deepEqual(memoryImports(module(false)), [{ module: 'env', field: 'memory', shared: false }]);
  assert.throws(() => memoryImports(module(true).subarray(0, 16)), /Truncated/);
});
test('Quack receipts reject changed source inputs and replaced artifacts', async () => {
  const { verifyQuackBuild, sha256 } = await import('./quack-build.js');
  const bytes = Buffer.from('synthetic artifact');
  const inputs = { revision: 'pinned-source' };
  assert.throws(() => verifyQuackBuild(bytes, { inputs: { revision: 'different' }, sha256: sha256(bytes) }, inputs), /inputs changed/);
  assert.throws(() => verifyQuackBuild(bytes, { inputs, sha256: 'wrong' }, inputs), /differs from its build receipt/);
});


test('BoilStream receipts reject changed source and altered artifacts', async () => {
  const { verifyWasmBuild } = await import('./build-inputs.js');
  const { sha256 } = await import('./quack-build.js');
  const bytes = Buffer.from('synthetic artifact');
  const inputs = { variant: 'wasm_threads', source: { 'module.rs': 'original' } };
  const receipt = { inputs, sha256: sha256(bytes) };
  verifyWasmBuild(bytes, receipt, inputs);
  assert.throws(() => verifyWasmBuild(bytes, receipt, { ...inputs, source: { 'module.rs': 'changed' } }), /inputs changed/);
  assert.throws(() => verifyWasmBuild(Buffer.from('old artifact'), receipt, inputs), /differs from its build receipt/);
});
