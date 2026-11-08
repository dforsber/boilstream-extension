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
  for (const name of ['boilstream_pragmas.test', 'boilstream_grammar.test', 'client_boundary.test']) {
    const source = await readFile(new URL('../sql/' + name, import.meta.url), 'utf8');
    const tests = parseTests(source);
    assert.equal(tests.length, source.split('\n').filter(line => /^(query|statement) /.test(line)).length);
    assert(tests.length >= (name === 'client_boundary.test' ? 5 : 20), `Unexpectedly small regression corpus: ${name}`);
    assert(tests.some(t => t.kind === 'query'));
    if (name !== 'client_boundary.test') assert(tests.some(t => t.mode === 'error'));
  }
});
test('new SQL files require an explicit browser coverage decision', async () => {
  const files = (await readdir(new URL('../sql/', import.meta.url))).filter(name => name.endsWith('.test')).sort();
  assert.deepEqual(files, ['boilstream_grammar.test', 'boilstream_pragmas.test', 'client_boundary.test',
    'quack_attach_with_manual_secret.test', 'quack_secret_autovend.test']);
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
test('threaded Quack rejects non-shared modules and missing entrypoints', async () => {
  const { assertThreadedQuack } = await import('./quack-build.js');
  const module = shared => new Uint8Array([
    0, 97, 115, 109, 1, 0, 0, 0,
    2, 16, 1, 3, 101, 110, 118, 6, 109, 101, 109, 111, 114, 121,
    2, shared ? 3 : 1, 0, 1,
  ]);
  assert.throws(() => assertThreadedQuack(module(false)), /must import shared memory/);
  assert.throws(() => assertThreadedQuack(module(true)), /Missing real Quack entrypoint/);
});

// A mismatched header/library selection must fail before any build or SQL runs.
test('native driver refuses source or extension from a different build tree', async () => {
  const { mkdtemp, mkdir, writeFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { assertNativeSelection } = await import('./ensure-native-build.js');
  const root = await mkdtemp(join(tmpdir(), 'boilstream-native-selection-'));
  try {
    for (const part of ['source', 'other', 'build/extension/boilstream'])
      await mkdir(join(root, part), { recursive: true });
    const extension = join(root, 'build/extension/boilstream/boilstream.duckdb_extension');
    await writeFile(extension, 'synthetic-not-loadable');
    await writeFile(join(root, 'other.duckdb_extension'), 'synthetic-not-loadable');
    await writeFile(join(root, 'build/CMakeCache.txt'), `CMAKE_HOME_DIRECTORY:INTERNAL=${join(root, 'source')}\n`);
    const selected = { source: join(root, 'source'), build: join(root, 'build'), extension,
      driver: join(root, 'runner/native_protocol_driver') };
    assertNativeSelection(selected);
    assert.throws(() => assertNativeSelection({ ...selected, source: join(root, 'other') }), /same selected tree/);
    assert.throws(() => assertNativeSelection({ ...selected, extension: join(root, 'other.duckdb_extension') }), /selected build tree/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

// Exercise the real shell entrypoint with a pre-existing archive and a failing
// compiler. Existence must never let a stale object bypass the required build.
test('FFI runner refuses a failed build even when an old archive exists', async () => {
  const { mkdtemp, mkdir, writeFile, copyFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { spawnSync } = await import('node:child_process');
  const root = await mkdtemp(join(tmpdir(), 'boilstream-ffi-build-'));
  try {
    for (const part of ['opaque-client/test-wasm', 'test/wasm', 'bin',
      'build/wasm-ffi-rust/wasm32-unknown-emscripten/release'])
      await mkdir(join(root, part), { recursive: true });
    await copyFile(new URL('../../opaque-client/test-wasm/test-ffi.sh', import.meta.url),
      join(root, 'opaque-client/test-wasm/test-ffi.sh'));
    await writeFile(join(root, 'test/wasm/baseline.json'), JSON.stringify(baseline));
    await writeFile(join(root, 'build/wasm-ffi-rust/wasm32-unknown-emscripten/release/libopaque_client.a'),
      'stale-fixture-not-a-library');
    await writeFile(join(root, 'bin/cargo'), '#!/bin/sh\necho "fixture compiler failure" >&2\nexit 17\n', { mode: 0o755 });
    await writeFile(join(root, 'bin/emcc'), `#!/bin/sh
if [ "$1" = --version ]; then
  echo 'emcc (Emscripten) ${baseline.emscriptenVersion}'
else
  echo 'unexpected link after build failure' >&2
  exit 99
fi
`, { mode: 0o755 });
    const env = { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}` };
    delete env.BOILSTREAM_RUST_WASM_LIB;
    delete env.WASM_BUILD_TYPE;
    const result = spawnSync('bash', [join(root, 'opaque-client/test-wasm/test-ffi.sh')],
      { env, encoding: 'utf8', timeout: 10_000 });
    assert.ifError(result.error);
    assert.equal(result.status, 17, result.stderr);
    assert.match(result.stderr, /fixture compiler failure/);
    assert.doesNotMatch(result.stderr, /unexpected link/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
