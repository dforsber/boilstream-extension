import * as duckdb from '@duckdb/duckdb-wasm/dist/duckdb-browser.mjs';
import { runSqlTests } from './sql-runner.js';

function assert(condition, message) { if (!condition) throw new Error(message); }
async function text(url) {
  const response = await fetch(url);
  assert(response.ok, `Missing test resource: ${url} (HTTP ${response.status})`);
  return response.text();
}
async function rejects(connection, sql, expected) {
  let error;
  try { await connection.query(sql); } catch (caught) { error = caught; }
  assert(error, `Expected rejection: ${sql}`);
  assert(expected.test(error.message), `Wrong rejection: ${error.message}`);
}

export async function runSuite(variant, report = () => {}, options = {}) {
  const baseline = JSON.parse(await text('/baseline.json'));
  assert(baseline.variants.includes(variant), `Unsupported WASM variant: ${variant}`);
  assert(duckdb.PACKAGE_VERSION === baseline.packageVersion, 'WASM package differs from baseline');
  assert(crossOriginIsolated, 'Thread-capable tests require cross-origin isolation');
  const threaded = variant === 'wasm_threads';
  const bundle = threaded ? 'threads' : 'base';
  const worker = new Worker(`/runtime/duckdb-browser-${bundle}.worker.js`);
  const db = new duckdb.AsyncDuckDB(new duckdb.VoidLogger(), worker);
  const connections = [];
  const connect = async () => { const c = await db.connect(); connections.push(c); return c; };
  let passed = 0;
  let quackCompatibility = options.quack ? 'supported' : 'not-requested';
  try {
    report(`Instantiating ${variant}`);
    await db.instantiate(`/runtime/duckdb-${bundle}.wasm`,
      threaded ? '/runtime/duckdb-browser-threads.pthread.worker.js' : undefined);
    // Load side modules before starting DuckDB's query workers. The pinned
    // runtime can stall in dlopen synchronization with an already running pool.
    await db.open({ allowUnsignedExtensions: true, maximumThreads: 1,
      query: { castBigIntToDouble: true } });
    const c = await connect();
    const version = (await c.query('SELECT version() AS version')).toArray()[0].version;
    assert(version === baseline.engineVersion, `Expected ${baseline.engineVersion}, got ${version}`);
    const platform = (await c.query('PRAGMA platform')).toArray()[0].platform;
    assert(platform === variant, `Expected platform ${variant}, got ${platform}`);
    report(`PASS ${version} / ${platform}`); passed++;
    // Keep this lane hermetic. Network-backed auth is a separate qualification.
    await c.query('SET autoinstall_known_extensions = false; SET autoload_known_extensions = false;');
    await c.query(`SET custom_extension_repository = '${location.origin}/fixtures/${options.quack ? 'core-extensions' : 'extensions'}'`);
    const extension = `${location.origin}/extension/${variant}/boilstream.duckdb_extension.wasm`;
    const response = await fetch(extension, { method: 'HEAD' });
    assert(response.ok, `Missing ${variant} extension; run ./build-wasm-fixed.sh ${variant}`);
    report(`Loading BoilStream into ${variant}`);
    await c.query(`LOAD '${extension}'`);
    const loaded = (await c.query("SELECT loaded FROM duckdb_extensions() WHERE extension_name = 'boilstream'")).toArray();
    assert(loaded.length === 1 && loaded[0].loaded === true, 'BoilStream was not loaded');
    report('PASS extension load'); passed++;
    if (options.quack) {
      const quack = (await c.query("SELECT loaded FROM duckdb_extensions() WHERE extension_name='quack'")).toArray();
      if (!(quack.length === 1 && quack[0].loaded)) {
        // Surface the loader's actual incompatibility instead of the optional
        // dependency loader's swallowed exception. Still require autoload success.
        let loadError;
        try { await c.query(`LOAD '${location.origin}/fixtures/core-extensions/${baseline.engineVersion}/${variant}/quack.duckdb_extension.wasm'`); }
        catch (error) { loadError = error; }
        if (!options.allowKnownQuackFailure || !threaded || !loadError ||
            !/did not contain the expected entrypoint function 'quack_duckdb_cpp_init'/.test(loadError.message)) {
          throw loadError || new Error('Required core Quack artifact did not autoload');
        }
        // The Node runner additionally requires the pinned artifact hash AND
        // the precise shared-memory LinkError emitted by the WASM worker.
        quackCompatibility = 'unsupported-shared-memory';
        assert((await c.query("SELECT loaded FROM duckdb_extensions() WHERE extension_name='quack'")).toArray()[0].loaded === false,
          'Quack unexpectedly registered after failed loading');
        assert((await c.query('SELECT 42 AS answer')).toArray()[0].answer === 42,
          'Connection unusable after the Quack loader failure');
        report('UNSUPPORTED core Quack: pinned threaded artifact imports non-shared memory; checking BoilStream recovery');
      }
      if (quackCompatibility === 'supported') {
      const type = (await c.query("SELECT default_provider, extension FROM duckdb_secret_types() WHERE type='quack'")).toArray();
      assert(type.length === 1 && type[0].default_provider === 'config' && type[0].extension === 'quack',
        'Quack secret type was missing or shadowed');
      await c.query("CREATE SECRET compatibility_secret (TYPE quack, TOKEN 'synthetic-client-token', SCOPE 'quack:127.0.0.1:1')");
      const secret = (await c.query("SELECT name, type FROM duckdb_secrets() WHERE name='compatibility_secret'")).toArray();
      assert(secret.length === 1 && secret[0].type === 'quack', 'Quack client secret was not registered');
      await c.query('DROP SECRET compatibility_secret');
      passed += 3;
      report('PASS core Quack loads, owns its secret type, and accepts a client secret');
      }
    }
    if (threaded) {
      await c.query('SET threads = 2');
      assert(Number((await c.query("SELECT current_setting('threads') AS n")).toArray()[0].n) === 2,
        'Threaded worker did not enable two query threads');
      report('PASS threaded execution enabled'); passed++;
    }
    for (const file of ['boilstream_pragmas.test', 'boilstream_grammar.test', 'quack_bridge.test']) {
      passed += await runSqlTests(await text(`/sql/${file}`), c, () => db.connect(), report);
    }
    if (threaded) {
      // range itself forces single-threaded execution. A materialized table has
      // multiple row groups available to the query worker pool.
      await c.query('CREATE TABLE authz_scan AS SELECT i FROM range(1000000) t(i)');
      const denied = await c.query("SELECT count(*) AS n FROM authz_scan WHERE boilstream_quack_authz(CAST(i AS VARCHAR), 'SELECT 1')");
      await c.query('DROP TABLE authz_scan');
      assert(Number(denied.toArray()[0].n) === 0, 'Threaded scan authorized an unowned session');
      report('PASS threaded authorization scan rejects every unowned session'); passed++;
    }
    // Negative result-table ownership/guessing: never expose an unowned auth result.
    const other = await connect();
    for (const connection of [c, other]) {
      await rejects(connection, 'SELECT * FROM boilstream_auth_result(1::UBIGINT)', /unavailable|expired|not found|invalid/i);
      assert((await connection.query("SELECT count(*) AS n FROM duckdb_secrets() WHERE storage='boilstream'")).toArray()[0].n === 0,
        'Unauthenticated connection exposed BoilStream secrets');
      assert((await connection.query('SELECT 42 AS answer')).toArray()[0].answer === 42, 'Connection unusable after rejection');
      passed += 3;
    }
    // Wrong extension content must cause a hard load failure, not a warning/pass.
    await rejects(c, `LOAD '${location.origin}/fixtures/corrupt.duckdb_extension.wasm'`, /metadata|magic|invalid.*extension/i);
    passed++;
    report(`PASS ${variant}: ${passed} checks`);
    return { variant, version, passed, quackCompatibility };
  } finally {
    for (const c of connections.reverse()) { try { await c.close(); } catch { /* terminate below */ } }
    await db.terminate();
    worker.terminate();
  }
}
