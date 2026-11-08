import { runAuthenticatedScenario } from './authenticated-scenario.js';
import * as duckdb from '@duckdb/duckdb-wasm/dist/duckdb-browser.mjs';

// The private harness supplies only public pins and synthetic one-use credentials.
// All authentication, encryption, SQL and HTTP execute in the loaded WASM client.
export async function runProtocolScenario(variant, fixture) {
  const baseline = await (await fetch('/baseline.json')).json();
  const check = (ok, message) => { if (!ok) throw new Error(message); };
  check(baseline.variants.includes(variant), 'Unknown WASM variant');
  check(duckdb.PACKAGE_VERSION === baseline.packageVersion, 'Package differs from baseline');
  check(crossOriginIsolated, 'Browser is not cross-origin isolated');
  const threaded = variant === 'wasm_threads';
  const bundle = threaded ? 'threads' : 'base';
  const worker = new Worker(`/runtime/duckdb-browser-${bundle}.worker.js`);
  const db = new duckdb.AsyncDuckDB(new duckdb.VoidLogger(), worker);
  const connections = [];
  const connect = async () => { const c = await db.connect(); connections.push(c); return c; };
  try {
    await db.instantiate(`/runtime/duckdb-${bundle}.wasm`,
      threaded ? '/runtime/duckdb-browser-threads.pthread.worker.js' : undefined);
    await db.open({ allowUnsignedExtensions: true, maximumThreads: 1, query: { castBigIntToDouble: true } });
    const c = await connect();
    check((await c.query('SELECT version() AS version')).toArray()[0].version === baseline.engineVersion,
      'Engine differs from DuckDB2.0 baseline');
    check((await c.query('PRAGMA platform')).toArray()[0].platform === variant, 'Wrong runtime variant');
    await c.query('SET autoinstall_known_extensions=false; SET autoload_known_extensions=false;');
    await c.query(`SET custom_extension_repository='${location.origin}/fixtures/core-extensions'`);
    await c.query(`LOAD '${location.origin}/extension/${variant}/boilstream.duckdb_extension.wasm'`);
    const quack = (await c.query("SELECT loaded FROM duckdb_extensions() WHERE extension_name='quack'")).toArray();
    check(quack.length === 1 && quack[0].loaded, 'Compatible Quack client did not load');
    if (threaded) {
      await c.query('SET threads=2');
      check(Number((await c.query("SELECT current_setting('threads') AS n")).toArray()[0].n) === 2,
        'Threaded query execution was not enabled');
    }
    const result = await runAuthenticatedScenario(fixture, connect, c, window);
    return { variant, ...result };
  } finally {
    for (const c of connections.reverse()) { try { await c.close(); } catch {} }
    await db.terminate();
    worker.terminate();
  }
}
