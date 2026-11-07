// Positive control: prove the fixture is accepted by the real native client.
// This distinguishes the browser host's lost headers from invalid test crypto.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';
import { startAuthFixture } from './auth-fixture.js';
const root = resolve(import.meta.dirname, '../..');
const fixture = await startAuthFixture({ platform: null });
const server = createServer(async (req, res) => {
  if (!await fixture.handle(req, res)) res.writeHead(404).end();
});
try {
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  const quote = value => "'" + value.replaceAll("'", "''") + "'";
  const sql = [`LOAD httpfs; LOAD ${quote(resolve(root, 'build/release/extension/boilstream/boilstream.duckdb_extension'))};`];
  for (const account of ['alice', 'bob', 'alice']) {
    sql.push(`PRAGMA boilstream_bootstrap_session('${url}/secrets/:synthetic-browser-${account}-password');`);
    sql.push(`SELECT CASE WHEN count(*)=1 AND min(catalog_name)='__BS_u42__${account}' THEN 1 ELSE error('Wrong catalog owner') END FROM boilstream_ducklakes();`);
  }
  await promisify(execFile)(resolve(root, 'build/release/duckdb'), ['-unsigned', '-batch', '-json', '-c', sql.join('\n')],
    { timeout: 60_000, env: { ...process.env, QUERY_FARM_TELEMETRY_OPT_OUT: '1' } });
  fixture.assertHealthy();
  assert.equal(fixture.counts.finish, 3);
  assert.equal(fixture.counts.secrets, 3);
  assert.equal(fixture.counts.catalogs, 3);
  console.log('PASS native public SQL accepts fixture OPAQUE, signatures, encrypted catalogs and account replacement');
} finally {
  await fixture.close();
  await new Promise(resolve => server.close(resolve));
}
