// The positive native control lives in the private real-server gate.
// This public check verifies the client releases no credentials to an impostor.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';
import { createUntrustedPeer } from './untrusted-peer.js';
import { untrustedPin, untrustedPassword } from './untrusted-values.js';
const root = resolve(import.meta.dirname, '../..');
execFileSync('cmake', ['--build', resolve(root, 'build/release'), '--parallel', process.env.CMAKE_BUILD_PARALLEL_LEVEL || '2'], { stdio: 'inherit' });
const fixture = createUntrustedPeer();
const server = createServer(async (req, res) => {
  if (!await fixture.handle(req, res)) res.writeHead(404).end();
});
try {
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  const quote = value => "'" + value.replaceAll("'", "''") + "'";
  const sql = `SET autoinstall_known_extensions=false; SET autoload_known_extensions=false;
    LOAD httpfs; LOAD ${quote(resolve(root, 'build/release/extension/boilstream/boilstream.duckdb_extension'))};`;
  const login = `PRAGMA boilstream_bootstrap_session('${url}/secrets/:${untrustedPassword}');`;
  for (const pin of [false, true]) {
    let error;
    try {
      await promisify(execFile)(resolve(root, 'build/release/duckdb'), ['-unsigned', '-batch', '-csv', '-noheader', '-c',
        sql + (pin ? `PRAGMA boilstream_server_key('${url}', '${untrustedPin}');` : '') + login],
      { timeout: 30_000, env: { ...process.env, QUERY_FARM_TELEMETRY_OPT_OUT: '1' } });
    } catch (caught) { error = caught; }
    assert(error && error.code === 1, 'Missing/forged proof must fail SQL, not crash or time out');
    assert.match(error.stderr, /Token exchange failed/);
    assert(!error.stderr.includes(untrustedPassword), 'Authentication error disclosed password');
    assert.equal(fixture.counts.handshake, pin ? 1 : 0);
    assert.equal(fixture.counts.application, 0);
    fixture.assertHealthy();
  }
  console.log('PASS native missing pin and forged proof reject before application credentials');
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
