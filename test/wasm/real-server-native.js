#!/usr/bin/env node
// Native adapter for the same authentication assertions used by both browsers.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { runAuthenticatedScenario } from './authenticated-scenario.js';
import { readFileSync } from 'node:fs';
import { ensureNativeBuild } from './ensure-native-build.js';
const baseline = JSON.parse(readFileSync(new URL('./baseline.json', import.meta.url), 'utf8'));

const input = createInterface({ input: process.stdin });
const lines = input[Symbol.asyncIterator]();
async function read(iterator) {
  const line = await iterator.next();
  assert(!line.done && line.value.length <= 65536, 'Missing or oversized fixture reply');
  return JSON.parse(line.value);
}
const fixture = await read(lines);
assert.equal(new URL(fixture.authority).hostname, '127.0.0.1');
assert.equal(new URL(fixture.authority).protocol, 'http:');
assert.match(fixture.pin, /^[a-f0-9]{64}$/);
ensureNativeBuild(fixture.native);
const child = spawn(fixture.native.driver, [], { stdio: ['pipe', 'pipe', 'inherit'], env: { ...process.env, QUERY_FARM_TELEMETRY_OPT_OUT: '1' } });
const exited = once(child, 'exit');
const output = createInterface({ input: child.stdout });
const replies = output[Symbol.asyncIterator]();
let pending = Promise.resolve();
function command(request) {
  const next = pending.then(async () => {
    child.stdin.write(`${JSON.stringify(request)}\n`);
    return await read(replies);
  });
  pending = next.catch(() => {});
  return next;
}
const controls = async (control, extra = {}) => {
  console.log(JSON.stringify({ control, ...extra }));
  return await read(lines);
};
const connections = [];
const connect = async () => {
  const { connection } = await command({ op: 'connect' });
  assert(Number.isSafeInteger(connection));
  const c = {
    query: async sql => {
      const result = await command({ op: 'query', connection, sql });
      if (result.error) throw new Error(result.error);
      assert(Array.isArray(result.rows));
      return { toArray: () => result.rows };
    },
    close: () => command({ op: 'close', connection })
  };
  connections.push(c);
  return c;
};
let deadline;
const timeout = new Promise((_, reject) => {
  deadline = setTimeout(() => reject(new Error('Native protocol test deadline exceeded')), 120_000);
});
async function run() {
  child.stdin.write(`${JSON.stringify(fixture.native)}\n`);
  assert.equal((await read(replies)).ready, true);
  const c = await connect();
  assert.equal((await c.query('SELECT version() AS version')).toArray()[0].version, baseline.engineVersion);
  const quack = (await c.query("SELECT loaded FROM duckdb_extensions() WHERE extension_name='quack'")).toArray();
  assert.equal(quack.length, 1);
  assert.equal(quack[0].loaded, 'true');
  const result = await runAuthenticatedScenario(fixture, connect, c, {
    fixtureTotp: (uri, used = []) => controls('totp', { uri, used }),
    armProtocolFault: async () => assert.equal((await controls('arm-fault')).armed, true),
    protocolRequestCount: async () => (await controls('request-count')).count,
    revokeFixtureIdentity: async () => assert.equal((await controls('revoke')).revoked, true)
  });
  for (const connection of connections.reverse()) await connection.close();
  await command({ op: 'quit' });
  child.stdin.end();
  const [code, signal] = await exited;
  assert.equal(code, 0);
  assert.equal(signal, null);
  console.log(JSON.stringify({ result: { variant: 'native', ...result } }));
}
try {
  await Promise.race([run(), timeout]);
} finally {
  clearTimeout(deadline);
  child.stdin.destroy();
  if (child.exitCode === null && child.signalCode === null) child.kill();
  await exited;
  output.close();
  input.close();
  process.stdin.destroy();
}
