// Loopback protocol fixture, never a production service. Real OPAQUE is handled
// by a native test peer; Node crypto independently implements the wire envelope.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { createHash, createHmac, hkdfSync, randomBytes, createCipheriv } from 'node:crypto';
const root = fileURLToPath(new URL('../../', import.meta.url));
const hash = value => createHash('sha256').update(value).digest('hex');
const mac = (key, value) => createHmac('sha256', key).update(value).digest();
const derive = (key, info) => Buffer.from(hkdfSync('sha256', key, 'boilstream-session-v1', info, 32));
const date = () => new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
function canonicalHeaders(headers, excluded) {
  const names = Object.keys(headers).filter(n => n.startsWith('x-boilstream-') && n !== excluded).sort();
  return [names.map(n => `${n}:${headers[n]}\n`).join(''), names.join(';')];
}
function signResponse(key, body, headers, status = 200) {
  const [fields, names] = canonicalHeaders(headers, 'x-boilstream-response-signature');
  return mac(derive(key, 'response-integrity-v1'), `${status}\n${fields}\n${names}\n${hash(body)}`).toString('base64');
}
function encrypted(key, value, corrupt = false) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', derive(key, 'response-encryption-v1'), nonce);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final(), cipher.getAuthTag()]);
  const hmac = mac(derive(key, 'response-integrity-v1'), Buffer.concat([nonce, ciphertext])).toString('hex');
  if (corrupt) ciphertext[0] ^= 1; // Keep the outer signature valid to exercise decryption integrity.
  return JSON.stringify({ encrypted: true, nonce: nonce.toString('base64'), ciphertext: ciphertext.toString('base64'), hmac });
}

export async function startAuthFixture({ platform = 'wasm' } = {}) {
  // Cargo rechecks the exact source on every run; never execute a stale test peer.
  const child = spawn('cargo', ['run', '--quiet', '--locked', '--manifest-path', 'opaque-client/Cargo.toml',
    '--example', 'browser_peer'], { cwd: root, stdio: ['pipe', 'pipe', 'inherit'] });
  const pending = [];
  const lines = createInterface({ input: child.stdout });
  const failures = [];
  let stopped = false;
  const fail = error => { failures.push(error.message); for (const p of pending.splice(0)) p.reject(error); };
  child.on('error', fail);
  child.stdin.on('error', fail);
  child.on('exit', () => { if (!stopped) fail(new Error('OPAQUE fixture exited unexpectedly')); });
  lines.on('line', line => {
    const next = pending.shift();
    try { assert(next, 'Unexpected peer output'); const result = JSON.parse(line); assert(!result.error, result.error); next.resolve(result); }
    catch (error) { next?.reject(error); fail(error); }
  });
  const command = value => new Promise((resolve, reject) => {
    if (failures.length) { reject(new Error('OPAQUE fixture is unavailable')); return; }
    const timer = setTimeout(() => fail(new Error('OPAQUE fixture command timed out')), 120_000);
    pending.push({ resolve: v => { clearTimeout(timer); resolve(v); }, reject: e => { clearTimeout(timer); reject(e); } });
    child.stdin.write(JSON.stringify(value) + '\n');
  });
  const accounts = new Map(), handshakes = new Map(), sessions = new Map(), faults = new Map();
  const counts = { login: 0, finish: 0, requests: 0, encrypted: 0, catalogs: 0, secrets: 0, faults: 0 };
  async function close() {
    stopped = true;
    if (child.exitCode !== null || child.signalCode !== null || !child.pid) { lines.close(); return; }
    const exited = once(child, 'exit');
    child.stdin.end();
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    await exited.finally(() => { clearTimeout(timer); lines.close(); });
  }
  try {
    for (const account of ['alice', 'bob']) {
      const password = `synthetic-browser-${account}-password`;
      const user_id = hash(password);
      accounts.set(user_id, account);
      await command({ op: 'enroll', user_id, password });
    }
  } catch (error) { await close(); throw error; }
  async function handle(req, res) {
    const url = new URL(req.url, 'http://fixture.invalid');
    if (!['/auth/api/opaque-login-start', '/auth/api/opaque-login-finish', '/secrets',
      '/secrets/ducklakes', '/fixtures/auth/control'].includes(url.pathname)) return false;
    try {
      assert(!url.searchParams.has('multitenant'), 'Legacy tenant routing leaked onto the wire');
      let body = '';
      for await (const chunk of req) { body += chunk; assert(body.length <= 16384, 'Fixture request exceeds limit'); }
      const data = body ? JSON.parse(body) : {};
      let payload, key, fault;
      if (url.pathname === '/fixtures/auth/control') {
        assert.equal(req.method, 'POST');
        assert(['alice', 'bob'].includes(data.account));
        assert(['missing-signature', 'wrong-key', 'body-tamper', 'bad-ciphertext', 'stale-date'].includes(data.fault));
        faults.set(data.account, data.fault);
        payload = { ok: true };
      } else if (url.pathname.endsWith('opaque-login-start')) {
        assert.equal(req.method, 'POST');
        payload = await command({ ...data, op: 'start' });
        handshakes.set(payload.state_id, accounts.get(data.user_id));
        counts.login++;
      } else if (url.pathname.endsWith('opaque-login-finish')) {
        assert.equal(req.method, 'POST');
        const account = handshakes.get(data.state_id);
        assert(account, 'Unknown login identity');
        const result = await command({ ...data, op: 'finish' });
        handshakes.delete(data.state_id);
        key = Buffer.from(result.session_key, 'base64');
        const token = randomBytes(32).toString('hex');
        sessions.set(token, { account, key, sequence: -1 });
        payload = { success: true, access_token: token, expires_at: Math.floor(Date.now() / 1000) + 3600, region: 'fixture' };
        counts.finish++;
      } else {
        assert.equal(req.method, 'GET');
        const token = req.headers.authorization?.replace(/^Bearer /, '');
        const session = sessions.get(token);
        assert(session, 'Request has no authenticated session');
        key = session.key;
        const sequence = Number(req.headers['x-boilstream-sequence']);
        assert(Number.isSafeInteger(sequence) && sequence > session.sequence, 'Sequence reused or missing');
        const timestamp = req.headers['x-boilstream-date'];
        assert.match(timestamp, /^\d{8}T\d{6}Z$/);
        const day = timestamp.slice(0, 8);
        assert.equal(req.headers['x-boilstream-credential'], `${token.slice(0, 8)}/${day}/fixture/secrets/boilstream_request`);
        const [fields, names] = canonicalHeaders(req.headers, 'x-boilstream-signature');
        const canonical = `${req.method}\n${url.pathname}\n${url.search.slice(1)}\n${fields}\n${names}\n${hash(body)}`;
        let signingKey = derive(key, 'request-integrity-v1');
        for (const scope of [day, 'fixture', 'secrets', 'boilstream_request']) signingKey = mac(signingKey, scope);
        assert.equal(req.headers['x-boilstream-signature'], mac(signingKey, canonical).toString('base64'), 'Invalid request signature');
        session.sequence = sequence;
        counts.requests++;
        if (url.pathname === '/secrets') {
          assert.equal(url.searchParams.get('platform'), platform);
          payload = []; counts.secrets++;
        } else {
          // A name resembling the retired server prefix must survive unchanged.
          payload = { catalogs: [{ catalog_id: '00000000-0000-4000-8000-000000000001',
            catalog_name: `__BS_u42__${session.account}`, access_mode: 'read_only', ownership: 'owned' }] };
          counts.catalogs++;
          fault = faults.get(session.account); faults.delete(session.account);
          if (fault) counts.faults++;
        }
      }
      let response = JSON.stringify(payload);
      const headers = { 'content-type': 'application/json' };
      if (key) {
        response = encrypted(key, payload, fault === 'bad-ciphertext');
        headers['x-boilstream-date'] = fault === 'stale-date' ? '20000101T000000Z' : date();
        headers['x-boilstream-encrypted'] = 'true'; headers['x-boilstream-cipher'] = '0x0001';
        if (fault !== 'missing-signature') headers['x-boilstream-response-signature'] = signResponse(
          fault === 'wrong-key' ? randomBytes(64) : key, response, headers);
        if (fault === 'body-tamper') response += ' ';
        counts.encrypted++;
      }
      res.writeHead(200, headers).end(response);
    } catch (error) {
      failures.push(error.message);
      res.writeHead(500).end('Protocol fixture assertion failed');
    }
    return true;
  }
  return { handle, counts, assertHealthy() { assert.deepEqual(failures, [], 'Protocol fixture failures'); }, close };
}
