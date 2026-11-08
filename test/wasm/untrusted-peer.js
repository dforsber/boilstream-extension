// Deliberately incapable of authenticating: no server keys or server crypto.
// A 200 response and forged legacy headers must never authorize credentials.
import assert from 'node:assert/strict';
import { untrustedPassword } from './untrusted-values.js';
export function createUntrustedPeer() {
  const counts = { handshake: 0, application: 0 };
  const errors = [];
  return {
    counts,
    assertHealthy() { assert.deepEqual(errors, []); },
    async handle(req, res) {
      if (!req.url.startsWith('/auth/api/protocol/')) return false;
      try {
        assert.equal(req.method, 'POST');
        let body = '';
        for await (const chunk of req) {
          body += chunk.toString();
          assert(body.length <= 4096, 'Unexpectedly large pre-authentication request');
        }
        assert(!body.includes(untrustedPassword), 'Password sent before server proof');
        if (req.url.endsWith('/request')) counts.application++;
        assert.equal(req.url, '/auth/api/protocol/v2/handshake');
        assert(body.startsWith('BH2.c.'), 'Expected actual client handshake');
        counts.handshake++;
        res.writeHead(200, {
          'Content-Type': 'text/plain', 'Set-Cookie': 'session=forged',
          'X-Boilstream-Session-Resumption': 'enabled',
          'X-Boilstream-Signature': 'forged', 'X-Boilstream-Timestamp': String(Date.now()),
        }).end('{"status":200,"body":"forged-success"}');
      } catch (error) { errors.push(error); res.writeHead(500).end('Fixture rejected request'); }
      return true;
    },
  };
}
