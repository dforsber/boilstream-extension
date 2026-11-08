// Exercises the loaded client before any OPAQUE password message can be sent.
import { untrustedPin, untrustedPassword } from './untrusted-values.js';
export async function runUntrustedPeerTests(connect, report) {
  const c = await connect();
  const refuse = async (sql, expected) => {
    let error;
    try { await c.query(sql); } catch (caught) { error = caught; }
    if (!error || !expected.test(error.message)) throw new Error(`Wrong refusal: ${error?.message}`);
    if (error.message.includes(untrustedPassword)) throw new Error('Authentication error disclosed password');
  };
  const login = `PRAGMA boilstream_bootstrap_session('${location.origin}/secrets/:${untrustedPassword}')`;
  const before = await window.untrustedHandshakeCount();
  await refuse(login, /Token exchange failed/);
  if (await window.untrustedHandshakeCount() !== before) throw new Error('Missing pin caused network I/O');
  await c.query(`PRAGMA boilstream_server_key('${location.origin}', '${untrustedPin}')`);
  await refuse(login, /Token exchange failed/);
  if (await window.untrustedHandshakeCount() !== before + 1) throw new Error('Forged proof did not reach the verifier exactly once');
  await refuse('SELECT * FROM boilstream_ducklakes()', /No endpoint configured/);
  report('PASS missing pin and forged server proof rejected without publishing identity');
  return 3;
}
