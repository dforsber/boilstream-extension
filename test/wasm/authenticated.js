// Run entirely through public SQL and the real WASM worker/HTTP/crypto path.
// No session injection, fixed session key, or mocked successful SQL result.
export async function runAuthenticatedTests(connect, report) {
  let passed = 0;
  const check = (ok, message) => { if (!ok) throw new Error(message); passed++; };
  const a = await connect(), b = await connect(), stranger = await connect();
  const bootstrap = (c, who) => c.query(`PRAGMA boilstream_bootstrap_session('${location.origin}/secrets/:synthetic-browser-${who}-password')`);
  const catalogs = async c => (await c.query('SELECT catalog_name FROM boilstream_ducklakes()')).toArray().map(r => r.catalog_name);
  const expectAccount = async (c, who) => check(JSON.stringify(await catalogs(c)) === JSON.stringify([`__BS_u42__${who}`]), 'Catalog identity leaked or name was rewritten');
  const reject = async (fn, message) => {
    let error; try { await fn(); } catch (caught) { error = caught; }
    check(Boolean(error), message);
    check(!/synthetic-browser-|ciphertext|credential_response|access_token/.test(error.message), 'Error disclosed authentication payload');
  };
  await bootstrap(a, 'alice'); await bootstrap(b, 'bob');
  await expectAccount(a, 'alice'); await expectAccount(b, 'bob');
  await reject(() => catalogs(stranger), 'Unauthenticated connection inherited a session');
  await reject(() => bootstrap(a, 'wrong'), 'Wrong password authenticated');
  await expectAccount(a, 'alice'); // Failed replacement must preserve the good session.
  await bootstrap(a, 'bob'); await expectAccount(a, 'bob');
  await expectAccount(b, 'bob'); // Replacing A cannot retire B, even with the same account.
  await bootstrap(a, 'alice'); await expectAccount(a, 'alice');
  report('PASS OPAQUE authentication, encrypted catalogs, connection isolation and account replacement');
  for (const fault of ['missing-signature', 'wrong-key', 'body-tamper', 'bad-ciphertext', 'stale-date']) {
    const control = await fetch('/fixtures/auth/control', { method: 'POST', body: JSON.stringify({ account: 'alice', fault }) });
    check(control.ok, 'Could not arm authenticated response fault');
    await reject(() => catalogs(a), `${fault} was accepted`);
    if (fault !== 'bad-ciphertext') await reject(() => catalogs(a), 'Forged response did not retire its session');
    await expectAccount(b, 'bob');
    await bootstrap(a, 'alice'); await expectAccount(a, 'alice');
  }
  report('PASS missing/forged/stale signatures, tampered body/ciphertext, isolated recovery');
  await a.close();
  const fresh = await connect();
  await reject(() => catalogs(fresh), 'Closed connection credentials were inherited');
  await expectAccount(b, 'bob');
  report(`PASS authenticated browser protocol: ${passed} assertions`);
  return passed;
}

// Baseline-specific failure regression, NOT successful authentication coverage.
// The pinned host discards all POST response headers. Remove this expectation
// and make runAuthenticatedTests mandatory when upgrading to a corrected host.
export async function runAuthTransportProbe(connect, report) {
  const c = await connect();
  let error;
  try {
    await c.query(`PRAGMA boilstream_bootstrap_session('${location.origin}/secrets/:synthetic-browser-alice-password')`);
  } catch (caught) { error = caught; }
  if (!error) throw new Error('POST transport now permits authentication: replace the baseline failure probe with mandatory authenticated coverage');
  if (!/^IO Error: Token exchange failed$/.test(error.message)) throw error;
  let catalogError;
  try { await c.query('SELECT * FROM boilstream_ducklakes()'); } catch (caught) { catalogError = caught; }
  if (!catalogError || !/No endpoint configured/.test(catalogError.message))
    throw new Error('Rejected login unexpectedly published a usable session');
  report('PASS fail-closed POST-header regression (successful browser authentication remains BLOCKED)');
  return 2;
}
