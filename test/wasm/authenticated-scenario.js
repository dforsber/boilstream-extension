// One behavioral contract for actual native and browser clients. The injected
// connection adapter executes SQL; controls only operate the private test fixture.
export async function runAuthenticatedScenario(fixture, connect, c, controls) {
  const check = (ok, message) => { if (!ok) throw new Error(message); };
  const quote = value => `'${value.replaceAll("'", "''")}'`;
  const login = (c, password = fixture.password) => c.query(`PRAGMA boilstream_bootstrap_session(${quote(`${fixture.authority}/secrets/:${password}`)})`);
  const resume = c => c.query('PRAGMA boilstream_resume_session');
  const pin = (c, key) => c.query(`PRAGMA boilstream_server_key(${quote(fixture.authority)}, ${quote(key)})`);
  const refuse = async (action, label, expected) => {
    let error; try { await action(); } catch (e) { error = e; }
    check(error, `${label} was accepted`);
    check(![fixture.password, fixture.siblingPassword, fixture.registrationPassword].some(value => error.message.includes(value)), `${label} disclosed credentials`);
    if (expected) check(expected.test(error.message), `${label} failed for an unrelated reason: ${error.message}`);
  };
  // Real registration ownership, email login and MFA. The private coordinator
  // generates codes from the URI actually returned by this loaded client.
  const a = await connect(), b = await connect();
  await Promise.all([a, b].map(connection => pin(connection, fixture.pin)));
  const register = async (connection, email) => {
    const rows = (await connection.query(`PRAGMA boilstream_register_user(${quote(`${fixture.authority}/${email}`)}, ${quote(fixture.registrationPassword)})`)).toArray();
    check(rows.length === 3, 'Manual enrollment result is missing');
    const uri = rows[2].qr_code;
    const parsed = new URL(uri);
    check(parsed.protocol === 'otpauth:' && parsed.hostname === 'totp', 'Enrollment URI is invalid');
    check(parsed.searchParams.get('algorithm') === 'SHA512', 'TOTP algorithm differs from server');
    check(rows[0].qr_code.replaceAll(' ', '') === parsed.searchParams.get('secret'), 'Displayed secret differs from URI');
    return uri;
  };
  const verify = (connection, code) => connection.query(`PRAGMA boilstream_verify_mfa(${quote(code)})`);
  const [uriA, uriB] = await Promise.all([register(a, 'client-a@example.test'), register(b, 'client-b@example.test')]);
  check(uriA !== uriB, 'Parallel registrations shared enrollment data');
  check(await register(a, 'client-a@example.test') === uriA, 'Same account lost cached enrollment');
  check(await register(a, 'client-c@example.test') !== uriA, 'Account replacement reused old enrollment');
  await refuse(() => register(a, 'client-b@example.test'), 'Duplicate registration');
  await refuse(() => verify(a, '123456'), 'Failed signup retained old identity');
  const uriD = await register(a, 'client-d@example.test');
  const totpB = await controls.fixtureTotp(uriB);
  await refuse(() => verify(b, totpB.wrong), 'Incorrect enrollment code', /HTTP 401/);
  const recoveryB = (await verify(b, totpB.code)).toArray().map(row => row.backup_code);
  check(recoveryB.length === 10 && new Set(recoveryB).size === 10 && recoveryB.every(code => typeof code === 'string' && code.length > 0), 'Recovery codes were not returned');
  await refuse(() => verify(b, totpB.code), 'Completed registration reused its cookie');
  const totpD = await controls.fixtureTotp(uriD);
  check((await verify(a, totpD.code)).toArray().length === 10, 'Sibling completion destroyed pending enrollment');
  const loginB = code => b.query(`PRAGMA boilstream_login(${quote(`${fixture.authority}/client-b@example.test`)}, ${quote(fixture.registrationPassword)}, ${quote(code)})`);
  await refuse(() => loginB(totpB.code), 'Replayed enrollment TOTP', /HTTP 429/);
  const fresh = await controls.fixtureTotp(uriB, [totpB.code]);
  await loginB(fresh.code);
  check((await b.query('SELECT * FROM boilstream_secrets()')).toArray().length === 0, 'Email user inherited another tenant');
  await b.query("CREATE PERSISTENT SECRET email_owned IN boilstream (TYPE quack, TOKEN 'synthetic-email-secret', SCOPE 'quack:127.0.0.1:1')");
  check((await b.query('SELECT name FROM boilstream_secrets()')).toArray()[0].name === 'email_owned', 'Email login did not authorize secret access');
  await refuse(() => login(c), 'Missing pin');
  await pin(c, fixture.wrongPin);
  await refuse(() => login(c), 'Wrong installation pin');
  await pin(c, fixture.pin);
  await login(c);
  const names = async () => (await c.query('SELECT name FROM boilstream_secrets() ORDER BY name')).toArray().map(r => r.name);
  check((await names()).length === 0, 'Another tenant secret was returned before creation');
  await c.query("CREATE PERSISTENT SECRET browser_fixture IN boilstream (TYPE quack, TOKEN 'synthetic-secret', SCOPE 'quack:127.0.0.1:1')");
  check(JSON.stringify(await names()) === JSON.stringify(['browser_fixture']), 'Created secret was missing or tenant isolation failed');
  // Rotate twice: reusing the first one-use refresh token would fail on the
  // second renewal. A configured pin change cannot silently repin a live flow.
  for (const key of [fixture.pin, fixture.wrongPin]) {
    await pin(c, key);
    const beforeResume = await controls.protocolRequestCount();
    const beforeHandshake = await controls.protocolHandshakeCount();
    check((await resume(c)).toArray()[0].status === 'Session resumed', 'Renewal was not acknowledged');
    check(await controls.protocolRequestCount() === beforeResume + 2, 'Renewal must perform one new OPAQUE exchange');
    check(await controls.protocolHandshakeCount() === beforeHandshake + 1, 'Renewal reused an old channel');
    check(JSON.stringify(await names()) === JSON.stringify(['browser_fixture']), 'Renewal lost its tenant or data');
  }
  await controls.verifyResumptionState();
  await pin(c, fixture.pin);
  await c.query('DROP PERSISTENT SECRET browser_fixture FROM boilstream');
  check((await names()).length === 0, 'Deleted secret was still returned');
  const other = await connect();
  await refuse(() => resume(other), 'Unauthenticated resumption', /authenticated connection/);
  await refuse(() => other.query('SELECT * FROM boilstream_secrets()'), 'Unauthenticated connection');
  await pin(other, fixture.pin);
  await refuse(() => login(other), 'Reused bootstrap');
  await login(other, fixture.siblingPassword);
  const siblings = await Promise.all([c, other].map(connection => connection.query('SELECT * FROM boilstream_secrets()')));
  check(siblings.every(result => result.toArray().length === 0), 'Concurrent connections mixed secret results');
  await controls.armProtocolFault();
  const beforeFault = await controls.protocolRequestCount();
  await refuse(() => c.query("CREATE PERSISTENT SECRET tampered_fixture IN boilstream (TYPE quack, TOKEN 'synthetic-secret', SCOPE 'quack:127.0.0.1:1')"), 'Forged encrypted response');
  check(await controls.protocolRequestCount() === beforeFault + 1, 'Failed request was retried');
  await refuse(() => c.query('SELECT * FROM boilstream_secrets()'), 'Retired channel');
  check(await controls.protocolRequestCount() === beforeFault + 1, 'Retired channel performed network I/O');
  // The mutation reached the server, but its reply was corrupted. The caller
  // must report an unknown outcome without retrying. A healthy sibling can
  // reconcile the actual single remote effect through a new verified request.
  const afterFailure = (await other.query('SELECT name FROM boilstream_secrets()')).toArray().map(row => row.name);
  check(JSON.stringify(afterFailure) === JSON.stringify(['tampered_fixture']),
    'Unknown mutation outcome was not observable from the healthy sibling');
  await controls.revokeFixtureIdentity();
  await refuse(() => resume(other), 'Revoked resumption', /HTTP 401/);
  await refuse(() => other.query('SELECT * FROM boilstream_secrets()'), 'Revoked identity', /HTTP 401/);
  const afterRevocation = await controls.protocolRequestCount();
  await refuse(() => other.query('SELECT * FROM boilstream_secrets()'), 'Retired revoked identity');
  check(await controls.protocolRequestCount() === afterRevocation, 'Revoked identity reused its channel');
  check((await b.query('SELECT name FROM boilstream_secrets()')).toArray()[0].name === 'email_owned', 'Revoking another tenant retired the email session');
  return { resumption: true, registration: true, mfa: true, emailLogin: true, authenticated: true, quackCompatibility: true, crud: true, isolated: true, tamperRejected: true, unknownOutcomeVerified: true, revocationRejected: true };
}
