# Native authenticated-client adapter

`sql_driver.cpp` executes ordinary SQL against the selected DuckDB shared library
and explicitly loads the selected HTTPFS, Quack and BoilStream artifacts. It has
no authentication implementation, synthetic successful server replies, or private
installation key. The public native security workflow compiles it; successful
server authentication is qualified in the private coordinated gate.

`../wasm/real-server-native.js` adapts its connection/query results to
`../wasm/authenticated-scenario.js`, the same assertions used by both browser
variants. Commands and fixture controls use private stdin/stdout pipes. All SQL
credentials are autonomous test values, never caller accounts or command-line
arguments. The private coordinator generates TOTP codes from the returned URI,
changes actual revocation state, observes plaintext wire traffic and corrupts
one real encrypted reply after a committed mutation. No test HTTP control route
is added to the server.

The native driver refreshes its selected CMake builds before loading. Source
headers, library build and extension must agree; a mismatched source or artifact
fails before building. Normal CMake/Cargo dependency tracking is authoritative.
No source hash inventory, receipt, forced clean or fallback artifact is used.

The private `test-application-protocol-clients` target prepares the native runner
and both WASM variants before bounded runtime tests. The native Quack artifact
must accompany the explicitly selected HTTPFS artifact in the same version/platform
directory. The complete shared scenario checks email registration/MFA, account
replacement, email/bootstrap login, consumed credentials, tenant isolation,
secret CRUD, tampered-response refusal without retries, unknown mutation outcome,
and live revocation with a healthy unrelated tenant. A green public CI check does
not substitute for this private positive gate.
