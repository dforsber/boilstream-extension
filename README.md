# BoilStream DuckDB Extension

This client extension connects stock DuckDB to BoilStream for authentication,
remote secret storage and managed Quack attachments.

The integration candidate uses a configured installation public key to authenticate
an encrypted application channel before sending credentials. OPAQUE login runs
inside that channel. Application authentication and confidentiality do not depend
on HTTP response headers or TLS confidentiality. See the
[client security requirements](SECURITY_SPECIFICATION.md) and
[configuration guide](docs/application-protocol-client.md).

## Requirements

The qualified native and browser baseline is **DuckDB v2.0.0**, including both WASM
EH and pthread variants. DuckDB 1.x is unsupported; later hosts require separate
qualification. Native builds use the matching `duckdb` submodule.

This branch is a breaking client/server integration candidate. It has not been
published as a community extension release. Coordinated server qualification and
release approval remain required.

## Login lifetime

Login credentials remain only in the DuckDB connection's memory. New connections
and process restarts require login again. The extension does not save credentials
to files or browser storage, and ignores credential files left by older releases.
Secure restart login is deferred.

Generic remote secrets are private to the authenticated connection. Logout,
replacement and connection teardown retire its cache; credentials are never
copied into shared `memory` storage. Complete secret lists replace the cache
atomically after validation. Each owner has at most 10,000 entries, 10 MiB of
serialized entries, and 1 MiB per entry; capacity errors preserve existing
entries. Explicit secrets created without login remain local to that connection.

This is a client extension for stock DuckDB. It provides remote authentication,
secret access and Quack client attachment. It does not provide server hosting
callbacks or an embedded-server session API.

## Running the extension

Use a BoilStream installation supporting this protocol and obtain its X25519
public key from trusted installation configuration. Configure that pin on each
DuckDB connection before login. A key obtained from an unverified server response
is not a trusted pin.

```sql
LOAD httpfs;
LOAD '/absolute/path/to/boilstream.duckdb_extension';
PRAGMA boilstream_server_key('https://api.example.com', '<64 hexadecimal characters>');
PRAGMA boilstream_bootstrap_session('https://api.example.com/secrets/:<bootstrap token>');
SELECT * FROM duckdb_secrets();
```

Use the candidate artifact matching the selected host. Published community
versions may use a different protocol. The authority passed to `boilstream_server_key`
has no trailing slash or path; the bootstrap URL contains the endpoint and token.
Missing or incorrect pins prevent credential transmission.

## Statement syntax (DuckDB 2.0)

The commands below have statement forms through the DuckDB 2.0 grammar extension
named `boilstream`. Their PRAGMA equivalents run the same implementation. Configure
the installation pin with `PRAGMA boilstream_server_key` first:

```sql
BOILSTREAM BOOTSTRAP SESSION 'https://localhost/secrets/:<token>';
BOILSTREAM LOGIN 'https://localhost/user@example.com' 'password' '123456';
BOILSTREAM REGISTER USER 'https://localhost/user@example.com' 'password';
BOILSTREAM VERIFY MFA '123456';
CREATE DUCKLAKE 'my_lake' 'optional description';
ATTACH DUCKLAKE '<catalog-uuid>' AS my_lake;
BOILSTREAM HELP;
```

Registration returns a setup key, verification instruction and authenticator URI.
If `textplot` is already loaded, the URI is rendered as a QR code. Registration
does not install extensions or require a third-party download; the setup key and
URI also work in WASM and offline extension installations.


The grammar is activated automatically for every connection opened after the extension loaded, which
covers builds that link the extension statically. A connection that already existed when `LOAD
boilstream` ran, and the DuckDB CLI (which selects its own `shell` grammar when it opens a database),
activate it explicitly:

```sql
SET active_grammar_extensions = ['boilstream'];          -- any connection
SET active_grammar_extensions = ['shell', 'boilstream']; -- DuckDB CLI, keeps the CLI shorthand
```

`RESET active_grammar_extensions` turns the statements back into syntax errors; the PRAGMA forms always
work. To stop the automatic activation for a whole process, `SET boilstream_grammar_auto_activate = false`
or export `BOILSTREAM_GRAMMAR_AUTO_ACTIVATE=0` before the first connection opens.

## Local development: trust the test server's CA

The extension verifies server certificates by default. For a local server signed by
your own CA, load `httpfs` and set its CA file **globally within the DuckDB database**
before login. The extension creates HTTP requests from the database instance, so
a connection-local `SET ca_cert_file` does not reach those requests.

```sql
LOAD httpfs;
SET GLOBAL ca_cert_file = '/absolute/path/to/test-ca.crt';
PRAGMA boilstream_server_key('https://localhost:443', '<64 hexadecimal characters>');
PRAGMA boilstream_bootstrap_session('https://localhost:443/secrets/:<token>');
```

This configures DuckDB without modifying the operating system's trust store.
Keep certificate verification enabled for both authentication and the managed
Quack connection.

TLS configuration does not replace the installation pin. The application channel
still authenticates the peer and protects request and response bodies.
