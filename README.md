# BoilStream DuckDB Extension

This extension allows you to use [boilstream](https://github.com/boilingdata/boilstream) server as a remote secure Secrets Storage.

It incorporates industrial grade e2e application level security even inside the TLS tunnel as well as anonymised login and lock-step protocol. We rely heavily on security standards like Facebook's audited OPAQUE PAKE, OAuth2, HKDF-SHA256, AES GCM, SHA256, etc. See the full [SECURITY_SPECIFICATION.md](SECURITY_SPECIFICATION.md) along with conformance test vectors. Interoperability verified through two independent implementations (Rust, C++).

> You can also create your own server that implements the required [REST API](src/README.md) to work with `boilstream` extension.

## Requirements

DuckDB **v2.0.0 or newer**. The extension is built against the DuckDB 2.0 C++ API and does not load
into DuckDB 1.x. The standalone build (`make`) needs the `duckdb` submodule on a v2.0 tag.

## Running the extension

1. Download and run [boilstream](https://github.com/boilingdata/boilstream)
2. Open BoilStream [web auth console](https://docs.boilstream.com/guide/auth/postgresql-web-auth.html#_2-login-options), register, and generate web token
3. Load the extension and provide token using PRAGMA (or the statement form) as below

```
% duckdb # -unsigned
D -- LOAD 'build/release/extension/boilstream/boilstream.duckdb_extension';
D INSTALL httpfs;
D LOAD httpfs;
D INSTALL boilstream FROM community;
D LOAD boilstream;
D PRAGMA duckdb_secrets_boilstream_endpoint('https://localhost/secrets:2c33eab800...996872e9ea84');
┌────────────────────────┬─────────────────────┐
│         status         │     expires_at      │
│        varchar         │      timestamp      │
├────────────────────────┼─────────────────────┤
│ Session token obtained │ 2025-10-09 00:10:30 │
└────────────────────────┴─────────────────────┘
D PRAGMA duckdb_secrets_boilstream_endpoint('https://localhost/secrets:2c33eab800...996872e9ea84');
┌────────────────────────┬─────────────────────┐
│         status         │     expires_at      │
│        varchar         │      timestamp      │
├────────────────────────┼─────────────────────┤
│ Session already active │ 2025-10-09 00:10:30 │
└────────────────────────┴─────────────────────┘
D FROM duckdb_secrets();
┌──────────────┬─────────┬──────────┬────────────┬────────────┬──────────────────────┬───────────────────────────────────────────────────────────────────────────────────┐
│     name     │  type   │ provider │ persistent │  storage   │        scope         │                                   secret_string                                   │
│   varchar    │ varchar │ varchar  │  boolean   │  varchar   │      varchar[]       │                                      varchar                                      │
├──────────────┼─────────┼──────────┼────────────┼────────────┼──────────────────────┼───────────────────────────────────────────────────────────────────────────────────┤
│ my_s3_secret │ s3      │ config   │ true       │ boilstream │ ['s3://my-test-buc…  │ name=my_s3_secret;type=s3;provider=config;serializable=true;scope=s3://my-test-…  │
│ test_crud    │ s3      │ config   │ true       │ boilstream │ ['s3://', 's3n://'…  │ name=test_crud;type=s3;provider=config;serializable=true;scope=s3://,s3n://,s3a…  │
└──────────────┴─────────┴──────────┴────────────┴────────────┴──────────────────────┴───────────────────────────────────────────────────────────────────────────────────┘
```

## Statement syntax (DuckDB 2.0)

Every `PRAGMA boilstream_*` command also has a statement form, added through a DuckDB 2.0 grammar
extension named `boilstream`. Both forms run the same implementation:

```sql
BOILSTREAM BOOTSTRAP SESSION 'https://localhost/secrets:<token>';
BOILSTREAM LOGIN 'https://localhost/user@example.com' 'password' '123456';
BOILSTREAM REGISTER USER 'https://localhost/user@example.com' 'password';
BOILSTREAM VERIFY MFA '123456';
CREATE DUCKLAKE 'my_lake' 'optional description';
ATTACH DUCKLAKE '<catalog-uuid>' AS my_lake;
BOILSTREAM HELP;
```

The grammar is activated automatically for every connection opened after the extension loaded, which
covers builds that link the extension statically. A connection that already existed when `LOAD
boilstream` ran, and the DuckDB CLI (which selects its own `shell` grammar when it opens a database),
activate it explicitly:

```sql
SET active_grammar_extensions = ['boilstream'];          -- any connection
SET active_grammar_extensions = ['shell', 'boilstream']; -- DuckDB CLI, keeps the CLI shorthand
```

`RESET active_grammar_extensions` turns the statements back into syntax errors; the PRAGMA forms always
work. Note that DuckDB 2.0 parses dotted setting names only when quoted: `SET "boilstream.tenant_id" = ...`.

## Local development: skipping TLS verification

The extension's HTTP client (DuckDB's `HTTPUtil` → libcurl) verifies the server certificate by default. When pointing at a local boilstream auth server with a self-signed cert this fails — and on macOS the standard knobs don't help: DuckDB's libcurl is statically linked against OpenSSL with `CURLSSLOPT_NATIVE_CA`, which silently ignores `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, and the DuckDB `ca_cert_file` setting on Darwin.

For local-dev only, set `BOILSTREAM_INSECURE_TLS=1` in the duckdb process's environment. The extension reads it on every outgoing request and, when set to `1`/`true`/`yes`, flips `HTTPParams.override_verify_ssl=true` and `HTTPParams.verify_ssl=false` — equivalent to `curl --insecure` but scoped to the extension's own calls.

```bash
BOILSTREAM_INSECURE_TLS=1 duckdb -c "
LOAD httpfs;
PRAGMA boilstream_bootstrap_session('https://localhost:443/secrets:<token>');
"
```

**Do not set this in production.** It's intentionally undocumented in the help text, intentionally per-process (no SQL knob, no config file), and the right fix on a real deployment is putting the auth server's cert on the host's trust path.
