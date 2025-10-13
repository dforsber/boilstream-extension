# BoilStream DuckDB Extension

This extension allows you to use [boilstream](https://github.com/boilingdata/boilstream) server as a remote secure Secrets Storage.

It incorporates industrial grade e2e application level security even inside the TLS tunnel as well as anonymised login and lock-step protocol. We rely heavily on security standards like Facebook's audited OPAQUE PAKE, OAuth2, HKDF-SHA256, AES GCM, SHA256, etc. See the full [SECURITY_SPECIFICATION.md](SECURITY_SPECIFICATION.md) along with conformance test vectors. Interoperability verified through two independent implementations (Rust, C++).

> You can also create your own server that implements the required [REST API](src/README.md) to work with `boilstream` extension.

## Running the extension

1. Download and run [boilstream](https://github.com/boilingdata/boilstream)
2. Open BoilStream [web auth console](https://docs.boilstream.com/guide/auth/postgresql-web-auth.html#_2-login-options), register, and generate web token
3. Load the extension and provide token using PRAGMA as below

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
