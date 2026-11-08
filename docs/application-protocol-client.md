# Pinned application protocol client candidate

Before login, configure the installation's independently obtained X25519 public
key on the same DuckDB connection:

```sql
PRAGMA boilstream_server_key('https://api.example.com', '<64 hexadecimal characters>');
PRAGMA boilstream_bootstrap_session('https://api.example.com/secrets/:<bootstrap token>');
```

The authority must be the exact scheme, host and optional port, without a path,
query or trailing slash. Obtain the public key from trusted installation
configuration, not from a response or discovery endpoint. There is no default pin,
automatic key replacement or legacy fallback. Missing/incorrect pins prevent
credential transmission. Provision every connection explicitly; public keys are
not passwords.

Registration, email/password login and MFA use the same configured pin. A
credential-free Noise handshake verifies the installation before any password,
bootstrap material or OPAQUE message is sent. Authenticated response bodies carry
application status, cookies and resumption metadata. Browser access to security
response headers is unnecessary. Keep HTTPS for browser requirements and defense
in depth; the existing URL policy permits plaintext HTTP only on test loopback.

Each logical authentication flow owns its channel. Requests serialize from
sequence allocation through response verification. HTTP redirects/retries are
disabled. An invalid/lost reply closes the channel and reports an unknown outcome:
a mutation may have committed. Do not blindly repeat it. Explicit resumption
creates a fresh channel. Existing generation checks protect identity publication.
Pin changes apply to new logins, not silently to active flows.

This is a breaking integration candidate, not a release-ready patch. Native and
DuckDB 2.0 browser/pthread end-to-end qualification, harness updates and release
gates remain in TASKS.md. The SPA and direct server-side DuckDB integration are
unchanged. Server implementation/peer tests remain private. Public builds need
only client sources and locked public dependencies.
