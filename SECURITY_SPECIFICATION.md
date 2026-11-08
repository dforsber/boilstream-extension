# Client security requirements

This document describes the encrypted application-protocol integration candidate
implemented by this repository. It replaces the retired header-signing design.
It is not a claim of release readiness, an independent security audit, or a server
implementation guide. The server implementation and coordinated peer tests remain
in the private server repository.

## Trust and credential transmission

Each DuckDB connection must be configured with the installation's independently
obtained X25519 public key and exact URL authority. There is no default key,
unauthenticated key discovery, automatic pin replacement or legacy fallback.
Malformed and low-order keys are rejected. A pinned Noise handshake authenticates
the installation before the client sends passwords, bootstrap tokens or OPAQUE
messages. Entropy failure must fail the operation; production code does not use
fixture keys or deterministic fallback randomness.

OPAQUE user authentication takes place inside this encrypted channel. Its session
key is distinct from the channel's handshake-derived encryption keys. The current
OPAQUE suite uses Ristretto255 and SHA-512; the channel uses
`Noise_NK_25519_AESGCM_SHA256`. See the actual locked dependencies and
[client protocol library](protocol-client/README.md) for the implementation.

## Authenticated exchanges

Requests and responses are protected in application bodies. Authentication,
status, cookies and resumption metadata come only from verified inner messages.
HTTP response headers cannot supply session authority or encryption parameters.
The client ignores them for those purposes and disables redirects and automatic
HTTP retries for protocol exchanges.

Each channel serializes complete request/response exchanges. Direction, authority,
channel identity, request identity, sequence and message lifetime are bound into
authenticated processing. A response is accepted only for its pending request.
Replayed, modified, expired or mismatched messages fail. Failure or abandonment
closes the cryptographic channel; sequence numbers must not reset under retained
keys. A lost reply means a mutation may already have committed. Do not blindly
repeat it.

HTTPS remains the deployment policy and provides additional protection. Plaintext
HTTP is permitted only for test loopback by the client's URL policy. The private
native/EH/pthread tests exercise encrypted exchanges over loopback without TLS
confidentiality or accessible security response headers. This is application
protocol protection, not protection against a compromised DuckDB process, browser,
installation private key or trusted server.

## Session lifetime and storage

Login credentials, OPAQUE session keys and refresh material remain in the owning
connection's memory. The extension does not persist them to files, OS keychains
or browser storage. New connections and process restarts require login again.
Old credential files are ignored rather than migrated or removed.

Authentication requires explicit, unambiguous success and a future server expiry
representable by the host clock. There is no invented default session lifetime.
A failed login or resumption cannot replace an existing connection identity.
Explicit resumption uses a fresh pinned channel and rotates the one-use refresh
credential without extending the original session lifetime. It requires a live,
unexpired in-memory session; it cannot restore a logged-out connection.

Logout, replacement and connection teardown invalidate the connection generation
and retire its credential cache. Retained cache handles cannot retrieve or publish
credentials after retirement. Remote credentials are not placed in shared DuckDB
memory storage. Sensitive buffers and temporary JSON allocations are wiped by the
production cleanup paths. Diagnostics must not echo credentials or untrusted
response content.

## Bounds and limits

The client validates message sizes, metadata, target syntax and authenticated
lifetimes. Remote-secret caches are bounded per owner and validated before
publication. These limits do not bound allocations already performed by DuckDB's
HTTP implementation before it returns a response. They also do not replace host
runtime security updates or query/data-plane resource controls.

Installation pins protect the authentication and secret-management application
protocol. Managed Quack query connections use their own transport and credentials;
this protocol must not be described as encrypting all query traffic.

## Evidence and release qualification

[The test guide](test/README_TESTS.md) distinguishes production C ABI vectors,
strict parser and lifecycle tests, loaded native tests and actual DuckDB 2.0
browser EH/pthread tests. A Rust implementation called through C++ FFI is not two
independent cryptographic implementations. Compile-only checks do not establish
successful authentication or browser compatibility.

Successful authentication, tenant isolation, revocation, renewal and failure
behavior require the coordinated private real-server gate. Public builds contain
only client sources and public dependencies; no private peer implementation or
installation secret is needed to build them. Release approval additionally
requires dependency audits and the server's native/full-product qualification.
