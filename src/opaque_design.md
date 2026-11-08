# Client authentication

The current design is documented in
[the pinned application protocol client guide](../docs/application-protocol-client.md)
and [the client protocol library](../protocol-client/README.md).

A configured installation public key authenticates the encrypted application
channel before passwords, bootstrap tokens or OPAQUE messages are transmitted.
OPAQUE authenticates the user inside that channel. HTTP response headers do not
provide application authentication, encryption parameters or session authority.

Session credentials and refresh material remain in connection-owned memory.
Explicit resumption authenticates on a fresh channel and rotates the refresh
credential without extending the original session lifetime. No export key or
refresh credential is written to the filesystem, OS keychain or browser storage.

The previous header-signing, cipher-negotiation, PKCE and persisted-export-key
sketch is retired. It is not a description of supported behavior. The server
implementation and its integration tests remain in the private server repository.
