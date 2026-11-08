# Client source guide

This directory implements the public DuckDB client extension. The server runtime,
server session registry and hosting callbacks belong to the private server codebase.

- [Usage and qualified host baseline](../README.md)
- [Installation pins and encrypted authentication](../docs/application-protocol-client.md)
- [Client security requirements](../SECURITY_SPECIFICATION.md)
- [Native and browser test coverage](../test/README_TESTS.md)
- [Client-only Rust protocol library](../protocol-client/README.md)

`boilstream_protocol.cpp` connects DuckDB HTTP transport to the Rust client channel.
`boilstream_secret_storage.cpp` implements connection-owned remote secret storage.
The connection state and cache retire credentials when their owning session ends.
`boilstream_extension.cpp` exposes client SQL operations; grammar support routes
supported statement forms into those operations.

The former REST-server example, PKCE exchange, header-signing and automatic
session-rotation instructions are obsolete and have been removed. They do not
describe the current client or provide a supported server implementation.
