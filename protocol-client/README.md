# BoilStream protocol client candidate

Client-only pinned handshake and established-session envelopes: `seal_request` and `open_response`.
The `wire` module shares message types, bounded framing and session key derivation.
It contains no server request handler, response encryption, replay store or
private-key management. Tests use fixed synthetic response vectors.

The handshake uses Noise NK (X25519/AES-256-GCM/SHA-256) with an independently
configured installation public key and authority. It accepts explicit CSPRNG
entropy and time, with no OS RNG, credentials, default keys or server SDK in this
crate. The first message cannot carry credentials; only successful completion
returns channel keys. A channel authenticates the server, not the user: OPAQUE
and server-side authorization are still required. Callers must enforce expiry,
replay admission, rate limits and fail-closed transport policy.

Tests use checked-in synthetic response vectors and client entropy; they require
no running service or secrets. Private server keys and the independent full peer
harness remain in the private repository. Never reuse test entropy in production.
Owned secrets are zeroized where supported; Snow does not guarantee erasure of
all its internal buffers. There is no complete process-memory erasure guarantee.

This candidate is not yet used by the extension. Product transport/C ABI wiring
and real authenticated browser coverage remain integration work. Do not disable
transport protection on its account.

```sh
cargo test --locked --manifest-path protocol-client/Cargo.toml
cargo clippy --locked --manifest-path protocol-client/Cargo.toml --all-targets -- -D warnings
cargo audit --deny warnings --file protocol-client/Cargo.lock
bash protocol-client/test-wasm.sh wasm_eh
bash protocol-client/test-wasm.sh wasm_threads
```

The WASM commands use the extension's existing pinned toolchain baseline. No
private source, package, credentials or server library is needed to build/test
this client crate or the community extension.
