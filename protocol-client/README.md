# BoilStream protocol client candidate

Client-only established-session envelopes: `seal_request` and `open_response`.
The `wire` module shares message types, bounded framing and session key derivation.
It contains no server request handler, response encryption, replay store or
private-key management. Tests use fixed synthetic response vectors.

This candidate is not yet used by the extension. It requires an already
authenticated OPAQUE session key; the installation-key handshake and product
transport integration remain separate work. Do not use it as a complete login
protocol or disable transport protection on its account.

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
