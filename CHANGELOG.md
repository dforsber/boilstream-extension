# Changelog

All notable changes to the Boilstream DuckDB Extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-10-13

### Added

- **OPAQUE PAKE authentication**: Replaces PKCE with IETF RFC 9807 OPAQUE protocol
  - Password-based authentication without transmitting passwords
  - Three-step login flow: `LoginStart` → `LoginFinish` → session established
  - Cryptographically derived `session_key` (32 bytes) from OPAQUE protocol
  - `export_key` generation for future session resumption support
- **HKDF key derivation** (RFC 5869): Derives separate keys from `session_key`
  - `signing_key`: HKDF-Expand(session_key, "boilstream-request-signing", 0x01)
  - `encryption_key`: HKDF-Expand(session_key, "boilstream-secret-encryption", 0x01)
  - `integrity_key`: HKDF-Expand(session_key, "boilstream-response-integrity", 0x01)
  - Key separation prevents cross-protocol attacks
- **Symmetric encryption for secrets and responses**: AES-256-GCM and ChaCha20-Poly1305
  - Server encrypts responses using session-derived encryption key
  - Encrypted format: `{"encrypted":true,"nonce":"...","ciphertext":"...","hmac":"..."}`
  - Cipher suite negotiation via `X-Boilstream-Cipher` header (0x0001=AES-GCM, 0x0002=ChaCha20)
  - Automatic detection and decryption of encrypted responses via `X-Boilstream-Encrypted` header
- **Defense in depth - HMAC before AEAD**: Two-layer integrity protection
  - HMAC-SHA256 over entire encrypted response (computed with `integrity_key`)
  - AEAD authentication tag from AES-GCM/ChaCha20-Poly1305 cipher
  - HMAC verified BEFORE attempting AEAD decryption (prevents oracle attacks)
  - Per SECURITY_SPECIFICATION.md Section 5.5.1: "verify HMAC first, decrypt second"
- **Canonical request signing**: Industry-standard format (similar to AWS SigV4)
  - Format: `METHOD\nURL\nBODY\nTIMESTAMP\nSEQUENCE`
  - HMAC-SHA256 signature using derived signing key
  - Request integrity protection independent of TLS
- **Lock-step sequence protocol**: Session hijacking prevention
  - `client_sequence` counter (starts at 0, increments per request)
  - Server validates exact sequence match (mismatch → session killed)
  - Prevents replay attacks and concurrent session abuse
- **Request signature headers**: Added to all HTTP requests (GET/POST/DELETE)
  - `X-Timestamp`: Unix timestamp in seconds
  - `X-Sequence`: Monotonically increasing counter
  - `X-Signature`: Base64-encoded HMAC-SHA256 signature
  - `X-Boilstream-Cipher`: Cipher suite preference (0x0001 or 0x0002)
- **Response integrity headers**: Server includes on all responses
  - `X-Boilstream-Encrypted`: "true" if response is encrypted
  - `X-Boilstream-Cipher`: Cipher suite used (0x0001=AES-256-GCM, 0x0002=ChaCha20-Poly1305)
  - `X-Response-Signature`: HMAC-SHA256 of response body
  - `X-Response-Timestamp`: Server timestamp (for freshness validation)
- **OPAQUE client library integration**:
  - Rust-based OPAQUE implementation with C FFI bindings
  - C++ wrapper classes for type-safe OPAQUE operations
  - Memory-safe buffer management with RAII wrappers
  - Cross-platform support: Linux, macOS (ARM64/x86_64), Windows, WASM
- **Comprehensive test suite**:
  - **Conformance tests** (22 tests, 68 assertions): Validates cryptographic implementation
    - A.10.2: AES-256-GCM encryption with specification test vectors
    - A.10.3: HMAC-SHA256 integrity with specification test vectors
    - A.10.4: JSON structure validation for EncryptedResponse format
    - A.10.9: End-to-end encryption/decryption flow validation
  - **Encryption unit tests**: DecryptResponse with AEAD ciphers
  - **Integration tests**: Real server connectivity with encrypted responses
  - **SQL logic tests**: URL validation and error handling without network dependency

### Changed

- **BREAKING**: Replaced PKCE authentication with OPAQUE PAKE protocol
- **BREAKING**: `PerformOpaqueLogin()` now used instead of `PerformTokenExchange()`
- **BREAKING**: Removed OpenSSL dependency - now uses DuckDB's mbedTLS exclusively
  - Enables WASM support (OpenSSL not available in browser environments)
  - Reduces dependency footprint and improves cross-platform compatibility
- Session state now includes `session_key` and `export_key` from OPAQUE
- HTTP requests now include cryptographic signatures for integrity
- HTTP responses are now encrypted by default (server-side feature)
- All HTTP methods (GET/POST/DELETE) decrypt responses before processing
- Error responses are now properly decrypted before displaying to user
- `client_sequence` resets to 0 on new session establishment
- Session key stored early in login flow to support encrypted login-finish responses
- Test error messages normalized to "Token exchange failed" for network failures

### Removed

- **BREAKING**: Removed all PKCE code and token rotation logic
  - Removed `PerformTokenExchange()` method
  - Removed `RotateSessionToken()` method
  - Removed `ShouldRotateToken()` method
  - Removed `GenerateCodeVerifier()` method
  - Removed `ComputeCodeChallenge()` method
  - Removed `code_verifier` field
  - Removed `is_rotating` flag and `rotation_lock` mutex
  - Removed automatic token rotation from HTTP methods
- **BREAKING**: Removed OpenSSL dependency from CMakeLists.txt and vcpkg.json
- No longer supports PKCE-based authentication (clean break)

### Fixed

- **CRITICAL**: Encrypted error responses now properly decrypted before display
  - Previously: Error messages displayed as encrypted gibberish (base64 blob)
  - Now: HTTP methods decrypt response BEFORE checking status code
  - Affects: HttpGet, HttpPost, HttpDelete - all fixed to decrypt first
  - User impact: Duplicate secret errors and other server errors now readable
- **CRITICAL**: OPAQUE login-finish encrypted response handling
  - Server sends encrypted response during login-finish step
  - Fixed: Store session_key immediately after OPAQUE derivation
  - Previously: session_key stored after response parsing (too late for decryption)
  - Added: session_key.clear() in all error handlers for clean failure states
- **HIGH**: macOS x86_64 cross-compilation support
  - Detect OSX_BUILD_ARCH environment variable from GitHub Actions
  - Pass --target=x86_64-apple-darwin or --target=aarch64-apple-darwin to Cargo
  - Fixed: Force-load Rust library with -Wl,-force_load linker flag
  - Added: CoreFoundation framework and resolv library for Rust dependencies
- **HIGH**: Windows build errors
  - MinGW/GCC: Added libgcc link library for Rust f16 compiler builtins (__extendhfsf2, __truncsfhf2)
  - MSVC: Fixed min/max macro conflicts with std::chrono (added NOMINMAX define)
  - MSVC: Removed gcc.lib linking (only needed for MinGW, not MSVC)
  - MSVC: Added ntdll.lib for Rust std NT native functions (NtReadFile, NtWriteFile, NtOpenFile, etc.)
  - Fixes: Both MinGW/rtools42 and MSVC builds now compile successfully
- **HIGH**: WASM build support
  - Removed platform guards from Rust C FFI functions
  - Added .cargo/config.toml with -O1 flag to skip wasm-opt
  - Fixed: wasm-opt compatibility issue with --enable-bulk-memory-opt flag
  - Platform-specific RNG: OsRng for native, StdRng for WASM
- **MEDIUM**: SQL logic tests network independence
  - Normalized network error messages to "Token exchange failed"
  - Tests pass without running server or network connection
  - Error patterns: "scheme is not supported", "not implemented", "Connection refused", etc.

### Security

- **Enhanced**: OPAQUE provides password-less authentication (no password transmission)
- **Enhanced**: Cryptographic key derivation using HKDF-SHA256
- **Enhanced**: Symmetric encryption for all sensitive data (AES-256-GCM, ChaCha20-Poly1305)
- **Enhanced**: Defense in depth - HMAC verified BEFORE AEAD decryption
  - Prevents padding oracle attacks and timing attacks
  - Two-layer integrity protection (HMAC + AEAD authentication tag)
  - Per security specification Section 5.5.1
- **Enhanced**: Request signing prevents tampering even if TLS is compromised
- **Enhanced**: Response signature verification detects tampering or downgrade attacks
- **Enhanced**: Lock-step sequence prevents session hijacking attacks
- **Enhanced**: One wrong sequence number kills the session (immediate attack detection)
- **Enhanced**: Replay attack prevention via timestamp + sequence validation
- **Enhanced**: Key separation (signing ≠ encryption ≠ integrity) prevents cross-protocol attacks
- **Enhanced**: Cipher suite negotiation allows algorithm upgrades without protocol changes
- **Enhanced**: All cryptographic operations validated against specification test vectors

### Technical Details

- **Authentication**: OPAQUE protocol (IETF RFC 9807, ristretto255 group)
- **Key derivation**: HKDF-SHA256 (RFC 5869) with domain separation
  - Info strings: "boilstream-request-signing", "boilstream-secret-encryption", "boilstream-response-integrity"
  - Salt: Empty (per HKDF specification for PRK extraction)
  - OKM length: 32 bytes per key (256-bit security)
- **Encryption ciphers**:
  - AES-256-GCM (cipher suite 0x0001): NIST standard, hardware-accelerated on most platforms
  - ChaCha20-Poly1305 (cipher suite 0x0002): Software-efficient, constant-time implementation
- **Integrity protection**:
  - Request signing: HMAC-SHA256 with canonical format
  - Response integrity: HMAC-SHA256 over encrypted response body
  - AEAD authentication: 128-bit tag from GCM or Poly1305
- **Nonce generation**: 12-byte random nonce per encryption operation
- **Session keys**: 32 bytes (256-bit security)
- **Sequence counter**: uint64_t (monotonically increasing, no rollover)
- **Signature format**: Base64-encoded HMAC-SHA256 output (44 characters)
- **Memory safety**: All keys stored in-memory only (`vector<uint8_t>`), never persisted
- **Export keys**: Prepared for future session resumption (not yet implemented)
- **Platform support**:
  - Linux: x86_64, ARM64
  - macOS: x86_64 (Intel), ARM64 (Apple Silicon)
  - Windows: x86_64 with MinGW/rtools42
  - WASM: mvp, eh, threads variants
- **Cryptographic library**: DuckDB's mbedTLS (cross-platform, WASM-compatible)
- **OPAQUE library**: Rust implementation with C FFI bindings
- **Test coverage**:
  - 22 conformance tests validating specification compliance
  - Unit tests for encryption/decryption with test vectors
  - Integration tests against live server with encrypted responses

## [0.2.0] - 2025-10-08

### Added

- PKCE (Proof Key for Code Exchange) token exchange flow for enhanced security (RFC 7636)
- Bootstrap token exchange: 5-minute one-time-use tokens exchanged for 8-hour session tokens
- Automatic session token rotation (rotates when <30 minutes remaining)
- Session tokens stored in-memory only (never persisted to disk or query history)
- New `PerformTokenExchange()` method for bootstrap → session token exchange
- New `RotateSessionToken()` method for session token renewal
- PKCE helper functions: `GenerateCodeVerifier()`, `ComputeCodeChallenge()`, `ValidateTokenFormat()`
- Session token validation with 30-minute expiry buffer
- Integration C++ tests against running server for testing PKCE token exchange and secrets mgmt
- Comprehensive C++ unit test suite (test/cpp/test_boilstream_security.cpp)
  - PKCE code verifier generation tests (uniqueness, entropy, character validity)
  - PKCE code challenge computation tests (RFC 7636 test vectors)
  - Token format validation tests
  - Session token state management tests
  - Thread safety tests (concurrent operations)
  - Security property tests (unpredictability, one-way hashing)
- SQL integration tests for URL validation and security controls
- Rejection sampling for cryptographically secure random number generation
- Token format validation (32-512 chars, alphanumeric + hyphens/underscores)
- Proper hostname extraction for URL validation (prevents bypass attacks)
- State rollback on token exchange failure (ensures consistent state)
- Thread-safe token rotation with mutex-based race condition prevention

### Changed

- **BREAKING**: `PRAGMA duckdb_secrets_boilstream_endpoint` now expects bootstrap token instead of session token
- PRAGMA handler now performs PKCE exchange automatically on token setup
- HTTP methods (GET/POST/DELETE) now use session tokens with automatic rotation
- Constructor signature: removed `auth_token` parameter (now unused)
- Session tokens automatically refresh before expiry during HTTP operations

### Removed

- **BREAKING**: Removed `SetAuthToken()` method (replaced by PKCE exchange)
- **BREAKING**: Removed `auth_token` field (replaced by `session_token`)
- Direct token authentication (all authentication now via PKCE flow)

### Security

- Bootstrap tokens are single-use and short-lived (5 minutes)
- Session tokens never exposed to users or stored persistently
- Code verifier never transmitted (used only for rotation proof)
- Automatic token rotation prevents long-term credential exposure
- **Fixed**: PKCE rotation protocol now correctly sends `new_code_challenge` to server (CRITICAL)
- **Fixed**: Weak RNG replaced with rejection sampling to eliminate modulo bias (CRITICAL)
- **Fixed**: Race condition in token rotation prevented with `rotation_lock` mutex (CRITICAL)
- **Fixed**: Bootstrap token no longer leaked in connection mapping (uses SHA256 hash instead) (HIGH)
- **Fixed**: Inconsistent state on exchange failure with proper rollback (HIGH)
- **Fixed**: Token exchange race condition prevented with `is_exchanging` flag (HIGH)
- **Fixed**: Token format validation enforces length and character restrictions (HIGH)
- **Fixed**: Rotation failures now properly surface errors instead of silent failures (HIGH)
- **Fixed**: URL validation bypass attacks prevented with proper hostname extraction (HIGH)

### Technical Details

- Uses mbedtls for SHA256 computation in PKCE challenge generation
- Code verifier: 64-character base64url random string (rejection sampling for uniform distribution)
- Code challenge: base64url(SHA256(code_verifier))
- Session token expiry buffer: 30 minutes (configurable)
- Token exchange endpoint: `POST /auth/api/token-exchange`
- Token rotation endpoint: `POST /auth/api/token-rotate` (includes `new_code_challenge`)
- Test framework: Catch2 v2.13.10 for C++ unit tests
- Test coverage: 236 assertions across 6 test cases
- Thread safety: Multiple mutexes protect concurrent access (session_lock, rotation_lock, endpoint_lock)
- Token validation: 32-512 character length, alphanumeric + hyphens/underscores only
- State flags: `is_rotating` and `is_exchanging` prevent concurrent operations

## [0.1.0] - 2025-10-06

### Added

- Initial release of Boilstream DuckDB Extension
- REST API-based secret storage for multi-tenant DuckDB deployments
- `PRAGMA duckdb_secrets_boilstream_endpoint` for configuring REST API endpoint
- Support for storing, retrieving, and deleting secrets via REST API
- HTTP GET/POST/DELETE operations with retry logic (3 retries, exponential backoff)
- Secret caching with expiration tracking (1-hour TTL, 5-minute refresh buffer)
- Thread-safe connection-to-user context mapping
- Idempotency key support for safe POST retries
- Bearer token authentication via Authorization header
- HTTPS enforcement (except localhost for testing)
- Binary secret serialization using DuckDB's binary format
- JSON communication using yyjson for safety
- Recursion guards to prevent infinite secret lookup loops
- Debug logging support via `BOILSTREAM_DEBUG` compile flag

### Security

- HTTPS required for non-localhost endpoints
- Tokens never echoed in query results or logs
- HTTP request bodies truncated in error messages to prevent credential leakage
- Thread-safe endpoint and token management

### Dependencies

- DuckDB core framework
- httpfs extension (required dependency for HTTP operations)
- yyjson for JSON parsing
- mbedtls for cryptographic operations

[0.3.0]: https://github.com/yourusername/boilstream-extension/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yourusername/boilstream-extension/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/boilstream-extension/releases/tag/v0.1.0
