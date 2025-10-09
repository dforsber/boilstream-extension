# Changelog

All notable changes to the Boilstream DuckDB Extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-10-09

### Added

- **OPAQUE PAKE authentication**: Replaces PKCE with IETF RFC 9807 OPAQUE protocol
  - Password-based authentication without transmitting passwords
  - Three-step login flow: `LoginStart` → `LoginFinish` → session established
  - Cryptographically derived `session_key` (32 bytes) from OPAQUE protocol
  - `export_key` generation for future session resumption support
- **HKDF key derivation** (RFC 5869): Derives separate keys from `session_key`
  - `signing_key`: HKDF-Expand(session_key, "boilstream-request-signing", 0x01)
  - `encryption_key`: HKDF-Expand(session_key, "boilstream-secret-encryption", 0x01)
  - Key separation prevents cross-protocol attacks
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
- **OPAQUE client library integration**:
  - Rust-based OPAQUE implementation with C FFI bindings
  - C++ wrapper classes for type-safe OPAQUE operations
  - Memory-safe buffer management with RAII wrappers

### Changed

- **BREAKING**: Replaced PKCE authentication with OPAQUE PAKE protocol
- **BREAKING**: `PerformOpaqueLogin()` now used instead of `PerformTokenExchange()`
- Session state now includes `session_key` and `export_key` from OPAQUE
- HTTP requests now include cryptographic signatures for integrity
- `client_sequence` resets to 0 on new session establishment

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
- No longer supports PKCE-based authentication (clean break)

### Security

- **Enhanced**: OPAQUE provides password-less authentication (no password transmission)
- **Enhanced**: Cryptographic key derivation using HKDF-SHA256
- **Enhanced**: Request signing prevents tampering even if TLS is compromised
- **Enhanced**: Lock-step sequence prevents session hijacking attacks
- **Enhanced**: One wrong sequence number kills the session (immediate attack detection)
- **Enhanced**: Replay attack prevention via timestamp + sequence validation
- **Enhanced**: Key separation (signing ≠ encryption) prevents cross-protocol attacks

### Technical Details

- OPAQUE protocol: IETF RFC 9807 (ristretto255 group)
- Key derivation: HKDF-SHA256 (RFC 5869)
- Request signing: HMAC-SHA256 with canonical format
- Session keys: 32 bytes (256-bit security)
- Sequence counter: uint64_t (monotonically increasing)
- Signature format: Base64-encoded HMAC output
- All keys stored in-memory only (`vector<uint8_t>`)
- Export keys prepared for future session resumption (not yet implemented)

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
