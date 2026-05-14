# Changelog

All notable changes to the Boilstream DuckDB Extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-05-14

### Added

- **Quack pre-execute SQL-rewriter hook**: new bridge surface for host-registered query-time rewriting.
  - `boilstream_quack_set_sql_rewriter(fn)` — setter (atomic slot, release-store at boot, acquire-load on the hot path; same lifecycle as the JWT verifier slot).
  - `boilstream_quack_pre_execute(session_id, sql_in, sql_out_buf, ...)` — `extern "C"` hook handler. Patched Quack calls this between authz and SendQuery; the handler routes through to the host-registered Rust rewriter. Caller owns the output buffer — no allocation crosses the C/Rust boundary.
  - Registered with patched Quack via `boilstream_lookup_runtime_symbol("quack_set_pre_execute_hook")`, re-using the portable POSIX / Windows shim introduced in v0.6.0. Vanilla DuckDB / stock Quack → no-op.

### Style

- `make format-fix` pass across 12 files — fixes the Code Quality / Format Check in the boilstream-extension distribution pipeline. Clang-format / cmake-format / sqllogic-test trailing-whitespace normalisation; no semantic changes.

## [0.6.0] - 2026-05-14

### Fixed

- **`CREATE SECRET (TYPE quack)` without `bootstrap_session`**: `RestApiSecretStorage::StoreSecret` previously threw `"No active boilstream session"` when no `conn_state` was attached to the calling transaction, blocking the legitimate workflow of `CREATE SECRET (TYPE quack, TOKEN ..., SCOPE 'quack:host')` from a DuckDB CLI session that never called `PRAGMA boilstream_bootstrap_session`. The path now falls back to in-process storage only (skips REST persist) — mirrors DuckDB's `TEMPORARY` secret semantics. Cross-session persistence still requires a live session.
- **Auto-vend no longer clobbers user-supplied quack secrets**: `LookupQuackSecret` previously matched its internal cache key (`__quack__<path>`) by inline string-comparison; refactored into a named helper `is_auto_vended_name(...)` that makes the convention explicit. Behaviour is unchanged — a scope-matching `TYPE quack` secret whose name doesn't follow the auto-vend convention is treated as user-supplied and returned as-is, never replaced by the server-vended JWT. Closes ingestion-agent-8hnt.

### Added

- **Quack remote-protocol bridge**: New `src/quack_bridge.{cpp,hpp}` exposing the scalar functions that DuckDB Quack's `quack_authentication_function` / `quack_authorization_function` GLOBAL settings dispatch to:
  - `boilstream_quack_authn(token)` — HS256 JWT verifier registered via `boilstream_quack_set_jwt_verifier`; populates the bridge SessionMap on success.
  - `boilstream_quack_authz(session_id, kind, statement)` — read-only gate (allows `SELECT` / `EXPLAIN` / `PRAGMA`, rejects DDL/DML).
  - `boilstream_quack_bind_session(session_id, tenant_id, …)` — SessionMap upsert used by the auth path.
  - `boilstream_quack_session_init(session_id, void* client_context)` — `extern "C"` hook handler `dlsym`-registered with patched Quack via `quack_set_session_init_hook`. On each new per-session Quack `Connection`, looks up the session_id in the SessionMap and stamps the tenant_id onto the freshly-spawned `ClientContext` via the fork's `duckdb_set_tenant_id_on_context` (also `dlsym`'d). On vanilla DuckDB / stock Quack the fork symbols aren't present and the bridge degrades silently — community-extension compatibility preserved.
- **`LookupQuackSecret` auto-vend** in `boilstream_secret_storage.cpp`: on first ATTACH against a `quack:` URI with no `TYPE quack` secret in cache, fetches one through the existing /secrets bootstrap path.
- **Tests**: `test/cpp/test_quack_attach_red.cpp` (TDD reproducer for the secret-lookup regression, now wired into CMakeLists and CTest as `QuackAttachRedTests`); SQL tests `test/sql/quack_attach_with_manual_secret.test`, `test/sql/quack_bridge.test`, `test/sql/quack_secret_autovend.test`.
- **`BOILSTREAM_INSECURE_TLS=1`** local-dev knob: skips certificate verification when set (intended only for `localhost` self-signed cert setups).

### Diagnostics

- **`BOILSTREAM_WARN` for silent catches in AllSecrets memory cache**: surfaces the production-critical failure paths inside `FetchAllSecretsFromServer` that were previously hidden behind `BOILSTREAM_LOG` (no-op without `-DBOILSTREAM_DEBUG`).

### Chore

- Clear all dependabot alerts on default branch.

## [0.5.1] - 2026-02-06

### Security

- **Fix SQL injection in PRAGMA return values**: All server-controlled data (ducklake names, backup codes, TOTP secrets) interpolated into PRAGMA return SQL strings is now escaped via `EscapeSqlLiteral()` to prevent SQL injection from a malicious server
- **Fix timestamp anti-replay bypass**: The `catch(...)` block in `VerifyResponseSignature` was swallowing the `IOException` thrown when a response timestamp exceeded the 60-second window, making the anti-replay check a no-op. The window check is now outside the try/catch so it always propagates
- **Require x-boilstream-date header**: Response signature verification now rejects responses missing the `x-boilstream-date` header, preventing timestamp check bypass by header omission
- **Fix insecure memory zeroing in ClearSession**: Replaced `std::fill` with volatile-write helpers (`SecureZeroString`, `SecureZeroVector`) to prevent the compiler from optimizing away memory clearing of sensitive session credentials
- **Fix missed SQL injection in cached TOTP path**: The cached registration code path was missing `EscapeSqlLiteral()` on `formatted_secret` and `cached_totp_uri`

### Fixed

- **Fix double response body in HttpGetWithState**: `response_handler` was assigning `response.body` while `content_handler` also appended chunks, causing potential data duplication
- **Add NULL checks for yyjson_mut_write**: All 16 call sites now use `SafeJsonSerialize()` which throws on allocation failure instead of passing NULL to `std::string` constructor (undefined behavior)
- **Fix broken Rust password validation test**: Test string `"12chars_ok"` was only 10 characters, causing the assertion to fail

## [0.5.0] - 2025-12-27

### Added

- **Per-Connection Authentication State**: Multi-tenant support with isolated OPAQUE sessions
  - New `BoilstreamConnectionState` class using DuckDB's `RegisteredStateManager` pattern
  - Each DuckDB connection gets independent session credentials (access_token, session_key, etc.)
  - Per-connection caches for secret expiration and catalog versions
  - Thread-safe access with per-connection mutexes (no cross-connection contention)
  - Secure memory wiping on connection destruction
- **Multi-Tenant Query Parameter**: Automatic `?multitenant=true` for tenant-aware deployments
  - Checks `boilstream.tenant_id` setting via `TryGetCurrentSetting()`
  - Appends parameter to `/secrets` and `/ducklakes` endpoints when tenant_id is set
  - Server prefixes returned names with `__BS_u{tenant_id}__` for transparent isolation
- **Connection State Unit Tests**: Comprehensive test suite for multi-tenant isolation
  - Tests for state creation, isolation, and cleanup
  - Secret expiration and catalog version isolation tests
  - Thread safety tests for concurrent snapshot access
  - Multiple connections concurrent access validation
  - New test executable: `boilstream_connection_state_test`

### Changed

- **DuckDB Compatibility**: Updated to DuckDB v1.4.3
  - Updated `duckdb` submodule to v1.4.3
  - Updated `extension-ci-tools` submodule to v1.4.3 branch
- **Session State Architecture**: Moved from global singleton to per-connection state
  - `RestApiSecretStorage` now delegates session state to `BoilstreamConnectionState`
  - HTTP methods use connection state from `CatalogTransaction` context
  - PRAGMAs use `EnsureConnectionState()` for explicit context access

### Technical Details

- **Connection state access pattern**: `context.registered_state->GetOrCreate<BoilstreamConnectionState>("boilstream_auth")`
- **Multi-tenant URL construction**: `AppendMultiTenantParam(url, transaction)` helper methods
- **State isolation**: Each connection has own `session_lock`, `expiration_lock`, `version_lock`
- **Backward compatible**: Single-connection usage works unchanged

## [0.4.1] - 2025-12-25

### Added

- **Catalog Version Polling**: On-demand detection of catalog master node changes
  - `CheckCatalogVersions()`: Rate-limited version check (60-second interval)
  - `FetchCatalogVersions()`: Fetches `GET /api/v1/catalog-versions` endpoint
  - `RefreshCatalogCredentials()`: Force-expires catalog secrets on version change
  - Automatically triggers credential refresh when master node changes
  - Enables seamless failover for hot tier data (in-memory on master)
  - WASM compatible (no background threads required)
- **Table function**: `boilstream_buckets()` - lists all available S3 buckets from server
  - Columns: bucket_id, bucket_name, region, cloud_provider, access_mode, can_create_ducklake
  - Makes GET /secrets/buckets API call
- **Unit tests**: Comprehensive test suite for catalog version functionality
  - Tests for rate limiting, version comparison, expiration logic
  - Thread safety tests for concurrent access
  - New test executable: `boilstream_catalog_version_test`

### Fixed

- **Session guard in FetchCatalogVersions**: Prevents HTTP calls when no active session exists
  - Avoids crashes when HTTP infrastructure isn't available
  - Gracefully returns empty result instead of attempting network call

### Technical Details

- **Version check flow**: Integrated into `AllSecrets()` for on-demand checking
- **Rate limiting**: 60-second interval stored in `last_version_check` timestamp
- **Version tracking**: `catalog_versions` map stores UUID → {version, catalog_name}
- **Credential refresh**: Sets secret expiration to `time_point::min()`, triggering `expired=true` flag on next lookup
- **Thread safety**: Uses `version_lock` mutex, releases before calling `RefreshCatalogCredentials()`
- **API response format**: `{"catalogs": {"uuid": {"version": N, "catalog_name": "name"}, ...}}`

## [0.4.0] - 2025-11-21

### Added

- **Email/Password Registration**: `PRAGMA boilstream_register_user(url_with_email, password)`
  - Complete registration flow with TOTP enrollment (displays QR code)
  - Auto-installs textplot extension for QR code rendering
  - Caches registration state for QR code re-display (if truncated)
  - Returns formatted TOTP secret and verification command
- **Email/Password/MFA Login**: `PRAGMA boilstream_login(url_with_email, password, mfa_code)`
  - 4-step authentication: CSRF token → login → MFA verification → bootstrap token
  - Performs OPAQUE session establishment inline (no delegation)
  - Auto-fetches secrets and attaches ducklakes
  - Returns session status with expiration timestamp
- **MFA Verification**: `PRAGMA boilstream_verify_mfa(totp_code)`
  - Completes registration after TOTP enrollment
  - Returns backup codes for account recovery
  - Clears registration state after successful verification
- **Registration Caching**: Re-run `boilstream_register_user` to see cached QR code
  - Allows users to correct display mode (`.maxrows 50` or `.mode csv`)
  - No duplicate server registrations
  - State persists until MFA verification completes

### Changed

- **Help text improvements**: Added security warnings and display tips
  - Security banner warns about passwords in shell history
  - Recommends Web Auth GUI for production use
  - Manual cleanup instructions: `rm ~/.duckdb_history`
  - Tip: Use `.maxrows 50` or `.mode csv` for full QR code display
- **Registration state storage**: Extended to include TOTP URI for caching

### Security

- **Shell history warning**: PRAGMA commands with passwords are saved to `~/.duckdb_history`
  - DuckDB query logs disabled by default (not a concern)
  - Shell history redaction not possible from extension
  - Users must clear manually or use Web Auth GUI

## [0.3.5] - 2025-11-19

### Added

- **Auto-attach ducklakes**: PRAGMA now returns multi-statement SQL for automatic ducklake mounting
  - Returns `ATTACH 'ducklake:name' AS name;` statements followed by status SELECT
  - Executes after PRAGMA lock release, preventing deadlock/hanging
  - Shows `ducklakes_attached` count in result (e.g., "2 ducklakes attached")
  - Solves ClientContext lock reentrancy issue via DuckDB's Parser.ParseQuery() multi-statement support
- **Table function**: `boilstream_ducklakes()` - lists all available ducklakes from server
  - Columns: catalog_id, catalog_name, description, access_mode, ownership, granted_by, granted_at, created_at
  - Makes GET /secrets/ducklakes API call
  - Handles both empty array `[]` and object `{"catalogs": [...]}` response formats
- **Table function**: `boilstream_secrets()` - lists all cached secrets with expiration
  - Columns: name, type, provider, scope (as LIST), expires_at
  - Shows expiration timestamps from server metadata
  - Displays all secrets from boilstream storage (postgres, s3, ducklake types)
- **PRAGMA function**: `boilstream_create_ducklake(catalog_name, description)` - creates new ducklakes
  - Makes POST /secrets/ducklakes API call
  - Second parameter (description) is optional via varargs
  - Fetches all secrets after creation (includes postgres, s3, ducklake secrets)
  - Returns success message with catalog_name
- **Extension auto-loading**: Automatically loads required extensions on startup
  - `httpfs` - HTTPS support for REST API calls
  - `postgres_scanner` - Enables postgres secret type caching
  - `ducklake` - Required for ATTACH ducklake commands
  - Uses `ExtensionHelper::TryAutoLoadExtension()` for seamless integration
- **SSO support**: Bootstrap token exchange for WASM/web environments
  - Proxy server (`test/wasm/server.js`) forwards `/auth/*` to boilstream server (bypasses CORS)
  - Auto-fetch bootstrap token from `/auth/api/bootstrap-token` in test page
  - Supports both SSO-authenticated and manual token workflows
  - Enables seamless DuckDB authentication in browser environments

### Changed

- PRAGMA result now includes `ducklakes_attached` column showing auto-attach count
- Empty endpoint initialization (constructor uses `""` instead of `"rest_api"`)
- Secret expires_at now distinguishes temporary vs permanent credentials
  - Temporary (SESSION_TOKEN): 1 hour from now
  - Permanent: 1 year from now (not hardcoded 2099)
- WASM test page auto-fetches bootstrap token, falls back to manual input

### Fixed

- **CRITICAL**: ClientContext lock reentrancy deadlock when auto-attaching ducklakes
  - Root cause: `context.Query("ATTACH...")` called from within PRAGMA (tries to re-acquire context_lock)
  - Solution: Return multi-statement SQL string, DuckDB parses/executes after lock release
  - Impact: PRAGMA no longer hangs when postgres/MinIO backends are running
- Postgres secrets now cache correctly (postgres_scanner auto-loaded before AllSecrets)
- Ducklake ATTACH commands work without manual `LOAD ducklake` (auto-loaded on startup)

### Security

- Bootstrap token never stored persistently in WASM (fetched on-demand from SSO session)
- Proxy server uses HTTPS for upstream requests (rejectUnauthorized: false for localhost testing only)

### Technical Details

- **Multi-statement SQL**: PRAGMA returns semicolon-separated statements
  - DuckDB's `PragmaHandler` parses via `Parser.ParseQuery()` (duckdb/src/planner/pragma_handler.cpp:40-46)
  - All statements execute sequentially after lock release
  - Example: `"ATTACH 'ducklake:cat1' AS cat1;\nATTACH 'ducklake:cat2' AS cat2;\nSELECT 'token' as status..."`
- **Auto-load timing**: Extensions loaded during `LoadInternal()` before storage registration
- **WASM proxy**: Node.js HTTP server with HTTPS proxy using native `https.request()`
  - Proxies `/auth/*` → `https://localhost/auth/*`
  - Copies all headers and request body
  - Returns 502 Bad Gateway on upstream errors
- **Table functions**: Use GlobalTableFunctionState pattern with Init/Function/Bind
- **PRAGMA varargs**: `LogicalType::VARCHAR` as fourth parameter makes description optional
- **JSON parsing**: Uses `duckdb_yyjson::` namespace for all yyjson calls
- **Timestamp handling**: `Timestamp::FromString(str, true)` with use_offset parameter
- **Expires_at detection**: Checks for "SESSION_TOKEN" or "session_token" in secret string

## [0.3.4] - 2025-10-27

### Security

- **CRITICAL**: Added explicit memory zeroing for all sensitive cryptographic material in Rust OPAQUE client using `zeroize` crate. Passwords stored in `RegistrationState`/`LoginState` now use `Zeroizing<Vec<u8>>` wrapper for automatic zeroing on drop. Session keys, export keys, and refresh tokens zeroed in `opaque_free_buffer()` before memory is freed. Intermediate HMAC keys (k_date, k_region, k_service) in AWS-style key derivation now wrapped in `Zeroizing` for automatic cleanup. Prevents sensitive data leakage from freed memory. (opaque-client/Cargo.toml, opaque-client/src/lib.rs:10,111,119,324-326,465-473)

## [0.3.3] - 2025-10-27

### Fixed

- **CRITICAL**: WASM builds failing with `Unknown option '--enable-bulk-memory-opt'` and `--enable-call-indirect-overlong'` errors in newer Emscripten (3.1.50+). CMakeLists.txt now automatically installs wasm-opt wrapper script during configuration that filters deprecated flags. Wrapper is idempotent and works in both local dev and GitHub Actions CI without modifying `.github` workflows. (CMakeLists.txt:27-63, scripts/wasm-opt-wrapper-template.sh)
- **CRITICAL**: Native builds failing with `multiple definition of 'duckdb::FileFlags::FILE_FLAGS_READ'` linker errors. Fixed C++17 ODR violation by using `FileOpenFlags::` constants directly instead of `FileFlags::` wrapper class, avoiding symbol generation in multiple translation units. (src/boilstream_secret_storage.cpp:309,349)
- **MEDIUM**: JavaScript null check in WASM EM_JS changed from `value === null` to idiomatic `Object.is(value, null)` for explicit null checking. Return value changed from `null` to `0` for C pointer type semantics. (src/boilstream_secret_storage.cpp:98)

## [0.3.2] - 2025-10-17

### Fixed

- **WASM Build**: Added explicit `LINKED_LIBS` configuration for WASM builds
  - Added to `extension_config.cmake`: Explicit path to Rust OPAQUE client library
  - Path: `opaque-client/target/wasm32-unknown-emscripten/release/libopaque_client.a`
  - Required by DuckDB extension build system to locate static library during WASM linking
  - Issue: WASM builds failed with missing library errors in CI/CD pipeline
  - Resolution: Extension build system now correctly links Rust library for all WASM variants (mvp, eh, threads)
- **WASM wasm-opt compatibility**: Replace wasm-opt binary with Binaryen version_124
  - Issue: Emscripten 3.1.71 uses Binaryen 120 which removed `--enable-bulk-memory-opt` flag
  - Error: `Unknown option '--enable-bulk-memory-opt'` during final WASM linking in CI
  - Root cause: DuckDB's hard-coded `-O3` optimization triggers wasm-opt with deprecated flags
  - Resolution: Replace wasm-opt binary during CMake configuration (CMakeLists.txt:22-93)
    - Detects emsdk location from `$EMSDK` environment variable
    - Downloads Binaryen version_124 from GitHub releases (same as Emscripten 4.0.16)
    - Extracts wasm-opt binary from archive
    - Backs up original to `wasm-opt.original`
    - Replaces emsdk's wasm-opt with newer version
    - Idempotent: skips if backup already exists (supports incremental builds)
    - Works without `.github` modifications (compatible with DuckDB community extensions)
  - Defense-in-depth: Also sets `-O1` CMAKE flags to reduce wasm-opt usage (lines 95-100)
  - Impact: Full compatibility - uses Binaryen 124 which doesn't have deprecated flags
  - Note: Rust builds already use `-O1` via `.cargo/config.toml` for consistency

### Technical Details

- **Build Configuration**: `extension_config.cmake` now includes `LINKED_LIBS` parameter
- **Library Path**: Uses `${CMAKE_CURRENT_LIST_DIR}` for absolute path resolution
- **wasm-opt Binary Replacement**: Direct binary upgrade approach (CMakeLists.txt:22-93)
  - Detection: Uses `$EMSDK` environment variable to locate emsdk installation
  - Target path: `$EMSDK/upstream/bin/wasm-opt`
  - Source: Downloads Binaryen version_124 tarball from GitHub releases
  - Download URL: `https://github.com/WebAssembly/binaryen/releases/download/version_124/binaryen-version_124-x86_64-linux.tar.gz`
  - Extraction: Uses CMake's built-in tar extraction
  - Binary path: `binaryen-version_124/bin/wasm-opt`
  - Backup: Copies original to `wasm-opt.original` before replacement
  - Installation: Copies new binary over original, preserves execute permissions
  - Idempotency: Skips if backup exists (incremental builds work)
  - Timing: Runs during CMake configuration (before build starts)
  - Binaryen 124: Matches Emscripten 4.0.16, doesn't have deprecated `--enable-bulk-memory-opt`
- **Optimization Override**: `-O1` set via CMAKE_CXX_FLAGS_RELEASE and CMAKE_C_FLAGS_RELEASE (lines 95-100)
  - Provides defense-in-depth by reducing wasm-opt invocations
  - Additional target_link_options also set (lines 189-190)
  - FORCE flag attempts to override DuckDB's -O3 defaults (limited effectiveness)
- **Affected Targets**: wasm32-unknown-emscripten (all variants: mvp, eh, threads)
- **Build System**: Compatible with DuckDB extension-ci-tools v1.4.0 (no .github changes needed)
- **Binaryen Compatibility**: Uses version_124 which is compatible with both old and new Emscripten

## [0.3.1] - 2025-10-15

### Added

- **Session Resumption**: Persistent sessions across DuckDB restarts
  - Refresh tokens derived from `session_key` using HKDF-Expand (RFC 5869)
  - Derivation: `refresh_token = HKDF-Expand(session_key, "session-resumption-v1", 32 bytes)`
  - Server-controlled via `X-Boilstream-Session-Resumption: enabled` header
  - Refresh tokens saved to `~/.duckdb/.boilstream_refresh_token` (encrypted JSON format)
  - Automatic session resumption on extension load (no re-authentication needed)
  - File permissions: 0600 (owner read/write only) on Unix systems
  - Expires after server-specified duration (included in refresh token metadata)
- **Refresh Token Security**:
  - `resume_user_id = SHA256(refresh_token)` for server-side lookup
  - Encrypted storage format with version, endpoint, region, and expiration metadata
  - Automatic deletion of expired or invalid tokens
  - Protected by filesystem permissions (not readable by other users)
- **New API Methods**:
  - `SaveRefreshToken(bool resumption_enabled)`: Save refresh token to disk (if enabled)
  - `LoadRefreshToken()`: Load and validate refresh token from disk
  - `DeleteRefreshToken()`: Remove refresh token file
  - `GetRefreshTokenPath()`: Get platform-specific path to token file
- **Conformance Tests**: Added test coverage for session resumption
  - A.4.4: Refresh token derivation with specification test vectors
  - Integration tests for save/load/resume workflows
  - Security tests for expired and invalid token handling

### Changed

- Extension now automatically attempts session resumption on load
- `PerformOpaqueLogin()` saves refresh token when server enables resumption
- Refresh token replaces `export_key` from OPAQUE protocol (same derivation, different purpose)
- Session resumption is opt-in via server configuration (not client-controlled)

### Fixed

- **CRITICAL**: Windows build failure with `CreateDirectory` macro conflict
  - Error: `'CreateDirectoryA': is not a member of 'duckdb::FileSystem'`
  - Fixed: Added `#undef CreateDirectory` after `<windows.h>` include (src/boilstream_secret_storage.cpp:36)
  - Windows.h defines `CreateDirectory` macro that expands to `CreateDirectoryA`
  - Now properly calls DuckDB's `FileSystem::CreateDirectory` method
  - Issue: Windows build failed on both MSVC and MinGW/rtools42
  - Resolution: Platform-specific macro cleanup (similar to existing `NOMINMAX` pattern)

### Security

- **Enhanced**: Session resumption uses cryptographic derivation from session_key
  - Refresh tokens are single-use and server-invalidated after use
  - Cannot be replayed or reused once consumed
- **Enhanced**: File permissions prevent other users from reading refresh tokens (Unix)
- **Enhanced**: Automatic cleanup of expired tokens prevents stale credential accumulation
- **Enhanced**: `resume_user_id` prevents refresh token enumeration attacks
  - Server stores SHA256(refresh_token), not the token itself
  - Attacker cannot reconstruct refresh token from database

### Technical Details

- **Refresh Token Derivation**: HKDF-Expand only (no Extract step)
  - PRK: `session_key` (from OPAQUE protocol, 32 bytes)
  - Info: `"session-resumption-v1"` (string literal)
  - OKM: 32 bytes (256-bit refresh token)
- **File Format**: JSON with encrypted metadata
  - `version`: Schema version (currently 1)
  - `refresh_token`: Base64-encoded token bytes
  - `endpoint_url`: API endpoint for resumption
  - `region`: Service region for request signing
  - `expires_at`: ISO 8601 timestamp (UTC)
- **File Path**: Platform-specific
  - Unix/macOS: `~/.duckdb/.boilstream_refresh_token`
  - Windows: `%USERPROFILE%\.duckdb\.boilstream_refresh_token`
- **Test Coverage**: 3 new integration tests
  - Refresh token save when server enables resumption
  - Session resumption after DuckDB restart
  - Automatic deletion of expired/invalid tokens
- **Conformance**: Test vector validation (SECURITY_SPECIFICATION.md A.4.4)
  - Expected refresh_token: `870246bc83f0728dac2c1d486834a7eefe1565c6252469c895374fc733828942`
  - Expected resume_user_id: `4cf42b1fbdc10b41302f03978931de2ae6d4581c8531c6b740aa3a5c0043bd33`

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
  - MinGW/GCC: Use linker groups for Rust library dependencies
    - Wraps all Rust dependencies in --start-group/--end-group for multi-pass linking
    - Libraries in group: ws2_32, userenv, bcrypt, ntdll, stdc++, gcc (with -static-libgcc/-static-libstdc++)
    - Provides f16 compiler builtins (**extendhfsf2, **truncsfhf2) from gcc
    - Provides C++ RTTI (??\_7type_info@@6B@) from stdc++
    - Provides stack checking (\_\_chkstk) from gcc
    - Uses --allow-multiple-definition for weak symbol conflicts
    - Resolves link order issues - symbols found regardless of library order
  - MSVC: Fixed min/max macro conflicts with std::chrono (added NOMINMAX define)
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

[0.4.1]: https://github.com/yourusername/boilstream-extension/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/yourusername/boilstream-extension/compare/v0.3.5...v0.4.0
[0.3.5]: https://github.com/yourusername/boilstream-extension/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/yourusername/boilstream-extension/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/yourusername/boilstream-extension/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/yourusername/boilstream-extension/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/yourusername/boilstream-extension/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/yourusername/boilstream-extension/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yourusername/boilstream-extension/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/boilstream-extension/releases/tag/v0.1.0
