# BoilStream Secrets Extension

A DuckDB extension that provides REST API-based secret storage for multi-tenant deployments.

## Overview

This extension replaces DuckDB's built-in file-based secret storage with a REST API backend, enabling:

- **Multi-tenant secret isolation** - Each user gets unique endpoint URL + token
- **Centralized secret management** - All secrets stored in your backend service
- **Secure token handling** - Tokens sent via Authorization header (not URLs)
- **Audit trails** - Track all secret access through your API
- **Dynamic secrets** - Integration with external providers (AWS Secrets Manager, Vault, etc.)

## Quick Start

```sql
-- 1. Load the extension
LOAD 'build/release/extension/boilstream/boilstream.duckdb_extension';

-- 2. Set your BoilStream API endpoint with BOOTSTRAP TOKEN (v0.2.0+)
-- Bootstrap token is short-lived (5 min) and exchanged for 8-hour session token via PKCE
PRAGMA duckdb_secrets_boilstream_endpoint('https://api.example.com/secrets/:your_bootstrap_token_here');

-- 3. Create and use secrets normally
CREATE PERSISTENT SECRET my_s3 (
    TYPE S3,
    KEY_ID 'AKIAIOSFODNN7EXAMPLE',
    SECRET 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    REGION 'us-east-1'
);

-- 4. Secrets work transparently
SELECT * FROM 's3://my-bucket/data.parquet';
```

**What's New in v0.2.0:**
- Uses PKCE (Proof Key for Code Exchange, RFC 7636) for enhanced security
- Bootstrap token (5-minute TTL, single-use) is exchanged for session token (8-hour TTL)
- Session token automatically rotates before expiry
- All tokens stored in-memory only (never persisted)

## Configuration

### Setting the Endpoint

**v0.2.0+** The endpoint format is: `<endpoint_url>:<bootstrap_token>`

```sql
-- Production (HTTPS required)
PRAGMA duckdb_secrets_boilstream_endpoint('https://api.example.com/secrets/:mu2iteixe0fe9Um1Eimie0leNguv7Aic');

-- Development (localhost allowed with HTTP)
PRAGMA duckdb_secrets_boilstream_endpoint('http://localhost:4332/secrets/:testtoken123');

-- With port
PRAGMA duckdb_secrets_boilstream_endpoint('https://api.example.com:8443/secrets/:bootstrap_token_here');
```

**Security Notes:**

- **Bootstrap token** is short-lived (5 minutes) and single-use
- Automatically exchanged for **session token** (8 hours) via PKCE flow
- Session token rotates automatically when <30 minutes remain
- All tokens sent via `Authorization: Bearer <token>` header (never in URL)
- HTTPS is enforced for production (non-localhost) endpoints
- Each user should have a unique endpoint URL + bootstrap token combination

**Token Lifecycle:**
1. User provides bootstrap token via PRAGMA
2. Extension performs PKCE token exchange (generates code_verifier and code_challenge)
3. Receives session token (valid for 8 hours)
4. Uses session token for all API requests
5. Automatically rotates session token before expiry

### Environment Variable (Optional)

Set a default endpoint at extension load time:

```bash
export DUCKDB_REST_API_URL="http://localhost:8080/api"
```

This is overridden by `PRAGMA duckdb_secrets_boilstream_endpoint()`.

## PKCE Authentication (v0.2.0+)

**Important:** v0.2.0 introduced PKCE (Proof Key for Code Exchange, RFC 7636) authentication. Your backend must implement these authentication endpoints in addition to the secret management endpoints below.

### Overview

PKCE provides enhanced security by ensuring that even if a token is intercepted, it cannot be used without the corresponding code_verifier. The flow works as follows:

1. **Bootstrap → Session**: Extension exchanges short-lived bootstrap token (5 min) for session token (8 hours)
2. **PKCE Proof**: Extension generates code_verifier (random 64-char string) and code_challenge (SHA256 hash)
3. **Server Storage**: Server stores code_challenge (never sees code_verifier)
4. **Rotation**: Before expiry, extension proves possession of code_verifier to rotate token
5. **Chain of Trust**: Each rotation includes new_code_challenge for the next rotation

### Authentication Endpoint 1: Token Exchange

**Endpoint:** `POST /auth/api/token-exchange`

**Purpose:** Exchange a short-lived bootstrap token for a long-lived session token.

**Request Headers:**
```
Content-Type: application/json
```

**Note:** NO Authorization header is sent for token exchange (bootstrap token is in body).

**Request Body:**
```json
{
  "bootstrap_token": "mu2iteixe0fe9Um1Eimie0leNguv7Aic",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256"
}
```

**Fields:**
- `bootstrap_token`: The short-lived (5 min) bootstrap token provided by user via PRAGMA
- `code_challenge`: base64url(SHA256(code_verifier)) - proves client has a secret code_verifier
- `code_challenge_method`: Always "S256" (SHA256 hashing)

**Response Body:**
```json
{
  "session_token": "Eechoh8ieb8uf5uo1eeG4ait4siexai7",
  "expires_at": "2025-10-08T20:00:00Z"
}
```

**Response Fields:**
- `session_token`: The long-lived session token (8 hours recommended)
- `expires_at`: ISO 8601 UTC timestamp OR Unix timestamp (seconds since epoch)

**Server Implementation Requirements:**

1. **Validate bootstrap token**
   - Check bootstrap token is valid and not expired (5 min TTL)
   - Mark bootstrap token as used (single-use only)
   - Return 401 if invalid or expired

2. **Store code_challenge**
   - Associate code_challenge with the new session_token
   - Store for verification during rotation
   - Never store code_verifier (client keeps it secret)

3. **Generate session token**
   - Create new session_token with 8-hour expiration
   - Use cryptographically secure random generation
   - Recommended length: 32-64 characters

4. **Error Handling**
   - 400 Bad Request: Missing or invalid fields
   - 401 Unauthorized: Invalid or expired bootstrap token
   - 409 Conflict: Bootstrap token already used

**Example (Node.js):**
```javascript
app.post('/auth/api/token-exchange', async (req, res) => {
  const { bootstrap_token, code_challenge, code_challenge_method } = req.body;

  // Validate bootstrap token
  const bootstrapRecord = await db.bootstrapTokens.findOne({ token: bootstrap_token });
  if (!bootstrapRecord || bootstrapRecord.used || Date.now() > bootstrapRecord.expires_at) {
    return res.status(401).json({ error: 'Invalid or expired bootstrap token' });
  }

  // Mark as used
  await db.bootstrapTokens.update({ token: bootstrap_token }, { used: true });

  // Generate session token
  const session_token = crypto.randomBytes(32).toString('base64url');
  const expires_at = new Date(Date.now() + 8 * 60 * 60 * 1000); // 8 hours

  // Store session with code_challenge
  await db.sessions.insert({
    token: session_token,
    code_challenge: code_challenge,
    expires_at: expires_at,
    user_id: bootstrapRecord.user_id
  });

  res.json({
    session_token: session_token,
    expires_at: expires_at.toISOString()
  });
});
```

---

### Authentication Endpoint 2: Token Rotation

**Endpoint:** `POST /auth/api/token-rotate`

**Purpose:** Rotate session token before expiry (automatic when <30 min remaining).

**Request Headers:**
```
Content-Type: application/json
Authorization: Bearer <current-session-token>
```

**Note:** Both Authorization header AND body contain session_token for verification.

**Request Body:**
```json
{
  "session_token": "Eechoh8ieb8uf5uo1eeG4ait4siexai7",
  "code_verifier": "v8K_N7zDfE...64-char-random-string...pQmL4bXwR9",
  "new_code_challenge": "t6K8uL2vN5rP...base64url-sha256...X9hZ3kJ1Y",
  "code_challenge_method": "S256"
}
```

**Fields:**
- `session_token`: Current session token (also in Authorization header)
- `code_verifier`: The secret 64-char random string from previous exchange/rotation
- `new_code_challenge`: base64url(SHA256(new_code_verifier)) for next rotation
- `code_challenge_method`: Always "S256"

**Response Body:**
```json
{
  "session_token": "Ohsh9OhV6rie0ahX0shaez0Quoo1eiph",
  "expires_at": "2025-10-09T04:00:00Z"
}
```

**Response Fields:**
- `session_token`: New session token (8 hours from now)
- `expires_at`: ISO 8601 UTC timestamp OR Unix timestamp

**Server Implementation Requirements:**

1. **Verify session token**
   - Verify Authorization header matches session_token in body
   - Check session token is valid and not expired
   - Return 401 if invalid or expired

2. **Verify PKCE proof**
   - Retrieve stored code_challenge for this session
   - Compute: base64url(SHA256(code_verifier))
   - Verify computed challenge matches stored code_challenge
   - Return 403 if verification fails (proves possession of code_verifier)

3. **Generate new session token**
   - Create new session_token with 8-hour expiration
   - Replace old session_token (invalidate it)
   - Store new_code_challenge for next rotation
   - Maintain user_id association

4. **Security Notes**
   - CRITICAL: Verify code_verifier matches stored code_challenge
   - This proves the client possesses the secret from original exchange
   - Even if session_token is intercepted, attacker cannot rotate without code_verifier

5. **Error Handling**
   - 400 Bad Request: Missing or invalid fields
   - 401 Unauthorized: Invalid or expired session token
   - 403 Forbidden: code_verifier does not match code_challenge

**Example (Node.js):**
```javascript
const crypto = require('crypto');

app.post('/auth/api/token-rotate', async (req, res) => {
  const authHeader = req.headers.authorization;
  const { session_token, code_verifier, new_code_challenge, code_challenge_method } = req.body;

  // Verify Authorization header matches body
  if (!authHeader || !authHeader.startsWith('Bearer ') || authHeader.substring(7) !== session_token) {
    return res.status(401).json({ error: 'Authorization mismatch' });
  }

  // Verify session token
  const session = await db.sessions.findOne({ token: session_token });
  if (!session || Date.now() > session.expires_at) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }

  // Verify PKCE: compute challenge from verifier and compare
  const computed_challenge = crypto
    .createHash('sha256')
    .update(code_verifier)
    .digest('base64url');

  if (computed_challenge !== session.code_challenge) {
    return res.status(403).json({ error: 'PKCE verification failed' });
  }

  // Generate new session token
  const new_session_token = crypto.randomBytes(32).toString('base64url');
  const expires_at = new Date(Date.now() + 8 * 60 * 60 * 1000); // 8 hours

  // Update session with new token and challenge
  await db.sessions.update(
    { token: session_token },
    {
      token: new_session_token,
      code_challenge: new_code_challenge,
      expires_at: expires_at
    }
  );

  res.json({
    session_token: new_session_token,
    expires_at: expires_at.toISOString()
  });
});
```

---

### PKCE Security Benefits

✅ **Token Interception Protection**: Even if session_token is intercepted, attacker cannot rotate it without code_verifier
✅ **Proof of Possession**: Client must prove possession of secret code_verifier on each rotation
✅ **Forward Secrecy**: Each rotation uses new code_verifier/code_challenge pair
✅ **No Shared Secrets**: Server only stores code_challenge (hash), not code_verifier
✅ **Single-Use Bootstrap**: Bootstrap tokens expire after 5 minutes and are single-use

---

## REST API Implementation Guide

Your backend must implement these HTTP endpoints for secret management. All requests include `Authorization: Bearer <session_token>` header (obtained from token exchange above).

### 1. Create Secret

**Endpoint:** `POST /secrets`

**Headers:**

```
Authorization: Bearer <token>
Content-Type: application/json
Idempotency-Key: <unique-key>
```

The `Idempotency-Key` header is sent by the extension to prevent duplicate secret creation during retries. Your API should:

1. Store the idempotency key with the operation result
2. Return the same response for duplicate requests with the same key
3. Keys should expire after 120 seconds (sufficient for retry window)

**Request Body:**

```json
{
  "secret": {
    "name": "my_s3_secret",
    "type": "s3",
    "provider": "config",
    "scope": ["s3://", "s3n://", "s3a://"],
    "data": "PGJhc2U2NC1lbmNvZGVkLWJpbmFyeS1zZWNyZXQ+"
  },
  "on_conflict": "replace"
}
```

**Fields:**

- `secret.name`: Secret name
- `secret.type`: Secret type (s3, gcs, azure, etc.)
- `secret.provider`: Provider name (config, env, etc.)
- `secret.scope`: Array of path prefixes this secret matches
- `secret.data`: Base64-encoded binary blob (DuckDB's serialized secret)
- `on_conflict`: `"replace"` or `"error"`

**Response:** `200 OK` (empty body)

**Example:**

```bash
curl -X POST https://api.example.com/secrets \
  -H "Authorization: Bearer mu2iteixe0fe9Um1Eimie0leNguv7Aic" \
  -H "Content-Type: application/json" \
  -d '{
    "secret": {
      "name": "my_s3_secret",
      "type": "s3",
      "provider": "config",
      "scope": ["s3://"],
      "data": "PGJhc2U2NC1lbmNvZGVkLWJpbmFyeS1zZWNyZXQ+"
    },
    "on_conflict": "replace"
  }'
```

---

### 2. Match Secret

**Endpoint:** `POST /secrets/match`

**Headers:**

```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "path": "s3://my-bucket/data.parquet",
  "type": "s3",
  "expired": false
}
```

**Fields:**

- `path`: The resource path to match against secret scopes
- `type`: The secret type (s3, gcs, azure, etc.)
- `expired`: Boolean indicating if the DuckDB client's cached version has expired (optional, defaults to false)

**Response:**

```json
{
  "name": "my_s3_secret",
  "type": "s3",
  "provider": "config",
  "scope": ["s3://"],
  "data": "PGJhc2U2NC1lbmNvZGVkLWJpbmFyeS1zZWNyZXQ+",
  "expires_at": "2025-10-06T15:30:00Z"
}
```

Return `{}` or `null` if no matching secret found.

**Response Fields:**

- `expires_at`: ISO 8601 UTC timestamp when the secret expires and should be refreshed from cache

**Behavior:**

- When `expired=false`: Return existing secret from storage
- When `expired=true`: Vend fresh credentials from provider (AWS STS, Vault, etc.), update storage, and return refreshed secret with new `expires_at`

**Example:**

```bash
# First fetch (not expired)
curl -X POST https://api.example.com/secrets/match \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{"path": "s3://bucket/file", "type": "s3", "expired": false}'

# Refresh fetch (cache expired)
curl -X POST https://api.example.com/secrets/match \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{"path": "s3://bucket/file", "type": "s3", "expired": true}'
```

---

### 3. Get Secret by Name

**Endpoint:** `POST /secrets/get`

**Headers:**

```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**

```json
{
  "name": "my_s3_secret",
  "expired": false
}
```

**Fields:**

- `name`: The secret name (can contain special characters like `/`, `:`)
- `expired`: Boolean indicating if the DuckDB client's cached version has expired (optional, defaults to false)

**Response:**

```json
{
  "name": "my_s3_secret",
  "type": "s3",
  "provider": "config",
  "scope": ["s3://"],
  "data": "PGJhc2U2NC1lbmNvZGVkLWJpbmFyeS1zZWNyZXQ+",
  "expires_at": "2025-10-06T15:30:00Z"
}
```

Return `{}` or `null` if secret not found.

**Behavior:**

- When `expired=false`: Return existing secret from storage
- When `expired=true`: Vend fresh credentials from provider, update storage, and return refreshed secret

**Example:**

```bash
# Get secret (not expired)
curl -X POST https://api.example.com/secrets/get \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{"name": "my_s3_secret", "expired": false}'

# Refresh secret (cache expired)
curl -X POST https://api.example.com/secrets/get \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d '{"name": "test/with:special", "expired": true}'
```

**Note:** Secret names can contain `/`, `:`, and other special characters. Since they're in the JSON body (not URL), no encoding is needed.

---

### 4. List All Secrets

**Endpoint:** `GET /secrets`

**Headers:**

```
Authorization: Bearer <token>
```

**Response:**

```json
[
  {
    "name": "my_s3_secret",
    "type": "s3",
    "provider": "config",
    "scope": ["s3://"],
    "data": "PGJhc2U2NC1lbmNvZGVkLWJpbmFyeS1zZWNyZXQ+",
    "expires_at": "2025-10-06T15:30:00Z"
  },
  {
    "name": "my_gcs_secret",
    "type": "gcs",
    "provider": "config",
    "scope": ["gs://"],
    "data": "YW5vdGhlci1iYXNlNjQtc2VjcmV0",
    "expires_at": "2025-10-06T15:35:00Z"
  }
]
```

---

### 5. Delete Secret

**Endpoint:** `DELETE /secrets/<url-encoded-name>`

**Headers:**

```
Authorization: Bearer <token>
```

**Response:**

- `200 OK` - Secret deleted
- `404 Not Found` - Secret doesn't exist (optional, extension handles this)

**Example:**

```bash
curl -X DELETE https://api.example.com/secrets/my_s3_secret \
  -H "Authorization: Bearer token"
```

---

## Secret Caching and Expiration

The extension implements **client-side caching** to reduce REST API calls and improve performance:

### How Caching Works

1. **First Access**: When a secret is first needed (via lookup, get by name, or list all), it's fetched from the REST API and stored in the local catalog
2. **Subsequent Access**: The cached version is used if not expired
3. **Expiration Check**: Before using a cached secret, the extension checks if `expires_at` timestamp has passed
4. **Refresh**: If expired, the extension fetches the latest version from REST API and updates the cache
5. **Explicit Updates**: `CREATE PERSISTENT SECRET` with `REPLACE` and `DROP SECRET` immediately update both cache and REST API

### Cache Invalidation

The cache is invalidated when:

- The `expires_at` timestamp (provided by REST API) is reached
- A secret is explicitly created/updated with `CREATE PERSISTENT SECRET ... (ON CONFLICT REPLACE)`
- A secret is dropped with `DROP SECRET`

### Performance Benefits

- **Reduced Latency**: Secrets are served from local memory for repeat access
- **Lower API Load**: REST API is only called when cache misses or expires
- **Configurable TTL**: Your REST API controls cache lifetime via `expires_at` (recommended: 5 minutes)

### expires_at Field

The REST API must include an `expires_at` field in all secret responses:

```json
{
  "name": "my_secret",
  "expires_at": "2025-10-06T15:30:00Z"
}
```

- **Format**: ISO 8601 UTC timestamp (e.g., `"2025-10-06T15:30:00Z"`)
- **Recommended TTL**: 1800-7200 seconds (30 minutes to 2 hours) from current time
- **Maximum TTL**: 86400 seconds (24 hours) - longer TTLs reduce security
- **Minimum effective TTL**: 300 seconds (5 minutes) - the client refreshes secrets with <5 minutes remaining
- **Purpose**: Balances cache performance with secret freshness and security

**Important:** The DuckDB extension considers a secret expired when it has **less than 5 minutes of lifetime remaining**. This ensures credentials are refreshed proactively before they become invalid.

**Expiration Logic:**

```javascript
// Server calculates expires_at (1 hour TTL example)
const expiresAt = new Date(Date.now() + 3600 * 1000);

// Client checks if expired with 5-minute buffer
const now = Date.now();
const expiresAtTime = new Date(expiresAt).getTime();
const BUFFER_MS = 5 * 60 * 1000; // 5 minutes

if (now >= expiresAtTime - BUFFER_MS) {
  // Secret considered expired, request refresh with expired=true
}
```

**Example calculation** (Node.js):

```javascript
const TTL_SECONDS = 3600; // 1 hour
const expiresAt = new Date(Date.now() + TTL_SECONDS * 1000).toISOString();
```

**Recommended TTL by secret type:**

- **Temporary credentials** (AWS STS, OAuth tokens): 1800-3600s (30min-1hr)
- **Long-lived credentials** (service accounts): 3600-7200s (1-2hrs)
- **Static credentials** (API keys): 7200-14400s (2-4hrs)
- **Never exceed**: 86400s (24hrs)

---

## Security Model

### Token-Based Isolation

Each user gets a unique **endpoint URL + token**:

```
User Alice: https://api.example.com/secrets/:token_alice_xyz123
User Bob:   https://api.example.com/secrets/:token_bob_abc456
```

The extension:

1. Extracts token from endpoint URL
2. Sends token via `Authorization: Bearer <token>` header
3. Never includes token in URL paths or query parameters

### Backend Responsibilities

Your REST API must:

1. **Validate Token**: Check `Authorization: Bearer` header on every request
2. **Enforce Isolation**: Map token → user and return only that user's secrets
3. **Handle URL Encoding**: Decode secret names in URL paths
4. **Encrypt at Rest**: Store secrets encrypted in your database
5. **Audit Logging**: Log all secret access with timestamps
6. **Idempotency Keys**: Handle `Idempotency-Key` header on POST requests to prevent duplicate operations during retries (cache for 120 seconds)

### Security Features

✅ **No Token Leakage**: Tokens in Authorization header (not logged in URLs)
✅ **HTTPS Enforced**: Production endpoints must use HTTPS
✅ **JSON Injection Protected**: Uses yyjson library (auto-escapes)
✅ **URL Injection Protected**: Secret names URL-encoded
✅ **SQL Injection Protected**: Proper escaping in PRAGMA returns
✅ **Thread-Safe**: Mutex-protected shared state
✅ **Recursion-Safe**: Prevents infinite loops during HTTP operations
✅ **Network Resilient**: Automatic retries with exponential backoff (up to 3 retries)
✅ **Idempotent**: Idempotency keys prevent duplicate secret creation during retries
✅ **Status Code Validation**: Explicit HTTP 2xx status code checks

---

## Retry Behavior and Idempotency

The extension automatically retries failed requests to handle transient network issues:

**Retry Policy:**

- **Max Retries**: 3 retries (4 total attempts: 1 initial + 3 retries)
- **Backoff**: Short exponential delays (100ms, 200ms, 400ms)
- **Worst-Case Delay**: 700ms total (keeps DuckDB responsive)
- **Retryable Errors**:
  - Network failures (connection errors, timeouts)
  - HTTP 408 Request Timeout
  - HTTP 429 Too Many Requests
  - HTTP 500 Internal Server Error
  - HTTP 503 Service Unavailable

**Non-Retryable Errors:**

- HTTP 401 Unauthorized (invalid token)
- HTTP 400 Bad Request (malformed request)
- HTTP 403 Forbidden (permission denied)
- HTTP 404 Not Found (secret doesn't exist)

**Idempotency Keys:**

To prevent duplicate secret creation during retries, the extension sends an `Idempotency-Key` header on POST requests:

```
Idempotency-Key: 12345678901234567890
```

**Cache Duration**: Idempotency keys should be cached for **120 seconds**, which covers:

- All retry attempts (max 700ms)
- Network delays
- Potential duplicate requests from client

Your API should implement idempotency:

```javascript
// Example: Store idempotency keys with operation results and TTL
const idempotencyCache = new Map(); // token -> { key -> { result, expiry } }

app.post("/secrets", (req, res) => {
  const idempotencyKey = req.headers["idempotency-key"];
  const token = req.token;

  // Check if we've seen this key before and it hasn't expired
  if (idempotencyCache.has(token)) {
    const tokenCache = idempotencyCache.get(token);
    const cached = tokenCache.get(idempotencyKey);

    if (cached && cached.expiry > Date.now()) {
      // Return cached result (same response as original request)
      return res.status(200).json(cached.result);
    }
  }

  // Process the request
  const result = createSecret(req.body, token);

  // Cache the result with 120 second expiry
  if (!idempotencyCache.has(token)) {
    idempotencyCache.set(token, new Map());
  }
  idempotencyCache.get(token).set(idempotencyKey, {
    result: result,
    expiry: Date.now() + 120000, // 120 seconds
  });

  res.status(200).json(result);
});

// Cleanup expired entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, tokenCache] of idempotencyCache) {
    for (const [key, cached] of tokenCache) {
      if (cached.expiry <= now) {
        tokenCache.delete(key);
      }
    }
    if (tokenCache.size === 0) {
      idempotencyCache.delete(token);
    }
  }
}, 60000); // Clean up every 60 seconds
```

---

## Secret Data Format

The `data` field contains a base64-encoded binary blob. This is DuckDB's internal secret serialization format.

**To decode** (for debugging only):

```python
import base64

# Example data from API response
data = "PGJhc2U2NC1lbmNvZGVkLWJpbmFyeS1zZWNyZXQ+"
binary = base64.b64decode(data)

# This is DuckDB's binary format - use DuckDB to deserialize
# Your API should treat this as opaque binary data
```

**DO NOT** parse or modify this binary data. Store it as-is and return it unchanged.

---

## Example: Complete Implementation (Node.js)

```javascript
const express = require("express");
const app = express();
app.use(express.json());

// In-memory storage (use database in production)
const secrets = new Map(); // token -> { secrets: Map }

// Middleware: Extract and validate token
app.use((req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  req.token = auth.substring(7);

  // Initialize storage for this token
  if (!secrets.has(req.token)) {
    secrets.set(req.token, { secrets: new Map() });
  }
  req.userSecrets = secrets.get(req.token).secrets;
  next();
});

// POST /secrets - Create secret
app.post("/secrets", (req, res) => {
  const { secret, on_conflict } = req.body;

  if (on_conflict === "error" && req.userSecrets.has(secret.name)) {
    return res.status(409).json({ error: "Secret already exists" });
  }

  req.userSecrets.set(secret.name, secret);
  res.status(200).send();
});

// POST /secrets/match - Find matching secret
app.post("/secrets/match", (req, res) => {
  const { path, type, expired } = req.body;

  let bestMatch = null;
  let bestScore = -1;

  for (const secret of req.userSecrets.values()) {
    if (secret.type.toLowerCase() !== type.toLowerCase()) continue;

    for (const scopePrefix of secret.scope) {
      if (path.startsWith(scopePrefix)) {
        const score = scopePrefix.length;
        if (score > bestScore) {
          bestScore = score;
          bestMatch = secret;
        }
      }
    }
  }

  if (!bestMatch) {
    return res.json({});
  }

  // If expired=true, vend fresh credentials (example: refresh AWS STS tokens)
  if (expired) {
    // TODO: Implement credential refresh logic here
    // - Call AWS STS AssumeRole for fresh temp credentials
    // - Update bestMatch.data with new credentials
    // - Update bestMatch.expires_at with new expiration
  }

  res.json(bestMatch);
});

// POST /secrets/get - Get secret by name
app.post("/secrets/get", (req, res) => {
  const { name, expired } = req.body;
  const secret = req.userSecrets.get(name);

  if (!secret) {
    return res.status(404).json({ error: "Not found" });
  }

  // If expired=true, vend fresh credentials
  if (expired) {
    // TODO: Implement credential refresh logic here
    // - Call AWS STS AssumeRole for fresh temp credentials
    // - Update secret.data with new credentials
    // - Update secret.expires_at with new expiration
  }

  res.json(secret);
});

// GET /secrets - List all secrets
app.get("/secrets", (req, res) => {
  res.json(Array.from(req.userSecrets.values()));
});

// DELETE /secrets/:name - Delete secret
app.delete("/secrets/:name", (req, res) => {
  const name = decodeURIComponent(req.params.name);
  const deleted = req.userSecrets.delete(name);

  res.status(deleted ? 200 : 404).send();
});

app.listen(4332, () => {
  console.log("REST Secrets API listening on port 4332");
});
```

**Test it:**

```bash
# Start the server
node server.js

# In DuckDB
PRAGMA duckdb_secrets_boilstream_endpoint('http://localhost:4332/secrets/:mytoken123');
CREATE PERSISTENT SECRET test (TYPE S3, KEY_ID 'key', SECRET 'secret');
SELECT * FROM duckdb_secrets();
```

---

## Building the Extension

```bash
# From extension root directory
GEN=ninja make

# The extension will be built at:
# build/release/extension/boilstream/boilstream.duckdb_extension

# If you get version mismatch errors, override the version to match your DuckDB:
OVERRIDE_GIT_DESCRIBE="v1.4.1" GEN=ninja make
```

---

## Testing

### Unit Tests

Unit tests verify security functions (PKCE, token validation, etc.) without requiring a server:

```bash
cd test/cpp
mkdir -p build && cd build
cmake ..
make
./boilstream_test  # Run all 236 unit tests
```

### Integration Tests

Integration tests verify end-to-end flows against a real boilstream server. **You must have a running server and a fresh bootstrap token.**

**Important:** Bootstrap tokens are short-lived (5 min) and single-use. The test suite exchanges the token once at startup and shares the session across all tests.

```bash
# 1. Build the extension first (override version to match your DuckDB)
cd /path/to/boilstream-extension
OVERRIDE_GIT_DESCRIBE="v1.4.1" GEN=ninja make

# 2. Get a fresh bootstrap token from your boilstream server

# 3. Set environment variables:
export BOILSTREAM_TEST_ENDPOINT="https://localhost/secrets:your_fresh_bootstrap_token"

# Optional: Specify extension path (default: ../../../build/release/extension/boilstream/boilstream.duckdb_extension)
export BOILSTREAM_EXTENSION_PATH="/path/to/build/release/extension/boilstream/boilstream.duckdb_extension"

# 4. Run integration tests
cd test/cpp/build
./boilstream_integration_test

# Note: Tests will fail if BOILSTREAM_TEST_ENDPOINT is not set
```

**Environment Variables:**
- `BOILSTREAM_TEST_ENDPOINT` (required): Full endpoint URL with fresh bootstrap token
- `BOILSTREAM_EXTENSION_PATH` (optional): Path to your local boilstream extension build

**How the tests work:**
1. First test exchanges the bootstrap token (single-use, consumed once)
2. All subsequent tests share the same session token (8-hour lifetime)
3. Invalid token tests use fake tokens to avoid consuming the real bootstrap token

**What the integration tests verify:**
- Bootstrap token exchange (successful exchange)
- Token validation (invalid/empty tokens, malformed URLs)
- Secret CRUD operations (create, list, delete)
- Token rotation (automatic before expiry)
- Error handling (non-existent secrets, duplicates)
- Concurrent operations (multiple connections)

---

## Troubleshooting

### "No endpoint URL configured"

You need to call `PRAGMA duckdb_secrets_boilstream_endpoint()` first:

```sql
PRAGMA duckdb_secrets_boilstream_endpoint('https://api.example.com/secrets/:token');
```

### "Could not establish connection"

Your REST API server is not running or not reachable. Check:

- Server is running
- Endpoint URL is correct
- Firewall allows connections
- HTTPS certificate is valid

### "URL must use HTTPS"

Production endpoints must use HTTPS. For local testing, use `localhost`:

```sql
-- ✅ Allowed (localhost)
PRAGMA duckdb_secrets_boilstream_endpoint('http://localhost:4332/secrets/:token');

-- ❌ Not allowed (non-localhost HTTP)
PRAGMA duckdb_secrets_boilstream_endpoint('http://192.168.1.100:4332/secrets/:token');

-- ✅ Allowed (HTTPS)
PRAGMA duckdb_secrets_boilstream_endpoint('https://api.example.com/secrets/:token');
```

### Secret Names with Special Characters

Secret names can contain `/`, `:`, and other special characters. The extension automatically URL-encodes them:

```sql
CREATE SECRET "test/with:special" (TYPE S3, KEY_ID 'key', SECRET 'sec');
-- Sent as: GET /secrets/test%2Fwith%3Aspecial
```

Your API must decode URL parameters: `decodeURIComponent(req.params.name)` in JavaScript.

---

## Limitations

1. **Connection Cleanup**: Connection-to-user mappings are not automatically cleaned up. For long-running servers, this map grows slowly (bounded by connection count).

2. **No HTTP Timeouts**: Requests can hang indefinitely if backend is slow. Configure timeouts in your HTTP client.

3. **No Extension Unload Handler**: If you unload and reload the extension, restart DuckDB.

---

## License

MIT License - Same as DuckDB
