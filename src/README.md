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

-- 2. Set your BoilStream API endpoint with token
PRAGMA duckdb_secrets_boilstream_endpoint('https://api.example.com/secrets/:your_token_here');

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

## Configuration

### Setting the Endpoint

The endpoint format is: `<endpoint_url>:<token>`

```sql
-- Production (HTTPS required)
PRAGMA duckdb_secrets_boilstream_endpoint('https://api.example.com/secrets/:mu2iteixe0fe9Um1Eimie0leNguv7Aic');

-- Development (localhost allowed with HTTP)
PRAGMA duckdb_secrets_boilstream_endpoint('http://localhost:4332/secrets/:testtoken123');

-- With port
PRAGMA duckdb_secrets_boilstream_endpoint('https://api.example.com:8443/secrets/:token');
```

**Security Notes:**

- Token is sent via `Authorization: Bearer <token>` header (never in URL)
- HTTPS is enforced for production (non-localhost) endpoints
- Each user should have a unique endpoint URL + token combination

### Environment Variable (Optional)

Set a default endpoint at extension load time:

```bash
export DUCKDB_REST_API_URL="http://localhost:8080/api"
```

This is overridden by `PRAGMA duckdb_secrets_boilstream_endpoint()`.

## REST API Implementation Guide

Your backend must implement these HTTP endpoints. All requests include `Authorization: Bearer <token>` header.

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
# From DuckDB root directory
GEN=ninja make

# The extension will be built at:
# build/release/extension/boilstream/boilstream.duckdb_extension
```

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
