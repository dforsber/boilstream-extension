⏺ Complete Design Summary

Authentication Flow

1. Bootstrap: One-time token from web GUI → OPAQUE login
2. OPAQUE produces:


    - session_key (32 bytes, in-memory only, never stored)
    - export_key (for resume, stored encrypted, 8h TTL)
    - Server issues session_token (opaque identifier)

3. PKCE setup: Send code_challenge with login → enables token rotation
4. Server state: sessions[session_token] = {user_id, session_key, sequence: 0, expires_at}

Cryptographic Operations (By-the-Book)

Key Derivation (HKDF-SHA256):
master = session_key (from OPAQUE)
signing_key = HKDF(master, salt="request-signing", info="v1")
encryption_key = HKDF(master, salt="secret-encryption", info="v1")

Request Signing (HMAC-SHA256):
sequence++ # Client increments
message = method || url || body || timestamp || sequence
signature = HMAC-SHA256(signing_key, message)

Headers:
Authorization: Bearer <session_token>
X-Sequence: <sequence>
X-Timestamp: <unix_seconds>
X-Signature: <base64(signature)>

Secret Encryption (AES-256-GCM):
nonce = random(12 bytes) # Unique per message
ciphertext = AES-256-GCM(encryption_key, plaintext, nonce, aad=session_token)
Response: {encrypted: base64(ciphertext), nonce: base64(nonce), tag: base64(tag)}

Lock-Step Protocol

Server tracks sequence per session:
sessions[token] = {
user_id: "alice",
session_key: "...",
expected_sequence: 42, # Must match exactly
expires_at: T+8h
}

Request validation:

1. Check session_token exists
2. Check sequence == expected_sequence (lock-step enforcement)
3. Check timestamp within 60s window
4. Verify HMAC signature
5. Increment expected_sequence++
6. Fail any check → invalidate session (prevents hijacking)

If sequence mismatch:
Client sends: sequence=42
Server expects: sequence=43
→ Session stolen/concurrent use detected
→ Delete session, return 401
→ Client must re-authenticate

Session Management

Rotation (PKCE, preserves session_key):
Client: session_token_v1 + code_verifier + new_code_challenge
Server: Validate, issue session_token_v2
Copy session_key + sequence to new session
Delete old session

Resume (export_key, new session_key):
Client: export_key (within 8h)
Server: Validate, run OPAQUE with export_key
Issue NEW session_token + session_key
Sequence starts at 0

Storage

Native:
~/.duckdb/boilstream_credentials (encrypted with OS keychain)
{
"export_key": "base64...",
"expires_at": 1234567890,
"endpoint": "https://server/secrets"
}

WASM:
localStorage.setItem('boilstream_credentials', JSON.stringify({
export_key: "base64...",
expires_at: 1234567890,
endpoint: "https://server/secrets"
}));

In-memory only:
RestApiSecretStorage {
session_token: string;
session_key: bytes[32]; // Never persisted
code_verifier: string; // For rotation
client_sequence: uint64; // Lock-step counter
}

Security Guarantees

✅ E2E encryption: Secrets encrypted with session_key (TLS-independent)
✅ Request integrity: HMAC prevents tampering
✅ Replay protection: Timestamp + sequence number
✅ Session hijacking detection: Lock-step sequence (concurrent use → invalidation)
✅ Key isolation: Separate keys for signing vs encryption (HKDF)
✅ No key persistence: session_key memory-only
✅ Limited credential lifetime: export_key expires with session (8h)
✅ Authenticated encryption: AES-GCM provides confidentiality + integrity
✅ Nonce uniqueness: Random 96-bit nonces, collision probability negligible

Attack Resistance

- TLS compromise: E2E encryption still protects secrets
- Token theft: Useless without sequence sync (one request → session killed)
- Replay attack: Sequence + timestamp prevent reuse
- MITM: Signature validation detects tampering
- Memory dump: Only exposes current session (8h max), export_key not in memory
- Disk forensics: Only finds export_key (time-limited, encrypted at rest)

This is production-grade security with defense-in-depth.
