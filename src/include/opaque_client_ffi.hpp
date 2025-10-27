#pragma once

#include <cstddef>
#include <cstdint>

// C FFI interface to Rust opaque_client library
// These functions are implemented in opaque-client/src/lib.rs

extern "C" {

/// Compute SHA256 hash
/// @param input Pointer to input data
/// @param input_len Length of input data in bytes
/// @param output Pointer to output buffer (must be at least 32 bytes)
void opaque_client_sha256(const uint8_t *input, size_t input_len, uint8_t *output);

/// Compute HMAC-SHA256
/// @param key Pointer to HMAC key
/// @param key_len Length of key in bytes
/// @param data Pointer to data to authenticate
/// @param data_len Length of data in bytes
/// @param output Pointer to output buffer (must be at least 32 bytes)
void opaque_client_hmac_sha256(const uint8_t *key, size_t key_len,
                                const uint8_t *data, size_t data_len,
                                uint8_t *output);

/// Derive integrity key using HKDF-SHA256
/// salt="boilstream-session-v1", info="request-integrity-v1"
/// @param session_key Pointer to session key (IKM)
/// @param session_key_len Length of session key
/// @param output Pointer to output buffer (must be 32 bytes)
/// @return 0 on success, non-zero on error
int opaque_client_derive_integrity_key(const uint8_t *session_key, size_t session_key_len, uint8_t *output);

/// Derive encryption key using HKDF-SHA256
/// salt="boilstream-session-v1", info="response-encryption-v1"
/// @param session_key Pointer to session key (IKM)
/// @param session_key_len Length of session key
/// @param output Pointer to output buffer (must be 32 bytes)
/// @return 0 on success, non-zero on error
int opaque_client_derive_encryption_key(const uint8_t *session_key, size_t session_key_len, uint8_t *output);

/// Derive signing key using HKDF-SHA256
/// salt="boilstream-session-v1", info="response-integrity-v1"
/// @param session_key Pointer to session key (IKM)
/// @param session_key_len Length of session key
/// @param output Pointer to output buffer (must be 32 bytes)
/// @return 0 on success, non-zero on error
int opaque_client_derive_signing_key(const uint8_t *session_key, size_t session_key_len, uint8_t *output);

/// Derive refresh token using HKDF-Expand
/// Uses session_key directly as PRK, info="session-resumption-v1"
/// @param session_key Pointer to session key (used as PRK)
/// @param session_key_len Length of session key
/// @param output Pointer to output buffer (must be 32 bytes)
/// @return 0 on success, non-zero on error
int opaque_client_derive_refresh_token(const uint8_t *session_key, size_t session_key_len, uint8_t *output);

/// Decrypt and verify AES-256-GCM encrypted response
/// @param ciphertext_with_tag Pointer to ciphertext + 16-byte authentication tag
/// @param ciphertext_with_tag_len Total length (ciphertext + 16)
/// @param nonce Pointer to 12-byte nonce
/// @param nonce_len Length of nonce (must be 12)
/// @param encryption_key Pointer to 32-byte encryption key
/// @param encryption_key_len Length of key (must be 32)
/// @param plaintext_out Pointer to output buffer (must be at least ciphertext_len bytes)
/// @param plaintext_out_len Size of output buffer
/// @return Length of plaintext on success, -1 on error (including auth tag verification failure)
long opaque_client_aes_gcm_decrypt(
    const uint8_t *ciphertext_with_tag, size_t ciphertext_with_tag_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *encryption_key, size_t encryption_key_len,
    uint8_t *plaintext_out, size_t plaintext_out_len);

} // extern "C"
