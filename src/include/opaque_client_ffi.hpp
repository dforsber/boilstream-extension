#pragma once

#include "opaque_client.h"
#include <cstddef>
#include <cstdint>

// C FFI interface to Rust opaque_client library
// These functions are implemented in opaque-client/src/lib.rs

extern "C" {

//===----------------------------------------------------------------------===//
// Email/Password Registration FFI
//===----------------------------------------------------------------------===//

/// Validate email format
/// @param email Pointer to null-terminated email string
/// @return 0 on success, -1 if email is invalid
int registration_validate_email(const char *email);

/// Validate password strength
/// @param password Pointer to password bytes
/// @param password_len Length of password in bytes
/// @return 0 on success, -1 if password is too weak (< 12 characters)
int registration_validate_password(const uint8_t *password, size_t password_len);

/// Build TOTP URI for QR code generation
/// @param email Pointer to null-terminated email string
/// @param secret Pointer to null-terminated TOTP secret string
/// @param issuer Pointer to null-terminated issuer string (NULL for default "BoilStream")
/// @param uri_buffer Pointer to output buffer for URI
/// @param uri_buffer_len Size of output buffer
/// @return Length of URI written to buffer on success, -1 on error (buffer too small or invalid input)
intptr_t registration_build_totp_uri(const char *email, const char *secret, const char *issuer, char *uri_buffer,
                                     size_t uri_buffer_len);

} // extern "C"
