//===----------------------------------------------------------------------===//
//                         DuckDB
//
// opaque_client.h
//
// C FFI bindings for the Rust OPAQUE-KE client library
//
//===----------------------------------------------------------------------===//

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque error codes
typedef enum {
	OPAQUE_SUCCESS = 0,
	OPAQUE_INVALID_INPUT = 1,
	OPAQUE_PROTOCOL_ERROR = 2,
	OPAQUE_SERIALIZATION_ERROR = 3,
	OPAQUE_MEMORY_ERROR = 4,
} OpaqueError;

// Buffer structure for data returned from Rust
typedef struct {
	uint8_t *data;
	size_t len;
} OpaqueBuffer;

// Result structure
typedef struct {
	OpaqueError error;
	OpaqueBuffer buffer;
} OpaqueResult;

// Opaque state handles (forward declarations)
typedef struct RegistrationState RegistrationState;
typedef struct LoginState LoginState;

//===----------------------------------------------------------------------===//
// Registration Flow
//===----------------------------------------------------------------------===//

/**
 * Start OPAQUE client registration (step 1)
 *
 * @param password Password bytes
 * @param password_len Length of password in bytes
 * @param state_out Output parameter for registration state (must be freed with opaque_free_registration_state)
 * @return OpaqueResult containing serialized RegistrationRequest on success
 *
 * The returned buffer must be freed with opaque_free_buffer.
 */
OpaqueResult opaque_client_registration_start(const char *password, size_t password_len, RegistrationState **state_out);

/**
 * Finish OPAQUE client registration (step 2)
 *
 * @param state Registration state from opaque_client_registration_start (will be consumed)
 * @param registration_response Serialized RegistrationResponse from server
 * @param registration_response_len Length of registration_response in bytes
 * @param upload_out Output parameter for serialized RegistrationUpload (must be freed with opaque_free_buffer)
 * @param export_key_out Output parameter for export key (must be freed with opaque_free_buffer)
 * @return OpaqueError indicating success or failure
 *
 * Both output buffers must be freed with opaque_free_buffer.
 * The state is consumed and freed by this function.
 */
OpaqueError opaque_client_registration_finish(RegistrationState *state, const uint8_t *registration_response,
                                              size_t registration_response_len, OpaqueBuffer *upload_out,
                                              OpaqueBuffer *export_key_out);

//===----------------------------------------------------------------------===//
// Login Flow
//===----------------------------------------------------------------------===//

/**
 * Start OPAQUE client login (step 1)
 *
 * @param password Password bytes
 * @param password_len Length of password in bytes
 * @param state_out Output parameter for login state (must be freed with opaque_free_login_state)
 * @return OpaqueResult containing serialized CredentialRequest on success
 *
 * The returned buffer must be freed with opaque_free_buffer.
 */
OpaqueResult opaque_client_login_start(const char *password, size_t password_len, LoginState **state_out);

/**
 * Finish OPAQUE client login (step 2)
 *
 * @param state Login state from opaque_client_login_start (will be consumed)
 * @param credential_response Serialized CredentialResponse from server
 * @param credential_response_len Length of credential_response in bytes
 * @param finalization_out Output parameter for serialized CredentialFinalization (must be freed with
 * opaque_free_buffer)
 * @param session_key_out Output parameter for session key (must be freed with opaque_free_buffer)
 * @param export_key_out Output parameter for export key (must be freed with opaque_free_buffer)
 * @return OpaqueError indicating success or failure
 *
 * All output buffers must be freed with opaque_free_buffer.
 * The state is consumed and freed by this function.
 */
OpaqueError opaque_client_login_finish(LoginState *state, const uint8_t *credential_response,
                                       size_t credential_response_len, OpaqueBuffer *finalization_out,
                                       OpaqueBuffer *session_key_out, OpaqueBuffer *export_key_out);

//===----------------------------------------------------------------------===//
// Memory Management
//===----------------------------------------------------------------------===//

/**
 * Free a buffer allocated by the Rust library
 *
 * @param buffer Buffer to free
 */
void opaque_free_buffer(OpaqueBuffer buffer);

/**
 * Free a registration state
 *
 * @param state State to free (can be NULL)
 */
void opaque_free_registration_state(RegistrationState *state);

/**
 * Free a login state
 *
 * @param state State to free (can be NULL)
 */
void opaque_free_login_state(LoginState *state);

//===----------------------------------------------------------------------===//
// AWS SigV4-style Canonical Request Signing
//===----------------------------------------------------------------------===//

/**
 * Build AWS SigV4-style canonical request
 *
 * @param method HTTP method (e.g., "GET", "POST")
 * @param method_len Length of method string
 * @param canonical_uri URI-encoded path (e.g., "/secrets/my-secret")
 * @param canonical_uri_len Length of canonical_uri
 * @param canonical_query Sorted, URI-encoded query string (e.g., "param1=value1&param2=value2")
 * @param canonical_query_len Length of canonical_query
 * @param canonical_headers Sorted, lowercase headers (e.g., "x-boilstream-date:20251009T120000Z\n")
 * @param canonical_headers_len Length of canonical_headers
 * @param signed_headers Semicolon-separated list of header names (e.g., "x-boilstream-date;x-boilstream-sequence")
 * @param signed_headers_len Length of signed_headers
 * @param payload Request body bytes (can be NULL for empty body)
 * @param payload_len Length of payload in bytes
 * @return OpaqueResult containing canonical request string on success
 *
 * The returned buffer must be freed with opaque_free_buffer.
 */
OpaqueResult aws_build_canonical_request(const char *method, size_t method_len, const char *canonical_uri,
                                         size_t canonical_uri_len, const char *canonical_query,
                                         size_t canonical_query_len, const char *canonical_headers,
                                         size_t canonical_headers_len, const char *signed_headers,
                                         size_t signed_headers_len, const uint8_t *payload, size_t payload_len);

/**
 * Derive AWS-style signing key (date-scoped)
 *
 * @param base_signing_key Base signing key derived from session_key via HKDF
 * @param base_signing_key_len Length of base_signing_key (typically 32 bytes)
 * @param date Date string in YYYYMMDD format (e.g., "20251009")
 * @param date_len Length of date string (typically 8)
 * @param region Region identifier (e.g., "us-east-1")
 * @param region_len Length of region string
 * @param service Service name (always "secrets")
 * @param service_len Length of service string
 * @return OpaqueResult containing derived signing key on success
 *
 * The returned buffer must be freed with opaque_free_buffer.
 */
OpaqueResult aws_derive_signing_key(const uint8_t *base_signing_key, size_t base_signing_key_len, const char *date,
                                    size_t date_len, const char *region, size_t region_len, const char *service,
                                    size_t service_len);

/**
 * Sign canonical request with HMAC-SHA256
 *
 * @param signing_key Derived signing key from aws_derive_signing_key
 * @param signing_key_len Length of signing_key (typically 32 bytes)
 * @param canonical_request Canonical request string to sign
 * @param canonical_request_len Length of canonical_request
 * @return OpaqueResult containing base64-encoded signature on success
 *
 * The returned buffer must be freed with opaque_free_buffer.
 */
OpaqueResult aws_sign_canonical_request(const uint8_t *signing_key, size_t signing_key_len,
                                        const char *canonical_request, size_t canonical_request_len);

#ifdef __cplusplus
}
#endif
