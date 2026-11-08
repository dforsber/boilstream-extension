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

// Application protocol handles require exclusive ownership/access. Buffers use
// opaque_free_buffer. Never retry or reuse a handle after an exchange failure.
typedef struct ApplicationProtocol ApplicationProtocol;
OpaqueResult bs_protocol_start(const uint8_t *authority, size_t authority_len, const uint8_t *key,
                               ApplicationProtocol **output);
OpaqueError bs_protocol_accept(ApplicationProtocol *handle, const uint8_t *body, size_t len);
OpaqueResult bs_protocol_seal(ApplicationProtocol *handle, const uint8_t *json, size_t len);
OpaqueResult bs_protocol_open(ApplicationProtocol *handle, const uint8_t *body, size_t len);
void bs_protocol_free(ApplicationProtocol *handle);

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

// SHA-256 and the OPAQUE refresh credential derivation, shared by native/WASM.
// Non-null inputs must cover their stated lengths. Output must cover 32 bytes
// and must not overlap the input. Refresh derivation returns nonzero on error.
void opaque_client_sha256(const uint8_t *input, size_t input_len, uint8_t *output);
int opaque_client_derive_refresh_token(const uint8_t *session_key, size_t session_key_len, uint8_t *output);

#ifdef __cplusplus
}
#endif
