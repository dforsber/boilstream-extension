//===----------------------------------------------------------------------===//
//                         DuckDB
//
// opaque_wrapper.hpp
//
// C++ wrapper for OPAQUE client operations
//
//===----------------------------------------------------------------------===//

#pragma once

#include "opaque_client.h"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/common/types/string_type.hpp"
#include <string>
#include <memory>

namespace duckdb {

// RAII wrapper for OpaqueBuffer
class OpaqueBufferWrapper {
public:
	OpaqueBufferWrapper() : buffer({nullptr, 0}) {
	}

	explicit OpaqueBufferWrapper(OpaqueBuffer buf) : buffer(buf) {
	}

	~OpaqueBufferWrapper() {
		if (buffer.data != nullptr) {
			opaque_free_buffer(buffer);
		}
	}

	// No copy
	OpaqueBufferWrapper(const OpaqueBufferWrapper &) = delete;
	OpaqueBufferWrapper &operator=(const OpaqueBufferWrapper &) = delete;

	// Move semantics
	OpaqueBufferWrapper(OpaqueBufferWrapper &&other) noexcept : buffer(other.buffer) {
		other.buffer = {nullptr, 0};
	}

	OpaqueBufferWrapper &operator=(OpaqueBufferWrapper &&other) noexcept {
		if (this != &other) {
			if (buffer.data != nullptr) {
				opaque_free_buffer(buffer);
			}
			buffer = other.buffer;
			other.buffer = {nullptr, 0};
		}
		return *this;
	}

	// Convert to string (makes a copy)
	string ToString() const {
		if (buffer.data == nullptr) {
			return "";
		}
		return string(reinterpret_cast<const char *>(buffer.data), buffer.len);
	}

	// Get as base64-encoded string
	string ToBase64() const {
		if (buffer.data == nullptr) {
			return "";
		}
		string buffer_str(reinterpret_cast<const char *>(buffer.data), buffer.len);
		return Blob::ToBase64(string_t(buffer_str));
	}

	const uint8_t *Data() const {
		return buffer.data;
	}
	size_t Length() const {
		return buffer.len;
	}

	OpaqueBuffer *GetPtr() {
		return &buffer;
	}

private:
	OpaqueBuffer buffer;
};

// Result of registration start
struct RegistrationStartResult {
	string registration_request_base64; // RegistrationRequest serialized and base64-encoded
	RegistrationState *state;           // Must be freed with opaque_free_registration_state or passed to finish
};

// Result of registration finish
struct RegistrationFinishResult {
	string registration_upload_base64; // RegistrationUpload serialized and base64-encoded
	string export_key_base64;          // Export key base64-encoded
};

// Result of login start
struct LoginStartResult {
	string credential_request_base64; // CredentialRequest serialized and base64-encoded
	LoginState *state;                // Must be freed with opaque_free_login_state or passed to finish
};

// Result of login finish
struct LoginFinishResult {
	string credential_finalization_base64; // CredentialFinalization serialized and base64-encoded
	string session_key_base64;             // Session key base64-encoded
	string export_key_base64;              // Export key base64-encoded
};

class OpaqueClientWrapper {
public:
	//! Start OPAQUE registration (client-side)
	//! Returns RegistrationRequest (base64) and state
	static RegistrationStartResult RegistrationStart(const string &password);

	//! Finish OPAQUE registration (client-side)
	//! Takes state and RegistrationResponse (base64) from server
	//! Returns RegistrationUpload (base64) and export_key (base64)
	//! Note: state is consumed by this function
	static RegistrationFinishResult RegistrationFinish(RegistrationState *state,
	                                                   const string &registration_response_base64);

	//! Start OPAQUE login (client-side)
	//! Returns CredentialRequest (base64) and state
	static LoginStartResult LoginStart(const string &password);

	//! Finish OPAQUE login (client-side)
	//! Takes state and CredentialResponse (base64) from server
	//! Returns CredentialFinalization (base64), session_key (base64), and export_key (base64)
	//! Note: state is consumed by this function
	static LoginFinishResult LoginFinish(LoginState *state, const string &credential_response_base64);
};

} // namespace duckdb
