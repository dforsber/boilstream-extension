//===----------------------------------------------------------------------===//
//                         DuckDB
//
// opaque_wrapper.cpp
//
// C++ wrapper implementation for OPAQUE client operations
//
//===----------------------------------------------------------------------===//

#include "opaque_wrapper.hpp"
#include "duckdb/common/exception.hpp"

namespace duckdb {

RegistrationStartResult OpaqueClientWrapper::RegistrationStart(const string &password) {
	RegistrationState *state = nullptr;

	OpaqueResult result = opaque_client_registration_start(password.c_str(), password.length(), &state);

	if (result.error != OPAQUE_SUCCESS) {
		if (state != nullptr) {
			opaque_free_registration_state(state);
		}
		if (result.buffer.data != nullptr) {
			opaque_free_buffer(result.buffer);
		}

		switch (result.error) {
		case OPAQUE_INVALID_INPUT:
			throw InvalidInputException("OPAQUE registration start: Invalid input");
		case OPAQUE_PROTOCOL_ERROR:
			throw IOException("OPAQUE registration start: Protocol error");
		case OPAQUE_SERIALIZATION_ERROR:
			throw IOException("OPAQUE registration start: Serialization error");
		case OPAQUE_MEMORY_ERROR:
			throw IOException("OPAQUE registration start: Memory error");
		default:
			throw IOException("OPAQUE registration start: Unknown error");
		}
	}

	OpaqueBufferWrapper buffer_wrapper(result.buffer);

	RegistrationStartResult output;
	output.registration_request_base64 = buffer_wrapper.ToBase64();
	output.state = state;

	return output;
}

RegistrationFinishResult OpaqueClientWrapper::RegistrationFinish(RegistrationState *state,
                                                                 const string &registration_response_base64) {
	if (state == nullptr) {
		throw InvalidInputException("OPAQUE registration finish: NULL state");
	}

	// Decode base64 registration response
	auto response_decoded = Blob::FromBase64(string_t(registration_response_base64));

	OpaqueBuffer upload_buffer = {nullptr, 0};
	OpaqueBuffer export_key_buffer = {nullptr, 0};

	OpaqueError error =
	    opaque_client_registration_finish(state, // state is consumed
	                                      reinterpret_cast<const uint8_t *>(response_decoded.c_str()),
	                                      response_decoded.length(), &upload_buffer, &export_key_buffer);

	if (error != OPAQUE_SUCCESS) {
		if (upload_buffer.data != nullptr) {
			opaque_free_buffer(upload_buffer);
		}
		if (export_key_buffer.data != nullptr) {
			opaque_free_buffer(export_key_buffer);
		}

		switch (error) {
		case OPAQUE_INVALID_INPUT:
			throw InvalidInputException("OPAQUE registration finish: Invalid input");
		case OPAQUE_PROTOCOL_ERROR:
			throw IOException("OPAQUE registration finish: Protocol error");
		case OPAQUE_SERIALIZATION_ERROR:
			throw IOException("OPAQUE registration finish: Invalid server response");
		case OPAQUE_MEMORY_ERROR:
			throw IOException("OPAQUE registration finish: Memory error");
		default:
			throw IOException("OPAQUE registration finish: Unknown error");
		}
	}

	OpaqueBufferWrapper upload_wrapper(upload_buffer);
	OpaqueBufferWrapper export_key_wrapper(export_key_buffer);

	RegistrationFinishResult output;
	output.registration_upload_base64 = upload_wrapper.ToBase64();
	output.export_key_base64 = export_key_wrapper.ToBase64();

	return output;
}

LoginStartResult OpaqueClientWrapper::LoginStart(const string &password) {
	LoginState *state = nullptr;

	OpaqueResult result = opaque_client_login_start(password.c_str(), password.length(), &state);

	if (result.error != OPAQUE_SUCCESS) {
		if (state != nullptr) {
			opaque_free_login_state(state);
		}
		if (result.buffer.data != nullptr) {
			opaque_free_buffer(result.buffer);
		}

		switch (result.error) {
		case OPAQUE_INVALID_INPUT:
			throw InvalidInputException("OPAQUE login start: Invalid input");
		case OPAQUE_PROTOCOL_ERROR:
			throw IOException("OPAQUE login start: Protocol error");
		case OPAQUE_SERIALIZATION_ERROR:
			throw IOException("OPAQUE login start: Serialization error");
		case OPAQUE_MEMORY_ERROR:
			throw IOException("OPAQUE login start: Memory error");
		default:
			throw IOException("OPAQUE login start: Unknown error");
		}
	}

	OpaqueBufferWrapper buffer_wrapper(result.buffer);

	LoginStartResult output;
	output.credential_request_base64 = buffer_wrapper.ToBase64();
	output.state = state;

	return output;
}

LoginFinishResult OpaqueClientWrapper::LoginFinish(LoginState *state, const string &credential_response_base64) {
	if (state == nullptr) {
		throw InvalidInputException("OPAQUE login finish: NULL state");
	}

	// Decode base64 credential response
	auto response_decoded = Blob::FromBase64(string_t(credential_response_base64));

	OpaqueBuffer finalization_buffer = {nullptr, 0};
	OpaqueBuffer session_key_buffer = {nullptr, 0};
	OpaqueBuffer export_key_buffer = {nullptr, 0};

	OpaqueError error = opaque_client_login_finish(state, // state is consumed
	                                               reinterpret_cast<const uint8_t *>(response_decoded.c_str()),
	                                               response_decoded.length(), &finalization_buffer, &session_key_buffer,
	                                               &export_key_buffer);

	if (error != OPAQUE_SUCCESS) {
		if (finalization_buffer.data != nullptr) {
			opaque_free_buffer(finalization_buffer);
		}
		if (session_key_buffer.data != nullptr) {
			opaque_free_buffer(session_key_buffer);
		}
		if (export_key_buffer.data != nullptr) {
			opaque_free_buffer(export_key_buffer);
		}

		switch (error) {
		case OPAQUE_INVALID_INPUT:
			throw InvalidInputException("OPAQUE login finish: Invalid input");
		case OPAQUE_PROTOCOL_ERROR:
			throw IOException("OPAQUE login finish: Protocol error - incorrect password or server state");
		case OPAQUE_SERIALIZATION_ERROR:
			throw IOException("OPAQUE login finish: Invalid server response");
		case OPAQUE_MEMORY_ERROR:
			throw IOException("OPAQUE login finish: Memory error");
		default:
			throw IOException("OPAQUE login finish: Unknown error");
		}
	}

	OpaqueBufferWrapper finalization_wrapper(finalization_buffer);
	OpaqueBufferWrapper session_key_wrapper(session_key_buffer);
	OpaqueBufferWrapper export_key_wrapper(export_key_buffer);

	LoginFinishResult output;
	output.credential_finalization_base64 = finalization_wrapper.ToBase64();
	output.session_key_base64 = session_key_wrapper.ToBase64();
	output.export_key_base64 = export_key_wrapper.ToBase64();

	return output;
}

} // namespace duckdb
