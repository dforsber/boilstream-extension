use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use sha2::{Digest, Sha256};
use std::ptr;
use std::slice;
use zeroize::{Zeroize, Zeroizing};

// Import registration module
pub mod application_protocol;
mod registration;

// Platform-specific imports
use std::os::raw::c_char;

use rand::{rand_core::UnwrapErr, rngs::SysRng};

// Use Ristretto255 with SHA-512 for the ciphersuite
pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_opaque::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

// Native and Emscripten use their OS entropy source; wasm32-unknown-unknown uses
// getrandom's explicit wasm_js feature. Entropy failure never falls back to a seed.
macro_rules! get_rng {
    () => {
        UnwrapErr(SysRng)
    };
}

// Opaque error codes
#[repr(C)]
pub enum OpaqueError {
    Success = 0,
    InvalidInput = 1,
    ProtocolError = 2,
    SerializationError = 3,
    MemoryError = 4,
}

// Buffer structure for returning data to C
#[repr(C)]
pub struct OpaqueBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl OpaqueBuffer {
    fn new(data: Vec<u8>) -> Self {
        // The C ABI carries only a pointer and length, so discard spare capacity
        // before transferring ownership. Reconstruct the same boxed slice on free.
        let data = data.into_boxed_slice();
        let len = data.len();
        let ptr = Box::into_raw(data) as *mut u8;
        OpaqueBuffer { data: ptr, len }
    }

    fn empty() -> Self {
        OpaqueBuffer {
            data: ptr::null_mut(),
            len: 0,
        }
    }
}

// Result structure for C
#[repr(C)]
pub struct OpaqueResult {
    pub error: OpaqueError,
    pub buffer: OpaqueBuffer,
}

impl OpaqueResult {
    fn success(data: Vec<u8>) -> Self {
        OpaqueResult {
            error: OpaqueError::Success,
            buffer: OpaqueBuffer::new(data),
        }
    }

    fn error(code: OpaqueError) -> Self {
        OpaqueResult {
            error: code,
            buffer: OpaqueBuffer::empty(),
        }
    }
}

// Registration state (opaque pointer for C)
// Password field uses Zeroizing<Vec<u8>> which automatically zeros memory on drop
pub struct RegistrationState {
    client_registration: ClientRegistration<DefaultCipherSuite>,
    password: Zeroizing<Vec<u8>>,
}

// Login state (opaque pointer for C)
// Password field uses Zeroizing<Vec<u8>> which automatically zeros memory on drop
pub struct LoginState {
    client_login: ClientLogin<DefaultCipherSuite>,
    password: Zeroizing<Vec<u8>>,
}

/// Initialize OPAQUE client registration (step 1)
/// Returns RegistrationRequest serialized + state handle
///
/// # Safety
/// `password` must reference `password_len` readable bytes. `state_out` must be
/// writable and must not alias input. On success, transfer the returned state
/// exactly once to registration_finish or opaque_free_registration_state.
#[no_mangle]
pub unsafe extern "C" fn opaque_client_registration_start(
    password: *const c_char,
    password_len: usize,
    state_out: *mut *mut RegistrationState,
) -> OpaqueResult {
    if password.is_null() || state_out.is_null() {
        return OpaqueResult::error(OpaqueError::InvalidInput);
    }

    let password_bytes = unsafe { slice::from_raw_parts(password as *const u8, password_len) };

    let mut rng = get_rng!();

    match ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password_bytes) {
        Ok(result) => {
            // Serialize registration request
            let serialized = result.message.serialize();

            // Create state with zeroizing password
            let state = Box::new(RegistrationState {
                client_registration: result.state,
                password: Zeroizing::new(password_bytes.to_vec()),
            });

            unsafe {
                *state_out = Box::into_raw(state);
            }

            OpaqueResult::success(serialized.to_vec())
        }
        Err(_) => OpaqueResult::error(OpaqueError::ProtocolError),
    }
}

/// Finish OPAQUE client registration (step 2)
/// Takes RegistrationResponse from server, returns RegistrationUpload + export_key
///
/// # Safety
/// `state` must be an exclusively owned live registration state from this library.
/// Response input must reference its stated readable length; outputs must be
/// distinct writable OpaqueBuffer slots, not aliasing any input. Once all
/// pointers pass null validation, this consumes state on success or failure.
#[no_mangle]
pub unsafe extern "C" fn opaque_client_registration_finish(
    state: *mut RegistrationState,
    registration_response: *const u8,
    registration_response_len: usize,
    upload_out: *mut OpaqueBuffer,
    export_key_out: *mut OpaqueBuffer,
) -> OpaqueError {
    if state.is_null()
        || registration_response.is_null()
        || upload_out.is_null()
        || export_key_out.is_null()
    {
        return OpaqueError::InvalidInput;
    }

    let state_box = unsafe { Box::from_raw(state) };
    let response_bytes =
        unsafe { slice::from_raw_parts(registration_response, registration_response_len) };

    let mut rng = get_rng!();

    // Deserialize registration response
    let registration_response =
        match RegistrationResponse::<DefaultCipherSuite>::deserialize(response_bytes) {
            Ok(resp) => resp,
            Err(_) => return OpaqueError::SerializationError,
        };

    // Finish registration
    let finish_result = state_box.client_registration.finish(
        &mut rng,
        state_box.password.as_slice(),
        registration_response,
        ClientRegistrationFinishParameters::default(),
    );

    match finish_result {
        Ok(finish_data) => {
            // Serialize upload
            let upload_serialized = finish_data.message.serialize();

            // Export key
            let export_key = finish_data.export_key.to_vec();

            unsafe {
                *upload_out = OpaqueBuffer::new(upload_serialized.to_vec());
                *export_key_out = OpaqueBuffer::new(export_key);
            }

            OpaqueError::Success
        }
        Err(_) => OpaqueError::ProtocolError,
    }
}

/// Initialize OPAQUE client login (step 1)
/// Returns CredentialRequest serialized + state handle
///
/// # Safety
/// `password` must reference `password_len` readable bytes. `state_out` must be
/// writable and must not alias input. On success, transfer the returned state
/// exactly once to login_finish or opaque_free_login_state.
#[no_mangle]
pub unsafe extern "C" fn opaque_client_login_start(
    password: *const c_char,
    password_len: usize,
    state_out: *mut *mut LoginState,
) -> OpaqueResult {
    if password.is_null() || state_out.is_null() {
        return OpaqueResult::error(OpaqueError::InvalidInput);
    }

    let password_bytes = unsafe { slice::from_raw_parts(password as *const u8, password_len) };

    let mut rng = get_rng!();

    match ClientLogin::<DefaultCipherSuite>::start(&mut rng, password_bytes) {
        Ok(result) => {
            // Serialize credential request
            let serialized = result.message.serialize();

            // Create state with zeroizing password
            let state = Box::new(LoginState {
                client_login: result.state,
                password: Zeroizing::new(password_bytes.to_vec()),
            });

            unsafe {
                *state_out = Box::into_raw(state);
            }

            OpaqueResult::success(serialized.to_vec())
        }
        Err(_) => OpaqueResult::error(OpaqueError::ProtocolError),
    }
}

/// Finish OPAQUE client login (step 2)
/// Takes CredentialResponse from server, returns CredentialFinalization + session_key + export_key
///
/// # Safety
/// `state` must be an exclusively owned live login state from this library.
/// Response input must reference its stated readable length; outputs must be
/// distinct writable OpaqueBuffer slots, not aliasing any input. Once all
/// pointers pass null validation, this consumes state on success or failure.
#[no_mangle]
pub unsafe extern "C" fn opaque_client_login_finish(
    state: *mut LoginState,
    credential_response: *const u8,
    credential_response_len: usize,
    finalization_out: *mut OpaqueBuffer,
    session_key_out: *mut OpaqueBuffer,
    export_key_out: *mut OpaqueBuffer,
) -> OpaqueError {
    if state.is_null()
        || credential_response.is_null()
        || finalization_out.is_null()
        || session_key_out.is_null()
        || export_key_out.is_null()
    {
        return OpaqueError::InvalidInput;
    }

    let state_box = unsafe { Box::from_raw(state) };
    let response_bytes =
        unsafe { slice::from_raw_parts(credential_response, credential_response_len) };

    // Deserialize credential response
    let credential_response =
        match CredentialResponse::<DefaultCipherSuite>::deserialize(response_bytes) {
            Ok(resp) => resp,
            Err(_) => return OpaqueError::SerializationError,
        };

    // Finish login
    let finish_result = state_box.client_login.finish(
        &mut get_rng!(),
        state_box.password.as_slice(),
        credential_response,
        ClientLoginFinishParameters::default(),
    );

    match finish_result {
        Ok(finish_data) => {
            // Serialize finalization
            let finalization_serialized = finish_data.message.serialize();

            // Session key and export key
            let session_key = finish_data.session_key.to_vec();
            let export_key = finish_data.export_key.to_vec();

            unsafe {
                *finalization_out = OpaqueBuffer::new(finalization_serialized.to_vec());
                *session_key_out = OpaqueBuffer::new(session_key);
                *export_key_out = OpaqueBuffer::new(export_key);
            }

            OpaqueError::Success
        }
        Err(_) => OpaqueError::ProtocolError,
    }
}

/// Free a buffer allocated by the Rust library
///
/// # Safety
/// A non-null buffer must be an unmodified allocation returned by this library,
/// exclusively owned and not previously freed. No outstanding references may
/// be used after this call. Null buffers are accepted.
#[no_mangle]
pub unsafe extern "C" fn opaque_free_buffer(buffer: OpaqueBuffer) {
    if !buffer.data.is_null() {
        unsafe {
            let mut bytes = Box::from_raw(ptr::slice_from_raw_parts_mut(buffer.data, buffer.len));
            // Zero the memory before dropping
            bytes.zeroize();
            // Rust frees the original allocation when the boxed slice goes out of scope.
        }
    }
}

/// Free a registration state
///
/// # Safety
/// A non-null state must come from registration_start, be exclusively owned,
/// and not have been consumed by registration_finish or previously freed.
#[no_mangle]
pub unsafe extern "C" fn opaque_free_registration_state(state: *mut RegistrationState) {
    if !state.is_null() {
        unsafe {
            let _ = Box::from_raw(state);
            // Rust will free the memory when the Box goes out of scope
        }
    }
}

/// Free a login state
///
/// # Safety
/// A non-null state must come from login_start, be exclusively owned,
/// and not have been consumed by login_finish or previously freed.
#[no_mangle]
pub unsafe extern "C" fn opaque_free_login_state(state: *mut LoginState) {
    if !state.is_null() {
        unsafe {
            let _ = Box::from_raw(state);
            // Rust will free the memory when the Box goes out of scope
        }
    }
}

/// Compute SHA256 hash (C FFI)
///
/// # Arguments
/// * `input` - pointer to input data
/// * `input_len` - length of input data
/// * `output` - pointer to output buffer (must be 32 bytes)
///
/// # Safety
/// Caller must ensure:
/// - `input` points to valid memory of at least `input_len` bytes
/// - `output` points to valid writable memory of at least 32 bytes
#[no_mangle]
pub unsafe extern "C" fn opaque_client_sha256(input: *const u8, input_len: usize, output: *mut u8) {
    if input.is_null() || output.is_null() {
        return;
    }

    let input_slice = slice::from_raw_parts(input, input_len);
    let mut hasher = Sha256::new();
    hasher.update(input_slice);
    let result = hasher.finalize();

    let output_slice = slice::from_raw_parts_mut(output, 32);
    output_slice.copy_from_slice(&result);
}

/// Derive refresh token using HKDF-Expand (C FFI)
/// Uses session_key directly as PRK, info="session-resumption-v1"
///
/// # Arguments
/// * `session_key` - pointer to session key (used as PRK)
/// * `session_key_len` - length of session key
/// * `output` - pointer to output buffer (must be 32 bytes)
///
/// # Returns
/// 0 on success, non-zero on error
///
/// # Safety
/// `session_key` must reference `session_key_len` readable bytes. `output`
/// must reference 32 writable bytes disjoint from the input region.
#[no_mangle]
pub unsafe extern "C" fn opaque_client_derive_refresh_token(
    session_key: *const u8,
    session_key_len: usize,
    output: *mut u8,
) -> i32 {
    use hmac::{Hmac, Mac};

    if session_key.is_null() || output.is_null() || session_key_len == 0 {
        return -1;
    }

    let session_key_slice = slice::from_raw_parts(session_key, session_key_len);
    let info = b"session-resumption-v1\x01"; // info || 0x01

    // HKDF-Expand: HMAC-SHA256(PRK=session_key, info || 0x01)
    let mut mac = match Hmac::<Sha256>::new_from_slice(session_key_slice) {
        Ok(m) => m,
        Err(_) => return -1,
    };
    mac.update(info);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    let output_slice = slice::from_raw_parts_mut(output, 32);
    output_slice.copy_from_slice(&code_bytes);

    0
}

//===----------------------------------------------------------------------===//
// Email/Password Registration FFI
//===----------------------------------------------------------------------===//

/// Validate email format (C FFI)
///
/// # Arguments
/// * `email` - pointer to null-terminated email string
///
/// # Returns
/// 0 on success, -1 if email is invalid
///
/// # Safety
/// A non-null `email` must reference a readable NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn registration_validate_email(email: *const c_char) -> i32 {
    if email.is_null() {
        return -1;
    }

    let email_cstr = std::ffi::CStr::from_ptr(email);
    let email_str = match email_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match registration::validate_email(email_str) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Validate password strength (C FFI)
///
/// # Arguments
/// * `password` - pointer to password bytes
/// * `password_len` - length of password in bytes
///
/// # Returns
/// 0 on success, -1 if password is too weak (< 12 characters)
///
/// # Safety
/// A non-null `password` must reference `password_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn registration_validate_password(
    password: *const u8,
    password_len: usize,
) -> i32 {
    if password.is_null() {
        return -1;
    }

    let password_slice = slice::from_raw_parts(password, password_len);
    let password_str = match std::str::from_utf8(password_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match registration::validate_password(password_str) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Build TOTP URI for QR code generation (C FFI)
///
/// # Arguments
/// * `email` - pointer to null-terminated email string
/// * `secret` - pointer to null-terminated TOTP secret string
/// * `issuer` - pointer to null-terminated issuer string (NULL for default "BoilStream")
/// * `uri_buffer` - pointer to output buffer for URI
/// * `uri_buffer_len` - size of output buffer
///
/// # Returns
/// Length of URI written to buffer on success, -1 on error (buffer too small or invalid input)
///
/// # Safety
/// Non-null string inputs must reference readable NUL-terminated strings.
/// `uri_buffer` must reference `uri_buffer_len` writable bytes disjoint from inputs.
#[no_mangle]
pub unsafe extern "C" fn registration_build_totp_uri(
    email: *const c_char,
    secret: *const c_char,
    issuer: *const c_char,
    uri_buffer: *mut c_char,
    uri_buffer_len: usize,
) -> isize {
    if email.is_null() || secret.is_null() || uri_buffer.is_null() {
        return -1;
    }

    let email_cstr = std::ffi::CStr::from_ptr(email);
    let email_str = match email_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let secret_cstr = std::ffi::CStr::from_ptr(secret);
    let secret_str = match secret_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let issuer_opt = if issuer.is_null() {
        None
    } else {
        let issuer_cstr = std::ffi::CStr::from_ptr(issuer);
        match issuer_cstr.to_str() {
            Ok(s) => Some(s),
            Err(_) => return -1,
        }
    };

    let uri = Zeroizing::new(registration::build_totp_uri(
        email_str, secret_str, issuer_opt,
    ));

    if uri.len() + 1 > uri_buffer_len {
        return -1; // Buffer too small
    }

    let uri_bytes = uri.as_bytes();
    let buffer_slice = slice::from_raw_parts_mut(uri_buffer as *mut u8, uri_bytes.len());
    buffer_slice.copy_from_slice(uri_bytes);

    // Null-terminate
    *(uri_buffer.add(uri_bytes.len()) as *mut u8) = 0;

    uri_bytes.len() as isize
}

#[cfg(test)]
mod buffer_tests {
    use super::*;

    // Miri checks that the allocator layout used by opaque_free_buffer matches
    // the original allocation, including when the input Vec has spare capacity.
    #[test]
    fn ffi_buffer_frees_spare_capacity() {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(b"secret");
        let buffer = OpaqueBuffer::new(bytes);
        assert_eq!(
            unsafe { slice::from_raw_parts(buffer.data, buffer.len) },
            b"secret"
        );
        unsafe { opaque_free_buffer(buffer) };
    }

    #[test]
    fn ffi_buffer_frees_empty_allocations() {
        unsafe { opaque_free_buffer(OpaqueBuffer::new(Vec::with_capacity(128))) };
        unsafe { opaque_free_buffer(OpaqueBuffer::new(Vec::new())) };
        unsafe { opaque_free_buffer(OpaqueBuffer::empty()) };
    }
}
