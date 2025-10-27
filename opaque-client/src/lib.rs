use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use opaque_ke::ciphersuite::CipherSuite;
use std::ptr;
use std::slice;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

// Platform-specific imports
use std::os::raw::c_char;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

// Use appropriate RNG for platform
#[cfg(target_arch = "wasm32")]
use rand::rngs::StdRng;
#[cfg(target_arch = "wasm32")]
use rand::SeedableRng;

#[cfg(not(target_arch = "wasm32"))]
use rand::rngs::OsRng;

// Use Ristretto255 with SHA-512 for the ciphersuite
pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

// Platform-specific RNG initialization
#[cfg(not(target_arch = "wasm32"))]
macro_rules! get_rng {
    () => {
        OsRng
    };
}

#[cfg(target_arch = "wasm32")]
macro_rules! get_rng {
    () => {
        StdRng::from_entropy()
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
        let len = data.len();
        let ptr = data.as_ptr() as *mut u8;
        std::mem::forget(data); // Prevent Rust from freeing the memory
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
pub struct RegistrationState {
    client_registration: ClientRegistration<DefaultCipherSuite>,
    password: Vec<u8>,
}

// Login state (opaque pointer for C)
pub struct LoginState {
    client_login: ClientLogin<DefaultCipherSuite>,
    password: Vec<u8>,
}

/// Initialize OPAQUE client registration (step 1)
/// Returns RegistrationRequest serialized + state handle
#[no_mangle]
pub extern "C" fn opaque_client_registration_start(
    password: *const c_char,
    password_len: usize,
    state_out: *mut *mut RegistrationState,
) -> OpaqueResult {
    if password.is_null() || state_out.is_null() {
        return OpaqueResult::error(OpaqueError::InvalidInput);
    }

    let password_bytes = unsafe {
        slice::from_raw_parts(password as *const u8, password_len)
    };

    let mut rng = get_rng!();

    match ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password_bytes) {
        Ok(result) => {
            // Serialize registration request
            let serialized = result.message.serialize();

            // Create state
            let state = Box::new(RegistrationState {
                client_registration: result.state,
                password: password_bytes.to_vec(),
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
#[no_mangle]
pub extern "C" fn opaque_client_registration_finish(
    state: *mut RegistrationState,
    registration_response: *const u8,
    registration_response_len: usize,
    upload_out: *mut OpaqueBuffer,
    export_key_out: *mut OpaqueBuffer,
) -> OpaqueError {
    if state.is_null() || registration_response.is_null() || upload_out.is_null() || export_key_out.is_null() {
        return OpaqueError::InvalidInput;
    }

    let state_box = unsafe { Box::from_raw(state) };
    let response_bytes = unsafe {
        slice::from_raw_parts(registration_response, registration_response_len)
    };

    let mut rng = get_rng!();

    // Deserialize registration response
    let registration_response = match RegistrationResponse::<DefaultCipherSuite>::deserialize(response_bytes) {
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
#[no_mangle]
pub extern "C" fn opaque_client_login_start(
    password: *const c_char,
    password_len: usize,
    state_out: *mut *mut LoginState,
) -> OpaqueResult {
    if password.is_null() || state_out.is_null() {
        return OpaqueResult::error(OpaqueError::InvalidInput);
    }

    let password_bytes = unsafe {
        slice::from_raw_parts(password as *const u8, password_len)
    };

    let mut rng = get_rng!();

    match ClientLogin::<DefaultCipherSuite>::start(&mut rng, password_bytes) {
        Ok(result) => {
            // Serialize credential request
            let serialized = result.message.serialize();

            // Create state
            let state = Box::new(LoginState {
                client_login: result.state,
                password: password_bytes.to_vec(),
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
#[no_mangle]
pub extern "C" fn opaque_client_login_finish(
    state: *mut LoginState,
    credential_response: *const u8,
    credential_response_len: usize,
    finalization_out: *mut OpaqueBuffer,
    session_key_out: *mut OpaqueBuffer,
    export_key_out: *mut OpaqueBuffer,
) -> OpaqueError {
    if state.is_null() || credential_response.is_null() || finalization_out.is_null()
        || session_key_out.is_null() || export_key_out.is_null() {
        return OpaqueError::InvalidInput;
    }

    let state_box = unsafe { Box::from_raw(state) };
    let response_bytes = unsafe {
        slice::from_raw_parts(credential_response, credential_response_len)
    };

    // Deserialize credential response
    let credential_response = match CredentialResponse::<DefaultCipherSuite>::deserialize(response_bytes) {
        Ok(resp) => resp,
        Err(_) => return OpaqueError::SerializationError,
    };

    // Finish login
    let finish_result = state_box.client_login.finish(
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
#[no_mangle]
pub extern "C" fn opaque_free_buffer(buffer: OpaqueBuffer) {
    if !buffer.data.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(buffer.data, buffer.len, buffer.len);
            // Rust will free the memory when the Vec goes out of scope
        }
    }
}

/// Free a registration state
#[no_mangle]
pub extern "C" fn opaque_free_registration_state(state: *mut RegistrationState) {
    if !state.is_null() {
        unsafe {
            let _ = Box::from_raw(state);
            // Rust will free the memory when the Box goes out of scope
        }
    }
}

/// Free a login state
#[no_mangle]
pub extern "C" fn opaque_free_login_state(state: *mut LoginState) {
    if !state.is_null() {
        unsafe {
            let _ = Box::from_raw(state);
            // Rust will free the memory when the Box goes out of scope
        }
    }
}

//===----------------------------------------------------------------------===//
// AWS SigV4-style Canonical Request Signing
//===----------------------------------------------------------------------===//

/// Build AWS SigV4-style canonical request
/// Returns canonical request string that needs to be signed
#[no_mangle]
pub extern "C" fn aws_build_canonical_request(
    method: *const c_char,
    method_len: usize,
    canonical_uri: *const c_char,
    canonical_uri_len: usize,
    canonical_query: *const c_char,
    canonical_query_len: usize,
    canonical_headers: *const c_char,
    canonical_headers_len: usize,
    signed_headers: *const c_char,
    signed_headers_len: usize,
    payload: *const u8,
    payload_len: usize,
) -> OpaqueResult {
    if method.is_null() || canonical_uri.is_null() || canonical_query.is_null()
        || canonical_headers.is_null() || signed_headers.is_null() {
        return OpaqueResult::error(OpaqueError::InvalidInput);
    }

    let method_str = unsafe {
        let slice = slice::from_raw_parts(method as *const u8, method_len);
        std::str::from_utf8(slice).unwrap_or("")
    };

    let canonical_uri_str = unsafe {
        let slice = slice::from_raw_parts(canonical_uri as *const u8, canonical_uri_len);
        std::str::from_utf8(slice).unwrap_or("")
    };

    let canonical_query_str = unsafe {
        let slice = slice::from_raw_parts(canonical_query as *const u8, canonical_query_len);
        std::str::from_utf8(slice).unwrap_or("")
    };

    let canonical_headers_str = unsafe {
        let slice = slice::from_raw_parts(canonical_headers as *const u8, canonical_headers_len);
        std::str::from_utf8(slice).unwrap_or("")
    };

    let signed_headers_str = unsafe {
        let slice = slice::from_raw_parts(signed_headers as *const u8, signed_headers_len);
        std::str::from_utf8(slice).unwrap_or("")
    };

    // Hash the payload with SHA-256
    let payload_bytes = if payload.is_null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(payload, payload_len) }
    };

    let mut hasher = Sha256::new();
    hasher.update(payload_bytes);
    let payload_hash = hasher.finalize();
    let payload_hash_hex = hex::encode(payload_hash);

    // Build canonical request: METHOD\nURI\nQUERY\nHEADERS\n\nSIGNED_HEADERS\nHASHED_PAYLOAD
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method_str,
        canonical_uri_str,
        canonical_query_str,
        canonical_headers_str,
        signed_headers_str,
        payload_hash_hex
    );

    OpaqueResult::success(canonical_request.as_bytes().to_vec())
}

/// Derive AWS-style signing key (date-scoped)
/// Returns the final signing key for HMAC
#[no_mangle]
pub extern "C" fn aws_derive_signing_key(
    base_signing_key: *const u8,
    base_signing_key_len: usize,
    date: *const c_char,
    date_len: usize,
    region: *const c_char,
    region_len: usize,
    service: *const c_char,
    service_len: usize,
) -> OpaqueResult {
    if base_signing_key.is_null() || date.is_null() || region.is_null() || service.is_null() {
        return OpaqueResult::error(OpaqueError::InvalidInput);
    }

    let key_bytes = unsafe {
        slice::from_raw_parts(base_signing_key, base_signing_key_len)
    };

    let date_str = unsafe {
        let slice = slice::from_raw_parts(date as *const u8, date_len);
        std::str::from_utf8(slice).unwrap_or("")
    };

    let region_str = unsafe {
        let slice = slice::from_raw_parts(region as *const u8, region_len);
        std::str::from_utf8(slice).unwrap_or("")
    };

    let service_str = unsafe {
        let slice = slice::from_raw_parts(service as *const u8, service_len);
        std::str::from_utf8(slice).unwrap_or("")
    };

    // AWS-style key derivation:
    // kDate = HMAC-SHA256(base_signing_key, date)
    // kRegion = HMAC-SHA256(kDate, region)
    // kService = HMAC-SHA256(kRegion, service)
    // signing_key = HMAC-SHA256(kService, "boilstream_request")

    let mut mac = HmacSha256::new_from_slice(key_bytes).unwrap();
    mac.update(date_str.as_bytes());
    let k_date = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&k_date).unwrap();
    mac.update(region_str.as_bytes());
    let k_region = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&k_region).unwrap();
    mac.update(service_str.as_bytes());
    let k_service = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&k_service).unwrap();
    mac.update(b"boilstream_request");
    let signing_key = mac.finalize().into_bytes();

    OpaqueResult::success(signing_key.to_vec())
}

/// Sign canonical request with HMAC-SHA256
/// Returns base64-encoded signature
#[no_mangle]
pub extern "C" fn aws_sign_canonical_request(
    signing_key: *const u8,
    signing_key_len: usize,
    canonical_request: *const c_char,
    canonical_request_len: usize,
) -> OpaqueResult {
    if signing_key.is_null() || canonical_request.is_null() {
        return OpaqueResult::error(OpaqueError::InvalidInput);
    }

    let key_bytes = unsafe {
        slice::from_raw_parts(signing_key, signing_key_len)
    };

    let request_bytes = unsafe {
        slice::from_raw_parts(canonical_request as *const u8, canonical_request_len)
    };

    // Compute HMAC-SHA256 signature
    let mut mac = HmacSha256::new_from_slice(key_bytes).unwrap();
    mac.update(request_bytes);
    let signature = mac.finalize().into_bytes();

    // Encode as base64
    use base64::Engine;
    let signature_base64 = base64::engine::general_purpose::STANDARD.encode(signature);

    OpaqueResult::success(signature_base64.as_bytes().to_vec())
}

//===----------------------------------------------------------------------===//
// WASM-specific bindings using wasm-bindgen
//===----------------------------------------------------------------------===//

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    // Helper to convert Vec<u8> to base64 string for WASM
    fn to_base64(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    fn from_base64(s: &str) -> Result<Vec<u8>, JsValue> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| JsValue::from_str(&format!("Base64 decode error: {}", e)))
    }

    #[wasm_bindgen]
    pub struct WasmRegistrationState {
        inner: RegistrationState,
    }

    #[wasm_bindgen]
    pub struct WasmLoginState {
        inner: LoginState,
    }

    #[wasm_bindgen]
    pub struct WasmRegistrationStartResult {
        registration_request_base64: String,
        state: Option<WasmRegistrationState>,
    }

    #[wasm_bindgen]
    impl WasmRegistrationStartResult {
        #[wasm_bindgen(getter)]
        pub fn registration_request_base64(&self) -> String {
            self.registration_request_base64.clone()
        }
    }

    #[wasm_bindgen]
    pub struct WasmRegistrationFinishResult {
        registration_upload_base64: String,
        export_key_base64: String,
    }

    #[wasm_bindgen]
    impl WasmRegistrationFinishResult {
        #[wasm_bindgen(getter)]
        pub fn registration_upload_base64(&self) -> String {
            self.registration_upload_base64.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn export_key_base64(&self) -> String {
            self.export_key_base64.clone()
        }
    }

    #[wasm_bindgen]
    pub struct WasmLoginStartResult {
        credential_request_base64: String,
        state: Option<WasmLoginState>,
    }

    #[wasm_bindgen]
    impl WasmLoginStartResult {
        #[wasm_bindgen(getter)]
        pub fn credential_request_base64(&self) -> String {
            self.credential_request_base64.clone()
        }
    }

    #[wasm_bindgen]
    pub struct WasmLoginFinishResult {
        credential_finalization_base64: String,
        session_key_base64: String,
        export_key_base64: String,
    }

    #[wasm_bindgen]
    impl WasmLoginFinishResult {
        #[wasm_bindgen(getter)]
        pub fn credential_finalization_base64(&self) -> String {
            self.credential_finalization_base64.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn session_key_base64(&self) -> String {
            self.session_key_base64.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn export_key_base64(&self) -> String {
            self.export_key_base64.clone()
        }
    }

    #[wasm_bindgen]
    pub fn wasm_opaque_client_registration_start(password: &str) -> Result<WasmRegistrationStartResult, JsValue> {
        let password_bytes = password.as_bytes();
        let mut rng = get_rng!();

        let result = ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password_bytes)
            .map_err(|e| JsValue::from_str(&format!("Registration start failed: {:?}", e)))?;

        let serialized = result.message.serialize();
        let registration_request_base64 = to_base64(&serialized);

        Ok(WasmRegistrationStartResult {
            registration_request_base64,
            state: Some(WasmRegistrationState {
                inner: RegistrationState {
                    client_registration: result.state,
                    password: password_bytes.to_vec(),
                },
            }),
        })
    }

    #[wasm_bindgen]
    pub fn wasm_opaque_client_registration_finish(
        mut state: WasmRegistrationState,
        registration_response_base64: &str,
    ) -> Result<WasmRegistrationFinishResult, JsValue> {
        let response_bytes = from_base64(registration_response_base64)?;
        let mut rng = get_rng!();

        let registration_response = RegistrationResponse::<DefaultCipherSuite>::deserialize(&response_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize registration response: {:?}", e)))?;

        let finish_data = state.inner.client_registration
            .finish(
                &mut rng,
                &state.inner.password,
                registration_response,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(|e| JsValue::from_str(&format!("Registration finish failed: {:?}", e)))?;

        let upload_serialized = finish_data.message.serialize();
        let export_key = finish_data.export_key.to_vec();

        Ok(WasmRegistrationFinishResult {
            registration_upload_base64: to_base64(&upload_serialized),
            export_key_base64: to_base64(&export_key),
        })
    }

    #[wasm_bindgen]
    pub fn wasm_opaque_client_login_start(password: &str) -> Result<WasmLoginStartResult, JsValue> {
        let password_bytes = password.as_bytes();
        let mut rng = get_rng!();

        let result = ClientLogin::<DefaultCipherSuite>::start(&mut rng, password_bytes)
            .map_err(|e| JsValue::from_str(&format!("Login start failed: {:?}", e)))?;

        let serialized = result.message.serialize();
        let credential_request_base64 = to_base64(&serialized);

        Ok(WasmLoginStartResult {
            credential_request_base64,
            state: Some(WasmLoginState {
                inner: LoginState {
                    client_login: result.state,
                    password: password_bytes.to_vec(),
                },
            }),
        })
    }

    #[wasm_bindgen]
    pub fn wasm_opaque_client_login_finish(
        mut state: WasmLoginState,
        credential_response_base64: &str,
    ) -> Result<WasmLoginFinishResult, JsValue> {
        let response_bytes = from_base64(credential_response_base64)?;

        let credential_response = CredentialResponse::<DefaultCipherSuite>::deserialize(&response_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize credential response: {:?}", e)))?;

        let finish_data = state.inner.client_login
            .finish(
                &state.inner.password,
                credential_response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|e| JsValue::from_str(&format!("Login finish failed: {:?}", e)))?;

        let finalization_serialized = finish_data.message.serialize();
        let session_key = finish_data.session_key.to_vec();
        let export_key = finish_data.export_key.to_vec();

        Ok(WasmLoginFinishResult {
            credential_finalization_base64: to_base64(&finalization_serialized),
            session_key_base64: to_base64(&session_key),
            export_key_base64: to_base64(&export_key),
        })
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
pub unsafe extern "C" fn opaque_client_sha256(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
) {
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

/// Compute HMAC-SHA256 (C FFI)
///
/// # Arguments
/// * `key` - pointer to HMAC key
/// * `key_len` - length of key in bytes
/// * `data` - pointer to data to authenticate
/// * `data_len` - length of data in bytes
/// * `output` - pointer to output buffer (must be 32 bytes)
///
/// # Safety
/// Caller must ensure:
/// - `key` points to valid memory of at least `key_len` bytes
/// - `data` points to valid memory of at least `data_len` bytes
/// - `output` points to valid writable memory of at least 32 bytes
#[no_mangle]
pub unsafe extern "C" fn opaque_client_hmac_sha256(
    key: *const u8,
    key_len: usize,
    data: *const u8,
    data_len: usize,
    output: *mut u8,
) {
    use hmac::{Hmac, Mac};

    if key.is_null() || data.is_null() || output.is_null() {
        return;
    }

    let key_slice = slice::from_raw_parts(key, key_len);
    let data_slice = slice::from_raw_parts(data, data_len);

    let mut mac = Hmac::<Sha256>::new_from_slice(key_slice)
        .expect("HMAC can take key of any length");
    mac.update(data_slice);
    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    let output_slice = slice::from_raw_parts_mut(output, 32);
    output_slice.copy_from_slice(&code_bytes);
}

/// Derive integrity key using HKDF-SHA256 (C FFI)
/// salt="boilstream-session-v1", info="request-integrity-v1"
///
/// # Arguments
/// * `session_key` - pointer to session key (IKM)
/// * `session_key_len` - length of session key
/// * `output` - pointer to output buffer (must be 32 bytes)
///
/// # Returns
/// 0 on success, non-zero on error
#[no_mangle]
pub unsafe extern "C" fn opaque_client_derive_integrity_key(
    session_key: *const u8,
    session_key_len: usize,
    output: *mut u8,
) -> i32 {
    use hkdf::Hkdf;

    if session_key.is_null() || output.is_null() || session_key_len == 0 {
        return -1;
    }

    let session_key_slice = slice::from_raw_parts(session_key, session_key_len);
    let salt = b"boilstream-session-v1";
    let info = b"request-integrity-v1";

    let hk = Hkdf::<Sha256>::new(Some(salt), session_key_slice);
    let output_slice = slice::from_raw_parts_mut(output, 32);

    match hk.expand(info, output_slice) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Derive encryption key using HKDF-SHA256 (C FFI)
/// salt="boilstream-session-v1", info="response-encryption-v1"
///
/// # Arguments
/// * `session_key` - pointer to session key (IKM)
/// * `session_key_len` - length of session key
/// * `output` - pointer to output buffer (must be 32 bytes)
///
/// # Returns
/// 0 on success, non-zero on error
#[no_mangle]
pub unsafe extern "C" fn opaque_client_derive_encryption_key(
    session_key: *const u8,
    session_key_len: usize,
    output: *mut u8,
) -> i32 {
    use hkdf::Hkdf;

    if session_key.is_null() || output.is_null() || session_key_len == 0 {
        return -1;
    }

    let session_key_slice = slice::from_raw_parts(session_key, session_key_len);
    let salt = b"boilstream-session-v1";
    let info = b"response-encryption-v1";

    let hk = Hkdf::<Sha256>::new(Some(salt), session_key_slice);
    let output_slice = slice::from_raw_parts_mut(output, 32);

    match hk.expand(info, output_slice) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// Derive signing key using HKDF-SHA256 (C FFI)
/// salt="boilstream-session-v1", info="response-integrity-v1"
///
/// # Arguments
/// * `session_key` - pointer to session key (IKM)
/// * `session_key_len` - length of session key
/// * `output` - pointer to output buffer (must be 32 bytes)
///
/// # Returns
/// 0 on success, non-zero on error
#[no_mangle]
pub unsafe extern "C" fn opaque_client_derive_signing_key(
    session_key: *const u8,
    session_key_len: usize,
    output: *mut u8,
) -> i32 {
    use hkdf::Hkdf;

    if session_key.is_null() || output.is_null() || session_key_len == 0 {
        return -1;
    }

    let session_key_slice = slice::from_raw_parts(session_key, session_key_len);
    let salt = b"boilstream-session-v1";
    let info = b"response-integrity-v1";

    let hk = Hkdf::<Sha256>::new(Some(salt), session_key_slice);
    let output_slice = slice::from_raw_parts_mut(output, 32);

    match hk.expand(info, output_slice) {
        Ok(_) => 0,
        Err(_) => -1,
    }
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

/// Decrypt and verify AES-256-GCM encrypted response (C FFI)
///
/// # Arguments
/// * `ciphertext_with_tag` - pointer to ciphertext + 16-byte authentication tag
/// * `ciphertext_with_tag_len` - total length (ciphertext + 16)
/// * `nonce` - pointer to 12-byte nonce
/// * `nonce_len` - length of nonce (must be 12)
/// * `encryption_key` - pointer to 32-byte encryption key
/// * `encryption_key_len` - length of key (must be 32)
/// * `plaintext_out` - pointer to output buffer (must be at least ciphertext_len bytes)
/// * `plaintext_out_len` - size of output buffer
///
/// # Returns
/// Length of plaintext on success, -1 on error (including auth tag verification failure)
#[no_mangle]
pub unsafe extern "C" fn opaque_client_aes_gcm_decrypt(
    ciphertext_with_tag: *const u8,
    ciphertext_with_tag_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    encryption_key: *const u8,
    encryption_key_len: usize,
    plaintext_out: *mut u8,
    plaintext_out_len: usize,
) -> isize {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm,
    };
    use aes_gcm::aead::generic_array::GenericArray;

    // Validate inputs
    if ciphertext_with_tag.is_null() || nonce.is_null() || encryption_key.is_null() || plaintext_out.is_null() {
        return -1;
    }

    if nonce_len != 12 || encryption_key_len != 32 || ciphertext_with_tag_len < 16 {
        return -1;
    }

    let ciphertext_len = ciphertext_with_tag_len - 16;
    if plaintext_out_len < ciphertext_len {
        return -1;
    }

    let ciphertext_with_tag_slice = slice::from_raw_parts(ciphertext_with_tag, ciphertext_with_tag_len);
    let nonce_slice = slice::from_raw_parts(nonce, nonce_len);
    let key_slice = slice::from_raw_parts(encryption_key, encryption_key_len);

    // Create cipher
    let cipher = match Aes256Gcm::new_from_slice(key_slice) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    // Create nonce from slice (12 bytes for GCM)
    let nonce_array = GenericArray::from_slice(nonce_slice);

    // Decrypt and verify (this includes tag verification)
    match cipher.decrypt(nonce_array, ciphertext_with_tag_slice) {
        Ok(plaintext) => {
            if plaintext.len() != ciphertext_len {
                return -1;
            }
            let output_slice = slice::from_raw_parts_mut(plaintext_out, ciphertext_len);
            output_slice.copy_from_slice(&plaintext);
            ciphertext_len as isize
        }
        Err(_) => -1, // Decryption or authentication failed
    }
}
