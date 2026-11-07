//! Exercise the production C ABI against an actual opaque-ke server. No test
//! success hook or fixed session key bypasses the password-authenticated exchange.
use opaque_client::*;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use std::{ptr, slice};

fn empty() -> OpaqueBuffer {
    OpaqueBuffer {
        data: ptr::null_mut(),
        len: 0,
    }
}
fn bytes(buffer: &OpaqueBuffer) -> &[u8] {
    assert!(!buffer.data.is_null());
    unsafe { slice::from_raw_parts(buffer.data, buffer.len) }
}

fn exchange(password: &[u8], tamper: bool) {
    let setup = ServerSetup::<DefaultCipherSuite>::new(&mut UnwrapErr(SysRng));
    let registered_password = b"synthetic-test-password";
    let identity = b"synthetic-account";
    let mut reg_state = ptr::null_mut();
    let request = opaque_client_registration_start(
        registered_password.as_ptr().cast(),
        registered_password.len(),
        &mut reg_state,
    );
    assert!(matches!(request.error, OpaqueError::Success));
    let response = ServerRegistration::start(
        &setup,
        RegistrationRequest::deserialize(bytes(&request.buffer)).unwrap(),
        identity,
    )
    .unwrap();
    opaque_free_buffer(request.buffer);
    let serialized = response.message.serialize();
    let (mut upload, mut registered_export) = (empty(), empty());
    assert!(matches!(
        opaque_client_registration_finish(
            reg_state,
            serialized.as_ptr(),
            serialized.len(),
            &mut upload,
            &mut registered_export
        ),
        OpaqueError::Success
    ));
    let record = ServerRegistration::finish(
        RegistrationUpload::<DefaultCipherSuite>::deserialize(bytes(&upload)).unwrap(),
    );
    opaque_free_buffer(upload);

    let mut login_state = ptr::null_mut();
    let request =
        opaque_client_login_start(password.as_ptr().cast(), password.len(), &mut login_state);
    assert!(matches!(request.error, OpaqueError::Success));
    let response = ServerLogin::start(
        &mut UnwrapErr(SysRng),
        &setup,
        Some(record),
        CredentialRequest::deserialize(bytes(&request.buffer)).unwrap(),
        identity,
        ServerLoginParameters::default(),
    )
    .unwrap();
    opaque_free_buffer(request.buffer);
    let mut serialized = response.message.serialize().to_vec();
    if tamper {
        let last = serialized.len() - 1;
        serialized[last] ^= 1;
    }
    let (mut finalization, mut session, mut exported) = (empty(), empty(), empty());
    let result = opaque_client_login_finish(
        login_state,
        serialized.as_ptr(),
        serialized.len(),
        &mut finalization,
        &mut session,
        &mut exported,
    );
    if password != registered_password || tamper {
        assert!(matches!(result, OpaqueError::ProtocolError));
        for value in [&finalization, &session, &exported] {
            assert!(value.data.is_null());
            assert_eq!(value.len, 0);
        }
    } else {
        assert!(matches!(result, OpaqueError::Success));
        let server = response
            .state
            .finish(
                CredentialFinalization::deserialize(bytes(&finalization)).unwrap(),
                ServerLoginParameters::default(),
            )
            .unwrap();
        assert_eq!(bytes(&session), server.session_key.as_slice());
        assert_eq!(bytes(&exported), bytes(&registered_export));
        assert_eq!(session.len, 64);
        assert!(bytes(&session).iter().any(|b| *b != 0));
    }
    for buffer in [finalization, session, exported, registered_export] {
        opaque_free_buffer(buffer);
    }
}

#[test]
fn ffi_registration_and_authenticated_login_agree_on_keys() {
    exchange(b"synthetic-test-password", false);
}
#[test]
fn ffi_wrong_password_never_publishes_keys() {
    exchange(b"wrong-test-password", false);
}
#[test]
fn ffi_modified_server_proof_never_publishes_keys() {
    exchange(b"synthetic-test-password", true);
}
