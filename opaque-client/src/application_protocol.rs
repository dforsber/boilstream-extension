//! C ABI for the client-only application protocol. Handles have one owner and
//! require exclusive access across start/accept and seal/HTTP/open. Callers free
//! them exactly once; no pointer may outlive its handle. All buffers use the
//! existing opaque_free_buffer allocator/zeroization contract.
use crate::{OpaqueError, OpaqueResult};
use boilstream_protocol_client::{
    handshake_wire::{Pin, SERVER_BYTES, SERVER_PREFIX},
    session::ClientSession,
    wire, Nonce, Request, RequestId,
};
use rand::{rand_core::TryRng, rngs::SysRng};
use std::{
    slice, str,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub struct ApplicationProtocol {
    session: ClientSession,
}
fn now() -> Result<u64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| ())
}
fn entropy<const N: usize>() -> Result<Zeroizing<[u8; N]>, ()> {
    let mut bytes = Zeroizing::new([0; N]);
    SysRng.try_fill_bytes(bytes.as_mut()).map_err(|_| ())?;
    Ok(bytes)
}
unsafe fn text<'a>(data: *const u8, len: usize, max: usize) -> Result<&'a str, ()> {
    if data.is_null() || len > max {
        return Err(());
    }
    str::from_utf8(unsafe { slice::from_raw_parts(data, len) }).map_err(|_| ())
}
/// # Safety
/// `authority` references `authority_len` bytes, `key` references 32 bytes and
/// `output` is writable. Returned ownership is freed with bs_protocol_free.
#[no_mangle]
pub unsafe extern "C" fn bs_protocol_start(
    authority: *const u8,
    authority_len: usize,
    key: *const u8,
    output: *mut *mut ApplicationProtocol,
) -> OpaqueResult {
    if output.is_null() {
        return OpaqueResult::error(OpaqueError::InvalidInput);
    }
    unsafe { *output = std::ptr::null_mut() };
    let result = (|| {
        let authority = unsafe { text(authority, authority_len, wire::MAX_TARGET_BYTES) }?;
        if key.is_null() {
            return Err(());
        }
        let key: [u8; 32] = unsafe { slice::from_raw_parts(key, 32) }
            .try_into()
            .map_err(|_| ())?;
        let pin = Pin::new(authority, key).map_err(|_| ())?;
        let (hello, session) = ClientSession::start(pin, entropy()?, now()?).map_err(|_| ())?;
        unsafe { *output = Box::into_raw(Box::new(ApplicationProtocol { session })) };
        Ok(hello)
    })();
    match result {
        Ok(body) => OpaqueResult::success(body.into_bytes()),
        Err(()) => OpaqueResult::error(OpaqueError::ProtocolError),
    }
}
/// # Safety
/// Handle is live and exclusively owned; body references exactly len bytes.
#[no_mangle]
pub unsafe extern "C" fn bs_protocol_accept(
    handle: *mut ApplicationProtocol,
    body: *const u8,
    len: usize,
) -> OpaqueError {
    let Some(handle) = (unsafe { handle.as_mut() }) else {
        return OpaqueError::InvalidInput;
    };
    let result = (|| {
        let body = unsafe {
            text(
                body,
                len,
                SERVER_PREFIX.len() + (SERVER_BYTES * 4).div_ceil(3),
            )
        }?;
        handle.session.accept(body, now()?).map_err(|_| ())
    })();
    if result.is_ok() {
        OpaqueError::Success
    } else {
        handle.session.close();
        OpaqueError::ProtocolError
    }
}
/// # Safety
/// Handle is live and exclusively owned; JSON references exactly len bytes.
#[no_mangle]
pub unsafe extern "C" fn bs_protocol_seal(
    handle: *mut ApplicationProtocol,
    json: *const u8,
    len: usize,
) -> OpaqueResult {
    let Some(handle) = (unsafe { handle.as_mut() }) else {
        return OpaqueResult::error(OpaqueError::InvalidInput);
    };
    let result = (|| {
        let json = unsafe { text(json, len, wire::MAX_REQUEST_BYTES) }?;
        let request: Request = serde_json::from_str(json).map_err(|_| ())?;
        handle
            .session
            .seal(
                &request,
                RequestId::from_csprng(*entropy()?),
                Nonce::from_csprng(*entropy()?),
                now()?,
            )
            .map_err(|_| ())
    })();
    match result {
        Ok(body) => OpaqueResult::success(body.into_bytes()),
        Err(()) => {
            handle.session.close();
            OpaqueResult::error(OpaqueError::ProtocolError)
        }
    }
}
/// Returns JSON containing verified inner status/body/cookies/resumption only.
/// # Safety
/// Handle is live and exclusively owned; body references exactly len bytes.
#[no_mangle]
pub unsafe extern "C" fn bs_protocol_open(
    handle: *mut ApplicationProtocol,
    body: *const u8,
    len: usize,
) -> OpaqueResult {
    let Some(handle) = (unsafe { handle.as_mut() }) else {
        return OpaqueResult::error(OpaqueError::InvalidInput);
    };
    let result = (|| {
        let body = unsafe { text(body, len, wire::max_wire_bytes(wire::MAX_RESPONSE_BYTES)) }?;
        let response = handle.session.open(body, now()?).map_err(|_| ())?;
        serde_json::to_vec(&response).map_err(|_| ())
    })();
    match result {
        Ok(body) => OpaqueResult::success(body),
        Err(()) => {
            handle.session.close();
            OpaqueResult::error(OpaqueError::ProtocolError)
        }
    }
}
/// # Safety
/// Null or a live exclusively owned handle. It must not be used or freed again.
#[no_mangle]
pub unsafe extern "C" fn bs_protocol_free(handle: *mut ApplicationProtocol) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_configuration_never_publishes_a_handle() {
        unsafe {
            let mut output = std::ptr::null_mut();
            let result = bs_protocol_start(
                b"https://fixture.test".as_ptr(),
                20,
                [0; 32].as_ptr(),
                &mut output,
            );
            assert!(!matches!(result.error, OpaqueError::Success));
            assert!(output.is_null());
            assert!(matches!(
                bs_protocol_accept(output, std::ptr::null(), 0),
                OpaqueError::InvalidInput
            ));
            bs_protocol_free(output);
        }
    }
    #[test]
    fn invalid_input_closes_the_real_ffi_channel() {
        unsafe {
            let mut output = std::ptr::null_mut();
            let key: [u8; 32] = [9; 32];
            let authority = b"https://fixture.test";
            let result = bs_protocol_start(
                authority.as_ptr(),
                authority.len(),
                key.as_ptr(),
                &mut output,
            );
            assert!(matches!(result.error, OpaqueError::Success));
            assert!(!output.is_null());
            crate::opaque_free_buffer(result.buffer);
            assert!(!matches!(
                bs_protocol_seal(output, b"{}".as_ptr(), 2).error,
                OpaqueError::Success
            ));
            assert!(!matches!(
                bs_protocol_accept(output, b"bad".as_ptr(), 3),
                OpaqueError::Success
            ));
            bs_protocol_free(output);
        }
    }
}
