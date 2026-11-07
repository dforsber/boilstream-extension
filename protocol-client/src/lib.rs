//! Client-only established-session protocol candidate. Not integrated yet.
//! Bootstrap trust, entropy, time and transport are supplied by the application.
//! Server protocol processing is deliberately not included, even behind features.
//!
//! ```compile_fail
//! use boilstream_protocol_client::open_request;
//! ```
//! ```compile_fail
//! use boilstream_protocol_client::seal_response;
//! ```
//! ```compile_fail
//! use boilstream_protocol_client::ReplyContext;
//! ```
//! ```compile_fail
//! use boilstream_protocol_client::admit_sequence;
//! ```
pub mod wire;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use wire::*;
pub use wire::{Error, Method, Nonce, Request, RequestId, Response, SessionKeys};
use zeroize::Zeroizing;
/// Held only by the initiating client. Opening a reply consumes it, even on error.
pub struct PendingResponse {
    context: Context,
    binding: [u8; 32],
}

pub fn seal_request(
    keys: &SessionKeys,
    request: &Request,
    sequence: u64,
    request_id: RequestId,
    nonce: Nonce,
    now: u64,
) -> Result<(String, PendingResponse), Error> {
    request.validate()?;
    let context = Context {
        session: keys.session_id(),
        request_id: request_id.0,
        sequence,
        issued: now,
        expires: now
            .checked_add(MAX_LIFETIME_SECONDS)
            .ok_or(Error::Expired)?,
    };
    context.validate(now)?;
    let plaintext = encode(request, MAX_REQUEST_BYTES)?;
    let wire = encrypt_request(keys.request_key(), &context, &[0; 32], nonce, &plaintext)?;
    let binding = Sha256::digest(wire.as_bytes()).into();
    Ok((wire, PendingResponse { context, binding }))
}
pub fn open_response(
    keys: &SessionKeys,
    pending: PendingResponse,
    wire: &str,
    now: u64,
) -> Result<Response, Error> {
    let frame = decode(wire, MAX_RESPONSE_BYTES)?;
    let (context, binding, plaintext) =
        decrypt_response(keys.response_key(), &keys.session_id(), &frame)?;
    context.validate(now)?;
    if context != pending.context || binding != pending.binding {
        return Err(Error::Authentication);
    }
    let response: Response =
        serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidMessage)?;
    response.validate()?;
    Ok(response)
}

fn encrypt_request(
    key: &[u8; 32],
    context: &Context,
    binding: &[u8; 32],
    nonce: Nonce,
    plaintext: &[u8],
) -> Result<String, Error> {
    if plaintext.len() > MAX_REQUEST_BYTES {
        return Err(Error::TooLarge);
    }
    let mut frame = header(REQUEST, context, binding, nonce)?;
    let aad = associated_data(&frame);
    let cipher = Aes256Gcm::new(key.into());
    let ciphertext = cipher
        .encrypt(
            frame[106..118].into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    frame.extend_from_slice(&ciphertext);
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(frame)))
}

type OpenedFrame = (Context, [u8; 32], Zeroizing<Vec<u8>>);

fn decrypt_response(
    key: &[u8; 32],
    session: &[u8; 32],
    frame: &[u8],
) -> Result<OpenedFrame, Error> {
    let (context, binding, nonce) = parse_header(frame, RESPONSE, session)?;
    let aad = associated_data(&frame[..HEADER_LEN]);
    let cipher = Aes256Gcm::new(key.into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &frame[HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    Ok((context, binding, plaintext))
}

#[cfg(test)]
mod tests;
