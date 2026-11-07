//! Shared message types, bounded framing and session key derivation.
//! Parsed headers are untrusted until the caller verifies the AEAD tag.
//! This module contains no server request processing or response encryption.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const PREFIX: &str = "BS2.";
pub const DOMAIN: &[u8] = b"boilstream/application/v2/envelope\0";
pub const HEADER_LEN: usize = 118;
pub const TAG_LEN: usize = 16;
pub const REQUEST: u8 = 1;
pub const RESPONSE: u8 = 2;
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_MESSAGES: u64 = 1 << 20;
pub const MAX_LIFETIME_SECONDS: u64 = 120;
pub const FUTURE_SKEW_SECONDS: u64 = 30;
pub const MAX_METADATA_BYTES: usize = 8192;
pub const MAX_TARGET_BYTES: usize = 2048;

/// Maximum transport body bytes for a given maximum plaintext size.
pub const fn max_wire_bytes(plaintext_limit: usize) -> usize {
    // Only public fixed limits are accepted by our codecs. Saturation makes this
    // utility safe even when an adapter passes an untrusted size.
    plaintext_limit
        .saturating_add(HEADER_LEN + TAG_LEN)
        .saturating_mul(4)
        .saturating_add(2)
        / 3
        + PREFIX.len()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    InvalidMessage,
    Authentication,
    Expired,
    TooLarge,
    Sequence,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid protocol input",
            Self::InvalidMessage => "invalid protocol message",
            Self::Authentication => "protocol authentication failed",
            Self::Expired => "protocol message outside validity window",
            Self::TooLarge => "protocol message exceeds limit",
            Self::Sequence => "protocol sequence rejected",
        })
    }
}
impl std::error::Error for Error {}

/// One fixed suite; no untrusted algorithm selection and no secret Debug/Clone.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    request: [u8; 32],
    response: [u8; 32],
    session: [u8; 32],
}

impl SessionKeys {
    pub fn request_key(&self) -> &[u8; 32] {
        &self.request
    }
    pub fn response_key(&self) -> &[u8; 32] {
        &self.response
    }
    pub fn session_id(&self) -> [u8; 32] {
        self.session
    }

    /// `authority` is the exact configured service identity, never a received
    /// Host/forwarding header. `secret` must be an authenticated channel master.
    pub fn derive(secret: &[u8; 64], session: [u8; 32], authority: &str) -> Result<Self, Error> {
        if session == [0; 32]
            || authority.is_empty()
            || authority.len() > MAX_TARGET_BYTES
            || !authority.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(Error::InvalidInput);
        }
        // Length-prefix the variable field; no ambiguous concatenation.
        let mut salt = Sha256::new();
        salt.update(b"boilstream/application/v2/session\0");
        salt.update((authority.len() as u64).to_be_bytes());
        salt.update(authority.as_bytes());
        salt.update(session);
        let kdf = Hkdf::<Sha256>::new(Some(&salt.finalize()), secret);
        let mut keys = Self {
            request: [0; 32],
            response: [0; 32],
            session,
        };
        kdf.expand(b"client-to-server", &mut keys.request)
            .map_err(|_| Error::InvalidInput)?;
        kdf.expand(b"server-to-client", &mut keys.response)
            .map_err(|_| Error::InvalidInput)?;
        Ok(keys)
    }
}

#[derive(Serialize, Deserialize)]
pub enum Method {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "DELETE")]
    Delete,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[zeroize(skip)]
    pub method: Method,
    pub target: String,
    pub body: String,
    pub cookie: Option<String>,
    pub idempotency_key: Option<String>,
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        // Route authorization and canonical path interpretation belong to the
        // server adapter. This check prevents URL/proxy and header injection.
        if !self.target.starts_with('/')
            || self.target.starts_with("//")
            || self.target.len() > MAX_TARGET_BYTES
            || !self.target.bytes().all(|b| b.is_ascii_graphic())
            || self.target.contains(['#', '\\'])
        {
            return Err(Error::InvalidMessage);
        }
        if self.body.len() > MAX_REQUEST_BYTES {
            return Err(Error::TooLarge);
        }
        if let Some(cookie) = &self.cookie {
            validate_metadata(cookie)?;
        }
        if let Some(id) = &self.idempotency_key {
            if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(Error::InvalidMessage);
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Response {
    #[zeroize(skip)]
    pub status: u16,
    pub body: String,
    #[serde(deserialize_with = "deserialize_cookies")]
    pub cookies: Vec<String>,
    #[zeroize(skip)]
    pub session_resumption: bool,
}

fn deserialize_cookies<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    struct Cookies;
    impl<'de> serde::de::Visitor<'de> for Cookies {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("at most 16 bounded cookie values")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut cookies = Zeroizing::new(Vec::new());
            let mut total = 0usize;
            while let Some(cookie) = seq.next_element::<String>()? {
                let cookie = Zeroizing::new(cookie);
                total = total.saturating_add(cookie.len());
                if cookies.len() == 16
                    || total > MAX_METADATA_BYTES
                    || validate_metadata(&cookie).is_err()
                {
                    return Err(serde::de::Error::custom("invalid cookie metadata"));
                }
                cookies.push(cookie.to_string());
            }
            Ok(std::mem::take(&mut *cookies))
        }
    }
    deserializer.deserialize_seq(Cookies)
}

impl Response {
    pub fn validate(&self) -> Result<(), Error> {
        // Redirects/informational statuses are not application results.
        if !matches!(self.status, 200..=299 | 400..=599) {
            return Err(Error::InvalidMessage);
        }
        if self.body.len() > MAX_RESPONSE_BYTES || self.cookies.len() > 16 {
            return Err(Error::TooLarge);
        }
        let mut total = 0usize;
        for cookie in &self.cookies {
            validate_metadata(cookie)?;
            total = total.saturating_add(cookie.len());
        }
        if total > MAX_METADATA_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
}

fn validate_metadata(value: &str) -> Result<(), Error> {
    if value.len() > MAX_METADATA_BYTES {
        return Err(Error::TooLarge);
    }
    if !value.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
        return Err(Error::InvalidMessage);
    }
    Ok(())
}

/// Fresh 96-bit nonce from the adapter's CSPRNG, consumed by sealing.
/// It is not a reusable constant, counter shared across keys, or caller password.
pub struct Nonce(pub(crate) [u8; 12]);
impl Nonce {
    pub fn from_csprng(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }
}

/// Fresh 128-bit entropy from the adapter's CSPRNG. No clock/counter fallback.
pub struct RequestId(pub(crate) [u8; 16]);
impl RequestId {
    pub fn from_csprng(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

#[derive(PartialEq, Eq)]
pub struct Context {
    pub session: [u8; 32],
    pub request_id: [u8; 16],
    pub sequence: u64,
    pub issued: u64,
    pub expires: u64,
}

impl Context {
    pub fn validate(&self, now: u64) -> Result<(), Error> {
        if self.sequence == 0 || self.sequence > MAX_MESSAGES {
            return Err(Error::Sequence);
        }
        if self.expires <= self.issued
            || self.expires - self.issued > MAX_LIFETIME_SECONDS
            || self.issued > now.saturating_add(FUTURE_SKEW_SECONDS)
            || now >= self.expires
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

pub fn associated_data(header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN.len() + header.len());
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(header);
    aad
}

pub fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Bound JSON escaping as it is written, rather than allocating up to six
    // times the input before checking the resulting plaintext length.
    struct Buffer {
        bytes: Zeroizing<Vec<u8>>,
        limit: usize,
        exceeded: bool,
    }
    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                self.exceeded = true;
                return Err(std::io::Error::other("protocol size limit"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut buffer = Buffer {
        bytes: Zeroizing::new(Vec::new()),
        limit,
        exceeded: false,
    };
    if serde_json::to_writer(&mut buffer, value).is_err() {
        return Err(if buffer.exceeded {
            Error::TooLarge
        } else {
            Error::InvalidInput
        });
    }
    Ok(buffer.bytes)
}

pub fn decode(wire: &str, limit: usize) -> Result<Vec<u8>, Error> {
    if wire.len() > max_wire_bytes(limit) {
        return Err(Error::TooLarge);
    }
    let encoded = wire.strip_prefix(PREFIX).ok_or(Error::InvalidMessage)?;
    let frame = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::InvalidMessage)?;
    if frame.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::InvalidMessage);
    }
    if frame.len() > HEADER_LEN + TAG_LEN + limit {
        return Err(Error::TooLarge);
    }
    Ok(frame)
}

pub(crate) fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    // Call sites only slice fixed, checked frame offsets.
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    out
}

/// Encode only the unencrypted frame header; this does not authenticate it.
pub fn header(
    direction: u8,
    context: &Context,
    binding: &[u8; 32],
    nonce: Nonce,
) -> Result<Vec<u8>, Error> {
    if direction != REQUEST && direction != RESPONSE {
        return Err(Error::InvalidInput);
    }
    let mut frame = Vec::with_capacity(HEADER_LEN);
    frame.extend_from_slice(&[2, direction]);
    frame.extend_from_slice(&context.session);
    frame.extend_from_slice(&context.request_id);
    frame.extend_from_slice(&context.sequence.to_be_bytes());
    frame.extend_from_slice(&context.issued.to_be_bytes());
    frame.extend_from_slice(&context.expires.to_be_bytes());
    frame.extend_from_slice(binding);
    frame.extend_from_slice(&nonce.0);
    Ok(frame)
}

/// Parse routing/binding fields only. No returned value is authenticated yet.
pub fn parse_header(
    frame: &[u8],
    direction: u8,
    session: &[u8; 32],
) -> Result<(Context, [u8; 32], [u8; 12]), Error> {
    if frame.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::InvalidMessage);
    }
    if !matches!(direction, REQUEST | RESPONSE)
        || frame[0] != 2
        || frame[1] != direction
        || &frame[2..34] != session
    {
        return Err(Error::Authentication);
    }
    let context = Context {
        session: array(&frame[2..34]),
        request_id: array(&frame[34..50]),
        sequence: u64::from_be_bytes(array(&frame[50..58])),
        issued: u64::from_be_bytes(array(&frame[58..66])),
        expires: u64::from_be_bytes(array(&frame[66..74])),
    };
    Ok((context, array(&frame[74..106]), array(&frame[106..118])))
}
