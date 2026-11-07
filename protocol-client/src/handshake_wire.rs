//! Shared Noise profile, framing and injected primitive providers; no server handler.
use crate::{Error, SessionKeys};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use curve25519_dalek::montgomery::MontgomeryPoint;
use snow::{
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};
use std::cell::RefCell;
use zeroize::Zeroizing;

pub const SUITE: &str = "Noise_NK_25519_AESGCM_SHA256";
pub const CLIENT_PREFIX: &str = "BH2.c.";
pub const SERVER_PREFIX: &str = "BH2.s.";
pub const CLIENT_BYTES: usize = 48;
pub const SERVER_BYTES: usize = 120;
pub const HANDSHAKE_SECONDS: u64 = 120;
pub const CHANNEL_SECONDS: u64 = 3600;

/// Trusted configuration only. A received key must never create or replace a pin.
#[derive(Clone)]
pub struct Pin {
    authority: String,
    public_key: [u8; 32],
}
impl Pin {
    pub fn new(authority: &str, public_key: [u8; 32]) -> Result<Self, Error> {
        // Reject noncanonical X25519 encodings (u >= 2^255 - 19), including
        // the ignored top bit. Reject low-order points through a DH check.
        let mut modulus = [0xff; 32];
        modulus[0] = 0xed;
        modulus[31] = 0x7f;
        if authority.is_empty()
            || authority.len() > crate::wire::MAX_TARGET_BYTES
            || !authority.bytes().all(|b| b.is_ascii_graphic())
            || public_key.iter().rev().cmp(modulus.iter().rev()).is_ge()
            || MontgomeryPoint(public_key)
                .mul_clamped([0x42; 32])
                .to_bytes()
                == [0; 32]
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            authority: authority.to_owned(),
            public_key,
        })
    }
    pub fn authority(&self) -> &str {
        &self.authority
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub fn prologue(&self) -> Vec<u8> {
        let mut bytes = b"boilstream/application/v2/handshake\0".to_vec();
        bytes.extend_from_slice(&(self.authority.len() as u64).to_be_bytes());
        bytes.extend_from_slice(self.authority.as_bytes());
        bytes.extend_from_slice(&self.public_key);
        bytes
    }
}

/// Server-authenticated channel, NOT an authenticated user or tenant.
/// Adapters must check expiry on each use and enforce durable replay admission.
pub struct Channel {
    keys: SessionKeys,
    expires_at: u64,
}
impl Channel {
    /// Shared derivation; call only after authenticating the handshake transcript.
    pub fn from_authenticated_master(
        master: &[u8; 64],
        transcript: [u8; 32],
        pin: &Pin,
        expires_at: u64,
    ) -> Result<Self, Error> {
        if master == &[0; 64] {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            keys: SessionKeys::derive(master, transcript, pin.authority())?,
            expires_at,
        })
    }
    pub fn keys(&self, now: u64) -> Result<&SessionKeys, Error> {
        if now >= self.expires_at {
            return Err(Error::Expired);
        }
        Ok(&self.keys)
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn session_id(&self) -> [u8; 32] {
        self.keys.session_id()
    }
}

/// Fixed-length canonical framing: bounds precede any allocation/decode.
pub fn decode_message(wire: &str, prefix: &str, size: usize) -> Result<Vec<u8>, Error> {
    if size != CLIENT_BYTES && size != SERVER_BYTES {
        return Err(Error::InvalidInput);
    }
    if wire.len() != prefix.len() + (size * 4).div_ceil(3) {
        return Err(Error::InvalidMessage);
    }
    let encoded = wire.strip_prefix(prefix).ok_or(Error::InvalidMessage)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::InvalidMessage)?;
    if bytes.len() != size || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(Error::InvalidMessage);
    }
    Ok(bytes)
}
pub fn encode_message(prefix: &str, bytes: &[u8]) -> String {
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Exactly one 32-byte CSPRNG draw, supplied by the adapter, consumed once.
/// No OS randomness, test-mode switch, PRNG fallback or key-generation default.
pub struct EntropyResolver(RefCell<Option<Zeroizing<[u8; 32]>>>);
impl EntropyResolver {
    pub fn new(entropy: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        if *entropy == [0; 32] {
            return Err(Error::InvalidInput);
        }
        Ok(Self(RefCell::new(Some(entropy))))
    }
}
struct OneDraw(Option<Zeroizing<[u8; 32]>>);
impl Random for OneDraw {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        let bytes = self.0.take().ok_or(snow::Error::Rng)?;
        if dest.len() != 32 {
            return Err(snow::Error::Rng);
        }
        dest.copy_from_slice(bytes.as_ref());
        Ok(())
    }
}
impl CryptoResolver for EntropyResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        self.0
            .borrow_mut()
            .take()
            .map(|bytes| Box::new(OneDraw(Some(bytes))) as Box<dyn Random>)
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::Curve25519 => Some(Box::new(CheckedDh::default())),
            _ => None,
        }
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        if *choice != HashChoice::SHA256 {
            return None;
        }
        DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        if *choice != CipherChoice::AESGCM {
            return None;
        }
        DefaultResolver.resolve_cipher(choice)
    }
}

/// RustCrypto X25519 with explicit low-order rejection and owned-key wiping.
/// Snow's other internal buffers do not promise erasure on drop.
struct CheckedDh {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}
impl Default for CheckedDh {
    fn default() -> Self {
        Self {
            secret: Zeroizing::new([0; 32]),
            public: [0; 32],
        }
    }
}
impl Dh for CheckedDh {
    fn name(&self) -> &'static str {
        "25519"
    }
    fn pub_len(&self) -> usize {
        32
    }
    fn priv_len(&self) -> usize {
        32
    }
    fn set(&mut self, key: &[u8]) {
        self.secret.copy_from_slice(key);
        self.public = MontgomeryPoint::mul_base_clamped(*self.secret).to_bytes();
    }
    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
        rng.try_fill_bytes(self.secret.as_mut())?;
        self.public = MontgomeryPoint::mul_base_clamped(*self.secret).to_bytes();
        Ok(())
    }
    fn pubkey(&self) -> &[u8] {
        &self.public
    }
    fn privkey(&self) -> &[u8] {
        self.secret.as_ref()
    }
    fn dh(&self, peer: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        let peer: [u8; 32] = peer
            .get(..32)
            .ok_or(snow::Error::Dh)?
            .try_into()
            .map_err(|_| snow::Error::Dh)?;
        // The same canonical/low-order policy applies to ephemeral peer keys.
        Pin::new("dh-validation", peer).map_err(|_| snow::Error::Dh)?;
        let secret = Zeroizing::new(MontgomeryPoint(peer).mul_clamped(*self.secret).to_bytes());
        if *secret == [0; 32] || out.len() < 32 {
            return Err(snow::Error::Dh);
        }
        out[..32].copy_from_slice(secret.as_ref());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entropy_is_single_use_and_has_no_default() {
        assert!(EntropyResolver::new(Zeroizing::new([0; 32])).is_err());
        let resolver = EntropyResolver::new(Zeroizing::new([1; 32])).unwrap();
        let mut rng = resolver.resolve_rng().unwrap();
        assert!(resolver.resolve_rng().is_none());
        let mut bytes = [0; 32];
        rng.try_fill_bytes(&mut bytes).unwrap();
        assert_eq!(bytes, [1; 32]);
        assert!(rng.try_fill_bytes(&mut bytes).is_err());
    }
    #[test]
    fn invalid_entropy_request_also_consumes_draw() {
        let resolver = EntropyResolver::new(Zeroizing::new([1; 32])).unwrap();
        let mut rng = resolver.resolve_rng().unwrap();
        assert!(rng.try_fill_bytes(&mut [0; 16]).is_err());
        assert!(rng.try_fill_bytes(&mut [0; 32]).is_err());
    }
    #[test]
    fn pins_reject_low_order_and_noncanonical_points() {
        for key in [[0; 32], [0xff; 32], {
            let mut one = [0; 32];
            one[0] = 1;
            one
        }] {
            assert!(Pin::new("https://example.test", key).is_err());
        }
    }
}
