//! Client half of a pinned, ephemeral Noise NK handshake.
//! The initial message cannot carry credentials. Completion consumes pending
//! state even on error; no retry, downgrade or trust-on-first-use is provided.
use crate::{handshake_wire::*, Error};
use zeroize::Zeroizing;

pub struct PendingHandshake {
    noise: snow::HandshakeState,
    pin: Pin,
    started: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/handshake-vector.json")).unwrap()
    }
    fn bytes<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }
    fn pending(v: &Value) -> (String, PendingHandshake) {
        start(
            Pin::new(
                v["authority"].as_str().unwrap(),
                bytes(v["server_public"].as_str().unwrap()),
            )
            .unwrap(),
            Zeroizing::new(bytes(v["client_entropy"].as_str().unwrap())),
            v["now"].as_u64().unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn independent_noise_vector_and_directional_keys() {
        let v = fixture();
        let now = v["now"].as_u64().unwrap();
        let (wire, state) = pending(&v);
        assert_eq!(wire, v["client_wire"]);
        let channel = state
            .finish(v["server_wire"].as_str().unwrap(), now)
            .unwrap();
        assert_eq!(channel.session_id(), bytes(v["session"].as_str().unwrap()));
        assert_eq!(
            *channel.keys(now).unwrap().request_key(),
            bytes(v["request_key"].as_str().unwrap())
        );
        assert_eq!(
            *channel.keys(now).unwrap().response_key(),
            bytes(v["response_key"].as_str().unwrap())
        );
        let expires = v["expires"].as_u64().unwrap();
        assert_eq!(channel.expires_at(), expires);
        assert!(channel.keys(expires - 1).is_ok());
        assert!(matches!(channel.keys(expires), Err(Error::Expired)));
    }
    #[test]
    fn every_server_handshake_byte_is_authenticated() {
        let v = fixture();
        let original = decode_message(
            v["server_wire"].as_str().unwrap(),
            SERVER_PREFIX,
            SERVER_BYTES,
        )
        .unwrap();
        for i in 0..original.len() {
            let mut changed = original.clone();
            changed[i] ^= 1;
            assert!(
                pending(&v)
                    .1
                    .finish(
                        &encode_message(SERVER_PREFIX, &changed),
                        v["now"].as_u64().unwrap()
                    )
                    .is_err(),
                "byte {i}"
            );
        }
    }
    #[test]
    fn authority_pin_and_initiator_are_bound() {
        let v = fixture();
        for field in ["authority", "server_public", "client_entropy"] {
            let mut changed = v.clone();
            changed[field] = match field {
                "authority" => Value::from("https://other.example.test"),
                "server_public" => v["rotated_public"].clone(),
                _ => Value::from("11".repeat(32)),
            };
            assert!(
                pending(&changed)
                    .1
                    .finish(
                        v["server_wire"].as_str().unwrap(),
                        v["now"].as_u64().unwrap()
                    )
                    .is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn handshake_deadline_and_clock_rollback_fail_closed() {
        let v = fixture();
        let now = v["now"].as_u64().unwrap();
        let reply = v["server_wire"].as_str().unwrap();
        assert!(pending(&v)
            .1
            .finish(reply, now + HANDSHAKE_SECONDS - 1)
            .is_ok());
        for time in [now - 1, now + HANDSHAKE_SECONDS, u64::MAX] {
            assert!(matches!(
                pending(&v).1.finish(reply, time),
                Err(Error::Expired)
            ));
        }
    }
    #[test]
    fn noncanonical_plaintext_truncated_and_oversized_replies_fail() {
        let v = fixture();
        let reply = v["server_wire"].as_str().unwrap();
        for message in [
            reply[..reply.len() - 1].to_owned(),
            format!("{reply}="),
            format!(" {reply}"),
            reply.replace("BH2.s.", "BH2.c."),
            "{\"status\":200}".to_owned(),
            "A".repeat(1_000_000),
        ] {
            assert!(pending(&v)
                .1
                .finish(&message, v["now"].as_u64().unwrap())
                .is_err());
        }
    }
    #[test]
    fn invalid_configuration_or_zero_entropy_cannot_start() {
        let v = fixture();
        let key = bytes(v["server_public"].as_str().unwrap());
        for authority in ["", "with space", "https://é.test"] {
            assert!(Pin::new(authority, key).is_err());
        }
        let pin = Pin::new("https://example.test", key).unwrap();
        assert!(start(pin.clone(), Zeroizing::new([0; 32]), 1).is_err());
        assert!(start(pin, Zeroizing::new([1; 32]), u64::MAX).is_err());
    }
}

pub fn start(
    pin: Pin,
    entropy: Zeroizing<[u8; 32]>,
    now: u64,
) -> Result<(String, PendingHandshake), Error> {
    now.checked_add(CHANNEL_SECONDS + crate::wire::FUTURE_SKEW_SECONDS)
        .ok_or(Error::Expired)?;
    let prologue = pin.prologue();
    let resolver = EntropyResolver::new(entropy)?;
    let mut noise = snow::Builder::with_resolver(
        SUITE.parse().map_err(|_| Error::InvalidInput)?,
        Box::new(resolver),
    )
    .prologue(&prologue)
    .map_err(|_| Error::InvalidInput)?
    .remote_public_key(pin.public_key())
    .map_err(|_| Error::InvalidInput)?
    .build_initiator()
    .map_err(|_| Error::InvalidInput)?;
    let mut message = [0; CLIENT_BYTES];
    let length = noise
        .write_message(&[], &mut message)
        .map_err(|_| Error::Authentication)?;
    if length != CLIENT_BYTES {
        return Err(Error::InvalidMessage);
    }
    Ok((
        encode_message(CLIENT_PREFIX, &message),
        PendingHandshake {
            noise,
            pin,
            started: now,
        },
    ))
}

impl PendingHandshake {
    pub fn finish(mut self, response: &str, now: u64) -> Result<Channel, Error> {
        if now < self.started || now - self.started >= HANDSHAKE_SECONDS {
            return Err(Error::Expired);
        }
        let message = decode_message(response, SERVER_PREFIX, SERVER_BYTES)?;
        let mut payload = Zeroizing::new([0; 72]);
        let length = self
            .noise
            .read_message(&message, payload.as_mut())
            .map_err(|_| Error::Authentication)?;
        if length != 72 || !self.noise.is_handshake_finished() {
            return Err(Error::InvalidMessage);
        }
        let expires = u64::from_be_bytes(
            payload[64..72]
                .try_into()
                .map_err(|_| Error::InvalidMessage)?,
        );
        if expires <= now
            || expires > self.started + CHANNEL_SECONDS + crate::wire::FUTURE_SKEW_SECONDS
        {
            return Err(Error::Expired);
        }
        let transcript = self
            .noise
            .get_handshake_hash()
            .try_into()
            .map_err(|_| Error::InvalidMessage)?;
        Channel::from_authenticated_master(
            payload[..64]
                .try_into()
                .map_err(|_| Error::InvalidMessage)?,
            transcript,
            &self.pin,
            expires,
        )
    }
}
