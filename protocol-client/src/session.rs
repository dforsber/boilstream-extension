//! Single-flight client channel lifecycle. No I/O, clock, RNG or retry policy.
//! A failed/abandoned exchange destroys keys; only a new pinned handshake recovers.
use crate::{
    handshake::{self, PendingHandshake},
    handshake_wire::{Channel, Pin},
    open_response, seal_request, Error, Nonce, PendingResponse, Request, RequestId, Response,
};
use zeroize::Zeroizing;

enum State {
    Handshake(Box<PendingHandshake>),
    Ready(Channel, u64),
    Waiting(Channel, u64, PendingResponse),
    Closed,
}
/// Own one channel per logical connection. The caller must serialize access across
/// seal, transport and open; overlapping calls close the channel rather than retry.
pub struct ClientSession {
    state: State,
}
impl ClientSession {
    pub fn start(
        pin: Pin,
        entropy: Zeroizing<[u8; 32]>,
        now: u64,
    ) -> Result<(String, Self), Error> {
        let (hello, pending) = handshake::start(pin, entropy, now)?;
        Ok((
            hello,
            Self {
                state: State::Handshake(Box::new(pending)),
            },
        ))
    }
    pub fn accept(&mut self, body: &str, now: u64) -> Result<(), Error> {
        let State::Handshake(pending) = std::mem::replace(&mut self.state, State::Closed) else {
            return Err(Error::Sequence);
        };
        let channel = pending.finish(body, now)?;
        self.state = State::Ready(channel, 1);
        Ok(())
    }
    pub fn seal(
        &mut self,
        request: &Request,
        request_id: RequestId,
        nonce: Nonce,
        now: u64,
    ) -> Result<String, Error> {
        let State::Ready(channel, sequence) = std::mem::replace(&mut self.state, State::Closed)
        else {
            return Err(Error::Sequence);
        };
        let (body, pending) = seal_request(
            channel.keys(now)?,
            request,
            sequence,
            request_id,
            nonce,
            now,
        )?;
        self.state = State::Waiting(channel, sequence, pending);
        Ok(body)
    }
    pub fn open(&mut self, body: &str, now: u64) -> Result<Response, Error> {
        let State::Waiting(channel, sequence, pending) =
            std::mem::replace(&mut self.state, State::Closed)
        else {
            return Err(Error::Sequence);
        };
        let response = open_response(channel.keys(now)?, pending, body, now)?;
        let next = sequence.checked_add(1).ok_or(Error::Sequence)?;
        self.state = State::Ready(channel, next);
        Ok(response)
    }
    /// Use on HTTP/clock/entropy/serialization failures too. Nothing may reset the
    /// sequence while keeping keys, or retry after an unknown mutation outcome.
    pub fn close(&mut self) {
        self.state = State::Closed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/handshake-vector.json")).unwrap()
    }
    fn bytes<const N: usize>(text: &str) -> [u8; N] {
        std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }
    fn start() -> (ClientSession, Value, u64) {
        let v = fixture();
        let now = v["now"].as_u64().unwrap();
        let pin = Pin::new(
            v["authority"].as_str().unwrap(),
            bytes(v["server_public"].as_str().unwrap()),
        )
        .unwrap();
        let (hello, state) = ClientSession::start(
            pin,
            Zeroizing::new(bytes(v["client_entropy"].as_str().unwrap())),
            now,
        )
        .unwrap();
        assert_eq!(hello, v["client_wire"]);
        (state, v, now)
    }
    fn ready() -> (ClientSession, u64) {
        let (mut state, v, now) = start();
        state
            .accept(v["server_wire"].as_str().unwrap(), now)
            .unwrap();
        (state, now)
    }
    fn request() -> Request {
        Request {
            method: crate::Method::Get,
            target: "/secrets".into(),
            body: String::new(),
            cookie: None,
            idempotency_key: None,
        }
    }
    fn seal(state: &mut ClientSession, now: u64) -> Result<String, Error> {
        state.seal(
            &request(),
            RequestId::from_csprng([3; 16]),
            Nonce::from_csprng([4; 12]),
            now,
        )
    }
    #[test]
    fn credentials_cannot_be_sealed_before_pin_verification() {
        let (mut state, v, now) = start();
        assert!(seal(&mut state, now).is_err());
        assert!(state
            .accept(v["server_wire"].as_str().unwrap(), now)
            .is_err());
    }
    #[test]
    fn failed_handshake_cannot_be_retried() {
        let (mut state, v, now) = start();
        assert!(state.accept("untrusted", now).is_err());
        assert!(state
            .accept(v["server_wire"].as_str().unwrap(), now)
            .is_err());
    }
    #[test]
    fn overlapping_requests_destroy_the_channel() {
        let (mut state, now) = ready();
        assert!(seal(&mut state, now).is_ok());
        assert!(seal(&mut state, now).is_err());
        assert!(state.open("anything", now).is_err());
    }
    #[test]
    fn unverified_reply_destroys_keys_and_pending_request() {
        let (mut state, now) = ready();
        seal(&mut state, now).unwrap();
        assert!(state.open("plaintext login success", now).is_err());
        assert!(seal(&mut state, now).is_err());
    }
    #[test]
    fn expired_or_abandoned_channel_cannot_resume() {
        let (mut state, now) = ready();
        assert!(seal(&mut state, now + 3601).is_err());
        assert!(seal(&mut state, now).is_err());
        let (mut state, now) = ready();
        state.close();
        assert!(seal(&mut state, now).is_err());
    }
    #[test]
    fn verified_policy_error_advances_sequence_and_returns_only_inner_metadata() {
        // Independent published client vector: no server implementation/private key.
        let v: Value = serde_json::from_str(include_str!("../tests/vector.json")).unwrap();
        let pin = Pin::new(
            "https://api.example.test",
            bytes(fixture()["server_public"].as_str().unwrap()),
        )
        .unwrap();
        let now = 1_700_000_000;
        let channel = Channel::from_authenticated_master(
            &std::array::from_fn(|i| i as u8),
            std::array::from_fn(|i| i as u8),
            &pin,
            now + 3600,
        )
        .unwrap();
        let mut state = ClientSession {
            state: State::Ready(channel, 7),
        };
        let req: Request = serde_json::from_value(v["request"].clone()).unwrap();
        let wire = state
            .seal(
                &req,
                RequestId::from_csprng(std::array::from_fn(|i| i as u8)),
                Nonce::from_csprng(std::array::from_fn(|i| i as u8)),
                now,
            )
            .unwrap();
        assert_eq!(wire, v["request_wire"]);
        let response = state
            .open(v["response_wire"].as_str().unwrap(), now)
            .unwrap();
        assert_eq!(serde_json::to_value(response).unwrap(), v["response"]);
        assert!(matches!(state.state, State::Ready(_, 8)));
        assert!(state
            .open(v["response_wire"].as_str().unwrap(), now)
            .is_err());
        assert!(seal(&mut state, now).is_err());
    }
}
