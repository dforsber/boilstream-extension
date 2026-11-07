use super::*;
use hkdf::Hkdf;
const NOW: u64 = 1_700_000_000;
fn keys() -> SessionKeys {
    SessionKeys::derive(
        &std::array::from_fn(|i| i as u8),
        std::array::from_fn(|i| i as u8),
        "https://api.example.test",
    )
    .unwrap()
}

fn request() -> Request {
    Request {
        method: Method::Post,
        target: "/secrets/match".into(),
        body: "{\"name\":\"test\"}".into(),
        cookie: None,
        idempotency_key: Some("fixture-1".into()),
    }
}

fn response() -> Response {
    Response {
        status: 403,
        body: "{\"error\":\"forbidden\"}".into(),
        cookies: vec!["session=synthetic; HttpOnly".into()],
        session_resumption: true,
    }
}

fn start(keys: &SessionKeys) -> (String, PendingResponse) {
    seal_request(
        keys,
        &request(),
        7,
        RequestId::from_csprng(std::array::from_fn(|i| i as u8)),
        Nonce::from_csprng(std::array::from_fn(|i| i as u8)),
        NOW,
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../tests/vector.json")).unwrap()
}
fn reply_wire() -> String {
    fixture()["response_wire"].as_str().unwrap().to_owned()
}
#[test]
fn independent_client_vectors() {
    let keys = keys();
    let vector = fixture();
    let (request, pending) = start(&keys);
    assert_eq!(hex(keys.request_key()), vector["request_key"]);
    assert_eq!(hex(keys.response_key()), vector["response_key"]);
    assert_eq!(request, vector["request_wire"]);
    let response = open_response(&keys, pending, &reply_wire(), NOW).unwrap();
    assert_eq!(serde_json::to_value(response).unwrap(), vector["response"]);
}
#[test]
fn published_hkdf_sha256_vector() {
    // RFC 5869 Appendix A.1: https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1
    let salt: Vec<u8> = (0..13).collect();
    let info: Vec<u8> = (0xf0..=0xf9).collect();
    let kdf = Hkdf::<Sha256>::new(Some(&salt), &[0x0b; 22]);
    let mut okm = [0; 42];
    kdf.expand(&info, &mut okm).unwrap();
    assert_eq!(
        hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

#[test]
fn published_aes256_gcm_vector() {
    // NIST GCM proposal, also in Google's BoringSSL crypto/cipher test vectors:
    // https://android.googlesource.com/platform/external/boringssl/+/1220bf946d0e44d24cef3f4a6c9f29c69ed6b463/src/crypto/cipher/test/cipher_test.txt
    let cipher = Aes256Gcm::new((&[0; 32]).into());
    let encrypted = cipher
        .encrypt((&[0; 12]).into(), [0; 16].as_slice())
        .unwrap();
    assert_eq!(
        hex(&encrypted),
        "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
    );
    assert_eq!(
        cipher
            .decrypt((&[0; 12]).into(), encrypted.as_slice())
            .unwrap(),
        [0; 16]
    );
}

#[test]
fn json_expansion_and_cookie_arrays_are_bounded() {
    let data = "\0".repeat(128);
    assert!(matches!(encode(&data, 128), Err(Error::TooLarge)));
    assert_eq!(&*encode(&"x", 3).unwrap(), b"\"x\"");
    assert!(matches!(encode(&"x", 2), Err(Error::TooLarge)));
    let mut value = serde_json::to_value(response()).unwrap();
    for cookies in [vec![""; 17], vec!["a"; 10000]] {
        value["cookies"] = serde_json::to_value(cookies).unwrap();
        assert!(serde_json::from_value::<Response>(value.clone()).is_err());
    }
}

#[test]
fn route_cookie_status_and_idempotency_validation() {
    for target in [
        "",
        "//evil.test",
        "http://evil.test/",
        "/x#fragment",
        "/x\r\nHost:evil",
        "/x\\y",
    ] {
        let mut request = request();
        request.target = target.into();
        assert!(request.validate().is_err());
    }
    for cookie in ["x\ny", "x\ry", "x\0y", "x\ty"] {
        let mut request = request();
        request.cookie = Some(cookie.into());
        assert!(request.validate().is_err());
    }
    let mut request = request();
    request.cookie = Some("a".repeat(MAX_METADATA_BYTES));
    assert!(request.validate().is_ok());
    request.cookie.as_mut().unwrap().push('a');
    assert_eq!(request.validate(), Err(Error::TooLarge));
    for id in ["", "x y", "x\ny"] {
        let mut request = super::tests::request();
        request.idempotency_key = Some(id.into());
        assert!(request.validate().is_err());
    }
    for status in [0, 101, 199, 300, 301, 399, 600, u16::MAX] {
        let mut response = response();
        response.status = status;
        assert!(response.validate().is_err());
    }
    for status in [200, 204, 299, 400, 401, 403, 429, 500, 599] {
        let mut response = response();
        response.status = status;
        assert!(response.validate().is_ok());
    }
    let mut response = response();
    response.cookies = vec!["x".repeat(MAX_METADATA_BYTES), "y".into()];
    assert_eq!(response.validate(), Err(Error::TooLarge));
}

#[test]
fn every_response_byte_is_authenticated() {
    let keys = keys();
    let wire = reply_wire();
    let original = decode(&wire, MAX_RESPONSE_BYTES).unwrap();
    for index in 0..original.len() {
        let mut modified = original.clone();
        modified[index] ^= 1;
        let modified = format!("BS2.{}", URL_SAFE_NO_PAD.encode(modified));
        let (_, pending) = start(&keys);
        assert!(
            open_response(&keys, pending, &modified, NOW).is_err(),
            "accepted byte {index}"
        );
    }
}

#[test]
fn response_context_fields_must_match_original_request() {
    let keys = keys();
    let reply_wire = reply_wire();
    for field in 0..5 {
        let (_, mut pending) = start(&keys);
        match field {
            0 => pending.context.request_id[0] ^= 1,
            1 => pending.context.sequence += 1,
            2 => pending.context.issued += 1,
            3 => pending.context.expires += 1,
            _ => pending.binding[0] ^= 1,
        }
        assert!(matches!(
            open_response(&keys, pending, &reply_wire, NOW),
            Err(Error::Authentication)
        ));
    }
}

#[test]
fn wrong_authority_session_or_secret_rejects_reply() {
    let valid = keys();
    let secret = std::array::from_fn(|i| i as u8);
    let wrong = [
        SessionKeys::derive(&secret, valid.session_id(), "https://other.example.test").unwrap(),
        SessionKeys::derive(&secret, [77; 32], "https://api.example.test").unwrap(),
        SessionKeys::derive(&[99; 64], valid.session_id(), "https://api.example.test").unwrap(),
    ];
    for key in wrong {
        let (_, pending) = start(&valid);
        assert!(matches!(
            open_response(&key, pending, &reply_wire(), NOW),
            Err(Error::Authentication)
        ));
    }
}
#[test]
fn expiry_and_sequence_limits() {
    let keys = keys();
    for now in [NOW - 31, NOW + 120, u64::MAX] {
        let (_, pending) = start(&keys);
        assert!(matches!(
            open_response(&keys, pending, &reply_wire(), now),
            Err(Error::Expired)
        ));
    }
    for sequence in [0, MAX_MESSAGES + 1, u64::MAX] {
        assert!(matches!(
            seal_request(
                &keys,
                &request(),
                sequence,
                RequestId::from_csprng([1; 16]),
                Nonce::from_csprng([2; 12]),
                NOW
            ),
            Err(Error::Sequence)
        ));
    }
    assert!(matches!(
        seal_request(
            &keys,
            &request(),
            1,
            RequestId::from_csprng([1; 16]),
            Nonce::from_csprng([2; 12]),
            u64::MAX
        ),
        Err(Error::Expired)
    ));
}
#[test]
fn truncated_noncanonical_and_plaintext_responses_are_rejected() {
    let keys = keys();
    let wire = reply_wire();
    for end in 0..wire.len() {
        let (_, pending) = start(&keys);
        assert!(open_response(&keys, pending, &wire[..end], NOW).is_err());
    }
    for suffix in ["=", "\n", " ", "A", "AAAA", "\0"] {
        let (_, pending) = start(&keys);
        assert!(open_response(&keys, pending, &format!("{wire}{suffix}"), NOW).is_err());
    }
    for text in [
        "",
        "{\"error\":\"expired\"}",
        "BS1.AA",
        "BS2.++//",
        "BS2.AB",
    ] {
        let (_, pending) = start(&keys);
        assert!(open_response(&keys, pending, text, NOW).is_err());
    }
}
#[test]
fn request_and_response_limits() {
    let keys = keys();
    let mut request = request();
    request.body = "a".repeat(MAX_REQUEST_BYTES);
    assert!(matches!(
        seal_request(
            &keys,
            &request,
            1,
            RequestId::from_csprng([1; 16]),
            Nonce::from_csprng([2; 12]),
            NOW
        ),
        Err(Error::TooLarge)
    ));
    let (_, pending) = start(&keys);
    let oversized = "a".repeat(max_wire_bytes(MAX_RESPONSE_BYTES) + 1);
    assert!(matches!(
        open_response(&keys, pending, &oversized, NOW),
        Err(Error::TooLarge)
    ));
}
#[test]
fn bounded_arbitrary_response_frames_do_not_panic() {
    let keys = keys();
    let mut seed = 1u64;
    for size in 0..1024 {
        let frame: Vec<_> = (0..size)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 32) as u8
            })
            .collect();
        let wire = format!("BS2.{}", URL_SAFE_NO_PAD.encode(frame));
        let (_, pending) = start(&keys);
        assert!(open_response(&keys, pending, &wire, NOW).is_err());
    }
}
#[test]
fn unauthenticated_header_parser_rejects_short_or_unknown_frames() {
    for size in 0..HEADER_LEN + TAG_LEN {
        assert!(parse_header(&vec![0; size], RESPONSE, &[0; 32]).is_err());
    }
    assert!(header(
        3,
        &Context {
            session: [1; 32],
            request_id: [2; 16],
            sequence: 1,
            issued: NOW,
            expires: NOW + 120
        },
        &[0; 32],
        Nonce::from_csprng([3; 12])
    )
    .is_err());
}
