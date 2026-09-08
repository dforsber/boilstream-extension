use opaque_client::{registration_build_totp_uri, registration_validate_password};
use std::ffi::CString;

#[test]
fn password_minimum_counts_unicode_characters() {
    for password in ["é".repeat(6), "🔐".repeat(3), "é".repeat(11)] {
        assert_eq!(
            unsafe { registration_validate_password(password.as_ptr(), password.len()) },
            -1
        );
    }
    for password in ["é".repeat(12), "🔐".repeat(12), "abcdefghijkl".to_owned()] {
        assert_eq!(
            unsafe { registration_validate_password(password.as_ptr(), password.len()) },
            0
        );
    }
}

#[test]
fn totp_uri_encodes_labels_and_query_values() {
    let email = CString::new("a+b#c@example.com").unwrap();
    let secret = CString::new("ABC=").unwrap();
    let issuer = CString::new("München & Co/?").unwrap();
    let expected = "otpauth://totp/M%C3%BCnchen%20%26%20Co%2F%3F:a%2Bb%23c%40example.com?secret=ABC%3D&issuer=M%C3%BCnchen%20%26%20Co%2F%3F&algorithm=SHA512&digits=6&period=30";
    let mut buffer = vec![0x7fu8; expected.len() + 2];
    let len = unsafe {
        registration_build_totp_uri(
            email.as_ptr(),
            secret.as_ptr(),
            issuer.as_ptr(),
            buffer.as_mut_ptr().cast(),
            expected.len() + 1,
        )
    };
    assert_eq!(len, expected.len() as isize);
    assert_eq!(&buffer[..expected.len()], expected.as_bytes());
    assert_eq!(buffer[expected.len()], 0);
    assert_eq!(buffer[expected.len() + 1], 0x7f);

    // Encoding expands the required size. A buffer without room for the NUL must fail.
    buffer.fill(0x7f);
    assert_eq!(
        unsafe {
            registration_build_totp_uri(
                email.as_ptr(),
                secret.as_ptr(),
                issuer.as_ptr(),
                buffer.as_mut_ptr().cast(),
                expected.len(),
            )
        },
        -1
    );
    assert!(buffer.iter().all(|&byte| byte == 0x7f));
}
