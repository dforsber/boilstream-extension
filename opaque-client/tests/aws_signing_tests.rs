//! Tests for AWS SigV4-style canonical request signing
//!
//! These tests verify the three main AWS signing functions:
//! 1. aws_build_canonical_request - builds canonical request with SHA-256 payload hashing
//! 2. aws_derive_signing_key - AWS-style date-scoped key derivation
//! 3. aws_sign_canonical_request - signs with HMAC-SHA256, returns base64

use opaque_client::*;

#[test]
fn test_aws_build_canonical_request_empty_payload() {
    // Test building canonical request with empty payload
    let method = "GET";
    let uri = "/secrets";
    let query = "";
    let headers = "x-boilstream-date:20251009T120000Z\n";
    let signed_headers = "x-boilstream-date";

    let result = aws_build_canonical_request(
        method.as_ptr() as *const i8,
        method.len(),
        uri.as_ptr() as *const i8,
        uri.len(),
        query.as_ptr() as *const i8,
        query.len(),
        headers.as_ptr() as *const i8,
        headers.len(),
        signed_headers.as_ptr() as *const i8,
        signed_headers.len(),
        std::ptr::null(),
        0,
    );

    assert_eq!(result.error as i32, OpaqueError::Success as i32);
    assert!(!result.buffer.data.is_null());

    let canonical_request = unsafe {
        std::str::from_utf8_unchecked(
            std::slice::from_raw_parts(result.buffer.data, result.buffer.len)
        )
    };

    // Should contain empty payload hash (SHA-256 of empty string)
    assert!(canonical_request.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    assert!(canonical_request.starts_with("GET\n"));
    assert!(canonical_request.contains("x-boilstream-date:20251009T120000Z\n"));

    // Cleanup
    opaque_free_buffer(result.buffer);
}

#[test]
fn test_aws_build_canonical_request_with_payload() {
    // Test building canonical request with non-empty payload
    let method = "POST";
    let uri = "/secrets/my-secret";
    let query = "";
    let headers = "x-boilstream-date:20251009T120000Z\nx-boilstream-sequence:42\n";
    let signed_headers = "x-boilstream-date;x-boilstream-sequence";
    let payload = b"{\"test\":\"data\"}";

    let result = aws_build_canonical_request(
        method.as_ptr() as *const i8,
        method.len(),
        uri.as_ptr() as *const i8,
        uri.len(),
        query.as_ptr() as *const i8,
        query.len(),
        headers.as_ptr() as *const i8,
        headers.len(),
        signed_headers.as_ptr() as *const i8,
        signed_headers.len(),
        payload.as_ptr(),
        payload.len(),
    );

    assert_eq!(result.error as i32, OpaqueError::Success as i32);
    assert!(!result.buffer.data.is_null());

    let canonical_request = unsafe {
        std::str::from_utf8_unchecked(
            std::slice::from_raw_parts(result.buffer.data, result.buffer.len)
        )
    };

    // Verify structure
    assert!(canonical_request.starts_with("POST\n"));
    assert!(canonical_request.contains("/secrets/my-secret"));
    assert!(canonical_request.contains("x-boilstream-date:20251009T120000Z\n"));
    assert!(canonical_request.contains("x-boilstream-sequence:42\n"));
    assert!(canonical_request.contains("x-boilstream-date;x-boilstream-sequence"));

    // Verify payload was hashed (SHA-256 of the payload bytes)
    // The actual hash will be computed by the function, so we just verify it's not the empty hash
    assert!(!canonical_request.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    // Cleanup
    opaque_free_buffer(result.buffer);
}

#[test]
fn test_aws_build_canonical_request_with_query_params() {
    // Test canonical request with query parameters
    let method = "GET";
    let uri = "/secrets";
    let query = "filter=active&limit=10";
    let headers = "x-boilstream-date:20251009T120000Z\n";
    let signed_headers = "x-boilstream-date";

    let result = aws_build_canonical_request(
        method.as_ptr() as *const i8,
        method.len(),
        uri.as_ptr() as *const i8,
        uri.len(),
        query.as_ptr() as *const i8,
        query.len(),
        headers.as_ptr() as *const i8,
        headers.len(),
        signed_headers.as_ptr() as *const i8,
        signed_headers.len(),
        std::ptr::null(),
        0,
    );

    assert_eq!(result.error as i32, OpaqueError::Success as i32);

    let canonical_request = unsafe {
        std::str::from_utf8_unchecked(
            std::slice::from_raw_parts(result.buffer.data, result.buffer.len)
        )
    };

    // Should include query string
    assert!(canonical_request.contains("filter=active&limit=10"));

    // Cleanup
    opaque_free_buffer(result.buffer);
}

#[test]
fn test_aws_derive_signing_key() {
    // Test AWS-style key derivation
    let base_key = b"test_base_signing_key_32bytes!!";
    let date = "20251009";
    let region = "us-east-1";
    let service = "secrets";

    let result = aws_derive_signing_key(
        base_key.as_ptr(),
        base_key.len(),
        date.as_ptr() as *const i8,
        date.len(),
        region.as_ptr() as *const i8,
        region.len(),
        service.as_ptr() as *const i8,
        service.len(),
    );

    assert_eq!(result.error as i32, OpaqueError::Success as i32);
    assert!(!result.buffer.data.is_null());
    assert_eq!(result.buffer.len, 32); // HMAC-SHA256 produces 32 bytes

    // Cleanup
    opaque_free_buffer(result.buffer);
}

#[test]
fn test_aws_derive_signing_key_deterministic() {
    // Test that key derivation is deterministic
    let base_key = b"test_base_signing_key_32bytes!!";
    let date = "20251009";
    let region = "us-east-1";
    let service = "secrets";

    let result1 = aws_derive_signing_key(
        base_key.as_ptr(),
        base_key.len(),
        date.as_ptr() as *const i8,
        date.len(),
        region.as_ptr() as *const i8,
        region.len(),
        service.as_ptr() as *const i8,
        service.len(),
    );

    let result2 = aws_derive_signing_key(
        base_key.as_ptr(),
        base_key.len(),
        date.as_ptr() as *const i8,
        date.len(),
        region.as_ptr() as *const i8,
        region.len(),
        service.as_ptr() as *const i8,
        service.len(),
    );

    assert_eq!(result1.error as i32, OpaqueError::Success as i32);
    assert_eq!(result2.error as i32, OpaqueError::Success as i32);

    // Compare the derived keys - they should be identical
    let key1 = unsafe {
        std::slice::from_raw_parts(result1.buffer.data, result1.buffer.len)
    };
    let key2 = unsafe {
        std::slice::from_raw_parts(result2.buffer.data, result2.buffer.len)
    };
    assert_eq!(key1, key2);

    // Cleanup
    opaque_free_buffer(result1.buffer);
    opaque_free_buffer(result2.buffer);
}

#[test]
fn test_aws_derive_signing_key_different_dates() {
    // Test that different dates produce different keys
    let base_key = b"test_base_signing_key_32bytes!!";
    let date1 = "20251009";
    let date2 = "20251010";
    let region = "us-east-1";
    let service = "secrets";

    let result1 = aws_derive_signing_key(
        base_key.as_ptr(),
        base_key.len(),
        date1.as_ptr() as *const i8,
        date1.len(),
        region.as_ptr() as *const i8,
        region.len(),
        service.as_ptr() as *const i8,
        service.len(),
    );

    let result2 = aws_derive_signing_key(
        base_key.as_ptr(),
        base_key.len(),
        date2.as_ptr() as *const i8,
        date2.len(),
        region.as_ptr() as *const i8,
        region.len(),
        service.as_ptr() as *const i8,
        service.len(),
    );

    assert_eq!(result1.error as i32, OpaqueError::Success as i32);
    assert_eq!(result2.error as i32, OpaqueError::Success as i32);

    // Compare the derived keys - they should be DIFFERENT
    let key1 = unsafe {
        std::slice::from_raw_parts(result1.buffer.data, result1.buffer.len)
    };
    let key2 = unsafe {
        std::slice::from_raw_parts(result2.buffer.data, result2.buffer.len)
    };
    assert_ne!(key1, key2);

    // Cleanup
    opaque_free_buffer(result1.buffer);
    opaque_free_buffer(result2.buffer);
}

#[test]
fn test_aws_sign_canonical_request() {
    // Test signing a canonical request
    let signing_key = b"test_signing_key_32_bytes_long!";
    let canonical_request = "POST\n/secrets\n\nx-boilstream-date:20251009T120000Z\n\nx-boilstream-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let result = aws_sign_canonical_request(
        signing_key.as_ptr(),
        signing_key.len(),
        canonical_request.as_ptr() as *const i8,
        canonical_request.len(),
    );

    assert_eq!(result.error as i32, OpaqueError::Success as i32);
    assert!(!result.buffer.data.is_null());

    let signature = unsafe {
        std::str::from_utf8_unchecked(
            std::slice::from_raw_parts(result.buffer.data, result.buffer.len)
        )
    };

    // Signature should be base64-encoded (44 chars for 32-byte HMAC-SHA256)
    assert_eq!(signature.len(), 44);
    assert!(signature.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='));

    // Cleanup
    opaque_free_buffer(result.buffer);
}

#[test]
fn test_aws_sign_canonical_request_deterministic() {
    // Test that signing is deterministic
    let signing_key = b"test_signing_key_32_bytes_long!";
    let canonical_request = "GET\n/secrets\n\nx-boilstream-date:20251009T120000Z\n\nx-boilstream-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let result1 = aws_sign_canonical_request(
        signing_key.as_ptr(),
        signing_key.len(),
        canonical_request.as_ptr() as *const i8,
        canonical_request.len(),
    );

    let result2 = aws_sign_canonical_request(
        signing_key.as_ptr(),
        signing_key.len(),
        canonical_request.as_ptr() as *const i8,
        canonical_request.len(),
    );

    assert_eq!(result1.error as i32, OpaqueError::Success as i32);
    assert_eq!(result2.error as i32, OpaqueError::Success as i32);

    // Compare signatures - they should be identical
    let sig1 = unsafe {
        std::slice::from_raw_parts(result1.buffer.data, result1.buffer.len)
    };
    let sig2 = unsafe {
        std::slice::from_raw_parts(result2.buffer.data, result2.buffer.len)
    };
    assert_eq!(sig1, sig2);

    // Cleanup
    opaque_free_buffer(result1.buffer);
    opaque_free_buffer(result2.buffer);
}

#[test]
fn test_aws_full_signing_flow() {
    // Test the complete signing flow from start to finish
    let base_key = b"test_base_signing_key_32bytes!!";
    let date = "20251009";
    let region = "us-east-1";
    let service = "secrets";

    // Step 1: Derive signing key
    let key_result = aws_derive_signing_key(
        base_key.as_ptr(),
        base_key.len(),
        date.as_ptr() as *const i8,
        date.len(),
        region.as_ptr() as *const i8,
        region.len(),
        service.as_ptr() as *const i8,
        service.len(),
    );
    assert_eq!(key_result.error as i32, OpaqueError::Success as i32);

    // Step 2: Build canonical request
    let method = "POST";
    let uri = "/secrets/my-secret";
    let query = "";
    let headers = "x-boilstream-date:20251009T120000Z\n";
    let signed_headers = "x-boilstream-date";
    let payload = b"{\"name\":\"test\"}";

    let canonical_result = aws_build_canonical_request(
        method.as_ptr() as *const i8,
        method.len(),
        uri.as_ptr() as *const i8,
        uri.len(),
        query.as_ptr() as *const i8,
        query.len(),
        headers.as_ptr() as *const i8,
        headers.len(),
        signed_headers.as_ptr() as *const i8,
        signed_headers.len(),
        payload.as_ptr(),
        payload.len(),
    );
    assert_eq!(canonical_result.error as i32, OpaqueError::Success as i32);

    // Step 3: Sign the canonical request
    let sig_result = aws_sign_canonical_request(
        key_result.buffer.data,
        key_result.buffer.len,
        canonical_result.buffer.data as *const i8,
        canonical_result.buffer.len,
    );
    assert_eq!(sig_result.error as i32, OpaqueError::Success as i32);

    let signature = unsafe {
        std::str::from_utf8_unchecked(
            std::slice::from_raw_parts(sig_result.buffer.data, sig_result.buffer.len)
        )
    };

    // Verify signature format
    assert_eq!(signature.len(), 44); // base64 of 32 bytes
    assert!(signature.ends_with('=')); // base64 padding

    // Cleanup
    opaque_free_buffer(key_result.buffer);
    opaque_free_buffer(canonical_result.buffer);
    opaque_free_buffer(sig_result.buffer);
}

#[test]
fn test_null_pointer_handling() {
    // Test that null pointers are handled gracefully
    let result = aws_build_canonical_request(
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
        std::ptr::null(),
        0,
    );

    assert_eq!(result.error as i32, OpaqueError::InvalidInput as i32);
    assert!(result.buffer.data.is_null());
}
