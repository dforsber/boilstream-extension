// Email/Password Registration with MFA Enrollment
// Provides data structures and utilities for user registration flow

use serde::{Deserialize, Serialize};
use std::fmt;

/// Registration request for email/password signup
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    pub csrf_token: String,
    pub turnstile_token: Option<String>,
}

/// Registration response from server
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct SignupResponse {
    pub success: bool,
    pub message: Option<String>,
    pub error: Option<String>,
    pub code: Option<String>,
}

/// Login request for email/password authentication
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub csrf_token: String,
    pub turnstile_token: Option<String>,
}

/// Session credentials from login
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct SessionCredentials {
    pub session_id: String,
    pub expires_at: u64,
}

/// Login response from server
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub credentials: Option<SessionCredentials>,
    pub mfa_required: Option<bool>,
    pub error: Option<String>,
}

/// TOTP enrollment response
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct TotpEnrollmentResponse {
    pub secret: String,
    pub qr_code_url: Option<String>,
    pub issuer: Option<String>,
}

/// MFA verification request
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct MfaVerificationRequest {
    pub method_type: String,
    pub code: String,
    pub secret: String,
}

/// MFA verification response with backup codes
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct MfaVerificationResponse {
    pub success: bool,
    pub backup_codes: Option<Vec<String>>,
    pub error: Option<String>,
}

/// Registration state for multi-step flow
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RegistrationState {
    pub email: String,
    pub session_id: String,
    pub totp_secret: String,
    pub totp_uri: String,
    pub expires_at: u64,
}

/// Error types for registration flow
#[allow(dead_code)]
#[derive(Debug)]
pub enum RegistrationError {
    EmailAlreadyExists,
    WeakPassword,
    InvalidEmail,
    SsoRequired,
    RateLimited,
    InvalidTotpCode,
    NetworkError(String),
    ParseError(String),
    UnknownError(String),
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::EmailAlreadyExists => write!(f, "Email already registered"),
            Self::WeakPassword => write!(f, "Password must be at least 12 characters"),
            Self::InvalidEmail => write!(f, "Invalid email address"),
            Self::SsoRequired => write!(f, "Local signup disabled - SSO required"),
            Self::RateLimited => write!(f, "Rate limit exceeded"),
            Self::InvalidTotpCode => write!(f, "Invalid TOTP code"),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::ParseError(msg) => write!(f, "Parse error: {}", msg),
            Self::UnknownError(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for RegistrationError {}

/// Validate email format (basic check)
pub fn validate_email(email: &str) -> Result<(), RegistrationError> {
    // Basic validation: must have @ and ., minimum 3 chars, @ not at start/end
    if email.len() < 3 {
        return Err(RegistrationError::InvalidEmail);
    }

    // Must contain @ but not at start or end
    if !email.contains('@') {
        return Err(RegistrationError::InvalidEmail);
    }

    let at_pos = email.find('@').unwrap();
    if at_pos == 0 || at_pos == email.len() - 1 {
        return Err(RegistrationError::InvalidEmail);
    }

    // Must have . after @ (domain must have a dot)
    let after_at = &email[at_pos + 1..];
    if !after_at.contains('.') {
        return Err(RegistrationError::InvalidEmail);
    }

    Ok(())
}

/// Validate password strength (minimum 12 characters)
pub fn validate_password(password: &str) -> Result<(), RegistrationError> {
    if password.len() < 12 {
        return Err(RegistrationError::WeakPassword);
    }
    Ok(())
}

/// Build TOTP URI for QR code generation
/// Format: otpauth://totp/BoilStream:email?secret=SECRET&issuer=BoilStream&algorithm=SHA512&digits=6&period=30
pub fn build_totp_uri(email: &str, secret: &str, issuer: Option<&str>) -> String {
    let issuer = issuer.unwrap_or("BoilStream");
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA512&digits=6&period=30",
        issuer, email, secret, issuer
    )
}

/// Parse error code from signup response
#[allow(dead_code)]
pub fn parse_signup_error(response: &SignupResponse) -> RegistrationError {
    match response.code.as_deref() {
        Some("EMAIL_EXISTS") => RegistrationError::EmailAlreadyExists,
        Some("WEAK_PASSWORD") => RegistrationError::WeakPassword,
        Some("INVALID_EMAIL") => RegistrationError::InvalidEmail,
        Some("SSO_REQUIRED") => RegistrationError::SsoRequired,
        Some("RATE_LIMITED") => RegistrationError::RateLimited,
        _ => RegistrationError::UnknownError(
            response.error.clone().unwrap_or_else(|| "Unknown error".to_string())
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("alice@company.org").is_ok());
        assert!(validate_email("test.user@sub.domain.com").is_ok());
    }

    #[test]
    fn test_validate_email_invalid() {
        assert!(validate_email("").is_err());
        assert!(validate_email("notanemail").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user").is_err());
    }

    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("SecurePass123!").is_ok());
        assert!(validate_password("ThisIsA12CharPass").is_ok());
        assert!(validate_password("VeryLongPasswordThatIsDefinitelySecure").is_ok());
    }

    #[test]
    fn test_validate_password_weak() {
        assert!(validate_password("").is_err());
        assert!(validate_password("short").is_err());
        assert!(validate_password("11chars____").is_err());
        assert!(validate_password("12chars_ok!!").is_ok());
    }

    #[test]
    fn test_build_totp_uri_default_issuer() {
        let uri = build_totp_uri("alice@example.com", "JBSWY3DPEHPK3PXP", None);

        assert!(uri.starts_with("otpauth://totp/BoilStream:alice@example.com"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=BoilStream"));
        assert!(uri.contains("algorithm=SHA512"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn test_build_totp_uri_custom_issuer() {
        let uri = build_totp_uri("bob@company.com", "SECRET123", Some("MyCompany"));

        assert!(uri.starts_with("otpauth://totp/MyCompany:bob@company.com"));
        assert!(uri.contains("secret=SECRET123"));
        assert!(uri.contains("issuer=MyCompany"));
    }

    #[test]
    fn test_parse_signup_error_email_exists() {
        let response = SignupResponse {
            success: false,
            message: None,
            error: Some("Email already registered".to_string()),
            code: Some("EMAIL_EXISTS".to_string()),
        };

        let err = parse_signup_error(&response);
        assert!(matches!(err, RegistrationError::EmailAlreadyExists));
    }

    #[test]
    fn test_parse_signup_error_weak_password() {
        let response = SignupResponse {
            success: false,
            message: None,
            error: Some("Password too weak".to_string()),
            code: Some("WEAK_PASSWORD".to_string()),
        };

        let err = parse_signup_error(&response);
        assert!(matches!(err, RegistrationError::WeakPassword));
    }

    #[test]
    fn test_parse_signup_error_sso_required() {
        let response = SignupResponse {
            success: false,
            message: None,
            error: Some("SSO enabled".to_string()),
            code: Some("SSO_REQUIRED".to_string()),
        };

        let err = parse_signup_error(&response);
        assert!(matches!(err, RegistrationError::SsoRequired));
    }

    #[test]
    fn test_signup_request_serialization() {
        let request = SignupRequest {
            email: "test@example.com".to_string(),
            password: "SecurePassword123!".to_string(),
            csrf_token: "csrf_abc123".to_string(),
            turnstile_token: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test@example.com"));
        assert!(json.contains("SecurePassword123!"));
        assert!(json.contains("csrf_abc123"));
    }

    #[test]
    fn test_login_response_deserialization() {
        let json = r#"{
            "success": true,
            "credentials": {
                "session_id": "uuid-session-123",
                "expires_at": 1700000000
            },
            "mfa_required": false
        }"#;

        let response: LoginResponse = serde_json::from_str(json).unwrap();
        assert!(response.success);
        assert!(response.credentials.is_some());

        let creds = response.credentials.unwrap();
        assert_eq!(creds.session_id, "uuid-session-123");
        assert_eq!(creds.expires_at, 1700000000);
    }

    #[test]
    fn test_totp_enrollment_response_deserialization() {
        let json = r#"{
            "secret": "JBSWY3DPEHPK3PXP",
            "qr_code_url": "data:image/png;base64,iVBOR...",
            "issuer": "BoilStream"
        }"#;

        let response: TotpEnrollmentResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.secret, "JBSWY3DPEHPK3PXP");
        assert!(response.qr_code_url.is_some());
        assert_eq!(response.issuer.unwrap(), "BoilStream");
    }

    #[test]
    fn test_mfa_verification_response_with_backup_codes() {
        let json = r#"{
            "success": true,
            "backup_codes": [
                "ABCD-1234-EFGH",
                "IJKL-5678-MNOP",
                "QRST-9012-UVWX"
            ]
        }"#;

        let response: MfaVerificationResponse = serde_json::from_str(json).unwrap();
        assert!(response.success);
        assert!(response.backup_codes.is_some());

        let codes = response.backup_codes.unwrap();
        assert_eq!(codes.len(), 3);
        assert_eq!(codes[0], "ABCD-1234-EFGH");
    }

    #[test]
    fn test_registration_state() {
        let state = RegistrationState {
            email: "alice@example.com".to_string(),
            session_id: "session-123".to_string(),
            totp_secret: "SECRET".to_string(),
            totp_uri: "otpauth://...".to_string(),
            expires_at: 1700000000,
        };

        // Test clone
        let cloned = state.clone();
        assert_eq!(cloned.email, "alice@example.com");
        assert_eq!(cloned.session_id, "session-123");
    }
}
