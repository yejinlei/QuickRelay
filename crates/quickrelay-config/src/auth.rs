//! REST authentication: Bearer token and HMAC request signature.
//!
//! Two independent schemes, each with its own switch, both may be enabled at
//! once (architecture §9.5).
//!
//! * **Bearer token** — `Authorization: Bearer <token>`, token from
//!   `--api-token`. Enabled by default.
//! * **HMAC request signature** — `X-QuickRelay-Date` (RFC 3339 or Unix
//!   seconds) plus `X-QuickRelay-Signature`
//!   (`HMAC-SHA256(secret, METHOD\nPATH\nDATE\nBODY-SHA256)` hex), secret from
//!   `--rest-secret`. Disabled by default. Carries a timestamp window so a
//!   captured request cannot be replayed after the window expires.
//!
//! Header names and the canonical string are an **independent implementation**;
//! they only *compare* against coturn's REST API convention and share no code
//! with it (repository licensing rule: coturn is GPL-2.0).
//!
//! Decision order when both are enabled (architecture §9.5):
//!
//! 1. `Authorization` header **present** -> Bearer only. A failed Bearer check
//!    is rejected outright; the request is **not** retried through the signature
//!    path. Failing closed here keeps the replay surface of the two schemes from
//!    blending into one.
//! 2. `Authorization` header **absent** -> HMAC, if HMAC is enabled. The date
//!    window is checked before the signature, so a stale request is answered
//!    without a MAC comparison.
//! 3. Nothing usable -> `401`; anything structurally wrong -> `403`.

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const AUTHORIZATION: &str = "authorization";
pub const QUICKRELAY_DATE: &str = "x-quickrelay-date";
pub const QUICKRELAY_SIGNATURE: &str = "x-quickrelay-signature";

/// Default clock-skew tolerance for signed requests.
pub const DEFAULT_HMAC_TOLERANCE: Duration = Duration::from_secs(300);

/// How a request was authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    Bearer,
    Hmac,
    /// Test-only escape hatch: neither scheme enabled. Never reached in
    /// production, where one scheme is always on.
    None,
}

impl AuthMethod {
    /// The `actor` field of the `config_changed` event. Never contains the
    /// credential itself.
    pub fn as_actor(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::Hmac => "hmac",
            Self::None => "anonymous",
        }
    }
}

/// Authentication failures and their HTTP mapping (architecture §9.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No usable credential at all: 401.
    Missing,
    /// Credentials present but wrong, stale or malformed: 403.
    Invalid,
}

impl AuthError {
    pub fn status(self) -> u16 {
        match self {
            Self::Missing => 401,
            Self::Invalid => 403,
        }
    }

    /// Human-readable reason, safe to send to the caller (no secret material).
    pub fn reason(self) -> &'static str {
        match self {
            Self::Missing => "missing credentials",
            Self::Invalid => "invalid credentials",
        }
    }
}

/// Evaluation result.
pub type AuthResult = Result<AuthMethod, AuthError>;

/// Authenticated form of one request, produced by the HTTP layer.
#[derive(Debug)]
pub struct AuthRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    /// `Authorization` header value, if any.
    pub authorization: Option<&'a str>,
    /// `X-QuickRelay-Date` header value, if any.
    pub date: Option<&'a str>,
    /// `X-QuickRelay-Signature` header value, if any.
    pub signature: Option<&'a str>,
    /// The raw request body, hashed into the signature.
    pub body: &'a [u8],
}

impl<'a> AuthRequest<'a> {
    pub fn new(method: &'a str, path: &'a str, body: &'a [u8]) -> Self {
        Self { method: method.as_bytes(), path: path.as_bytes(), authorization: None, date: None, signature: None, body }
    }

    pub fn with_authorization(mut self, v: &'a str) -> Self {
        self.authorization = Some(v);
        self
    }

    pub fn with_date(mut self, v: &'a str) -> Self {
        self.date = Some(v);
        self
    }

    pub fn with_signature(mut self, v: &'a str) -> Self {
        self.signature = Some(v);
        self
    }
}

/// The two schemes and their parameters.
#[derive(Clone, Debug)]
pub struct AuthPolicy {
    pub bearer_enabled: bool,
    pub bearer_token: Option<String>,
    pub hmac_enabled: bool,
    pub hmac_secret: Option<Vec<u8>>,
    /// Clock-skew tolerance, symmetric: requests up to this far in the past or
    /// the future are accepted.
    pub hmac_tolerance: Duration,
}

impl AuthPolicy {
    /// `--api-token` set means Bearer on; HMAC stays off until enabled.
    pub fn bearer_only(token: impl Into<String>) -> Self {
        let token = token.into();
        Self {
            bearer_enabled: true,
            bearer_token: Some(token),
            hmac_enabled: false,
            hmac_secret: None,
            hmac_tolerance: DEFAULT_HMAC_TOLERANCE,
        }
    }

    /// Both schemes on: the documented priority applies.
    pub fn both(token: impl Into<String>, secret: impl Into<Vec<u8>>, tolerance: Duration) -> Self {
        Self {
            bearer_enabled: true,
            bearer_token: Some(token.into()),
            hmac_enabled: true,
            hmac_secret: Some(secret.into()),
            hmac_tolerance: tolerance,
        }
    }

    /// Neither scheme on. The HTTP layer refuses to start with this policy in
    /// release builds; tests use it to prove the 401 path.
    pub fn none() -> Self {
        Self {
            bearer_enabled: false,
            bearer_token: None,
            hmac_enabled: false,
            hmac_secret: None,
            hmac_tolerance: DEFAULT_HMAC_TOLERANCE,
        }
    }

    /// Entry point: implements the decision order of the module docs.
    pub fn verify(&self, req: &AuthRequest<'_>, now: SystemClock) -> AuthResult {
        if let Some(header) = req.authorization {
            if !self.bearer_enabled {
                // Bearer was sent but not accepted: the request is not retried
                // through HMAC (architecture §9.5 step 1).
                return Err(AuthError::Invalid);
            }
            return self.verify_bearer(header);
        }

        if self.hmac_enabled {
            if req.date.is_none() || req.signature.is_none() {
                return Err(AuthError::Missing);
            }
            return self.verify_signature(req, now);
        }

        if self.bearer_enabled {
            Err(AuthError::Missing)
        } else {
            Ok(AuthMethod::None)
        }
    }

    fn verify_bearer(&self, header: &str) -> AuthResult {
        let rest = match header.strip_prefix("Bearer ") {
            Some(r) => r.trim(),
            None => return Err(AuthError::Invalid),
        };
        if rest.is_empty() || rest.contains(char::is_whitespace) {
            return Err(AuthError::Invalid);
        }
        match &self.bearer_token {
            Some(token) if ct_eq(token.as_bytes(), rest.as_bytes()) => Ok(AuthMethod::Bearer),
            _ => Err(AuthError::Invalid),
        }
    }

    fn verify_signature(&self, req: &AuthRequest<'_>, now: SystemClock) -> AuthResult {
        let Some(date) = req.date else {
            return Err(AuthError::Missing);
        };
        let Some(signature) = req.signature else {
            return Err(AuthError::Missing);
        };
        let Some(secret) = &self.hmac_secret else {
            return Err(AuthError::Invalid);
        };

        let timestamp = match parse_date(date) {
            Some(ts) => ts,
            None => return Err(AuthError::Invalid),
        };
        let elapsed = (now.now_s() - timestamp).abs();
        if elapsed > self.hmac_tolerance.as_secs() {
            return Err(AuthError::Invalid);
        }

        if !is_valid_hex(signature) || signature.len() != 64 {
            return Err(AuthError::Invalid);
        }

        let canonical = canonical_string(req.method, req.path, date, req.body);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| AuthError::Invalid)?;
        mac.update(canonical.as_bytes());
        let expected = hex_lower(&mac.finalize().into_bytes());

        if !ct_eq(expected.as_bytes(), signature.trim().as_bytes()) {
            return Err(AuthError::Invalid);
        }
        Ok(AuthMethod::Hmac)
    }
}

/// Shared clock seam so the replay-window tests are deterministic.
pub trait Clock: Send + Sync {
    fn now_s(&self) -> i64;
}

#[derive(Clone, Copy, Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_s(&self) -> i64 {
        SystemTimeSeconds::now()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FixedClock(i64);

impl FixedClock {
    pub fn new(unix_seconds: i64) -> Self {
        Self(unix_seconds)
    }
}

impl Clock for FixedClock {
    fn now_s(&self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy)]
struct SystemTimeSeconds;

impl SystemTimeSeconds {
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// The canonical string signed by a client.
pub fn canonical_string(method: &str, path: &str, date: &str, body: &[u8]) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        method.trim().to_ascii_uppercase(),
        path.trim_start_matches('/'),
        date.trim(),
        body_hash_hex(body),
    )
}

pub fn body_hash_hex(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex_lower(&hasher.finalize())
}

/// Verify a signature produced with [`sign`].
pub fn sign(secret: &[u8], method: &str, path: &str, date: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(canonical_string(method, path, date, body).as_bytes());
    hex_lower(&mac.finalize().into_bytes())
}

/// Unix seconds or RFC 3339, including a fractional second and a `Z` suffix.
fn parse_date(value: &str) -> Option<i64> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<i64>() {
        return Some(secs);
    }
    chrono::DateTime::parse_from_rfc3339(value)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339_opt(value).map_err(|_| ()))
        .map(|dt| dt.timestamp())
        .ok()
}

fn is_valid_hex(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Constant-time comparison for token and signature material.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Convenience type for sharing a policy across axum handlers.
pub type SharedAuthPolicy = Arc<AuthPolicy>;

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"rest-secret-0123456789";
    const NOW: i64 = 1_752_700_000;

    fn policy() -> AuthPolicy {
        AuthPolicy::both("tok-123", SECRET, Duration::from_secs(300))
    }

    #[test]
    fn bearer_accepts_the_configured_token() {
        let p = policy();
        let req = AuthRequest::new("GET", "/api/v1/config", b"").with_authorization("Bearer tok-123");
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Ok(AuthMethod::Bearer));
    }

    #[test]
    fn bearer_rejects_wrong_token() {
        let p = policy();
        let req = AuthRequest::new("GET", "/api/v1/config", b"").with_authorization("Bearer wrong");
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Invalid));
    }

    #[test]
    fn bearer_rejects_wrong_scheme() {
        let p = policy();
        let req = AuthRequest::new("GET", "/api/v1/config", b"").with_authorization("Basic dG9r");
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Invalid));
    }

    #[test]
    fn hmac_accepts_a_fresh_signature() {
        let p = policy();
        let body = b"{\"max-bps\": 2000000}";
        let req = AuthRequest::new("PATCH", "/api/v1/config", body)
            .with_date(&NOW.to_string())
            .with_signature(&sign(SECRET, "PATCH", "/api/v1/config", &NOW.to_string(), body));
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Ok(AuthMethod::Hmac));
    }

    #[test]
    fn hmac_accepts_rfc3339_dates() {
        let p = policy();
        let body = b"{}";
        let ts = chrono::DateTime::from_timestamp(NOW, 0).unwrap();
        let date = ts.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let req = AuthRequest::new("GET", "/api/v1/config", body)
            .with_date(&date)
            .with_signature(&sign(SECRET, "GET", "/api/v1/config", &date, body));
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Ok(AuthMethod::Hmac));
    }

    #[test]
    fn hmac_rejects_stale_requests() {
        let p = policy();
        let stale = NOW - 301;
        let body = b"{}";
        let req = AuthRequest::new("GET", "/api/v1/config", body)
            .with_date(&stale.to_string())
            .with_signature(&sign(SECRET, "GET", "/api/v1/config", &stale.to_string(), body));
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Invalid));
    }

    #[test]
    fn hmac_rejects_future_requests_outside_the_window() {
        let p = policy();
        let future = NOW + 301;
        let body = b"{}";
        let req = AuthRequest::new("GET", "/api/v1/config", body)
            .with_date(&future.to_string())
            .with_signature(&sign(SECRET, "GET", "/api/v1/config", &future.to_string(), body));
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Invalid));
    }

    #[test]
    fn hmac_rejects_tampered_bodies() {
        let p = policy();
        let body = b"{\"max-bps\": 2000000}";
        let sig = sign(SECRET, "GET", "/api/v1/config", &NOW.to_string(), body);
        let tampered = AuthRequest::new("GET", "/api/v1/config", b"{\"max-bps\": 1}")
            .with_date(&NOW.to_string())
            .with_signature(&sig);
        assert_eq!(p.verify(&tampered, FixedClock::new(NOW)), Err(AuthError::Invalid));
    }

    #[test]
    fn hmac_rejects_wrong_secret() {
        let p = policy();
        let body = b"{}";
        let req = AuthRequest::new("GET", "/api/v1/config", body)
            .with_date(&NOW.to_string())
            .with_signature(&sign(b"other", "GET", "/api/v1/config", &NOW.to_string(), body));
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Invalid));
    }

    #[test]
    fn hmac_rejects_malformed_signature() {
        let p = policy();
        let req = AuthRequest::new("GET", "/api/v1/config", b"{}")
            .with_date(&NOW.to_string())
            .with_signature("not-hex");
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Invalid));
    }

    #[test]
    fn missing_credentials_is_401() {
        let p = policy();
        let req = AuthRequest::new("GET", "/api/v1/config", b"");
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Missing));
        assert_eq!(AuthError::Missing.status(), 401);
    }

    #[test]
    fn signature_path_without_date_is_401() {
        let p = policy();
        let req = AuthRequest::new("GET", "/api/v1/config", b"{}").with_signature("00");
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Missing));
    }

    #[test]
    fn bearer_priority_no_fallback_to_signature() {
        // A correct signature accompanies a wrong bearer token: still 403, and
        // the signature must not be consulted.
        let p = policy();
        let body = b"{}";
        let req = AuthRequest::new("GET", "/api/v1/config", body)
            .with_authorization("Bearer wrong")
            .with_date(&NOW.to_string())
            .with_signature(&sign(SECRET, "GET", "/api/v1/config", &NOW.to_string(), body));
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Invalid));
    }

    #[test]
    fn bearer_beats_signature_when_both_are_present_and_valid() {
        let p = policy();
        let body = b"{}";
        let req = AuthRequest::new("GET", "/api/v1/config", body)
            .with_authorization("Bearer tok-123")
            .with_date(&NOW.to_string())
            .with_signature(&sign(SECRET, "GET", "/api/v1/config", &NOW.to_string(), body));
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Ok(AuthMethod::Bearer));
    }

    #[test]
    fn bearer_only_policy_ignores_signature_requests() {
        let p = AuthPolicy::bearer_only("tok-123");
        let body = b"{}";
        let req = AuthRequest::new("GET", "/api/v1/config", body)
            .with_date(&NOW.to_string())
            .with_signature(&sign(SECRET, "GET", "/api/v1/config", &NOW.to_string(), body));
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Missing));
    }

    #[test]
    fn neither_scheme_enabled_yields_anonymous_for_the_test_only_path() {
        let p = AuthPolicy::none();
        let req = AuthRequest::new("GET", "/api/v1/config", b"");
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Ok(AuthMethod::None));
    }

    #[test]
    fn tolerance_is_configurable() {
        let p = AuthPolicy::both("tok", SECRET, Duration::from_secs(10));
        let ts = NOW - 11;
        let body = b"{}";
        let req = AuthRequest::new("GET", "/api/v1/config", body)
            .with_date(&ts.to_string())
            .with_signature(&sign(SECRET, "GET", "/api/v1/config", &ts.to_string(), body));
        assert_eq!(p.verify(&req, FixedClock::new(NOW)), Err(AuthError::Invalid));
    }

    #[test]
    fn system_clock_is_reasonably_current() {
        let now = SystemClock.now_s();
        assert!(now > 1_700_000_000, "system clock sanity: {now}");
        assert!(now < 2_000_000_000, "system clock sanity: {now}");
    }
}
