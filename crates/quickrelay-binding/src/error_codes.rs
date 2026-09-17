//! Error-code decisions for STUN Binding responses.
//!
//! Every value here MUST be assigned in the IANA STUN registry. 430, 390 and
//! 370 are Unassigned and must never be emitted; the legacy RFC 3489 codes are
//! obsolete.
//!
//! Protocol error-code decisions. Wire-level `ERROR-CODE` construction lives in
//! `quickrelay-protocol`; the mapping between the two is `quickrelay-server`.

/// Protocol error codes this crate can decide on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Bad Request (RFC 5389 Section 12.1.1).
    BadRequest,
    /// Unauthorized (RFC 5389 Section 12.1.2).
    Unauthorized,
    /// Forbidden (RFC 5389 Section 12.1.3).
    Forbidden,
    /// Unknown Attribute (RFC 5389 Section 12.1.4).
    UnknownAttribute,
    /// Stale Nonce (RFC 8489 Section 9.2.5).
    StaleNonce,
    /// Unsupported Address Family (RFC 5389 Section 12.2.6).
    UnsupportedAddressFamily,
    /// Role Conflict (RFC 8445 Section 7.2.1.1).
    RoleConflict,
    /// Too Many Bindings (RFC 5389 Section 12.2.1).
    TooManyBindings,
    /// Server Error (RFC 5389 Section 12.2.3).
    ServerError,
}

impl ErrorCode {
    /// The numeric value carried in the `ERROR-CODE` attribute.
    pub const fn number(self) -> u16 {
        match self {
            ErrorCode::BadRequest => 400,
            ErrorCode::Unauthorized => 401,
            ErrorCode::Forbidden => 403,
            ErrorCode::UnknownAttribute => 388,
            ErrorCode::StaleNonce => 438,
            ErrorCode::UnsupportedAddressFamily => 437,
            ErrorCode::RoleConflict => 487,
            ErrorCode::TooManyBindings => 486,
            ErrorCode::ServerError => 500,
        }
    }

    /// The human-readable reason phrase (RFC 8489 obsoletes `REASON-PHRASE`).
    pub const fn reason(self) -> ReasonPhrase {
        match self {
            ErrorCode::BadRequest => ReasonPhrase::BadRequest,
            ErrorCode::Unauthorized => ReasonPhrase::Unauthorized,
            ErrorCode::Forbidden => ReasonPhrase::Forbidden,
            ErrorCode::UnknownAttribute => ReasonPhrase::UnknownAttribute,
            ErrorCode::StaleNonce => ReasonPhrase::StaleNonce,
            ErrorCode::UnsupportedAddressFamily => ReasonPhrase::UnsupportedAddressFamily,
            ErrorCode::RoleConflict => ReasonPhrase::RoleConflict,
            ErrorCode::TooManyBindings => ReasonPhrase::TooManyBindings,
            ErrorCode::ServerError => ReasonPhrase::ServerError,
        }
    }
}

/// Human-readable reason phrases paired with [`ErrorCode::reason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonPhrase {
    BadRequest,
    Unauthorized,
    Forbidden,
    UnknownAttribute,
    StaleNonce,
    UnsupportedAddressFamily,
    RoleConflict,
    TooManyBindings,
    ServerError,
}

impl ReasonPhrase {
    /// Canonical wire spelling for the `ERROR-CODE` reason text.
    pub const fn as_str(self) -> &'static str {
        match self {
            ReasonPhrase::BadRequest => "Bad Request",
            ReasonPhrase::Unauthorized => "Unauthorized",
            ReasonPhrase::Forbidden => "Forbidden",
            ReasonPhrase::UnknownAttribute => "Unknown Attribute",
            ReasonPhrase::StaleNonce => "Stale Nonce",
            ReasonPhrase::UnsupportedAddressFamily => "Unsupported Address Family",
            ReasonPhrase::RoleConflict => "Role Conflict",
            ReasonPhrase::TooManyBindings => "Too Many Bindings",
            ReasonPhrase::ServerError => "Server Error",
        }
    }
}
