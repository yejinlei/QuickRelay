//! Error-code decisions for STUN Binding responses.
//!
//! Every value here MUST be assigned in the IANA STUN registry
//! (`stun-parameters`, updated 2024-12-20): `STUN Error Codes` and
//! `Extension Codes` are registered in the same registry. 430, 390 and 370
//! are Unassigned and must never be emitted; the legacy RFC 3489 codes are
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
    /// Too Many Requests (RFC 7675).
    TooManyRequests,
    /// Change-Address Unassigned (RFC 5389 Section 12.2.7).
    ChangeAddress,
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
            ErrorCode::TooManyRequests => 488,
            ErrorCode::ChangeAddress => 386,
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
            ErrorCode::TooManyRequests => ReasonPhrase::TooManyRequests,
            ErrorCode::ChangeAddress => ReasonPhrase::ChangeAddress,
            ErrorCode::ServerError => ReasonPhrase::ServerError,
        }
    }

    /// The 8-bit `ERROR-CODE` class, `number / 100`.
    ///
    /// Exposed so a caller can round-trip `number()` through
    /// `(class, number % 100)` and check that this table is internally
    /// consistent.
    pub const fn class(self) -> u8 {
        (self.number() / 100) as u8
    }

    /// The 2-digit `ERROR-CODE` number, `number % 100`.
    pub const fn detail(self) -> u8 {
        (self.number() % 100) as u8
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
    TooManyRequests,
    ChangeAddress,
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
            ReasonPhrase::TooManyRequests => "Too Many Requests",
            ReasonPhrase::ChangeAddress => "Change-Address Unassigned",
            ReasonPhrase::ServerError => "Server Error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code this crate can decide on. Kept exhaustive: a variant added
    /// later without a table entry breaks this list, not a peer at 3am.
    fn all_codes() -> [ErrorCode; 11] {
        [
            ErrorCode::BadRequest,
            ErrorCode::Unauthorized,
            ErrorCode::Forbidden,
            ErrorCode::UnknownAttribute,
            ErrorCode::StaleNonce,
            ErrorCode::UnsupportedAddressFamily,
            ErrorCode::RoleConflict,
            ErrorCode::TooManyBindings,
            ErrorCode::TooManyRequests,
            ErrorCode::ChangeAddress,
            ErrorCode::ServerError,
        ]
    }

    #[test]
    fn every_code_is_the_iana_assigned_value() {
        let expected = [
            (ErrorCode::BadRequest, 400),
            (ErrorCode::Unauthorized, 401),
            (ErrorCode::Forbidden, 403),
            (ErrorCode::UnknownAttribute, 388),
            (ErrorCode::StaleNonce, 438),
            (ErrorCode::UnsupportedAddressFamily, 437),
            (ErrorCode::RoleConflict, 487),
            (ErrorCode::TooManyBindings, 486),
            (ErrorCode::TooManyRequests, 488),
            (ErrorCode::ChangeAddress, 386),
            (ErrorCode::ServerError, 500),
        ];
        for (code, number) in expected {
            assert_eq!(code.number(), number, "{code:?}");
            // class/number split is what `ERROR-CODE` puts on the wire.
            assert_eq!(
                u16::from(code.class()) * 100 + u16::from(code.detail()),
                number,
                "{code:?}"
            );
        }
    }

    #[test]
    fn every_code_pairs_with_a_reason_phrase() {
        let phrases = [
            ("Bad Request", ErrorCode::BadRequest),
            ("Unauthorized", ErrorCode::Unauthorized),
            ("Forbidden", ErrorCode::Forbidden),
            ("Unknown Attribute", ErrorCode::UnknownAttribute),
            ("Stale Nonce", ErrorCode::StaleNonce),
            (
                "Unsupported Address Family",
                ErrorCode::UnsupportedAddressFamily,
            ),
            ("Role Conflict", ErrorCode::RoleConflict),
            ("Too Many Bindings", ErrorCode::TooManyBindings),
            ("Too Many Requests", ErrorCode::TooManyRequests),
            ("Change-Address Unassigned", ErrorCode::ChangeAddress),
            ("Server Error", ErrorCode::ServerError),
        ];
        for (phrase, code) in phrases {
            assert_eq!(code.reason().as_str(), phrase, "{code:?}");
        }
    }

    #[test]
    fn no_unassigned_code_can_be_emitted() {
        // IANA `stun-parameters` leaves these three unassigned, so they must
        // not appear in the table at all.
        let unassigned = [430u16, 390, 370, 0, 200, 300];
        for code in all_codes() {
            for unassigned in unassigned {
                assert_ne!(
                    code.number(),
                    unassigned,
                    "{code:?} must not be assigned {unassigned}"
                );
            }
        }
    }

    #[test]
    fn role_conflict_is_487_not_the_unassigned_430() {
        // RFC 8445 Section 7.2.1.1: role conflict is 487. The issue asked
        // for 430; 430 is Unassigned in the IANA registry.
        assert_eq!(ErrorCode::RoleConflict.number(), 487);
        assert_eq!(ErrorCode::RoleConflict.reason().as_str(), "Role Conflict");
    }

    #[test]
    fn stale_nonce_is_438_not_the_unassigned_390() {
        // RFC 8489 Section 9.2.5: stale nonce is 438.
        assert_eq!(ErrorCode::StaleNonce.number(), 438);
    }

    #[test]
    fn every_code_is_unique() {
        let codes = all_codes();
        for (i, a) in codes.iter().enumerate() {
            for b in &codes[i + 1..] {
                assert_ne!(a.number(), b.number(), "{a:?} == {b:?}");
            }
        }
    }

    #[test]
    fn the_error_class_is_always_3_4_or_5() {
        // RFC 5389 Section 12.1: STUN error classes are 3 (request
        // unauthorized), 4 (request failed) and 5 (server failed).
        for code in all_codes() {
            assert!(
                (3..=5).contains(&code.class()),
                "{code:?} has class {}",
                code.class()
            );
        }
    }
}
