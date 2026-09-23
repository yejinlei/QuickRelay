//! Error-code decisions for STUN Binding responses.
//!
//! Every value here has a row in the STUN error-code table, which RFC 5389
//! Section 15.6 and RFC 8489 Section 14.8 reproduce (300, 400, 401, 420, 438,
//! 500) and RFC 8445 Section 16.2 extends (487). Nothing in this file invents
//! a number: every `number()` below is quoted from one of those tables.
//!
//! The three numbers a duplicate request used to be answered with are gone.
//! 370, 390 and 430 appear in no STUN error-code table — 430 was RFC 3489's
//! "Stale Credentials" and died with that document — so there is no variant
//! for them, and no code to remove. A duplicate request is not an error at
//! all: the server replays the datagram it already sent, which is the
//! transaction cache in `quickrelay-server`.
//!
//! Protocol error-code decisions. Wire-level `ERROR-CODE` construction lives in
//! `quickrelay-protocol`; the mapping between the two is `quickrelay-server`.

/// Protocol error codes this crate can decide on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// The client should contact an alternate server (RFC 8489 Section 14.8).
    TryAlternate,
    /// The request was malformed (RFC 8489 Section 14.8).
    BadRequest,
    /// The request did not contain the correct credentials. Kept the name
    /// `Unauthorized` so call sites stay put; RFC 8489 renamed the registered
    /// reason phrase to `Unauthenticated`, and `reason()` below follows the
    /// rename.
    Unauthorized,
    /// The server received a comprehension-required attribute it did not
    /// understand (RFC 8489 Section 14.8).
    UnknownAttribute,
    /// The NONCE was no longer valid (RFC 8489 Section 14.8).
    StaleNonce,
    /// The Binding request asserted an ICE role that conflicted with the
    /// server (RFC 8445 Section 16.2).
    RoleConflict,
    /// The server suffered a temporary error (RFC 8489 Section 14.8).
    ServerError,
}

impl ErrorCode {
    /// The numeric value carried in the `ERROR-CODE` attribute.
    pub const fn number(self) -> u16 {
        match self {
            ErrorCode::TryAlternate => 300,
            ErrorCode::BadRequest => 400,
            ErrorCode::Unauthorized => 401,
            ErrorCode::UnknownAttribute => 420,
            ErrorCode::StaleNonce => 438,
            ErrorCode::RoleConflict => 487,
            ErrorCode::ServerError => 500,
        }
    }

    /// The human-readable reason phrase (RFC 8489 obsoletes `REASON-PHRASE`).
    pub const fn reason(self) -> ReasonPhrase {
        match self {
            ErrorCode::TryAlternate => ReasonPhrase::TryAlternate,
            ErrorCode::BadRequest => ReasonPhrase::BadRequest,
            ErrorCode::Unauthorized => ReasonPhrase::Unauthorized,
            ErrorCode::UnknownAttribute => ReasonPhrase::UnknownAttribute,
            ErrorCode::StaleNonce => ReasonPhrase::StaleNonce,
            ErrorCode::RoleConflict => ReasonPhrase::RoleConflict,
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
    TryAlternate,
    BadRequest,
    Unauthorized,
    UnknownAttribute,
    StaleNonce,
    RoleConflict,
    ServerError,
}

impl ReasonPhrase {
    /// Canonical wire spelling for the `ERROR-CODE` reason text.
    pub const fn as_str(self) -> &'static str {
        match self {
            ReasonPhrase::TryAlternate => "Try Alternate",
            ReasonPhrase::BadRequest => "Bad Request",
            ReasonPhrase::Unauthorized => "Unauthenticated",
            ReasonPhrase::UnknownAttribute => "Unknown Attribute",
            ReasonPhrase::StaleNonce => "Stale Nonce",
            ReasonPhrase::RoleConflict => "Role Conflict",
            ReasonPhrase::ServerError => "Server Error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code this crate can decide on. Kept exhaustive: a variant added
    /// later without a table entry breaks this list, not a peer at 3am.
    fn all_codes() -> [ErrorCode; 7] {
        [
            ErrorCode::TryAlternate,
            ErrorCode::BadRequest,
            ErrorCode::Unauthorized,
            ErrorCode::UnknownAttribute,
            ErrorCode::StaleNonce,
            ErrorCode::RoleConflict,
            ErrorCode::ServerError,
        ]
    }

    #[test]
    fn every_code_is_the_iana_assigned_value() {
        // Each number is a row of the STUN error-code table: RFC 8489
        // Section 14.8 for 300/400/401/420/438/500, RFC 8445 Section 16.2 for
        // 487.
        let expected = [
            (ErrorCode::TryAlternate, 300),
            (ErrorCode::BadRequest, 400),
            (ErrorCode::Unauthorized, 401),
            (ErrorCode::UnknownAttribute, 420),
            (ErrorCode::StaleNonce, 438),
            (ErrorCode::RoleConflict, 487),
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
            ("Try Alternate", ErrorCode::TryAlternate),
            ("Bad Request", ErrorCode::BadRequest),
            // RFC 8489 renamed the 401 phrase; the enum variant keeps the old
            // name, the wire string does not.
            ("Unauthenticated", ErrorCode::Unauthorized),
            ("Unknown Attribute", ErrorCode::UnknownAttribute),
            ("Stale Nonce", ErrorCode::StaleNonce),
            ("Role Conflict", ErrorCode::RoleConflict),
            ("Server Error", ErrorCode::ServerError),
        ];
        for (phrase, code) in phrases {
            assert_eq!(code.reason().as_str(), phrase, "{code:?}");
        }
    }

    /// The three numbers the issue asked for. None of them has a row in any
    /// STUN error-code table, so the table itself is what keeps them out:
    /// there is no variant to assign them to.
    #[test]
    fn no_unassigned_code_can_be_emitted() {
        // 370/390/430 were asked for by the issue; 430 was RFC 3489's
        // "Stale Credentials". Also probed with the other gaps between the
        // table rows.
        let unassigned = [430u16, 390, 370, 0, 200, 386, 388, 403, 437, 440, 486, 488];
        for code in all_codes() {
            for number in unassigned {
                assert_ne!(
                    code.number(),
                    number,
                    "{code:?} must not be assigned {number}"
                );
            }
        }
    }

    #[test]
    fn role_conflict_is_487_not_the_unassigned_430() {
        // RFC 8445 Section 16.2 registers 487 (Role Conflict). The issue
        // asked for 430, which appears in no STUN error-code table.
        assert_eq!(ErrorCode::RoleConflict.number(), 487);
        assert_eq!(ErrorCode::RoleConflict.reason().as_str(), "Role Conflict");
        assert_eq!(ErrorCode::RoleConflict.class(), 4);
        assert_eq!(ErrorCode::RoleConflict.detail(), 87);
    }

    #[test]
    fn stale_nonce_is_438_not_the_unassigned_390() {
        // RFC 8489 Section 14.8 lists 438 (Stale Nonce); 390 has no row.
        assert_eq!(ErrorCode::StaleNonce.number(), 438);
        assert_eq!(ErrorCode::StaleNonce.reason().as_str(), "Stale Nonce");
    }

    /// There is no "request already in progress" code to assert on: it has
    /// no row in any STUN error-code table. The assertion is on the shape of
    /// the enum — no variant carries 370, and no reason phrase names an
    /// in-progress request — because the duplicate-request mechanism is not an
    /// error at all, so it cannot be pinned by a code value.
    #[test]
    fn there_is_no_request_already_in_progress_code() {
        let all = all_codes();
        assert!(
            !all.iter().any(|c| c.number() == 370),
            "370 must not exist; a duplicate request is replayed, not rejected"
        );
        assert!(
            !all.iter().any(|c| c.reason().as_str().contains("Progress")),
            "no reason phrase may name an in-progress request"
        );
        assert!(
            !all.iter().any(|c| c.number() == 0 || c.number() == 200),
            "a success response is not an error code"
        );
    }

    #[test]
    fn unknown_attribute_is_420_with_its_reason_phrase() {
        // RFC 8489 Section 14.8: 420 (Unknown Attribute), with the unknown
        // attribute carried in an UNKNOWN-ATTRIBUTES attribute.
        assert_eq!(ErrorCode::UnknownAttribute.number(), 420);
        assert_eq!(ErrorCode::UnknownAttribute.reason().as_str(), "Unknown Attribute");
        assert_eq!(ErrorCode::UnknownAttribute.class(), 4);
        assert_eq!(ErrorCode::UnknownAttribute.detail(), 20);
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
        // RFC 8489 Section 14.8 encodes the class separately and requires it
        // to be between 3 and 6; every code in the table sits at 3, 4 or 5.
        // RFC 8489 Section 6.3.4 reads 3xx as "try another server", 4xx as
        // "the request failed" and 5xx as "the server failed".
        for code in all_codes() {
            assert!(
                (3..=5).contains(&code.class()),
                "{code:?} has class {}",
                code.class()
            );
        }
    }
}
