//! Trailer ordering rules for FINGERPRINT and MESSAGE-INTEGRITY.
//!
//! RFC 8489 section 14.4: MESSAGE-INTEGRITY "MUST be the second-to-last
//! attribute of a STUN message" -- it may only be followed by FINGERPRINT.
//! RFC 8489 section 14.5: FINGERPRINT "MUST be the last attribute of the
//! STUN message".  The issue text cites RFC 5389 sections 15.5 / 15.4, which
//! are the same two sections before the renumbering.
//!
//! This module is deliberately independent of the codec: it takes a plain
//! slice of attribute type codes and reports a verdict, so the ordering rule
//! can be unit-tested without constructing a message, computing a CRC-32, or
//! touching any socket.  The codec calls [`validate`] as its last parsing
//! step.

use crate::err::ProtocolError;
use crate::method::Class;

/// FINGERPRINT type code (RFC 8489, section 14.5).
const FINGERPRINT: u16 = 0x8028;
/// MESSAGE-INTEGRITY type code (RFC 8489, section 14.4).
const MESSAGE_INTEGRITY: u16 = 0x0008;
/// MESSAGE-INTEGRITY-SHA256 type code (RFC 8489, section 18.3.2).
const MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;

/// Verdict for a message's attribute sequence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TrailerOrder {
    /// No MESSAGE-INTEGRITY and no FINGERPRINT.
    Plain,
    /// MESSAGE-INTEGRITY followed by FINGERPRINT.
    IntegrityThenFingerprint,
    /// MESSAGE-INTEGRITY as the final attribute.
    IntegrityOnly,
    /// FINGERPRINT as the final attribute.
    FingerprintOnly,
}

/// Is `code` a trailer attribute (one that may only appear at the end)?
const fn is_trailer(code: u16) -> bool {
    matches!(code, FINGERPRINT | MESSAGE_INTEGRITY | MESSAGE_INTEGRITY_SHA256)
}

/// Validate the trailer layout of `codes`.
///
/// `codes` is the attribute sequence in wire order.  Returns
/// [`ProtocolError::BadTrailerOrder`] when the layout is impossible; the
/// caller should treat a bad order as *not STUN traffic* and drop silently
/// (see [`ProtocolError::is_silent`]).
pub fn validate(codes: &[u16]) -> Result<TrailerOrder, ProtocolError> {
    let mut trailer_started = false;
    let mut saw_fingerprint = false;
    let mut saw_integrity = false;

    for &code in codes {
        if trailer_started && !is_trailer(code) {
            // An ordinary attribute followed a trailer.  With FINGERPRINT
            // present that violates "FINGERPRINT is last"; without it, only
            // FINGERPRINT may follow MESSAGE-INTEGRITY.
            return Err(ProtocolError::BadTrailerOrder);
        }
        if trailer_started {
            // FINGERPRINT is the last attribute of the message, full stop:
            // nothing -- not even MESSAGE-INTEGRITY -- may follow it.
            if saw_fingerprint {
                return Err(ProtocolError::BadTrailerOrder);
            }
            // Only FINGERPRINT is permitted to follow an integrity attribute;
            // a second one is redundant.
            if code != FINGERPRINT && saw_integrity {
                return Err(ProtocolError::BadTrailerOrder);
            }
        }
        if is_trailer(code) {
            trailer_started = true;
            if code == FINGERPRINT {
                saw_fingerprint = true;
            } else {
                saw_integrity = true;
            }
        }
    }

    Ok(match (saw_integrity, saw_fingerprint) {
        (true, true) => TrailerOrder::IntegrityThenFingerprint,
        (true, false) => TrailerOrder::IntegrityOnly,
        (false, true) => TrailerOrder::FingerprintOnly,
        (false, false) => TrailerOrder::Plain,
    })
}

/// Whether a message of this class must carry MESSAGE-INTEGRITY.
///
/// RFC 8489 section 7.2: every response to a request that carries
/// MESSAGE-INTEGRITY must itself carry one.  Requests never authenticate, so
/// a MESSAGE-INTEGRITY-bearing Binding request is malformed.
pub fn requires_integrity(class: Class) -> bool {
    class.is_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPPED: u16 = 0x0001;
    const USERNAME: u16 = 0x0006;
    const ERROR_CODE: u16 = 0x0009;
    const REALM: u16 = 0x0014;
    const NONCE: u16 = 0x0015;
    const XMAP: u16 = 0x0020;
    const SOFTWARE: u16 = 0x8022;

    #[test]
    fn plain_binding_request_has_no_trailer() {
        assert_eq!(
            validate(&[USERNAME, SOFTWARE]),
            Ok(TrailerOrder::Plain)
        );
        assert_eq!(validate(&[]), Ok(TrailerOrder::Plain));
    }

    #[test]
    fn fingerprint_alone_is_legal() {
        assert_eq!(
            validate(&[XMAP, FINGERPRINT]),
            Ok(TrailerOrder::FingerprintOnly)
        );
        assert_eq!(validate(&[FINGERPRINT]), Ok(TrailerOrder::FingerprintOnly));
    }

    #[test]
    fn integrity_alone_is_legal() {
        assert_eq!(
            validate(&[ERROR_CODE, REALM, NONCE, MESSAGE_INTEGRITY]),
            Ok(TrailerOrder::IntegrityOnly)
        );
    }

    #[test]
    fn integrity_then_fingerprint_is_the_only_two_trailer_order() {
        assert_eq!(
            validate(&[ERROR_CODE, REALM, NONCE, MESSAGE_INTEGRITY, FINGERPRINT]),
            Ok(TrailerOrder::IntegrityThenFingerprint)
        );
    }

    #[test]
    fn fingerprint_before_integrity_is_rejected() {
        assert!(matches!(
            validate(&[XMAP, FINGERPRINT, MESSAGE_INTEGRITY]),
            Err(ProtocolError::BadTrailerOrder)
        ));
    }

    #[test]
    fn fingerprint_must_be_last() {
        assert!(matches!(
            validate(&[XMAP, FINGERPRINT, SOFTWARE]),
            Err(ProtocolError::BadTrailerOrder)
        ));
        assert!(matches!(
            validate(&[XMAP, FINGERPRINT, MAPPED]),
            Err(ProtocolError::BadTrailerOrder)
        ));
    }

    #[test]
    fn nothing_may_follow_integrity_but_fingerprint() {
        assert!(matches!(
            validate(&[XMAP, MESSAGE_INTEGRITY, SOFTWARE, FINGERPRINT]),
            Err(ProtocolError::BadTrailerOrder)
        ));
    }

    #[test]
    fn fingerprint_may_only_be_followed_by_nothing() {
        // The one shape my first implementation missed: FINGERPRINT is last,
        // so MESSAGE-INTEGRITY after it is as illegal as FINGERPRINT after it.
        assert!(matches!(
            validate(&[XMAP, FINGERPRINT, MESSAGE_INTEGRITY]),
            Err(ProtocolError::BadTrailerOrder)
        ));
        assert!(matches!(
            validate(&[XMAP, FINGERPRINT, FINGERPRINT]),
            Err(ProtocolError::BadTrailerOrder)
        ));
        assert!(matches!(
            validate(&[XMAP, MESSAGE_INTEGRITY, FINGERPRINT, MESSAGE_INTEGRITY]),
            Err(ProtocolError::BadTrailerOrder)
        ));
    }

    #[test]
    fn duplicate_integrity_is_rejected() {
        assert!(matches!(
            validate(&[XMAP, MESSAGE_INTEGRITY, MESSAGE_INTEGRITY]),
            Err(ProtocolError::BadTrailerOrder)
        ));
        assert!(matches!(
            validate(&[XMAP, MESSAGE_INTEGRITY, MESSAGE_INTEGRITY, FINGERPRINT]),
            Err(ProtocolError::BadTrailerOrder)
        ));
    }

    #[test]
    fn order_violations_are_silent() {
        // A malformed trailer must be dropped, not answered: replying would
        // turn a malformed-datagram scanner into an amplification channel.
        assert!(ProtocolError::BadTrailerOrder.is_silent());
    }

    #[test]
    fn real_world_binding_error_shapes() {
        // 401 from an authenticated Binding round trip.
        assert_eq!(
            validate(&[ERROR_CODE, REALM, NONCE, MESSAGE_INTEGRITY]),
            Ok(TrailerOrder::IntegrityOnly)
        );
        // The same response with a FINGERPRINT, which RFC 8489 section 14.5
        // explicitly endorses ("the same is true of responses to Binding
        // requests").
        assert_eq!(
            validate(&[ERROR_CODE, REALM, NONCE, MESSAGE_INTEGRITY, FINGERPRINT]),
            Ok(TrailerOrder::IntegrityThenFingerprint)
        );
    }

    #[test]
    fn only_responses_may_carry_integrity() {
        use crate::method::Class;
        assert!(!requires_integrity(Class::Request));
        assert!(!requires_integrity(Class::Indication));
        assert!(requires_integrity(Class::Success));
        assert!(requires_integrity(Class::Error));
    }
}
