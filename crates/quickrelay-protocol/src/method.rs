//! STUN method numbers, message classes and the message-type codec.
//!
//! The 16-bit message-type field is a *scrambled* (method, class) pair, not a
//! low/high split: the two class bits land on bits 4 and 8 and displace the
//! method bits, so encoding is a per-window scatter and decoding is the
//! inverse scatter -- *not* "strip the class bits".
//!
//! Bit layout (RFC 5389 section 6, Figure 3), MSB first:
//!
//! ```text
//!     bits 15-14 : reserved, MUST be zero
//!     bits 13-12 : method bits 11-10
//!     bits 11-10 : method bits  9- 8
//!     bit   9    : method bit   7
//!     bit   8    : class bit 1 (C1)
//!     bits  7-5  : method bits  6- 4
//!     bit   4    : class bit 0 (C0)
//!     bits  3-0  : method bits  3- 0
//! ```
//!
//! This is the legacy RFC 3489 accident RFC 5389 section 6 flags: a Binding
//! request is `0x0001`, a Binding success is `0x0101` and a Binding error is
//! `0x0111` -- never `0x0301`.  The class can be isolated with the mask
//! `0x0110`, which is what RFC 5389 Appendix A's `IS_REQUEST` /
//! `IS_INDICATION` / `IS_SUCCESS_RESP` / `IS_ERR_RESP` compare against.
//!
//! Method numbers are transcribed from RFC 5389 section 18.1, RFC 5766
//! section 13 and RFC 6062; error codes from RFC 5389 section 15.6,
//! RFC 5766 section 15, RFC 8656 section 19 and RFC 6062 section 6.3.

use crate::{err::ProtocolError, MAX_METHOD};

/// Class bits 4 and 8 of the message-type field, isolated.
///
/// The same mask RFC 5389 Appendix A uses for its `IS_*` macros.
pub const CLASS_MASK: u16 = 0x0110;

/// Message-type bits 14-15 are reserved and must always be zero.
///
/// Only the two top bits are reserved: RFC 5389 section 6 says "The most
/// significant 2 bits of every STUN message MUST be zeroes", and Figure 3
/// shows bits 2-3 as method bits `M1` / `M0`.  Masking `0xC00C` would
/// wrongly reject every method whose number has bit 0 or bit 1 set --
/// Binding itself is `M0`, so `0xC00C` rejects the entire Binding chain.
pub const RESERVED_MASK: u16 = 0xC000;

/// Message class, i.e. the two-bit value held in `CLASS_MASK`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Class {
    /// Request.
    Request = 0b00,
    /// Indication.
    Indication = 0b01,
    /// Success response.
    Success = 0b10,
    /// Error response.
    Error = 0b11,
}

impl Class {
    /// Decode the class from the normalised two-bit value.
    ///
    /// All four values are matched explicitly: a wildcard for `Error` would
    /// silently read an error response as a request, which turns the whole
    /// Binding chain into a no-op.
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => Self::Request,
            0b01 => Self::Indication,
            0b10 => Self::Success,
            _ => Self::Error,
        }
    }

    /// The class value as it appears in `CLASS_MASK`.
    pub const fn bits(self) -> u16 {
        self.masked()
    }

    /// The class value as the RFC numbers it (0-3), unmasked.
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// The class bits placed at their position in the message-type field.
    ///
    /// `Indication` is `0x0010` (bit 4 only), `Success` is `0x0100` (bit 8
    /// only) and `Error` is `0x0110`.  The high bit needs `<< 7`, not `<< 3`:
    /// `0x0100` is the constant RFC 5389 Appendix A compares against in
    /// `IS_SUCCESS_RESP` / `IS_ERR_RESP`.
    pub const fn masked(self) -> u16 {
        ((self as u16 & 0x01) << 4) | ((self as u16 & 0x02) << 7)
    }

    /// Is this class allowed to carry a transaction id and produce a response?
    pub const fn is_request(self) -> bool {
        matches!(self, Self::Request)
    }

    /// Is this class an indication (one-way, no response)?
    pub const fn is_indication(self) -> bool {
        matches!(self, Self::Indication)
    }

    /// Is this class a response?
    pub const fn is_response(self) -> bool {
        matches!(self, Self::Success | Self::Error)
    }
}

/// Decode the class half of a message-type field.
///
/// The two class bits sit at bit 4 and bit 8, four apart, so a single
/// shift cannot normalise them: `(bits & 0x0110) >> 4` would leave the
/// upper bit one window too high.  Note the parenthesisation trap as
/// well -- `bits & 0x0110 >> 4` parses as `bits & (0x0110 >> 4)`,
/// i.e. `bits & 0x0001`, which silently reads the *method*'s low bit
/// instead of the class.  Each class bit is therefore normalised on its
/// own.
///
/// Reserved-bit checking is the caller's job; use [`decode_msg_type`] to
/// get it done together.
pub const fn class_of(bits: u16) -> Class {
    Class::from_bits((((bits & 0x0010) >> 4) | ((bits & 0x0100) >> 7)) as u8)
}

/// STUN / TURN method number (12 bits).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum Method {
    /// STUN Binding (RFC 5389, section 7.3.1).
    Binding = 0x0001,
    /// TURN Allocate (RFC 5766, section 6).
    Allocate = 0x0003,
    /// TURN Refresh (RFC 5766, section 7).
    Refresh = 0x0004,
    /// TURN Send (RFC 5766, section 10.1).
    Send = 0x0006,
    /// TURN Data (RFC 5766, section 10.2).
    Data = 0x0007,
    /// TURN CreatePermission (RFC 5766, section 9).
    CreatePermission = 0x0008,
    /// TURN ChannelBind (RFC 5766, section 11).
    ChannelBind = 0x0009,
    /// TURN Connect (RFC 6062, section 4).
    Connect = 0x000A,
    /// TURN ConnectionBind (RFC 6062, section 6).
    ConnectionBind = 0x000B,
    /// TURN ConnectionAttempt (RFC 6062, section 8).
    ConnectionAttempt = 0x000C,
}

impl Method {
    /// The unencoded method number.
    pub const fn bits(self) -> u16 {
        self as u16
    }

    /// Parse a method value, rejecting values outside the 12-bit space.
    pub const fn try_from_bits(bits: u16) -> Result<Method, ProtocolError> {
        if bits > MAX_METHOD as u16 {
            return Err(ProtocolError::BadMethodNumber(bits));
        }
        Ok(match bits {
            0x0001 => Self::Binding,
            0x0003 => Self::Allocate,
            0x0004 => Self::Refresh,
            0x0006 => Self::Send,
            0x0007 => Self::Data,
            0x0008 => Self::CreatePermission,
            0x0009 => Self::ChannelBind,
            0x000A => Self::Connect,
            0x000B => Self::ConnectionBind,
            0x000C => Self::ConnectionAttempt,
            _ => return Err(ProtocolError::UnknownMethod(bits)),
        })
    }

    /// The name of the method (used in logs and error text).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Binding => "Binding",
            Self::Allocate => "Allocate",
            Self::Refresh => "Refresh",
            Self::Send => "Send",
            Self::Data => "Data",
            Self::CreatePermission => "CreatePermission",
            Self::ChannelBind => "ChannelBind",
            Self::Connect => "Connect",
            Self::ConnectionBind => "ConnectionBind",
            Self::ConnectionAttempt => "ConnectionAttempt",
        }
    }

    /// Is this method answered by the QuickRelay server?
    ///
    /// Stage 2 (this issue, YEJ-141) answers only the STUN Binding chain.  The
    /// TURN allocation methods belong to Stage 3 and are answered with
    /// `486 Method Not Implemented`; `SEND` and `DATA` are indications that
    /// only exist inside an allocation, so with no allocation live they are
    /// silently discarded (RFC 5766, section 10) -- the TCP framing path in
    /// this issue still has to parse and reject them, which is the caller's
    /// job, not this predicate's.
    pub const fn is_implemented(self) -> bool {
        matches!(self, Self::Binding)
    }
}

/// Error codes defined by STUN and TURN, as used in the `ERROR-CODE` attribute.
///
/// Variants hold the plain decimal code, which is how the RFCs and the
/// IANA registry print them.  The wire form is different: the hundreds
/// digit goes into bits 8-10 and the code modulo 100 into bits 0-7, so
/// `400` travels as `0x0400` and `508` as `0x0508`.  `number()` is the
/// decimal form and `bits()` the wire form.
///
/// Codes are transcribed from RFC 5389 section 15.6, RFC 5766 section 15 and
/// RFC 8656 section 19, with RFC 6062 section 6.3 contributing 447; the
/// reason phrases are the IANA registry recommendations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum ErrorCode {
    /// 300: The client should contact an alternate server for this request.
    TryAlternate = 300,
    /// 400: The request was malformed; do not retry without modification.
    BadRequest = 400,
    /// 401: The request did not contain the correct credentials.
    Unauthorized = 401,
    /// 403: The request is valid but administratively restricted.
    Forbidden = 403,
    /// 420: A comprehension-required attribute was not understood.
    UnknownAttribute = 420,
    /// 437: The request does not match the current allocation state.
    AllocationMismatch = 437,
    /// 438: The NONCE used by the client is no longer valid.
    StaleNonce = 438,
    /// 440: The address family requested by the client is not supported.
    UnsupportedAddressFamily = 440,
    /// 441: The credentials do not match those used to create the allocation.
    WrongCredentials = 441,
    /// 442: The transport protocol requested is not supported.
    UnsupportedTransport = 442,
    /// 443: The peer address is in a different family than the allocation.
    PeerAddressFamilyMismatch = 443,
    /// 444: The requested allocation conflicts with another allocation.
    RequestAllocationConflict = 444,
    /// 447: The TCP connection timed out or failed.
    ConnectionTimeoutOrFailure = 447,
    /// 480: The message method is not recognised.
    UnknownMethod = 480,
    /// 486: The method is understood but not implemented.
    MethodNotImplemented = 486,
    /// 487: The server is temporarily out of resources.
    ResourceLimited = 487,
    /// 500: The server suffered a temporary internal error.
    ServerError = 500,
    /// 508: The server cannot carry out the request for capacity reasons.
    InsufficientCapacity = 508,
}

impl ErrorCode {
    /// The decimal error number as the RFCs and the IANA registry print it.
    pub const fn number(self) -> u16 {
        self as u16
    }

    /// The two-byte value written into the `ERROR-CODE` attribute.
    ///
    /// `[Reserved:5][Class:3][Number:8]`: `Class` is the hundreds digit
    /// (bits 8-10), `Number` is the code modulo 100 (bits 0-7), and the
    /// five high bits 11-15 are reserved -- receivers MUST ignore them
    /// (RFC 5389 section 15.6), so they stay zero here.  RFC 5389 section
    /// 15.6 Figure 7 prints this as `Reserved:6` / `Class:2`, which is not
    /// self-consistent: the same section requires the Class to be between
    /// 3 and 6, and 4-6 need three bits.  Take it from the prose, not the
    /// figure: `400` is `0x0400`, `480` is `0x0450`, `500` is `0x0500`
    /// and `508` is `0x0508`.
    pub const fn bits(self) -> u16 {
        (self.number() / 100) << 8 | self.number() % 100
    }

    /// The recommended reason phrase for this code.
    pub const fn reason_phrase(self) -> &'static str {
        match self {
            Self::TryAlternate => "Try Alternate",
            Self::BadRequest => "Bad Request",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::UnknownAttribute => "Unknown Attribute",
            Self::AllocationMismatch => "Allocation Mismatch",
            Self::StaleNonce => "Stale Nonce",
            Self::UnsupportedAddressFamily => "Address Family not Supported",
            Self::WrongCredentials => "Wrong Credentials",
            Self::UnsupportedTransport => "Unsupported Transport Protocol",
            Self::PeerAddressFamilyMismatch => "Peer Address Family Mismatch",
            Self::RequestAllocationConflict => "Request Allocation Conflict",
            Self::ConnectionTimeoutOrFailure => "Connection Timeout or Failure",
            Self::UnknownMethod => "Unknown Method",
            Self::MethodNotImplemented => "Method Not Implemented",
            Self::ResourceLimited => "Resource Limited",
            Self::ServerError => "Server Error",
            Self::InsufficientCapacity => "Insufficient Capacity",
        }
    }
}

/// Encode a message-type field from class and method.
///
/// The inverse of [`decode_msg_type`]; both reject reserved bits.
pub fn encode_msg_type(class: Class, method: Method) -> u16 {
    let bits = encode_raw(method.bits(), class);
    debug_assert_eq!(
        bits & RESERVED_MASK,
        0,
        "reserved message-type bits must stay zero"
    );
    bits
}

/// Decode a message-type field into class and method.
/// The method is *scrambled*, not shifted, so decoding is not "strip the
/// class bits".  `GET_STUN_REQUEST(msg_type)` in coturn is `msg_type &
/// 0xFEEF` and is only for comparing two message-type fields against each
/// other; it does not recover the method number.
pub fn decode_msg_type(bits: u16) -> Result<(Class, Method), ProtocolError> {
    if bits & RESERVED_MASK != 0 {
        return Err(ProtocolError::BadMessageClass(bits));
    }
    let class = class_of(bits);
    let method = Method::try_from_bits(method_of(bits))?;
    Ok((class, method))
}

/// Encode a message-type field from raw, unencoded inputs.
///
/// Pure bit manipulation: keeps the method bits and splats the class into
/// bits 4 and 8.  Exposed so the codec can build response message types
/// without going through the `Method` enum.
pub const fn encode_raw(method: u16, class: Class) -> u16 {
    let m = method & 0x0FFF;
    let c = class as u8 & 0x03;
    (m & 0x000F) | ((m >> 4 & 0x7) << 5) | ((m >> 7 & 0x7) << 9) | ((m >> 10 & 0x3) << 12)
        | ((c as u16 & 0x01) << 4) | ((c as u16 & 0x02) << 7)
}

/// Recover the method number from a message-type field, undoing the scramble.
///
/// Parenthesise the mask before the shift: in Rust `<<` binds tighter than
/// `&`, so `bits & 0x7 << 4` is `bits & (0x7 << 4)` = `bits & 0x70`, which
/// silently drops the upper method window.  `method_of(0x3EEF)` then yields
/// `0x7F` instead of `0x0FFF`.  Every method in the registry is `<= 0x0C`,
/// which lives entirely in bits 0-3, so the defect is invisible on real
/// traffic -- only the exhaustive method-space test can see it.
pub const fn method_of(bits: u16) -> u16 {
    (bits & 0x000F)
        | (((bits >> 5) & 0x07) << 4)
        | (((bits >> 9) & 0x07) << 7)
        | (((bits >> 12) & 0x03) << 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_bits_match_rfc_assignments() {
        assert_eq!(Method::Binding.bits(), 0x0001);
        assert_eq!(Method::Allocate.bits(), 0x0003);
        assert_eq!(Method::Refresh.bits(), 0x0004);
        assert_eq!(Method::Send.bits(), 0x0006);
        assert_eq!(Method::Data.bits(), 0x0007);
        assert_eq!(Method::CreatePermission.bits(), 0x0008);
        assert_eq!(Method::ChannelBind.bits(), 0x0009);
        assert_eq!(Method::Connect.bits(), 0x000A);
        assert_eq!(Method::ConnectionBind.bits(), 0x000B);
        assert_eq!(Method::ConnectionAttempt.bits(), 0x000C);
    }

    #[test]
    fn message_type_encoding_is_the_rfc_3489_legacy_layout() {
        // RFC 5389 section 6: Binding request = 0x0001, Binding response =
        // 0x0101.  The class lands in bits 4 and 8, so the error variant is
        // 0x0111 -- not 0x0301.
        assert_eq!(encode_msg_type(Class::Request, Method::Binding), 0x0001);
        assert_eq!(encode_msg_type(Class::Success, Method::Binding), 0x0101);
        assert_eq!(encode_msg_type(Class::Error, Method::Binding), 0x0111);
        assert_eq!(encode_msg_type(Class::Indication, Method::Data), 0x0017);
        assert_eq!(encode_msg_type(Class::Indication, Method::Send), 0x0016);
        assert_eq!(encode_msg_type(Class::Success, Method::Allocate), 0x0103);
        assert_eq!(encode_msg_type(Class::Error, Method::Allocate), 0x0113);
        assert_eq!(
            encode_msg_type(Class::Success, Method::ConnectionBind),
            0x010B
        );
        assert_eq!(
            decode_msg_type(0x0111),
            Ok((Class::Error, Method::Binding))
        );
    }

    #[test]
    fn class_mask_reproduces_the_rfc_5389_appendix_a_macros() {
        // RFC 5389 Appendix A: IS_REQUEST/INDICATION/SUCCESS_RESP/ERR_RESP
        // are `(msg_type & 0x0110) == 0x0000 / 0x0010 / 0x0100 / 0x0110`.
        let cases = [
            (0x0001, Class::Request),
            (0x0017, Class::Indication),
            (0x0101, Class::Success),
            (0x0111, Class::Error),
            (0x0103, Class::Success),
            (0x0113, Class::Error),
        ];
        for (bits, class) in cases {
            assert_eq!(bits & CLASS_MASK, class.masked(), "{bits:#06x}");
            assert_eq!(class_of(bits), class);
        }
        assert!(Class::Request.masked() == 0x0000);
        assert!(Class::Indication.masked() == 0x0010);
        assert!(Class::Success.masked() == 0x0100);
        assert!(Class::Error.masked() == 0x0110);
    }

    #[test]
    fn method_of_and_encode_round_trip_the_whole_method_space() {
        for method in 0u16..=MAX_METHOD as u16 {
            for class in [
                Class::Request,
                Class::Indication,
                Class::Success,
                Class::Error,
            ] {
                let bits = encode_raw(method, class);
                assert_eq!(bits & RESERVED_MASK, 0, "{bits:#06x}");
                assert_eq!(method_of(bits), method);
                assert_eq!(class_of(bits), class);
            }
        }
    }

    #[test]
    fn high_methods_decode_through_the_scramble_not_by_masking() {
        // Regression: `decode_msg_type` used to recover the method with
        // `bits & !CLASS_MASK`, which only clears bits 4 and 8.  For method
        // numbers >= 0x10 the top method bits scatter into bits 12-13, where
        // that mask leaves them, so `0x3EEF` (method 0x0FFF, class request)
        // would have decoded as method 0x0EEF.  Every method in the registry
        // is <= 0x0C, so no earlier test could see it.
        let bits = encode_raw(0x0FFF, Class::Request);
        assert_eq!(bits, 0x3EEF);
        assert_eq!(bits & CLASS_MASK, 0);
        // Masking alone gets it wrong; the inverse scatter does not.
        assert_ne!(method_of(bits), bits & !CLASS_MASK);
        assert_eq!(method_of(bits), 0x0FFF);
        assert_eq!(class_of(bits), Class::Request);

        // A class carrying bits must not disturb the recovered method either.
        for method in [0x0001u16, 0x0007, 0x000C, 0x00FF, 0x0FFF] {
            for class in [
                Class::Request,
                Class::Indication,
                Class::Success,
                Class::Error,
            ] {
                assert_eq!(method_of(encode_raw(method, class)), method);
            }
        }
    }

    #[test]
    fn reserved_bits_are_rejected() {
        // Only bits 14-15 are reserved (RFC 5389 section 6); bits 2-3 are
        // method bits M1/M0 and must be accepted.
        assert!(matches!(
            decode_msg_type(0x8001),
            Err(ProtocolError::BadMessageClass(0x8001))
        ));
        assert!(matches!(
            decode_msg_type(0xC000),
            Err(ProtocolError::BadMessageClass(0xC000))
        ));
        assert!(matches!(
            decode_msg_type(0xFF01),
            Err(ProtocolError::BadMessageClass(0xFF01))
        ));
        // Bits 2-3 are method bits, not reserved: 0x000C has both of them
        // set and is the registered ConnectionAttempt request.
        assert_eq!(
            decode_msg_type(0x000C),
            Ok((Class::Request, Method::ConnectionAttempt))
        );
        // Unassigned methods fail on method lookup, never on the
        // reserved-bit check.  0x0002 is reserved by RFC 5389 section 18.1
        // and 0x0005 is simply unallocated -- neither sets a reserved bit.
        assert!(matches!(
            decode_msg_type(0x0002),
            Err(ProtocolError::UnknownMethod(0x0002))
        ));
        assert!(matches!(
            decode_msg_type(0x0005),
            Err(ProtocolError::UnknownMethod(0x0005))
        ));
        assert!(decode_msg_type(0x0001).is_ok());
    }

    #[test]
    fn unknown_methods_are_rejected() {
        assert!(matches!(
            Method::try_from_bits(0x0010),
            Err(ProtocolError::UnknownMethod(0x0010))
        ));
        assert!(matches!(
            Method::try_from_bits(0x1FFF),
            Err(ProtocolError::BadMethodNumber(0x1FFF))
        ));
    }

    #[test]
    fn error_codes_match_registry_values() {
        assert_eq!(ErrorCode::TryAlternate.number(), 300);
        assert_eq!(ErrorCode::BadRequest.number(), 400);
        assert_eq!(ErrorCode::Unauthorized.number(), 401);
        assert_eq!(ErrorCode::Forbidden.number(), 403);
        assert_eq!(ErrorCode::UnknownAttribute.number(), 420);
        assert_eq!(ErrorCode::AllocationMismatch.number(), 437);
        assert_eq!(ErrorCode::StaleNonce.number(), 438);
        assert_eq!(ErrorCode::UnsupportedAddressFamily.number(), 440);
        assert_eq!(ErrorCode::WrongCredentials.number(), 441);
        assert_eq!(ErrorCode::UnsupportedTransport.number(), 442);
        assert_eq!(ErrorCode::PeerAddressFamilyMismatch.number(), 443);
        assert_eq!(ErrorCode::RequestAllocationConflict.number(), 444);
        assert_eq!(ErrorCode::ConnectionTimeoutOrFailure.number(), 447);
        assert_eq!(ErrorCode::UnknownMethod.number(), 480);
        assert_eq!(ErrorCode::MethodNotImplemented.number(), 486);
        assert_eq!(ErrorCode::ResourceLimited.number(), 487);
        assert_eq!(ErrorCode::ServerError.number(), 500);
        assert_eq!(ErrorCode::InsufficientCapacity.number(), 508);
    }

    #[test]
    fn error_code_wire_form_splits_the_hundreds_digit() {
        // [Reserved:5][Class:3][Number:8]: Class = code / 100 (bits 8-10),
        // Number = code % 100 (bits 0-7).  Five bits are reserved because
        // the hundreds digit 4-6 needs three bits of its own; see
        // `ErrorCode::bits`.
        let cases = [
            (ErrorCode::TryAlternate, 0x0300u16),
            (ErrorCode::BadRequest, 0x0400),
            (ErrorCode::Forbidden, 0x0403),
            (ErrorCode::UnknownAttribute, 0x0414),
            (ErrorCode::AllocationMismatch, 0x0425),
            (ErrorCode::StaleNonce, 0x0426),
            (ErrorCode::UnsupportedAddressFamily, 0x0428),
            (ErrorCode::WrongCredentials, 0x0429),
            (ErrorCode::UnsupportedTransport, 0x042A),
            (ErrorCode::PeerAddressFamilyMismatch, 0x042B),
            (ErrorCode::RequestAllocationConflict, 0x042C),
            (ErrorCode::ConnectionTimeoutOrFailure, 0x042F),
            (ErrorCode::UnknownMethod, 0x0450),
            (ErrorCode::MethodNotImplemented, 0x0456),
            (ErrorCode::ResourceLimited, 0x0457),
            (ErrorCode::ServerError, 0x0500),
            (ErrorCode::InsufficientCapacity, 0x0508),
        ];
        for (code, wire) in cases {
            assert_eq!(code.bits(), wire, "{code:?}");
            // Reserved bits 11-15 stay zero and the wire form recovers the number.
            assert_eq!(code.bits() & 0xF800, 0);
            assert_eq!((wire >> 8) * 100 + (wire & 0x00FF), code.number());
        }
    }

    #[test]
    fn error_codes_carry_registry_reason_phrases() {
        assert_eq!(ErrorCode::BadRequest.reason_phrase(), "Bad Request");
        assert_eq!(ErrorCode::StaleNonce.reason_phrase(), "Stale Nonce");
        assert_eq!(
            ErrorCode::ConnectionTimeoutOrFailure.reason_phrase(),
            "Connection Timeout or Failure"
        );
        assert_eq!(
            ErrorCode::MethodNotImplemented.reason_phrase(),
            "Method Not Implemented"
        );
        assert_eq!(ErrorCode::ServerError.reason_phrase(), "Server Error");
        assert_eq!(
            ErrorCode::InsufficientCapacity.reason_phrase(),
            "Insufficient Capacity"
        );
    }

    #[test]
    fn class_bits_are_disjoint() {
        assert!(Class::Request.is_request());
        assert!(Class::Indication.is_indication());
        assert!(Class::Success.is_response() && Class::Error.is_response());
        assert!(!Class::Request.is_response());
    }

    #[test]
    fn only_binding_is_implemented_in_stage_2() {
        assert!(Method::Binding.is_implemented());
        assert!(!Method::Allocate.is_implemented());
        assert!(!Method::Refresh.is_implemented());
        assert!(!Method::Send.is_implemented());
        assert!(!Method::Data.is_implemented());
        assert!(!Method::Connect.is_implemented());
    }
}
