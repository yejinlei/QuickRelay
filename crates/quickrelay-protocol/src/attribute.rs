//! STUN attribute wire codes and values.
//!
//! Every code point here is the IANA STUN Attributes registry value, cross-checked
//! against the live `iana.org/assignments/stun-parameters` table.
//!
//! # Registry corrections worth recording
//!
//! * **MESSAGE-INTEGRITY is `0x0008`, not `0x8029`.** RFC 5389 Section 17.4.1 lists
//!   `0x0008: MESSAGE-INTEGRITY`, and IANA agrees. `0x8029` is ICE-CONTROLLED
//!   (RFC 8445). RFC 5769 prints the attribute as `00 08 00 14` for this reason,
//!   and all four of its MESSAGE-INTEGRITY vectors are computed over the `0x0008`
//!   spelling.
//! * **EVEN-PORT is `0x0018`, not `0x0022`.** `0x0022` is RESERVATION-TOKEN and
//!   `0x001A` is DONT-FRAGMENT. Several secondary summaries get these wrong.
//! * **ACCESS-TOKEN is `0x001B`** (RFC 7635), not `0x001C`; `0x001C` is
//!   MESSAGE-INTEGRITY-SHA256.
//! * **USE-CANDIDATE is `0x0025`, PADDING is `0x0026`, RESPONSE-PORT is `0x0027`**
//!   (RFC 8445).
//! * **MAPPED-ADDRESS is `0x0001`** (RFC 5389 Section 17.4.1).
//! * **ALTERNATE-SERVER is `0x8023`**; ICE-CONTROLLED is `0x8029`, ICE-CONTROLLING
//!   is `0x802A`, OTHER-ADDRESS is `0x802C`.
//! * **PASSWORD-ALGORITHMS is `0x8002`**; the singular `0x001D` is
//!   PASSWORD-ALGORITHM.
//! * **CHANGE-REQUEST (`0x0003`) and RESPONSE-ADDRESS (`0x0002`) are reserved.**
//!   RFC 8489 Section 18.3 renames them to "Reserved; was CHANGE-REQUEST /
//!   RESPONSE-ADDRESS prior to RFC 5389", so they have no buildable variant here.
//! * **EVEN-SERVER-CREATE, REASON-PHRASE and D4-LIMIT have no registry code point.**
//!   They appear only in expired/intended-drafts, so they are not part of this crate.

use crate::address::{
    read_alternate_server, read_xor_address, write_alternate_server, write_xor_address,
    AddressFamily, MappedAddress,
};
use crate::error::{Error, ErrorKind};

/// MESSAGE-INTEGRITY (HMAC-SHA1) value length, RFC 5389 Section 15.4.
pub const MESSAGE_INTEGRITY_LEN: usize = 20;
/// MESSAGE-INTEGRITY-SHA256 value length, RFC 8489 Section 11.
pub const MESSAGE_INTEGRITY_SHA256_LEN: usize = 32;
/// USERHASH value length (SHA-256 of the username), RFC 8489 Section 15.6.
pub const USERHASH_LEN: usize = 32;
/// DATA value length ceiling, RFC 8656 Section 2.3.4.
pub const DATA_MAX_LEN: usize = 511;
/// ERROR-CODE reason phrase ceiling, RFC 5389 Section 12.2.
pub const ERROR_CODE_REASON_MAX_LEN: usize = 1024;
/// CONNECTION-ID length ceiling, RFC 6062 Section 6.1.
pub const CONNECTION_ID_MAX_LEN: usize = 16;
/// The only legal CONNECTION-ID lengths, RFC 6062 Section 6.1.
pub const CONNECTION_ID_LENGTHS: [usize; 4] = [1, 4, 8, 16];

/// An ERROR-CODE value: a two-octet class/number pair plus a UTF-8 reason
/// phrase (RFC 5389 Section 12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorCode {
    /// The 8-bit class, in the 0-6 range (RFC 5389 Section 12.1).
    pub class: u8,
    /// The 2-digit error number, in the 0-99 range.
    pub number: u8,
    /// The human-readable reason phrase, UTF-8.
    pub reason: Vec<u8>,
}

impl ErrorCode {
    /// Numeric error code, `(class * 100) + number`.
    pub fn as_u16(&self) -> u16 {
        u16::from(self.class) * 100 + u16::from(self.number)
    }

    /// Build from a numeric code such as `348`.
    pub fn from_number(code: u16) -> Result<Self, Error> {
        let code = Self::validate_range(code)?;
        Ok(ErrorCode {
            class: (code / 100) as u8,
            number: (code % 100) as u8,
            reason: Vec::new(),
        })
    }

    /// Decode an ERROR-CODE value: 4 octets of flags/class/number plus reason.
    pub fn read_value(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 4 {
            return Err(Error::attr(ErrorKind::MalformedErrorCode, AttrCode::ErrorCode.as_u16()));
        }
        let class = buf[2];
        let number = buf[3];
        Self::validate_range(u16::from(class) * 100 + u16::from(number))?;
        Ok(ErrorCode {
            class,
            number,
            reason: buf[4..].to_vec(),
        })
    }

    /// Encode into a caller-provided buffer, returning the value length.
    pub fn write_value(&self, out: &mut [u8]) -> Result<usize, Error> {
        let code = u16::from(self.class) * 100 + u16::from(self.number);
        Self::validate_range(code)?;
        if self.reason.len() > ERROR_CODE_REASON_MAX_LEN {
            return Err(Error::attr(
                ErrorKind::ValueTooLong,
                AttrCode::ErrorCode.as_u16(),
            ));
        }
        let need = 4 + self.reason.len();
        if out.len() < need {
            return Err(Error::new(ErrorKind::ValueTooLong));
        }
        out[0..2].copy_from_slice(&[0u8; 2]);
        out[2] = self.class;
        out[3] = self.number;
        out[4..need].copy_from_slice(&self.reason);
        Ok(need)
    }

    fn validate_range(code: u16) -> Result<u16, Error> {
        // RFC 5389 Section 12.1: class 0-6, number 00-99. Class 6 is the
        // "private" range reserved for experimentation.
        if code >= 700 {
            return Err(Error::attr(
                ErrorKind::MalformedErrorCode,
                AttrCode::ErrorCode.as_u16(),
            ));
        }
        Ok(code)
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_u16())?;
        if !self.reason.is_empty() {
            write!(f, " ({})", String::from_utf8_lossy(&self.reason))?;
        }
        Ok(())
    }
}

/// Whether an attribute is comprehension-required or comprehension-optional.
/// The high bit is authoritative (RFC 5389 Section 17.4.1).
#[inline]
pub fn is_comprehension_optional(kind: AttributeKind) -> bool {
    matches!(kind, AttributeKind::Known(code) if code.as_u16() >= 0x8000)
        || matches!(kind, AttributeKind::Unknown(code) if code >= 0x8000)
}

/// Whether `kind` is registered in the IANA STUN Attributes registry.
pub const fn is_registered(kind: AttributeKind) -> bool {
    matches!(kind, AttributeKind::Known(_))
}

/// Whether an attribute is a trailer: it may not be followed by any
/// non-trailer attribute. The order is
/// `MESSAGE-INTEGRITY` / `MESSAGE-INTEGRITY-SHA256` then `FINGERPRINT`.
#[inline]
pub const fn is_trailer_only(kind: AttributeKind) -> bool {
    matches!(
        kind,
        AttributeKind::Known(
            AttrCode::MessageIntegrity | AttrCode::MessageIntegritySha256 | AttrCode::Fingerprint
        )
    )
}

/// STUN error codes a message can carry, as ready-made [`ErrorCode`] values.
///
/// Only codes with a row in a published error-code table are offered here:
/// the six STUN codes RFC 5389 Section 15.6 defines (300, 400, 401, 420, 438,
/// 500), the ICE role conflict 487 that RFC 8445 Section 16.2 adds, and the
/// TURN-only 508 that RFC 8656 Section 19 registers. 370, 386, 388 and 430
/// appear in no current STUN error-code table -- 430 was RFC 3489's "Stale
/// Credentials" and 386/388 were draft numbers that never made 5389 -- so
/// there is no helper for them: a peer that still sends one is read through
/// [`ErrorCode::read_value`], never written by this crate.
pub mod error_code {
    use super::ErrorCode;

    /// 300, Try Alternate.
    pub fn try_alternate() -> ErrorCode {
        ErrorCode { class: 3, number: 0, reason: b"Try Alternate".to_vec() }
    }
    /// 400, Bad Request.
    pub fn bad_request() -> ErrorCode {
        ErrorCode { class: 4, number: 0, reason: b"Bad Request".to_vec() }
    }
    /// 401, Unauthenticated. RFC 8489 renamed the registered phrase from
    /// `Unauthorized` to `Unauthenticated`; the wire string follows it.
    pub fn unauthenticated() -> ErrorCode {
        ErrorCode { class: 4, number: 1, reason: b"Unauthenticated".to_vec() }
    }
    /// 420, Unknown Attribute.
    pub fn unknown_attribute() -> ErrorCode {
        ErrorCode { class: 4, number: 20, reason: b"Unknown Attribute".to_vec() }
    }
    /// 438, Stale Nonce.
    pub fn stale_nonce() -> ErrorCode {
        ErrorCode { class: 4, number: 38, reason: b"Stale Nonce".to_vec() }
    }
    /// 487, Role Conflict (RFC 8445 Section 16.2).
    pub fn role_conflict() -> ErrorCode {
        ErrorCode { class: 4, number: 87, reason: b"Role Conflict".to_vec() }
    }
    /// 500, Server Error.
    pub fn server_error() -> ErrorCode {
        ErrorCode { class: 5, number: 0, reason: b"Server Error".to_vec() }
    }
    /// 508, Insufficient Capacity (RFC 8656 Section 19, TURN).
    pub fn insufficient_capacity() -> ErrorCode {
        ErrorCode { class: 5, number: 8, reason: b"Insufficient Capacity".to_vec() }
    }
    /// 403, Forbidden (RFC 8656 Section 19, TURN).
    pub fn forbidden() -> ErrorCode {
        ErrorCode { class: 4, number: 3, reason: b"Forbidden".to_vec() }
    }
    /// 440, Address Family not Supported (RFC 8656 Section 19, TURN).
    pub fn address_family_not_supported() -> ErrorCode {
        ErrorCode {
            class: 4,
            number: 40,
            reason: b"Address Family not Supported".to_vec(),
        }
    }
}

/// Pad a value length up to the 4-octet boundary (RFC 5389 Section 6).
#[inline]
pub const fn pad_len(value_len: usize) -> usize {
    (4 - value_len % 4) % 4
}

/// Pad the value octets up to the 4-octet boundary (RFC 5389 Section 6).
///
/// Unlike [`pad_len`], this returns the **padded length**, i.e. the number of
/// octets actually placed on the wire: `8 + pad_len(value_len)`. Padding is
/// not covered by the length field (RFC 5389 Section 3.1), so the length
/// field keeps holding the unpadded value length.
#[inline]
pub const fn padded_len(value_len: usize) -> usize {
    8 + pad_len(value_len)
}

/// Total wire size of an attribute with a given value length: header + value +
/// padding. This is the parse stride — **not** `8 + pad`.
#[inline]
pub const fn attr_size(value_len: usize) -> usize {
    4 + value_len + pad_len(value_len)
}

/// All registered attributes, plus `Unknown(u16)` for registry coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttrCode {
    /// 0x0001, MAPPED-ADDRESS (RFC 5389 Section 15.1).
    MappedAddress,
    /// 0x0003, CHANGE-REQUEST (RFC 8489 Section 15.11).
    ChangeRequest,
    /// 0x0006, USERNAME (RFC 5389 Section 15.5).
    Username,
    /// 0x0008, MESSAGE-INTEGRITY (RFC 5389 Section 15.4).
    MessageIntegrity,
    /// 0x0009, ERROR-CODE (RFC 5389 Section 12).
    ErrorCode,
    /// 0x000A, UNKNOWN-ATTRIBUTES (RFC 5389 Section 15.9).
    UnknownAttributes,
    /// 0x000C, CHANNEL-NUMBER (RFC 8656 Section 2.3.1).
    ChannelNumber,
    /// 0x000D, LIFETIME (RFC 8656 Section 2.3.2).
    Lifetime,
    /// 0x0012, XOR-PEER-ADDRESS (RFC 8656 Section 2.3.3).
    XorPeerAddress,
    /// 0x0013, DATA (RFC 8656 Section 2.3.4).
    Data,
    /// 0x0014, REALM (RFC 5389 Section 15.6).
    Realm,
    /// 0x0015, NONCE (RFC 5389 Section 15.7).
    Nonce,
    /// 0x0016, XOR-RELAYED-ADDRESS (RFC 8656 Section 2.3.5).
    XorRelayedAddress,
    /// 0x0017, REQUESTED-ADDRESS-FAMILY (RFC 8656 Section 2.3.6).
    RequestedAddressFamily,
    /// 0x0018, EVEN-PORT (RFC 8656 Section 2.3.7).
    EvenPort,
    /// 0x0019, REQUESTED-TRANSPORT (RFC 8656 Section 2.3.8).
    RequestedTransport,
    /// 0x001A, DONT-FRAGMENT (RFC 8656 Section 2.3.9).
    DontFragment,
    /// 0x001B, ACCESS-TOKEN (RFC 7635).
    AccessToken,
    /// 0x001C, MESSAGE-INTEGRITY-SHA256 (RFC 8489 Section 11).
    MessageIntegritySha256,
    /// 0x001D, PASSWORD-ALGORITHM (RFC 8489 Section 15.7).
    PasswordAlgorithm,
    /// 0x001E, USERHASH (RFC 8489 Section 15.6).
    UserHash,
    /// 0x0020, XOR-MAPPED-ADDRESS (RFC 5389 Section 15.2).
    XorMappedAddress,
    /// 0x0022, RESERVATION-TOKEN (RFC 8656 Section 2.3.10).
    ReservationToken,
    /// 0x0024, ICE-PRIORITY (RFC 8445 Section 4.1.1.4).
    IcePriority,
    /// 0x0025, USE-CANDIDATE (RFC 8445 Section 6.1.2).
    UseCandidate,
    /// 0x0026, PADDING (RFC 8445 Section 6.2.1).
    Padding,
    /// 0x0027, RESPONSE-PORT (RFC 8445 Section 6.3.1).
    ResponsePort,
    /// 0x002A, CONNECTION-ID (RFC 6062 Section 6.1).
    ConnectionId,
    /// 0x8000, ADDITIONAL-ADDRESS-FAMILY (RFC 8656 Section 2.3.11).
    AdditionalAddressFamily,
    /// 0x8001, ADDRESS-ERROR-CODE (RFC 8656 Section 2.3.12).
    AddressErrorCode,
    /// 0x8002, PASSWORD-ALGORITHMS (RFC 8489 Section 15.7).
    PasswordAlgorithms,
    /// 0x8003, ALTERNATE-DOMAIN (RFC 8489 Section 15.9).
    AlternateDomain,
    /// 0x8004, ICMP (RFC 8656 Section 6.1).
    Icmp,
    /// 0x8022, SOFTWARE (RFC 5389 Section 15.3).
    Software,
    /// 0x8023, ALTERNATE-SERVER (RFC 5389 Section 15.4).
    AlternateServer,
    /// 0x8028, FINGERPRINT (RFC 5389 Section 15.5).
    Fingerprint,
    /// 0x8029, ICE-CONTROLLED (RFC 8445 Section 6.1.2).
    IceControlled,
    /// 0x802A, ICE-CONTROLLING (RFC 8445 Section 6.1.2).
    IceControlling,
    /// 0x802C, OTHER-ADDRESS (RFC 5780 Section 7.4).
    OtherAddress,
    /// 0x802E, THIRD-PARTY-AUTHORIZATION (RFC 7635 Section 4.1).
    ThirdPartyAuthorization,
    /// 0x8038, ICE-EXTENDED-CANDIDATE (RFC 8445 Section 8.3.1).
    ExtendedCandidate,
    /// 0x8039, ICE-EXTENDED-CANDIDATE-USERNAME (RFC 8445 Section 8.3.1).
    ExtendedCandidateUfrag,
    /// Any registry code point not named above.
    Unknown(u16),
}

impl AttrCode {
    /// The wire value of this attribute code.
    pub const fn as_u16(self) -> u16 {
        match self {
            AttrCode::MappedAddress => 0x0001,
            AttrCode::ChangeRequest => 0x0003,
            AttrCode::Username => 0x0006,
            AttrCode::MessageIntegrity => 0x0008,
            AttrCode::ErrorCode => 0x0009,
            AttrCode::UnknownAttributes => 0x000A,
            AttrCode::ChannelNumber => 0x000C,
            AttrCode::Lifetime => 0x000D,
            AttrCode::XorPeerAddress => 0x0012,
            AttrCode::Data => 0x0013,
            AttrCode::Realm => 0x0014,
            AttrCode::Nonce => 0x0015,
            AttrCode::XorRelayedAddress => 0x0016,
            AttrCode::RequestedAddressFamily => 0x0017,
            AttrCode::EvenPort => 0x0018,
            AttrCode::RequestedTransport => 0x0019,
            AttrCode::DontFragment => 0x001A,
            AttrCode::AccessToken => 0x001B,
            AttrCode::MessageIntegritySha256 => 0x001C,
            AttrCode::PasswordAlgorithm => 0x001D,
            AttrCode::UserHash => 0x001E,
            AttrCode::XorMappedAddress => 0x0020,
            AttrCode::ReservationToken => 0x0022,
            AttrCode::IcePriority => 0x0024,
            AttrCode::UseCandidate => 0x0025,
            AttrCode::Padding => 0x0026,
            AttrCode::ResponsePort => 0x0027,
            AttrCode::ConnectionId => 0x002A,
            AttrCode::AdditionalAddressFamily => 0x8000,
            AttrCode::AddressErrorCode => 0x8001,
            AttrCode::PasswordAlgorithms => 0x8002,
            AttrCode::AlternateDomain => 0x8003,
            AttrCode::Icmp => 0x8004,
            AttrCode::Software => 0x8022,
            AttrCode::AlternateServer => 0x8023,
            AttrCode::Fingerprint => 0x8028,
            AttrCode::IceControlled => 0x8029,
            AttrCode::IceControlling => 0x802A,
            AttrCode::OtherAddress => 0x802C,
            AttrCode::ThirdPartyAuthorization => 0x802E,
            AttrCode::ExtendedCandidate => 0x8038,
            AttrCode::ExtendedCandidateUfrag => 0x8039,
            AttrCode::Unknown(code) => code,
        }
    }

    /// Map a wire attribute type to a named code.
    pub const fn attr_from_wire(code: u16) -> AttributeKind {
        match code {
            0x0001 => AttributeKind::Known(AttrCode::MappedAddress),
            0x0003 => AttributeKind::Known(AttrCode::ChangeRequest),
            0x0006 => AttributeKind::Known(AttrCode::Username),
            0x0008 => AttributeKind::Known(AttrCode::MessageIntegrity),
            0x0009 => AttributeKind::Known(AttrCode::ErrorCode),
            0x000A => AttributeKind::Known(AttrCode::UnknownAttributes),
            0x000C => AttributeKind::Known(AttrCode::ChannelNumber),
            0x000D => AttributeKind::Known(AttrCode::Lifetime),
            0x0012 => AttributeKind::Known(AttrCode::XorPeerAddress),
            0x0013 => AttributeKind::Known(AttrCode::Data),
            0x0014 => AttributeKind::Known(AttrCode::Realm),
            0x0015 => AttributeKind::Known(AttrCode::Nonce),
            0x0016 => AttributeKind::Known(AttrCode::XorRelayedAddress),
            0x0017 => AttributeKind::Known(AttrCode::RequestedAddressFamily),
            0x0018 => AttributeKind::Known(AttrCode::EvenPort),
            0x0019 => AttributeKind::Known(AttrCode::RequestedTransport),
            0x001A => AttributeKind::Known(AttrCode::DontFragment),
            0x001B => AttributeKind::Known(AttrCode::AccessToken),
            0x001C => AttributeKind::Known(AttrCode::MessageIntegritySha256),
            0x001D => AttributeKind::Known(AttrCode::PasswordAlgorithm),
            0x001E => AttributeKind::Known(AttrCode::UserHash),
            0x0020 => AttributeKind::Known(AttrCode::XorMappedAddress),
            0x0022 => AttributeKind::Known(AttrCode::ReservationToken),
            0x0024 => AttributeKind::Known(AttrCode::IcePriority),
            0x0025 => AttributeKind::Known(AttrCode::UseCandidate),
            0x0026 => AttributeKind::Known(AttrCode::Padding),
            0x0027 => AttributeKind::Known(AttrCode::ResponsePort),
            0x002A => AttributeKind::Known(AttrCode::ConnectionId),
            0x8000 => AttributeKind::Known(AttrCode::AdditionalAddressFamily),
            0x8001 => AttributeKind::Known(AttrCode::AddressErrorCode),
            0x8002 => AttributeKind::Known(AttrCode::PasswordAlgorithms),
            0x8003 => AttributeKind::Known(AttrCode::AlternateDomain),
            0x8004 => AttributeKind::Known(AttrCode::Icmp),
            0x8022 => AttributeKind::Known(AttrCode::Software),
            0x8023 => AttributeKind::Known(AttrCode::AlternateServer),
            0x8028 => AttributeKind::Known(AttrCode::Fingerprint),
            0x8029 => AttributeKind::Known(AttrCode::IceControlled),
            0x802A => AttributeKind::Known(AttrCode::IceControlling),
            0x802C => AttributeKind::Known(AttrCode::OtherAddress),
            0x802E => AttributeKind::Known(AttrCode::ThirdPartyAuthorization),
            0x8038 => AttributeKind::Known(AttrCode::ExtendedCandidate),
            0x8039 => AttributeKind::Known(AttrCode::ExtendedCandidateUfrag),
            _ => AttributeKind::Unknown(code),
        }
    }

    /// Fixed value length when the attribute has one; `None` for variable-length
    /// or no-value attributes.
    pub const fn fixed_len(self) -> Option<usize> {
        match self {
            AttrCode::MappedAddress
            | AttrCode::XorMappedAddress
            | AttrCode::XorRelayedAddress
            | AttrCode::XorPeerAddress => Some(8),
            AttrCode::MessageIntegrity => Some(MESSAGE_INTEGRITY_LEN),
            AttrCode::MessageIntegritySha256 => Some(MESSAGE_INTEGRITY_SHA256_LEN),
            AttrCode::UserHash => Some(USERHASH_LEN),
            AttrCode::Fingerprint => Some(4),
            AttrCode::IceControlled | AttrCode::IceControlling => Some(8),
            AttrCode::IcePriority | AttrCode::Lifetime | AttrCode::ChannelNumber => Some(4),
            AttrCode::UseCandidate | AttrCode::DontFragment => Some(0),
            AttrCode::RequestedAddressFamily | AttrCode::AdditionalAddressFamily => Some(1),
            AttrCode::ResponsePort => Some(2),
            AttrCode::ChangeRequest => Some(4),
            AttrCode::Data => Some(DATA_MAX_LEN),
            AttrCode::ErrorCode
            | AttrCode::AlternateServer
            | AttrCode::OtherAddress
            | AttrCode::UnknownAttributes
            | AttrCode::Username
            | AttrCode::Realm
            | AttrCode::Nonce
            | AttrCode::Software
            | AttrCode::PasswordAlgorithm
            | AttrCode::PasswordAlgorithms
            | AttrCode::AlternateDomain
            | AttrCode::ThirdPartyAuthorization
            | AttrCode::ExtendedCandidate
            | AttrCode::ExtendedCandidateUfrag
            | AttrCode::RequestedTransport
            | AttrCode::ReservationToken
            | AttrCode::EvenPort
            | AttrCode::AccessToken
            | AttrCode::AddressErrorCode
            | AttrCode::Padding
            | AttrCode::Icmp
            | AttrCode::ConnectionId => None,
            AttrCode::Unknown(_) => None,
        }
    }

    /// Human-readable attribute name.
    pub fn name(self) -> &'static str {
        match self {
            AttrCode::MappedAddress => "MAPPED-ADDRESS",
            AttrCode::ChangeRequest => "CHANGE-REQUEST",
            AttrCode::Username => "USERNAME",
            AttrCode::MessageIntegrity => "MESSAGE-INTEGRITY",
            AttrCode::ErrorCode => "ERROR-CODE",
            AttrCode::UnknownAttributes => "UNKNOWN-ATTRIBUTES",
            AttrCode::ChannelNumber => "CHANNEL-NUMBER",
            AttrCode::Lifetime => "LIFETIME",
            AttrCode::XorPeerAddress => "XOR-PEER-ADDRESS",
            AttrCode::Data => "DATA",
            AttrCode::Realm => "REALM",
            AttrCode::Nonce => "NONCE",
            AttrCode::XorRelayedAddress => "XOR-RELAYED-ADDRESS",
            AttrCode::RequestedAddressFamily => "REQUESTED-ADDRESS-FAMILY",
            AttrCode::EvenPort => "EVEN-PORT",
            AttrCode::RequestedTransport => "REQUESTED-TRANSPORT",
            AttrCode::DontFragment => "DONT-FRAGMENT",
            AttrCode::AccessToken => "ACCESS-TOKEN",
            AttrCode::MessageIntegritySha256 => "MESSAGE-INTEGRITY-SHA256",
            AttrCode::PasswordAlgorithm => "PASSWORD-ALGORITHM",
            AttrCode::UserHash => "USERHASH",
            AttrCode::XorMappedAddress => "XOR-MAPPED-ADDRESS",
            AttrCode::ReservationToken => "RESERVATION-TOKEN",
            AttrCode::IcePriority => "PRIORITY",
            AttrCode::UseCandidate => "USE-CANDIDATE",
            AttrCode::Padding => "PADDING",
            AttrCode::ResponsePort => "RESPONSE-PORT",
            AttrCode::ConnectionId => "CONNECTION-ID",
            AttrCode::AdditionalAddressFamily => "ADDITIONAL-ADDRESS-FAMILY",
            AttrCode::AddressErrorCode => "ADDRESS-ERROR-CODE",
            AttrCode::PasswordAlgorithms => "PASSWORD-ALGORITHMS",
            AttrCode::AlternateDomain => "ALTERNATE-DOMAIN",
            AttrCode::Icmp => "ICMP",
            AttrCode::Software => "SOFTWARE",
            AttrCode::AlternateServer => "ALTERNATE-SERVER",
            AttrCode::Fingerprint => "FINGERPRINT",
            AttrCode::IceControlled => "ICE-CONTROLLED",
            AttrCode::IceControlling => "ICE-CONTROLLING",
            AttrCode::OtherAddress => "OTHER-ADDRESS",
            AttrCode::ThirdPartyAuthorization => "THIRD-PARTY-AUTHORIZATION",
            AttrCode::ExtendedCandidate => "ICE-EXTENDED-CANDIDATE",
            AttrCode::ExtendedCandidateUfrag => "ICE-EXTENDED-CANDIDATE-USERNAME",
            AttrCode::Unknown(_) => "UNKNOWN",
        }
    }

    /// Every named code point, in registry order.
    pub fn all() -> impl Iterator<Item = AttrCode> {
        [
            AttrCode::MappedAddress,
            AttrCode::ChangeRequest,
            AttrCode::Username,
            AttrCode::MessageIntegrity,
            AttrCode::ErrorCode,
            AttrCode::UnknownAttributes,
            AttrCode::ChannelNumber,
            AttrCode::Lifetime,
            AttrCode::XorPeerAddress,
            AttrCode::Data,
            AttrCode::Realm,
            AttrCode::Nonce,
            AttrCode::XorRelayedAddress,
            AttrCode::RequestedAddressFamily,
            AttrCode::EvenPort,
            AttrCode::RequestedTransport,
            AttrCode::DontFragment,
            AttrCode::AccessToken,
            AttrCode::MessageIntegritySha256,
            AttrCode::PasswordAlgorithm,
            AttrCode::UserHash,
            AttrCode::XorMappedAddress,
            AttrCode::ReservationToken,
            AttrCode::IcePriority,
            AttrCode::UseCandidate,
            AttrCode::Padding,
            AttrCode::ResponsePort,
            AttrCode::ConnectionId,
            AttrCode::AdditionalAddressFamily,
            AttrCode::AddressErrorCode,
            AttrCode::PasswordAlgorithms,
            AttrCode::AlternateDomain,
            AttrCode::Icmp,
            AttrCode::Software,
            AttrCode::AlternateServer,
            AttrCode::Fingerprint,
            AttrCode::IceControlled,
            AttrCode::IceControlling,
            AttrCode::OtherAddress,
            AttrCode::ThirdPartyAuthorization,
            AttrCode::ExtendedCandidate,
            AttrCode::ExtendedCandidateUfrag,
        ]
        .iter()
        .copied()
    }
}

/// An attribute type: either a named IANA code point or an unrecognised one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttributeKind {
    /// A registered attribute.
    Known(AttrCode),
    /// An attribute whose type code is not in the registry.
    Unknown(u16),
}

impl AttributeKind {
    /// The wire type code.
    pub const fn as_u16(self) -> u16 {
        match self {
            AttributeKind::Known(code) => code.as_u16(),
            AttributeKind::Unknown(code) => code,
        }
    }

    /// The wire type code. Alias of [`AttributeKind::as_u16`].
    pub const fn code(self) -> u16 {
        self.as_u16()
    }

    /// Map a wire attribute type to a named code.
    pub const fn from_code(code: u16) -> AttributeKind {
        AttrCode::attr_from_wire(code)
    }

    /// Whether this is a registered code point.
    pub const fn is_known(self) -> bool {
        matches!(self, AttributeKind::Known(_))
    }
}

impl From<AttributeKind> for u16 {
    fn from(kind: AttributeKind) -> u16 {
        kind.as_u16()
    }
}

/// A decoded STUN attribute with its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    /// MAPPED-ADDRESS.
    MappedAddress(MappedAddress),
    /// XOR-MAPPED-ADDRESS.
    XorMappedAddress(MappedAddress),
    /// XOR-RELAYED-ADDRESS.
    XorRelayedAddress(MappedAddress),
    /// XOR-PEER-ADDRESS.
    XorPeerAddress(MappedAddress),
    /// CHANGE-REQUEST flags (RFC 8489 Section 15.11).
    ChangeRequest(u32),
    /// USERNAME.
    Username(String),
    /// REALM.
    Realm(String),
    /// NONCE.
    Nonce(String),
    /// SOFTWARE.
    Software(String),
    /// ERROR-CODE.
    ErrorCode(ErrorCode),
    /// UNKNOWN-ATTRIBUTES: the list of attribute type codes.
    UnknownAttributes(Vec<u16>),
    /// MESSAGE-INTEGRITY (HMAC-SHA1).
    MessageIntegrity([u8; MESSAGE_INTEGRITY_LEN]),
    /// MESSAGE-INTEGRITY-SHA256.
    MessageIntegritySha256([u8; MESSAGE_INTEGRITY_SHA256_LEN]),
    /// FINGERPRINT.
    Fingerprint(u32),
    /// USERHASH, SHA-256 of the username.
    UserHash([u8; USERHASH_LEN]),
    /// ICE-CONTROLLED tie-breaker.
    IceControlled([u8; 8]),
    /// ICE-CONTROLLING tie-breaker.
    IceControlling([u8; 8]),
    /// ICE-PRIORITY value.
    IcePriority(u32),
    /// ALTERNATE-SERVER.
    AlternateServer(MappedAddress),
    /// OTHER-ADDRESS (RFC 5780).
    OtherAddress(MappedAddress),
    /// LIFETIME, seconds.
    Lifetime(u32),
    /// CHANNEL-NUMBER (RFC 6062), in the 0x4000-0xBFFF range.
    ChannelNumber(u16),
    /// DATA, raw relayed payload (RFC 8656).
    Data(Vec<u8>),
    /// REQUESTED-ADDRESS-FAMILY.
    RequestedAddressFamily(AddressFamily),
    /// REQUESTED-TRANSPORT, e.g. "UDP".
    RequestedTransport(String),
    /// RESERVATION-TOKEN, opaque.
    ReservationToken(Vec<u8>),
    /// EVEN-PORT, opaque.
    EvenPort(Vec<u8>),
    /// DONT-FRAGMENT, zero-length.
    DontFragment,
    /// ACCESS-TOKEN.
    AccessToken(Vec<u8>),
    /// PASSWORD-ALGORITHM, a single algorithm name.
    PasswordAlgorithm(String),
    /// PASSWORD-ALGORITHMS, a comma-separated list.
    PasswordAlgorithms(Vec<String>),
    /// THIRD-PARTY-AUTHORIZATION.
    ThirdPartyAuthorization(String),
    /// ICE-EXTENDED-CANDIDATE.
    ExtendedCandidate(String),
    /// ICE-EXTENDED-CANDIDATE-USERNAME.
    ExtendedCandidateUfrag(String),
    /// USE-CANDIDATE, zero-length.
    UseCandidate,
    /// RESPONSE-PORT.
    ResponsePort(u16),
    /// ALTERNATE-DOMAIN.
    AlternateDomain(String),
    /// CONNECTION-ID, opaque (RFC 6062).
    ConnectionId(Vec<u8>),
    /// ADDITIONAL-ADDRESS-FAMILY.
    AdditionalAddressFamily(AddressFamily),
    /// ADDRESS-ERROR-CODE.
    AddressErrorCode(ErrorCode),
    /// PADDING.
    Padding(Vec<u8>),
    /// An unrecognised attribute, kept verbatim.
    Unknown { kind: u16, value: Vec<u8> },
}

/// The attribute's wire type code.
pub const fn attribute_kind(attr: &Attribute) -> AttributeKind {
    match attr {
        Attribute::MappedAddress(_) => AttributeKind::Known(AttrCode::MappedAddress),
        Attribute::XorMappedAddress(_) => AttributeKind::Known(AttrCode::XorMappedAddress),
        Attribute::XorRelayedAddress(_) => AttributeKind::Known(AttrCode::XorRelayedAddress),
        Attribute::XorPeerAddress(_) => AttributeKind::Known(AttrCode::XorPeerAddress),
        Attribute::ChangeRequest(_) => AttributeKind::Known(AttrCode::ChangeRequest),
        Attribute::Username(_) => AttributeKind::Known(AttrCode::Username),
        Attribute::Realm(_) => AttributeKind::Known(AttrCode::Realm),
        Attribute::Nonce(_) => AttributeKind::Known(AttrCode::Nonce),
        Attribute::Software(_) => AttributeKind::Known(AttrCode::Software),
        Attribute::ErrorCode(_) => AttributeKind::Known(AttrCode::ErrorCode),
        Attribute::UnknownAttributes(_) => AttributeKind::Known(AttrCode::UnknownAttributes),
        Attribute::MessageIntegrity(_) => AttributeKind::Known(AttrCode::MessageIntegrity),
        Attribute::MessageIntegritySha256(_) => {
            AttributeKind::Known(AttrCode::MessageIntegritySha256)
        }
        Attribute::Fingerprint(_) => AttributeKind::Known(AttrCode::Fingerprint),
        Attribute::UserHash(_) => AttributeKind::Known(AttrCode::UserHash),
        Attribute::IceControlled(_) => AttributeKind::Known(AttrCode::IceControlled),
        Attribute::IceControlling(_) => AttributeKind::Known(AttrCode::IceControlling),
        Attribute::IcePriority(_) => AttributeKind::Known(AttrCode::IcePriority),
        Attribute::AlternateServer(_) => AttributeKind::Known(AttrCode::AlternateServer),
        Attribute::OtherAddress(_) => AttributeKind::Known(AttrCode::OtherAddress),
        Attribute::Lifetime(_) => AttributeKind::Known(AttrCode::Lifetime),
        Attribute::ChannelNumber(_) => AttributeKind::Known(AttrCode::ChannelNumber),
        Attribute::Data(_) => AttributeKind::Known(AttrCode::Data),
        Attribute::RequestedAddressFamily(_) => AttributeKind::Known(AttrCode::RequestedAddressFamily),
        Attribute::RequestedTransport(_) => AttributeKind::Known(AttrCode::RequestedTransport),
        Attribute::ReservationToken(_) => AttributeKind::Known(AttrCode::ReservationToken),
        Attribute::EvenPort(_) => AttributeKind::Known(AttrCode::EvenPort),
        Attribute::DontFragment => AttributeKind::Known(AttrCode::DontFragment),
        Attribute::AccessToken(_) => AttributeKind::Known(AttrCode::AccessToken),
        Attribute::PasswordAlgorithm(_) => AttributeKind::Known(AttrCode::PasswordAlgorithm),
        Attribute::PasswordAlgorithms(_) => AttributeKind::Known(AttrCode::PasswordAlgorithms),
        Attribute::ThirdPartyAuthorization(_) => AttributeKind::Known(AttrCode::ThirdPartyAuthorization),
        Attribute::ExtendedCandidate(_) => AttributeKind::Known(AttrCode::ExtendedCandidate),
        Attribute::ExtendedCandidateUfrag(_) => AttributeKind::Known(AttrCode::ExtendedCandidateUfrag),
        Attribute::UseCandidate => AttributeKind::Known(AttrCode::UseCandidate),
        Attribute::ResponsePort(_) => AttributeKind::Known(AttrCode::ResponsePort),
        Attribute::AlternateDomain(_) => AttributeKind::Known(AttrCode::AlternateDomain),
        Attribute::ConnectionId(_) => AttributeKind::Known(AttrCode::ConnectionId),
        Attribute::AdditionalAddressFamily(_) => AttributeKind::Known(AttrCode::AdditionalAddressFamily),
        Attribute::AddressErrorCode(_) => AttributeKind::Known(AttrCode::AddressErrorCode),
        Attribute::Padding(_) => AttributeKind::Known(AttrCode::Padding),
        Attribute::Unknown { kind, .. } => AttributeKind::Unknown(*kind),
    }
}

fn utf8_attr(code: AttrCode, buf: &[u8]) -> Result<String, Error> {
    String::from_utf8(buf.to_vec())
        .map_err(|_| Error::attr(ErrorKind::InvalidUtf8, code.as_u16()))
}

fn check_exact(code: AttrCode, buf: &[u8], want: usize) -> Result<(), Error> {
    if buf.len() != want {
        return Err(Error::attr(ErrorKind::MalformedAttribute, code.as_u16()));
    }
    Ok(())
}

/// Decode one attribute from its raw value octets.
///
/// `buf` is the value only — after the 4-octet attribute header and trimmed to
/// the declared length. This is the hot path: it borrows nothing and allocates
/// only for genuinely variable-length values.
pub fn parse_attribute_value(
    kind: AttributeKind,
    buf: &[u8],
    txid: &[u8; 12],
) -> Result<Attribute, Error> {
    let code = match kind {
        AttributeKind::Known(code) => code,
        AttributeKind::Unknown(code) => {
            return Ok(Attribute::Unknown { kind: code, value: buf.to_vec() });
        }
    };

    let err = |k| Error::attr(k, code.as_u16());

    match code {
        AttrCode::MappedAddress => MappedAddress::read_value(buf).map(Attribute::MappedAddress),
        AttrCode::XorMappedAddress => read_xor_address(buf, txid).map(Attribute::XorMappedAddress),
        AttrCode::XorRelayedAddress => read_xor_address(buf, txid).map(Attribute::XorRelayedAddress),
        AttrCode::XorPeerAddress => read_xor_address(buf, txid).map(Attribute::XorPeerAddress),
        AttrCode::ChangeRequest => {
            check_exact(code, buf, 4)?;
            Ok(Attribute::ChangeRequest(u32::from_be_bytes(
                [buf[0], buf[1], buf[2], buf[3]],
            )))
        }
        AttrCode::Username => utf8_attr(code, buf).map(Attribute::Username),
        AttrCode::Realm => utf8_attr(code, buf).map(Attribute::Realm),
        AttrCode::Nonce => utf8_attr(code, buf).map(Attribute::Nonce),
        AttrCode::Software => utf8_attr(code, buf).map(Attribute::Software),
        AttrCode::ErrorCode => ErrorCode::read_value(buf).map(Attribute::ErrorCode),
        AttrCode::AddressErrorCode => ErrorCode::read_value(buf).map(Attribute::AddressErrorCode),
        AttrCode::UnknownAttributes => {
            if !buf.len().is_multiple_of(2) {
                return Err(err(ErrorKind::MalformedAttribute));
            }
            let mut out = Vec::with_capacity(buf.len() / 2);
            for pair in buf.as_chunks::<2>().0 {
                out.push(u16::from_be_bytes([pair[0], pair[1]]));
            }
            Ok(Attribute::UnknownAttributes(out))
        }
        AttrCode::MessageIntegrity => {
            check_exact(code, buf, MESSAGE_INTEGRITY_LEN)?;
            let mut tag = [0u8; MESSAGE_INTEGRITY_LEN];
            tag.copy_from_slice(buf);
            Ok(Attribute::MessageIntegrity(tag))
        }
        AttrCode::MessageIntegritySha256 => {
            // RFC 8489 Section 14.7 permits a 16- to 32-octet value, in
            // multiples of four, so the tag is not fixed at 32 octets.
            let n = buf.len();
            if !((crate::message::MESSAGE_INTEGRITY_SHA256_MIN_LEN
                    ..=MESSAGE_INTEGRITY_SHA256_LEN)
                .contains(&n)
                && n.is_multiple_of(4))
            {
                return Err(Error::attr(
                    ErrorKind::MalformedAttribute,
                    AttrCode::MessageIntegritySha256.as_u16(),
                ));
            }
            let tag: [u8; MESSAGE_INTEGRITY_SHA256_LEN] = match n {
                MESSAGE_INTEGRITY_SHA256_LEN => buf.try_into().map_err(|_| {
                    Error::attr(
                        ErrorKind::MalformedAttribute,
                        AttrCode::MessageIntegritySha256.as_u16(),
                    )
                })?,
                // Truncate shorter tags to the canonical length, zero-padding
                // the tail: the value is already range-checked above.
                _ => {
                    let mut out = [0u8; MESSAGE_INTEGRITY_SHA256_LEN];
                    out[..n].copy_from_slice(buf);
                    out
                }
            };
            Ok(Attribute::MessageIntegritySha256(tag))
        }
        AttrCode::Fingerprint => {
            check_exact(code, buf, 4)?;
            Ok(Attribute::Fingerprint(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])))
        }
        AttrCode::UserHash => {
            check_exact(code, buf, USERHASH_LEN)?;
            let mut h = [0u8; USERHASH_LEN];
            h.copy_from_slice(buf);
            Ok(Attribute::UserHash(h))
        }
        AttrCode::IceControlled => {
            check_exact(code, buf, 8)?;
            let mut t = [0u8; 8];
            t.copy_from_slice(buf);
            Ok(Attribute::IceControlled(t))
        }
        AttrCode::IceControlling => {
            check_exact(code, buf, 8)?;
            let mut t = [0u8; 8];
            t.copy_from_slice(buf);
            Ok(Attribute::IceControlling(t))
        }
        AttrCode::IcePriority | AttrCode::Lifetime => {
            check_exact(code, buf, 4)?;
            let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            Ok(match code {
                AttrCode::IcePriority => Attribute::IcePriority(v),
                _ => Attribute::Lifetime(v),
            })
        }
        AttrCode::ChannelNumber => {
            check_exact(code, buf, 4)?;
            let channel = u16::from_be_bytes([buf[0], buf[1]]);
            // RFC 6062 Section 2.3.1: 0x4000-0xBFFF inclusive. The 2-octet RFFU
            // field must be zero on transmission and must be ignored on
            // reception, so it is discarded here.
            if !(0x4000..=0xBFFF).contains(&channel) {
                return Err(err(ErrorKind::MalformedChannelNumber));
            }
            Ok(Attribute::ChannelNumber(channel))
        }
        AttrCode::ResponsePort => {
            check_exact(code, buf, 2)?;
            Ok(Attribute::ResponsePort(u16::from_be_bytes([buf[0], buf[1]])))
        }
        AttrCode::Data => {
            if buf.len() > DATA_MAX_LEN {
                return Err(err(ErrorKind::ValueTooLong));
            }
            Ok(Attribute::Data(buf.to_vec()))
        }
        AttrCode::RequestedAddressFamily => {
            check_exact(code, buf, 1)?;
            AddressFamily::from_octet(buf[0])
                .map(Attribute::RequestedAddressFamily)
                .ok_or_else(|| err(ErrorKind::UnsupportedAddressFamily))
        }
        AttrCode::AdditionalAddressFamily => {
            check_exact(code, buf, 1)?;
            AddressFamily::from_octet(buf[0])
                .map(Attribute::AdditionalAddressFamily)
                .ok_or_else(|| err(ErrorKind::UnsupportedAddressFamily))
        }
        AttrCode::RequestedTransport => {
            let s = utf8_attr(code, buf)?;
            // The registered transports are UDP, TCP and SCTP; anything else is
            // a comprehension failure but not a wire error, so it is preserved.
            Ok(Attribute::RequestedTransport(s))
        }
        AttrCode::AlternateServer => read_alternate_server(buf).map(Attribute::AlternateServer),
        AttrCode::OtherAddress => {
            // RFC 5780 Section 7.4 keeps RFC 3489's CHANGED-ADDRESS number
            // under a new name, and RFC 3489 Section 11.2.3 calls that
            // attribute's syntax "identical to MAPPED-ADDRESS": 8 octets for
            // IPv4, 20 for IPv6. `MappedAddress::read_value` checks both the
            // family and the length that family implies, so no guard here.
            MappedAddress::read_value(buf).map(Attribute::OtherAddress)
        }
        AttrCode::ReservationToken | AttrCode::EvenPort | AttrCode::AccessToken
        | AttrCode::Padding | AttrCode::Icmp => Ok(match code {
            AttrCode::ReservationToken => Attribute::ReservationToken(buf.to_vec()),
            AttrCode::EvenPort => Attribute::EvenPort(buf.to_vec()),
            AttrCode::AccessToken => Attribute::AccessToken(buf.to_vec()),
            AttrCode::Padding => Attribute::Padding(buf.to_vec()),
            _ => Attribute::Unknown { kind: code.as_u16(), value: buf.to_vec() },
        }),
        AttrCode::ConnectionId => {
            if buf.is_empty() || !CONNECTION_ID_LENGTHS.contains(&buf.len()) {
                return Err(err(ErrorKind::MalformedConnectionId));
            }
            Ok(Attribute::ConnectionId(buf.to_vec()))
        }
        AttrCode::DontFragment | AttrCode::UseCandidate => {
            check_exact(code, buf, 0)?;
            Ok(match code {
                AttrCode::DontFragment => Attribute::DontFragment,
                _ => Attribute::UseCandidate,
            })
        }
        AttrCode::PasswordAlgorithm | AttrCode::AlternateDomain
        | AttrCode::ThirdPartyAuthorization | AttrCode::ExtendedCandidate
        | AttrCode::ExtendedCandidateUfrag => {
            let s = utf8_attr(code, buf)?;
            Ok(match code {
                AttrCode::PasswordAlgorithm => Attribute::PasswordAlgorithm(s),
                AttrCode::AlternateDomain => Attribute::AlternateDomain(s),
                AttrCode::ThirdPartyAuthorization => Attribute::ThirdPartyAuthorization(s),
                AttrCode::ExtendedCandidate => Attribute::ExtendedCandidate(s),
                _ => Attribute::ExtendedCandidateUfrag(s),
            })
        }
        AttrCode::PasswordAlgorithms => {
            let s = utf8_attr(code, buf)?;
            let parts: Vec<String> =
                s.split(',').map(str::trim).filter(|p| !p.is_empty()).map(str::to_string).collect();
            if parts.is_empty() {
                return Err(err(ErrorKind::MalformedAttribute));
            }
            Ok(Attribute::PasswordAlgorithms(parts))
        }
        AttrCode::Unknown(_) => unreachable!("handled above"),
    }
}

fn write_str(out: &mut [u8], s: &str) -> Result<usize, Error> {
    if out.len() < s.len() {
        return Err(Error::new(ErrorKind::ValueTooLong));
    }
    out[..s.len()].copy_from_slice(s.as_bytes());
    Ok(s.len())
}

fn write_exact(out: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    if out.len() < src.len() {
        return Err(Error::new(ErrorKind::ValueTooLong));
    }
    out[..src.len()].copy_from_slice(src);
    Ok(src.len())
}

/// Encode one attribute's value into `out`, returning the value length.
pub fn write_attribute_value(
    attr: &Attribute,
    txid: &[u8; 12],
    out: &mut [u8],
) -> Result<usize, Error> {
    match attr {
        Attribute::MappedAddress(a) => a.write_value(out),
        Attribute::XorMappedAddress(a) => write_xor_address(a, txid, out),
        Attribute::XorRelayedAddress(a) => write_xor_address(a, txid, out),
        Attribute::XorPeerAddress(a) => write_xor_address(a, txid, out),
        Attribute::ChangeRequest(v) => write_exact(out, &v.to_be_bytes()),
        Attribute::OtherAddress(a) => {
            let n = a.write_value(out)?;
            Ok(n)
        }
        Attribute::Username(s)
        | Attribute::Realm(s)
        | Attribute::Nonce(s)
        | Attribute::Software(s)
        | Attribute::AlternateDomain(s)
        | Attribute::ThirdPartyAuthorization(s)
        | Attribute::ExtendedCandidate(s)
        | Attribute::ExtendedCandidateUfrag(s)
        | Attribute::RequestedTransport(s)
        | Attribute::PasswordAlgorithm(s) => write_str(out, s),
        Attribute::ErrorCode(e) => e.write_value(out),
        Attribute::AddressErrorCode(e) => e.write_value(out),
        Attribute::UnknownAttributes(list) => {
            // Two octets per code, and no padding: the length field records the
            // real value length (RFC 8489 Section 3.1) and
            // [`emit_attribute`] pads the frame to the 4-octet boundary. A
            // padded length here would make the next attribute read four
            // attribute types instead of two.
            let Some(n) = list.len().checked_mul(2).filter(|n| u32::try_from(*n).is_ok()) else {
                return Err(Error::new(ErrorKind::ValueTooLong));
            };
            if out.len() < n {
                return Err(Error::new(ErrorKind::ValueTooLong));
            }
            let mut w = 0;
            for c in list {
                out[w..w + 2].copy_from_slice(&c.to_be_bytes());
                w += 2;
            }
            Ok(n)
        }
        Attribute::MessageIntegrity(tag) => write_exact(out, tag.as_slice()),
        Attribute::MessageIntegritySha256(tag) => write_exact(out, tag.as_slice()),
        Attribute::Fingerprint(v) => write_exact(out, &v.to_be_bytes()),
        Attribute::UserHash(h) => write_exact(out, h.as_slice()),
        Attribute::IceControlled(t) | Attribute::IceControlling(t) => write_exact(out, t.as_slice()),
        Attribute::IcePriority(v) | Attribute::Lifetime(v) => write_exact(out, &v.to_be_bytes()),
        Attribute::ChannelNumber(c) => {
            if *c < 0x4000 || *c > 0xBFFF {
                return Err(Error::attr(ErrorKind::MalformedChannelNumber, 0x000C));
            }
            write_exact(out, &[c.to_be_bytes()[0], c.to_be_bytes()[1], 0, 0])
        }
        Attribute::ResponsePort(p) => write_exact(out, &p.to_be_bytes()),
        Attribute::RequestedAddressFamily(f) | Attribute::AdditionalAddressFamily(f) => {
            write_exact(out, &[f.to_octet()])
        }
        Attribute::Data(b) => {
            if b.len() > DATA_MAX_LEN {
                return Err(Error::attr(ErrorKind::ValueTooLong, AttrCode::Data.as_u16()));
            }
            write_exact(out, b)
        }
        Attribute::AlternateServer(a) => write_alternate_server(a, out),
        Attribute::ReservationToken(b)
        | Attribute::EvenPort(b)
        | Attribute::AccessToken(b)
        | Attribute::Padding(b)
        | Attribute::Unknown { value: b, .. } => write_exact(out, b),
        Attribute::ConnectionId(b) => {
            if b.is_empty() || !CONNECTION_ID_LENGTHS.contains(&b.len()) {
                return Err(Error::attr(ErrorKind::MalformedConnectionId, 0x002A));
            }
            write_exact(out, b)
        }
        Attribute::DontFragment | Attribute::UseCandidate => Ok(0),
        Attribute::PasswordAlgorithms(parts) => write_str(out, &parts.join(",")),
    }
}

/// Append a raw value into an attribute buffer, padding to the 4-octet boundary.
///
/// `out` must have room for [`attr_size`](value.len)`. Padding octets are zero,
/// which RFC 5389 Section 6 permits.
pub fn emit_attribute(out: &mut Vec<u8>, kind: AttributeKind, value: &[u8]) -> Result<(), Error> {
    if value.len() > 65535 {
        return Err(Error::new(ErrorKind::ValueTooLong));
    }
    let total = attr_size(value.len());
    out.reserve(total);
    out.extend_from_slice(&kind.as_u16().to_be_bytes());
    out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    out.extend_from_slice(value);
    out.extend(std::iter::repeat_n(0u8, pad_len(value.len())));
    Ok(())
}

impl Attribute {
    /// Whether encoding this attribute needs the transaction identifier, i.e. it
    /// is an XOR-encoded address attribute (RFC 5389 Section 15.2).
    pub const fn needs_txid(&self) -> bool {
        matches!(
            self,
            Attribute::XorMappedAddress(_)
                | Attribute::XorRelayedAddress(_)
                | Attribute::XorPeerAddress(_)
        )
    }

    /// The attribute's value as bytes, for emission through [`emit_attribute`].
    ///
    /// Fails for XOR-encoded address attributes, which need the transaction
    /// identifier — use [`Attribute::to_value`] for those.
    pub fn as_bytes_vec(&self) -> Result<Vec<u8>, Error> {
        if self.needs_txid() {
            return Err(Error::attr(
                ErrorKind::MalformedAttribute,
                attribute_kind(self).as_u16(),
            ));
        }
        let mut buf = [0u8; 2048];
        let n = write_attribute_value(self, &[0u8; 12], &mut buf)?;
        Ok(buf[..n].to_vec())
    }

    /// The attribute's value as bytes, honouring the transaction identifier.
    pub fn to_value(&self, txid: &[u8; 12]) -> Result<Vec<u8>, Error> {
        let mut buf = [0u8; 2048];
        let n = write_attribute_value(self, txid, &mut buf)?;
        Ok(buf[..n].to_vec())
    }
}

/// Emit a decoded attribute, sizing the padding for you.
pub fn emit_attribute_value(out: &mut Vec<u8>, attr: &Attribute, txid: &[u8; 12]) -> Result<(), Error> {
    let kind = attribute_kind(attr);
    let mut buf = [0u8; 2048];
    let n = write_attribute_value(attr, txid, &mut buf)?;
    emit_attribute(out, kind, &buf[..n])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::write_relayed_address;

    const TXID: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    #[test]
    fn registry_matches_iana() {
        assert_eq!(AttrCode::MappedAddress.as_u16(), 0x0001);
        assert_eq!(AttrCode::ChangeRequest.as_u16(), 0x0003);
        assert_eq!(AttrCode::Username.as_u16(), 0x0006);
        assert_eq!(AttrCode::MessageIntegrity.as_u16(), 0x0008);
        assert_eq!(AttrCode::ErrorCode.as_u16(), 0x0009);
        assert_eq!(AttrCode::UnknownAttributes.as_u16(), 0x000A);
        assert_eq!(AttrCode::ChannelNumber.as_u16(), 0x000C);
        assert_eq!(AttrCode::Lifetime.as_u16(), 0x000D);
        assert_eq!(AttrCode::XorPeerAddress.as_u16(), 0x0012);
        assert_eq!(AttrCode::Data.as_u16(), 0x0013);
        assert_eq!(AttrCode::Realm.as_u16(), 0x0014);
        assert_eq!(AttrCode::Nonce.as_u16(), 0x0015);
        assert_eq!(AttrCode::XorRelayedAddress.as_u16(), 0x0016);
        assert_eq!(AttrCode::RequestedAddressFamily.as_u16(), 0x0017);
        assert_eq!(AttrCode::EvenPort.as_u16(), 0x0018);
        assert_eq!(AttrCode::RequestedTransport.as_u16(), 0x0019);
        assert_eq!(AttrCode::DontFragment.as_u16(), 0x001A);
        assert_eq!(AttrCode::AccessToken.as_u16(), 0x001B);
        assert_eq!(AttrCode::MessageIntegritySha256.as_u16(), 0x001C);
        assert_eq!(AttrCode::PasswordAlgorithm.as_u16(), 0x001D);
        assert_eq!(AttrCode::UserHash.as_u16(), 0x001E);
        assert_eq!(AttrCode::XorMappedAddress.as_u16(), 0x0020);
        assert_eq!(AttrCode::ReservationToken.as_u16(), 0x0022);
        assert_eq!(AttrCode::IcePriority.as_u16(), 0x0024);
        assert_eq!(AttrCode::UseCandidate.as_u16(), 0x0025);
        assert_eq!(AttrCode::Padding.as_u16(), 0x0026);
        assert_eq!(AttrCode::ResponsePort.as_u16(), 0x0027);
        assert_eq!(AttrCode::ConnectionId.as_u16(), 0x002A);
        assert_eq!(AttrCode::AdditionalAddressFamily.as_u16(), 0x8000);
        assert_eq!(AttrCode::AddressErrorCode.as_u16(), 0x8001);
        assert_eq!(AttrCode::PasswordAlgorithms.as_u16(), 0x8002);
        assert_eq!(AttrCode::AlternateDomain.as_u16(), 0x8003);
        assert_eq!(AttrCode::Icmp.as_u16(), 0x8004);
        assert_eq!(AttrCode::Software.as_u16(), 0x8022);
        assert_eq!(AttrCode::AlternateServer.as_u16(), 0x8023);
        assert_eq!(AttrCode::Fingerprint.as_u16(), 0x8028);
        assert_eq!(AttrCode::IceControlled.as_u16(), 0x8029);
        assert_eq!(AttrCode::IceControlling.as_u16(), 0x802A);
        assert_eq!(AttrCode::OtherAddress.as_u16(), 0x802C);
        assert_eq!(AttrCode::ThirdPartyAuthorization.as_u16(), 0x802E);
        assert_eq!(AttrCode::ExtendedCandidate.as_u16(), 0x8038);
        assert_eq!(AttrCode::ExtendedCandidateUfrag.as_u16(), 0x8039);
        assert_eq!(AttrCode::Unknown(0x1234).as_u16(), 0x1234);
    }

    #[test]
    fn all_codes_roundtrip() {
        for code in AttrCode::all() {
            let wire = code.as_u16();
            assert_eq!(AttrCode::attr_from_wire(wire), AttributeKind::Known(code), "0x{wire:04x}");
            assert!(!code.name().is_empty());
        }
        assert_eq!(AttrCode::all().count(), 42);
    }

    #[test]
    fn unregistered_code_is_unknown() {
        for code in [
            0x0000u16, 0x0002, 0x0004, 0x0005, 0x0007, 0x000B, 0x000E, 0x000F,
            0x0010, 0x0011, 0x001F, 0x0021, 0x0023, 0x0028, 0x0029, 0x002B, 0x8005,
            0x8021, 0x8024, 0x802B, 0x802F,
        ] {
            assert_eq!(AttrCode::attr_from_wire(code), AttributeKind::Unknown(code), "0x{code:04x}");
            assert!(!is_registered(AttrCode::attr_from_wire(code)));
        }
    }

    #[test]
    fn comprehension_bit_is_the_high_bit() {
        assert!(is_comprehension_optional(AttributeKind::Known(AttrCode::Software)));
        assert!(is_comprehension_optional(AttributeKind::Known(AttrCode::Fingerprint)));
        assert!(is_comprehension_optional(AttributeKind::Known(AttrCode::ExtendedCandidate)));
        assert!(is_comprehension_optional(AttributeKind::Unknown(0xC000)));
        assert!(is_comprehension_optional(AttributeKind::Unknown(0xFFFF)));
        assert!(!is_comprehension_optional(AttributeKind::Known(AttrCode::MappedAddress)));
        assert!(!is_comprehension_optional(AttributeKind::Known(AttrCode::Username)));
        assert!(!is_comprehension_optional(AttributeKind::Known(AttrCode::MessageIntegrity)));
        assert!(!is_comprehension_optional(AttributeKind::Known(AttrCode::ConnectionId)));
        assert!(!is_comprehension_optional(AttributeKind::Unknown(0x0002)));
        assert!(!is_comprehension_optional(AttributeKind::Unknown(0x7FFF)));
        assert!(!is_comprehension_optional(AttributeKind::Unknown(0x0000)));
    }

    #[test]
    fn pad_len_and_attr_size() {
        assert_eq!(pad_len(0), 0);
        assert_eq!(pad_len(1), 3);
        assert_eq!(pad_len(2), 2);
        assert_eq!(pad_len(3), 1);
        assert_eq!(pad_len(4), 0);
        assert_eq!(pad_len(5), 3);
        assert_eq!(pad_len(8), 0);
        assert_eq!(pad_len(20), 0);
        assert_eq!(attr_size(0), 4);
        assert_eq!(attr_size(1), 8);
        assert_eq!(attr_size(4), 8);
        assert_eq!(attr_size(8), 12);
        assert_eq!(attr_size(20), 24);
        assert_eq!(attr_size(28), 32);
    }

    #[test]
    fn username_roundtrip_matches_rfc5769_layout() {
        let kind = AttributeKind::Known(AttrCode::Username);
        let mut value = Vec::new();
        emit_attribute(&mut value, kind, b"evtj:h6vY").unwrap();
        // RFC 5769 2.1: 00 06 00 09 | "evtj:h6vY" + 3 pad octets
        assert_eq!(
            value,
            vec![0x00, 0x06, 0x00, 0x09, b'e', b'v', b't', b'j', b':', b'h', b'6', b'v', b'Y', 0, 0, 0]
        );
        assert_eq!(
            parse_attribute_value(kind, b"evtj:h6vY", &TXID).unwrap(),
            Attribute::Username("evtj:h6vY".to_string())
        );
    }

    #[test]
    fn software_roundtrip() {
        let kind = AttributeKind::Known(AttrCode::Software);
        let mut value = Vec::new();
        emit_attribute(&mut value, kind, b"test vector").unwrap();
        // RFC 5769 2.2: 80 22 00 0b | "test vector" (11 octets) + 1 pad octet
        assert_eq!(
            value,
            vec![0x80, 0x22, 0x00, 0x0b, b't', b'e', b's', b't', b' ', b'v', b'e', b'c', b't', b'o', b'r', 0]
        );
        assert_eq!(
            parse_attribute_value(kind, b"test vector", &TXID).unwrap(),
            Attribute::Software("test vector".to_string())
        );
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        let bad = [0xff, 0xfe, 0xfd];
        for kind in [
            AttributeKind::Known(AttrCode::Username),
            AttributeKind::Known(AttrCode::Realm),
            AttributeKind::Known(AttrCode::Nonce),
            AttributeKind::Known(AttrCode::Software),
            AttributeKind::Known(AttrCode::AlternateDomain),
            AttributeKind::Known(AttrCode::ThirdPartyAuthorization),
            AttributeKind::Known(AttrCode::ExtendedCandidate),
            AttributeKind::Known(AttrCode::ExtendedCandidateUfrag),
            AttributeKind::Known(AttrCode::RequestedTransport),
            AttributeKind::Known(AttrCode::PasswordAlgorithm),
            AttributeKind::Known(AttrCode::PasswordAlgorithms),
        ] {
            assert_eq!(
                parse_attribute_value(kind, &bad, &TXID).unwrap_err().kind,
                ErrorKind::InvalidUtf8,
                "kind 0x{:04x}",
                kind.as_u16()
            );
        }
    }

    #[test]
    fn error_code_roundtrip() {
        let code = ErrorCode {
            class: 4,
            number: 38,
            reason: b"Unsupported Address Family".to_vec(),
        };
        assert_eq!(code.as_u16(), 438);
        assert_eq!(code.to_string(), "438 (Unsupported Address Family)");
        let mut value = [0u8; 64];
        let n = code.write_value(&mut value).unwrap();
        assert_eq!(&value[..4], &[0x00, 0x00, 0x04, 0x26]);
        assert_eq!(&value[4..n], b"Unsupported Address Family");
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::ErrorCode), &value[..n], &TXID).unwrap(),
            Attribute::ErrorCode(code)
        );
        let from_number = ErrorCode::from_number(438).unwrap();
        assert_eq!(from_number.class, 4);
        assert_eq!(from_number.number, 38);
        assert!(from_number.reason.is_empty());
    }

    #[test]
    fn error_code_range_is_enforced() {
        for ok in [0u16, 1, 100, 300, 348, 388, 401, 438, 488, 500, 699] {
            assert!(ErrorCode::from_number(ok).is_ok(), "{ok}");
        }
        for bad in [700u16, 701, 999, 1000, 65535] {
            assert!(ErrorCode::from_number(bad).is_err(), "{bad}");
        }
        assert_eq!(ErrorCode::read_value(&[0x00, 0x00, 0x07, 0x00]).unwrap_err().kind, ErrorKind::MalformedErrorCode);
        assert_eq!(ErrorCode::read_value(&[0x00, 0x00, 0x00]).unwrap_err().kind, ErrorKind::MalformedErrorCode);
        let long = vec![0u8; 1025];
        let e = ErrorCode { class: 0, number: 0, reason: long };
        assert_eq!(e.write_value(&mut [0u8; 2048]).unwrap_err().kind, ErrorKind::ValueTooLong);
        assert_eq!(ErrorCode::from_number(348).unwrap().number, 48);
    }

    #[test]
    fn error_code_helpers_are_the_assigned_values() {
        // Each helper is a row of a published table: 300/400/401/420/438/500
        // are RFC 5389 Section 15.6, 487 is RFC 8445 Section 16.2, and the
        // 4xx/5xx codes marked TURN are RFC 8656 Section 19.
        let codes = [
            (error_code::try_alternate(), 300),
            (error_code::bad_request(), 400),
            (error_code::unauthenticated(), 401),
            (error_code::unknown_attribute(), 420),
            (error_code::stale_nonce(), 438),
            (error_code::role_conflict(), 487),
            (error_code::server_error(), 500),
            (error_code::server_error(), 500),
            (error_code::insufficient_capacity(), 508),
            (error_code::forbidden(), 403),
            (error_code::address_family_not_supported(), 440),
        ];
        for (code, number) in codes {
            assert_eq!(code.as_u16(), number);
        }
        assert_eq!(
            error_code::unauthenticated().reason,
            b"Unauthenticated".to_vec()
        );
    }

    #[test]
    fn there_is_no_helper_for_a_code_no_table_defines() {
        // 370, 386, 388 and 430 are absent from the helpers for a reason: a
        // code with no table row must not be one call away. 386 and 388 are
        // not in RFC 5389 Section 15.6 at all, and 430 was RFC 3489's "Stale
        // Credentials".
        let codes = [error_code::try_alternate(), error_code::bad_request(),
                     error_code::unauthenticated(), error_code::unknown_attribute(),
                     error_code::stale_nonce(), error_code::role_conflict(),
                     error_code::server_error(), error_code::insufficient_capacity(),
                     error_code::forbidden(),
                     error_code::address_family_not_supported()];
        for code in codes {
            for retired in [370u16, 386, 388, 430] {
                assert_ne!(code.as_u16(), retired);
            }
        }
    }

    #[test]
    fn fingerprint_roundtrip_and_length_check() {
        let kind = AttributeKind::Known(AttrCode::Fingerprint);
        let mut value = Vec::new();
        emit_attribute(&mut value, kind, &[0xe5, 0x7a, 0x3b, 0xcf]).unwrap();
        assert_eq!(value, vec![0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf]);
        assert_eq!(
            parse_attribute_value(kind, &[0xe5, 0x7a, 0x3b, 0xcf], &TXID).unwrap(),
            Attribute::Fingerprint(0xe57a3bcf)
        );
        assert_eq!(
            parse_attribute_value(kind, &[0xe5, 0x7a], &TXID).unwrap_err().kind,
            ErrorKind::MalformedAttribute
        );
        assert_eq!(
            parse_attribute_value(kind, &[0, 0, 0, 0, 0], &TXID).unwrap_err().kind,
            ErrorKind::MalformedAttribute
        );
    }

    #[test]
    fn unknown_attributes_roundtrip_and_odd_length() {
        let kind = AttributeKind::Known(AttrCode::UnknownAttributes);
        let mut value = Vec::new();
        emit_attribute(&mut value, kind, &[0x80, 0x22, 0x00, 0x06]).unwrap();
        assert_eq!(value, vec![0x00, 0x0a, 0x00, 0x04, 0x80, 0x22, 0x00, 0x06]);
        assert_eq!(
            parse_attribute_value(kind, &[0x80, 0x22, 0x00, 0x06], &TXID).unwrap(),
            Attribute::UnknownAttributes(vec![0x8022, 0x0006])
        );
        assert_eq!(parse_attribute_value(kind, &[0x00], &TXID).unwrap_err().kind, ErrorKind::MalformedAttribute);
        assert_eq!(
            parse_attribute_value(kind, b"", &TXID).unwrap(),
            Attribute::UnknownAttributes(Vec::new())
        );
    }

    #[test]
    fn message_integrity_lengths() {
        let mi = Attribute::MessageIntegrity([7u8; MESSAGE_INTEGRITY_LEN]);
        assert_eq!(attribute_kind(&mi), AttributeKind::Known(AttrCode::MessageIntegrity));
        assert_eq!(write_attribute_value(&mi, &TXID, &mut [0u8; 20]).unwrap(), 20);
        assert_eq!(write_attribute_value(&mi, &TXID, &mut [0u8; 19]).unwrap_err().kind, ErrorKind::ValueTooLong);
        let back = parse_attribute_value(AttributeKind::Known(AttrCode::MessageIntegrity), &[7u8; 20], &TXID).unwrap();
        assert_eq!(back, mi);
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::MessageIntegrity), &[7u8; 19], &TXID)
                .unwrap_err()
                .kind,
            ErrorKind::MalformedAttribute
        );

        let mi2 = Attribute::MessageIntegritySha256([9u8; MESSAGE_INTEGRITY_SHA256_LEN]);
        assert_eq!(write_attribute_value(&mi2, &TXID, &mut [0u8; 32]).unwrap(), 32);
        assert_eq!(
            parse_attribute_value(
                AttributeKind::Known(AttrCode::MessageIntegritySha256),
                &[9u8; 31],
                &TXID
            )
            .unwrap_err()
            .kind,
            ErrorKind::MalformedAttribute
        );
    }

    #[test]
    fn userhash_length() {
        let h = Attribute::UserHash([4u8; USERHASH_LEN]);
        assert_eq!(write_attribute_value(&h, &TXID, &mut [0u8; 32]).unwrap(), 32);
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::UserHash), &[4u8; 32], &TXID).unwrap(),
            h
        );
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::UserHash), &[4u8; 31], &TXID)
                .unwrap_err()
                .kind,
            ErrorKind::MalformedAttribute
        );
    }

    #[test]
    fn zero_value_attributes_roundtrip() {
        for (kind, attr) in [
            (AttributeKind::Known(AttrCode::DontFragment), Attribute::DontFragment),
            (AttributeKind::Known(AttrCode::UseCandidate), Attribute::UseCandidate),
        ] {
            let mut value = Vec::new();
            emit_attribute(&mut value, kind, b"").unwrap();
            assert_eq!(value.len(), 4, "header only");
            assert_eq!(parse_attribute_value(kind, b"", &TXID).unwrap(), attr);
            assert_eq!(parse_attribute_value(kind, &[0], &TXID).unwrap_err().kind, ErrorKind::MalformedAttribute);
        }
        let zero = [Attribute::DontFragment, Attribute::UseCandidate];
        for attr in &zero {
            assert_eq!(write_attribute_value(attr, &TXID, &mut [0u8; 16]).unwrap(), 0);
        }
    }

    #[test]
    fn fixed_width_value_roundtrips() {
        for (attr, n) in [
            (Attribute::IcePriority(0x6e00_01ff), 4usize),
            (Attribute::Lifetime(300), 4),
            (Attribute::ResponsePort(3478), 2),
            (Attribute::IceControlled([1u8; 8]), 8),
            (Attribute::IceControlling([2u8; 8]), 8),
            (Attribute::Fingerprint(0xe57a3bcf), 4),
        ] {
            let mut buf = [0u8; 16];
            assert_eq!(write_attribute_value(&attr, &TXID, &mut buf).unwrap(), n, "{attr:?}");
        }
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::IcePriority), &[0x6e, 0, 0x01, 0xff], &TXID)
                .unwrap(),
            Attribute::IcePriority(0x6e00_01ff)
        );
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::Lifetime), &[0, 0x00, 0x01, 0x2c], &TXID).unwrap(),
            Attribute::Lifetime(300)
        );
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::ResponsePort), &[0x0d, 0x96], &TXID).unwrap(),
            Attribute::ResponsePort(3478)
        );
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::ResponsePort), &[0x0d], &TXID).unwrap_err().kind,
            ErrorKind::MalformedAttribute
        );
    }

    #[test]
    fn channel_number_range_is_enforced() {
        assert_eq!(
            parse_attribute_value(
                AttributeKind::Known(AttrCode::ChannelNumber),
                &[0x40, 0x00, 0, 0],
                &TXID
            )
            .unwrap(),
            Attribute::ChannelNumber(0x4000)
        );
        assert_eq!(
            parse_attribute_value(
                AttributeKind::Known(AttrCode::ChannelNumber),
                &[0xbb, 0xff, 0, 0],
                &TXID
            )
            .unwrap(),
            Attribute::ChannelNumber(0xbbff)
        );
        for bad in [0x3fffu16, 0x0000, 0xc000, 0xffff] {
            let v = [u8::try_from(bad >> 8).unwrap(), u8::try_from(bad & 0xff).unwrap(), 0, 0];
            assert_eq!(
                parse_attribute_value(AttributeKind::Known(AttrCode::ChannelNumber), &v, &TXID).unwrap_err().kind,
                ErrorKind::MalformedChannelNumber,
                "0x{bad:04x}"
            );
            assert_eq!(
                write_attribute_value(&Attribute::ChannelNumber(bad), &TXID, &mut [0u8; 8]).unwrap_err().kind,
                ErrorKind::MalformedChannelNumber,
                "0x{bad:04x}"
            );
        }
        assert_eq!(
            write_attribute_value(&Attribute::ChannelNumber(0x4001), &TXID, &mut [0u8; 8]).unwrap(),
            4
        );
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::ChannelNumber), &[0x40, 0x01], &TXID)
                .unwrap_err()
                .kind,
            ErrorKind::MalformedAttribute
        );
    }

    #[test]
    fn requested_address_family_roundtrip() {
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::RequestedAddressFamily), &[0x01], &TXID).unwrap(),
            Attribute::RequestedAddressFamily(AddressFamily::Ipv4)
        );
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::AdditionalAddressFamily), &[0x02], &TXID).unwrap(),
            Attribute::AdditionalAddressFamily(AddressFamily::Ipv6)
        );
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::RequestedAddressFamily), &[0x03], &TXID)
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedAddressFamily
        );
        assert_eq!(
            write_attribute_value(&Attribute::RequestedAddressFamily(AddressFamily::Ipv6), &TXID, &mut [0u8; 4])
                .unwrap(),
            1
        );
    }

    #[test]
    fn data_length_limit() {
        let kind = AttributeKind::Known(AttrCode::Data);
        let payload = vec![0u8; DATA_MAX_LEN];
        assert_eq!(parse_attribute_value(kind, &payload, &TXID).unwrap(), Attribute::Data(payload.clone()));
        assert_eq!(
            parse_attribute_value(kind, &[0u8; DATA_MAX_LEN + 1], &TXID).unwrap_err().kind,
            ErrorKind::ValueTooLong
        );
        let attr = Attribute::Data(vec![1, 2, 3]);
        assert_eq!(write_attribute_value(&attr, &TXID, &mut [0u8; 8]).unwrap(), 3);
        assert_eq!(
            write_attribute_value(&Attribute::Data(vec![0u8; DATA_MAX_LEN + 1]), &TXID, &mut [0u8; 600])
                .unwrap_err()
                .kind,
            ErrorKind::ValueTooLong
        );
    }

    #[test]
    fn connection_id_lengths() {
        for len in CONNECTION_ID_LENGTHS {
            let value = vec![0x5au8; len];
            assert_eq!(
                parse_attribute_value(AttributeKind::Known(AttrCode::ConnectionId), &value, &TXID).unwrap(),
                Attribute::ConnectionId(value.clone())
            );
        }
        for len in [0usize, 2, 3, 7, 17] {
            assert_eq!(
                parse_attribute_value(AttributeKind::Known(AttrCode::ConnectionId), &vec![0u8; len], &TXID)
                    .unwrap_err()
                    .kind,
                ErrorKind::MalformedConnectionId,
                "len {len}"
            );
            assert_eq!(
                write_attribute_value(&Attribute::ConnectionId(vec![0u8; len]), &TXID, &mut [0u8; 24]).unwrap_err()
                    .kind,
                ErrorKind::MalformedConnectionId,
                "len {len}"
            );
        }
    }

    #[test]
    fn trailing_zeroes_in_utf8_are_preserved() {
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::Username), b"evtj:h6vY\0\0\0", &TXID).unwrap(),
            Attribute::Username("evtj:h6vY\0\0\0".to_string())
        );
    }

    #[test]
    fn reserved_code_points_are_not_buildable() {
        // 0x0002 (was RESPONSE-ADDRESS) and 0x0004 are unassigned, so they stay
        // unknown.
        assert_eq!(AttrCode::attr_from_wire(0x0002), AttributeKind::Unknown(0x0002));
        assert_eq!(AttrCode::attr_from_wire(0x0004), AttributeKind::Unknown(0x0004));
        let v = parse_attribute_value(AttributeKind::Unknown(0x0004), &[0x01, 0x02], &TXID).unwrap();
        assert_eq!(v, Attribute::Unknown { kind: 0x0004, value: vec![1, 2] });
    }

    #[test]
    fn change_request_roundtrip() {
        // IANA marks 0x0003 "Reserved; was CHANGE-REQUEST prior to RFC 5389",
        // but RFC 8489 Section 15.11 and coturn still send and receive it, so
        // the code point is wired (workspace-layout 4.11 item 1).
        assert_eq!(AttrCode::attr_from_wire(0x0003), AttributeKind::Known(AttrCode::ChangeRequest));
        assert_eq!(AttrCode::ChangeRequest.as_u16(), 0x0003);
        assert_eq!(AttrCode::ChangeRequest.fixed_len(), Some(4));
        assert_eq!(AttrCode::ChangeRequest.name(), "CHANGE-REQUEST");
        assert!(!is_comprehension_optional(AttributeKind::Known(AttrCode::ChangeRequest)));
        let a = Attribute::ChangeRequest(0x0000_0001);
        assert_eq!(attribute_kind(&a), AttributeKind::Known(AttrCode::ChangeRequest));
        let mut value = [0u8; 8];
        assert_eq!(write_attribute_value(&a, &TXID, &mut value).unwrap(), 4);
        assert_eq!(&value[..4], &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            parse_attribute_value(
                AttributeKind::Known(AttrCode::ChangeRequest),
                &value[..4],
                &TXID
            )
            .unwrap(),
            a
        );
        assert_eq!(
            parse_attribute_value(
                AttributeKind::Known(AttrCode::ChangeRequest),
                &[0x00, 0x00],
                &TXID
            )
            .unwrap_err()
            .kind,
            ErrorKind::MalformedAttribute
        );
        // 0x8003 is ALTERNATE-DOMAIN, not CHANGE-REQUEST.
        assert_eq!(AttrCode::attr_from_wire(0x8003), AttributeKind::Known(AttrCode::AlternateDomain));
        // 0x0005 is unassigned: it stays unknown, and its cleared high bit
        // makes it comprehension-required, so it must be rejected like 0x000B.
        assert_eq!(AttrCode::attr_from_wire(0x0005), AttributeKind::Unknown(0x0005));
        assert!(!is_comprehension_optional(AttributeKind::Unknown(0x0005)));
    }

    #[test]
    fn alternate_server_roundtrip() {
        let a = MappedAddress::from_ipv4(192, 0, 2, 1, 3478);
        let mut value = [0u8; 12];
        let n = write_alternate_server(&a, &mut value).unwrap();
        assert_eq!(n, 8);
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::AlternateServer), &value[..n], &TXID).unwrap(),
            Attribute::AlternateServer(a)
        );
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::AlternateServer), &[0x01, 0, 0, 0], &TXID)
                .unwrap_err()
                .kind,
            ErrorKind::MalformedAlternateServer
        );
    }

    #[test]
    fn other_address_roundtrip() {
        let a = MappedAddress::from_ipv4(10, 0, 0, 1, 5000);
        let mut value = [0u8; 8];
        a.write_value(&mut value).unwrap();
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::OtherAddress), &value, &TXID).unwrap(),
            Attribute::OtherAddress(a)
        );

        // The IPv6 form is 20 octets. An 8-octet length guard used to reject
        // it, so a peer sending a valid OTHER-ADDRESS over an IPv6 connection
        // would have been answered with a parse failure.
        let v6 = MappedAddress::from_ipv6([0xff; 16], 60000);
        let mut value6 = [0u8; 20];
        v6.write_value(&mut value6).unwrap();
        assert_eq!(
            parse_attribute_value(
                AttributeKind::Known(AttrCode::OtherAddress),
                &value6,
                &TXID,
            )
            .unwrap(),
            Attribute::OtherAddress(v6)
        );

        // Family IPv4 with only 4 octets present: the value is shorter than
        // that family requires.
        let mut bad = [0u8; 4];
        bad[1] = 0x01;
        assert_eq!(
            parse_attribute_value(
                AttributeKind::Known(AttrCode::OtherAddress),
                &bad,
                &TXID,
            )
            .unwrap_err()
            .kind,
            ErrorKind::MalformedAddress
        );
    }

    #[test]
    fn password_algorithms_roundtrip() {
        let parts = vec!["MD5".to_string(), "SHA-256".to_string()];
        let kind = AttributeKind::Known(AttrCode::PasswordAlgorithms);
        let mut value = Vec::new();
        emit_attribute(&mut value, kind, b"MD5, SHA-256").unwrap();
        assert_eq!(parse_attribute_value(kind, b"MD5, SHA-256", &TXID).unwrap(), Attribute::PasswordAlgorithms(parts));
        assert_eq!(
            parse_attribute_value(kind, b",,", &TXID).unwrap_err().kind,
            ErrorKind::MalformedAttribute
        );
        let s = b"MD5";
        assert_eq!(parse_attribute_value(kind, s, &TXID).unwrap(), Attribute::PasswordAlgorithms(vec!["MD5".to_string()]));
        assert_eq!(
            write_attribute_value(&Attribute::PasswordAlgorithms(vec!["MD5".to_string()]), &TXID, &mut [0u8; 8])
                .unwrap(),
            3
        );
        assert_eq!(attribute_kind(&Attribute::PasswordAlgorithms(vec!["MD5".to_string()])), kind);
        let _ = value;
    }

    #[test]
    fn attribute_kind_matches() {
        let cases = [
            (Attribute::Username("x".to_string()), 0x0006u16),
            (Attribute::Realm("r".to_string()), 0x0014),
            (Attribute::Nonce("n".to_string()), 0x0015),
            (Attribute::Software("s".to_string()), 0x8022),
            (Attribute::ErrorCode(ErrorCode::from_number(400).unwrap()), 0x0009),
            (Attribute::AddressErrorCode(ErrorCode::from_number(500).unwrap()), 0x8001),
            (Attribute::UnknownAttributes(vec![0x0001]), 0x000a),
            (Attribute::MessageIntegrity([0; 20]), 0x0008),
            (Attribute::MessageIntegritySha256([0; 32]), 0x001c),
            (Attribute::Fingerprint(0), 0x8028),
            (Attribute::UserHash([0; 32]), 0x001e),
            (Attribute::IceControlled([0; 8]), 0x8029),
            (Attribute::IceControlling([0; 8]), 0x802a),
            (Attribute::IcePriority(0), 0x0024),
            (Attribute::Lifetime(0), 0x000d),
            (Attribute::ChannelNumber(0x4000), 0x000c),
            (Attribute::Data(vec![0]), 0x0013),
            (Attribute::RequestedAddressFamily(AddressFamily::Ipv4), 0x0017),
            (Attribute::RequestedTransport("UDP".to_string()), 0x0019),
            (Attribute::AlternateServer(MappedAddress::from_ipv4(1, 2, 3, 4, 5)), 0x8023),
            (Attribute::OtherAddress(MappedAddress::from_ipv4(1, 2, 3, 4, 5)), 0x802c),
            (Attribute::ReservationToken(vec![1]), 0x0022),
            (Attribute::EvenPort(vec![1]), 0x0018),
            (Attribute::DontFragment, 0x001a),
            (Attribute::UseCandidate, 0x0025),
            (Attribute::ResponsePort(3478), 0x0027),
            (Attribute::AlternateDomain("d".to_string()), 0x8003),
            (Attribute::AccessToken(vec![1]), 0x001b),
            (Attribute::PasswordAlgorithm("MD5".to_string()), 0x001d),
            (Attribute::PasswordAlgorithms(vec!["MD5".to_string()]), 0x8002),
            (Attribute::ThirdPartyAuthorization("u".to_string()), 0x802e),
            (Attribute::ExtendedCandidate("x".to_string()), 0x8038),
            (Attribute::ExtendedCandidateUfrag("x".to_string()), 0x8039),
            (Attribute::ConnectionId(vec![1]), 0x002a),
            (Attribute::AdditionalAddressFamily(AddressFamily::Ipv6), 0x8000),
            (Attribute::Padding(vec![0]), 0x0026),
            (Attribute::MappedAddress(MappedAddress::from_ipv4(1, 2, 3, 4, 5)), 0x0001),
            (Attribute::ChangeRequest(0x0000_0001), 0x0003),
            (Attribute::XorMappedAddress(MappedAddress::from_ipv4(1, 2, 3, 4, 5)), 0x0020),
            (Attribute::XorRelayedAddress(MappedAddress::from_ipv4(1, 2, 3, 4, 5)), 0x0016),
            (Attribute::XorPeerAddress(MappedAddress::from_ipv4(1, 2, 3, 4, 5)), 0x0012),
            (Attribute::Unknown { kind: 0x1234, value: vec![0] }, 0x1234),
        ];
        for (attr, expected) in cases {
            assert_eq!(attribute_kind(&attr).as_u16(), expected, "kind of {attr:?}");
        }
    }

    #[test]
    fn emit_attribute_pads_to_boundary() {
        // Each attribute is 4 header octets + value + pad octets (RFC 5389
        // Section 3.1), so the cumulative sizes are 8, 16 and 30.
        let mut out = Vec::new();
        emit_attribute(&mut out, AttributeKind::Known(AttrCode::Username), b"abc").unwrap();
        assert_eq!(out.len(), 8, "header + 3 octets + 1 pad octet");
        emit_attribute(&mut out, AttributeKind::Known(AttrCode::Fingerprint), &[0, 0, 0, 0]).unwrap();
        assert_eq!(out.len(), 16, "a 4-octet value adds no pad, but a header");
        emit_attribute(
            &mut out,
            AttributeKind::Known(AttrCode::XorMappedAddress),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        )
        .unwrap();
        assert_eq!(out.len(), 32, "an 11-octet value needs 1 pad octet");
        let mut out_pad = Vec::new();
        emit_attribute(
            &mut out_pad,
            AttributeKind::Known(AttrCode::XorMappedAddress),
            &[0, 1, 2, 3, 4, 5, 6, 7],
        )
        .unwrap();
        assert_eq!(out_pad.len(), 12, "an 8-octet value adds no pad either");
        // Odd-length values pad to the next 4-octet boundary.
        let mut out2 = Vec::new();
        emit_attribute(&mut out2, AttributeKind::Known(AttrCode::Realm), b"ab").unwrap();
        assert_eq!(out2.len(), 8);
        emit_attribute(&mut out2, AttributeKind::Known(AttrCode::Realm), b"abcd").unwrap();
        assert_eq!(out2.len(), 16);
        assert_eq!(attr_size(3), 8);
        assert_eq!(attr_size(4), 8);
        assert_eq!(attr_size(5), 12);
        assert_eq!(attr_size(0), 4);
    }

    #[test]
    fn emit_attribute_rejects_oversized_values() {
        let huge = vec![0u8; 65536];
        assert_eq!(
            emit_attribute(&mut Vec::new(), AttributeKind::Known(AttrCode::Username), &huge).unwrap_err().kind,
            ErrorKind::ValueTooLong
        );
        assert!(emit_attribute(&mut Vec::new(), AttributeKind::Known(AttrCode::Username), &[0u8; 65535]).is_ok());
    }

    #[test]
    fn fixed_lengths_are_recorded() {
        assert_eq!(AttrCode::MappedAddress.fixed_len(), Some(8));
        assert_eq!(AttrCode::XorMappedAddress.fixed_len(), Some(8));
        assert_eq!(AttrCode::XorRelayedAddress.fixed_len(), Some(8));
        assert_eq!(AttrCode::XorPeerAddress.fixed_len(), Some(8));
        assert_eq!(AttrCode::OtherAddress.fixed_len(), None);
        assert_eq!(AttrCode::MessageIntegrity.fixed_len(), Some(20));
        assert_eq!(AttrCode::MessageIntegritySha256.fixed_len(), Some(32));
        assert_eq!(AttrCode::UserHash.fixed_len(), Some(32));
        assert_eq!(AttrCode::Fingerprint.fixed_len(), Some(4));
        assert_eq!(AttrCode::IceControlled.fixed_len(), Some(8));
        assert_eq!(AttrCode::IceControlling.fixed_len(), Some(8));
        assert_eq!(AttrCode::IcePriority.fixed_len(), Some(4));
        assert_eq!(AttrCode::Lifetime.fixed_len(), Some(4));
        assert_eq!(AttrCode::ChannelNumber.fixed_len(), Some(4));
        assert_eq!(AttrCode::ResponsePort.fixed_len(), Some(2));
        assert_eq!(AttrCode::Data.fixed_len(), Some(511));
        assert_eq!(AttrCode::RequestedAddressFamily.fixed_len(), Some(1));
        assert_eq!(AttrCode::AdditionalAddressFamily.fixed_len(), Some(1));
        assert_eq!(AttrCode::DontFragment.fixed_len(), Some(0));
        assert_eq!(AttrCode::UseCandidate.fixed_len(), Some(0));
        assert_eq!(AttrCode::ErrorCode.fixed_len(), None);
        assert_eq!(AttrCode::Username.fixed_len(), None);
        assert_eq!(AttrCode::AlternateServer.fixed_len(), None);
        assert_eq!(AttrCode::UnknownAttributes.fixed_len(), None);
        assert_eq!(AttrCode::ConnectionId.fixed_len(), None);
        assert_eq!(AttrCode::Padding.fixed_len(), None);
        assert_eq!(AttrCode::Icmp.fixed_len(), None);
        assert_eq!(AttrCode::Unknown(0x1234).fixed_len(), None);
    }

    #[test]
    fn trailer_only_markers() {
        assert!(is_trailer_only(AttributeKind::Known(AttrCode::MessageIntegrity)));
        assert!(is_trailer_only(AttributeKind::Known(AttrCode::MessageIntegritySha256)));
        assert!(is_trailer_only(AttributeKind::Known(AttrCode::Fingerprint)));
        assert!(!is_trailer_only(AttributeKind::Known(AttrCode::Username)));
        assert!(!is_trailer_only(AttributeKind::Unknown(0x0008)));
        assert!(!is_trailer_only(AttributeKind::Unknown(0x8028)));
    }

    #[test]
    fn unknown_value_is_preserved_verbatim() {
        let kind = AttributeKind::Unknown(0x4242);
        let value = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(
            parse_attribute_value(kind, &value, &TXID).unwrap(),
            Attribute::Unknown { kind: 0x4242, value: vec![1, 2, 3, 4, 5] }
        );
        let attr = Attribute::Unknown { kind: 0x4242, value: value.to_vec() };
        assert_eq!(attribute_kind(&attr), AttributeKind::Unknown(0x4242));
        assert_eq!(write_attribute_value(&attr, &TXID, &mut [0u8; 16]).unwrap(), 5);
        let mut out = Vec::new();
        emit_attribute(&mut out, AttributeKind::Unknown(0x4242), &value).unwrap();
        assert_eq!(out.len(), 12, "4 header + 5 value + 3 pad octets");
        assert_eq!(&out[..4], &[0x42, 0x42, 0x00, 0x05]);
        assert!(!is_comprehension_optional(AttributeKind::Unknown(0x4242)),
            "0x4242 has the comprehension-required bit cleared");
    }

    #[test]
    fn names_are_non_empty() {
        for code in AttrCode::all() {
            assert!(!code.name().is_empty(), "name of 0x{:04x}", code.as_u16());
            // Registry names are uppercase ASCII, digits, and hyphens.
            assert!(
                code.name()
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'),
                "name of 0x{:04x}: {}",
                code.as_u16(),
                code.name()
            );
        }
        assert_eq!(AttrCode::Unknown(0x1234).name(), "UNKNOWN");
        // A code point without a registry name still reports something.
        assert!(!AttrCode::Unknown(0x0001).name().is_empty());
    }

    #[test]
    fn registered_marker() {
        assert!(is_registered(AttributeKind::Known(AttrCode::Username)));
        assert!(!is_registered(AttributeKind::Unknown(0x1234)));
        assert!(AttributeKind::Known(AttrCode::Username).is_known());
        assert!(!AttributeKind::Unknown(0x1234).is_known());
        assert_eq!(u16::from(AttributeKind::Known(AttrCode::Fingerprint)), 0x8028);
    }

    #[test]
    fn address_attributes_need_txid_for_values() {
        let attr = Attribute::XorMappedAddress(MappedAddress::from_ipv4(192, 0, 2, 1, 32853));
        assert_eq!(
            attr.to_value(&TXID).unwrap(),
            vec![0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]
        );
        let mut out = Vec::new();
        emit_attribute_value(&mut out, &attr, &TXID).unwrap();
        assert_eq!(
            out,
            vec![0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]
        );
        // as_bytes_vec cannot see the transaction id, so it is rejected.
        assert!(attr.as_bytes_vec().is_err());
        let plain = Attribute::Username("u".to_string());
        assert_eq!(plain.as_bytes_vec().unwrap(), vec![b'u']);
    }

    #[test]
    fn icmp_is_passthrough() {
        let value = vec![0x45, 0x00];
        assert_eq!(
            parse_attribute_value(AttributeKind::Known(AttrCode::Icmp), &value, &TXID).unwrap(),
            Attribute::Unknown { kind: 0x8004, value: vec![0x45, 0x00] }
        );
        let mut out = Vec::new();
        emit_attribute(&mut out, AttributeKind::Known(AttrCode::Icmp), &value).unwrap();
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn write_value_into_short_buffer_errors() {
        let addr = MappedAddress::from_ipv4(1, 2, 3, 4, 5);
        let mut short = [0u8; 4];
        assert_eq!(addr.write_value(&mut short).unwrap_err().kind, ErrorKind::ValueTooLong);
            // RELAYED-ADDRESS (IPv4) needs 8 octets; the 16 here fits, so writing
        // succeeds rather than erroring.
        let mut relayed = [0u8; 8];
        assert_eq!(
            write_relayed_address(&addr, &mut relayed).unwrap(),
            8
        );
        let mut short2 = [0u8; 4];
        assert_eq!(write_relayed_address(&addr, &mut short2).unwrap_err().kind, ErrorKind::ValueTooLong);
        // ALTERNATE-SERVER needs 12 octets.
        let mut short3 = [0u8; 7];
        assert_eq!(write_alternate_server(&addr, &mut short3).unwrap_err().kind, ErrorKind::ValueTooLong);
    }
}
