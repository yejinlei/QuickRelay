//! STUN attribute registry: type codes and comprehension classification.
//!
//! Every STUN message is a sequence of TLV attributes (RFC 8489 sections 5
//! and 15).  This module is the single source of truth for which type code
//! means which attribute, so that the codec and the transport layer cannot
//! drift apart.
//!
//! Codes are transcribed from the RFC attribute tables: RFC 8489 sections 14
//! and 18.3, RFC 8656 sections 18 and 22, RFC 5766 section 14, and the
//! pre-STUN drafts documented by RFC 5769.  Nothing here is copied from
//! coturn.
//!
//! Three traps this registry is written around:
//!
//! * The comprehension bit really is the MSB (`0x8000`).  RFC 8489 section
//!   5.1 and its section 18.3 registry both put `0x8000` on the boundary,
//!   so every TURN attribute (`0x000C`, `0x000D`, `0x0012`, ...) is
//!   comprehension-required and unknown-optional attributes live at `0x80xx`.
//! * TURN's drafts moved several codes.  `0x000C` is CHANNEL-NUMBER, not
//!   BANDWIDTH; `0x000D` is LIFETIME, not TIMER-VAL; `0x0018` is EVEN-PORT.
//!   `0x0010` (was BANDWIDTH) and `0x0021` (was TIMER-VAL) are now
//!   *Reserved* per RFC 8656 section 18, so those two codes deliberately
//!   have no variant here.
//! * The legacy draft used `0x8020` for XOR-MAPPED-ADDRESS before RFC 5389
//!   moved it to `0x0020`.  Old clients still send it, so the code stays in
//!   the registry as [`Attribute::LegacyXorMappedAddress`] -- but note it
//!   carries a *plain* address, not a XOR-obfuscated one.


use crate::err::ProtocolError;

/// Comprehension status of a STUN attribute type (RFC 8489, section 5.1).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Comprehension {
    /// Must be understood to process the message.
    Required,
    /// MAY be ignored when unknown.
    Optional,
}

impl Comprehension {
    /// Classify a raw attribute code by its comprehension bit.
    ///
    /// The MSB is the test: RFC 8489 section 5.1 says a type "MUST NOT be
    /// used if its type is in the range `0x0000` through `0x7FFF` and the
    /// STUN software does not understand it", and the section 18.3 registry
    /// labels the two halves `0x0000-0x7FFF` / `0x8000-0xFFFF`.
    pub const fn of_bits(bits: u16) -> Self {
        if bits & 0x8000 != 0 {
            Self::Optional
        } else {
            Self::Required
        }
    }
}

/// A STUN attribute, identified by its 16-bit type code.
///
/// Variant names are the wire-level attribute names.  Codes come from the RFC
/// attribute tables; comprehension status is derived from the MSB.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum Attribute {
    /// 0x0001: MAPPED-ADDRESS (RFC 8489, section 14.1).
    MappedAddress = 0x0001,
    /// 0x0003: CHANGE-REQUEST (legacy; comprehension-optional in RFC 5389).
    ChangeRequest = 0x0003,
    /// 0x0006: USERNAME (RFC 8489, section 14.3).
    Username = 0x0006,
    /// 0x0008: MESSAGE-INTEGRITY (RFC 8489, section 14.4).
    MessageIntegrity = 0x0008,
    /// 0x0009: ERROR-CODE (RFC 8489, section 14.6).
    ErrorCode = 0x0009,
    /// 0x000A: UNKNOWN-ATTRIBUTES (RFC 8489, section 14.13).
    UnknownAttributes = 0x000A,
    /// 0x000C: CHANNEL-NUMBER (RFC 8656, section 18.1).
    ChannelNumber = 0x000C,
    /// 0x000D: LIFETIME (RFC 8656, section 18.2).
    Lifetime = 0x000D,
    /// 0x0012: XOR-PEER-ADDRESS (RFC 8656, section 18.3).
    XorPeerAddress = 0x0012,
    /// 0x0013: DATA (RFC 8656, section 18.4).
    Data = 0x0013,
    /// 0x0014: REALM (RFC 8489, section 14.7).
    Realm = 0x0014,
    /// 0x0015: NONCE (RFC 8489, section 14.8).
    Nonce = 0x0015,
    /// 0x0016: XOR-RELAYED-ADDRESS (RFC 8656, section 18.5).
    XorRelayedAddress = 0x0016,
    /// 0x0017: REQUESTED-ADDRESS-FAMILY (RFC 8656, section 18.6).
    RequestedAddressFamily = 0x0017,
    /// 0x0018: EVEN-PORT (RFC 8656, section 18.7).
    EvenPort = 0x0018,
    /// 0x0019: REQUESTED-TRANSPORT (RFC 8656, section 18.8).
    RequestedTransport = 0x0019,
    /// 0x001A: DONT-FRAGMENT (RFC 8656, section 18.9).
    DontFragment = 0x001A,
    /// 0x0024: PRIORITY (RFC 5245, used by ICE; RFC 5769 test vectors).
    Priority = 0x0024,
    /// 0x001C: MESSAGE-INTEGRITY-SHA256 (RFC 8489, section 18.3.2).
    MessageIntegritySha256 = 0x001C,
    /// 0x001D: PASSWORD-ALGORITHM (RFC 8489, section 18.3.2).
    PasswordAlgorithm = 0x001D,
    /// 0x001E: USERHASH (RFC 8489, section 18.3.2).
    UserHash = 0x001E,
    /// 0x0020: XOR-MAPPED-ADDRESS (RFC 8489, section 14.2).
    XorMappedAddress = 0x0020,
    /// 0x0022: RESERVATION-TOKEN (RFC 8656, section 18.10).
    ReservationToken = 0x0022,
    /// 0x8002: PASSWORD-ALGORITHMS (RFC 8489, section 18.3.2).
    PasswordAlgorithms = 0x8002,
    /// 0x8020: XOR-MAPPED-ADDRESS, pre-RFC-5389 code (RFC 5769).
    ///
    /// Same attribute name, *different encoding*: the value is a plain
    /// address rather than a XOR-obfuscated one.  Kept so old clients are
    /// not rejected as carrying an unknown required attribute.
    LegacyXorMappedAddress = 0x8020,
    /// 0x8022: SOFTWARE (RFC 8489, section 14.10).
    Software = 0x8022,
    /// 0x8023: ALTERNATE-SERVER (RFC 8489, section 14.11).
    AlternateServer = 0x8023,
    /// 0x8028: FINGERPRINT (RFC 8489, section 14.5).
    Fingerprint = 0x8028,
    /// 0x8029: ICE-CONTROLLED (RFC 5573 / IANA registry).
    IceControlled = 0x8029,
    /// 0x802B: RESPONSE-PORT (RFC 5769 test-vector draft).
    ResponsePort = 0x802B,
    /// 0x802C: RESPONSE-ORIGIN (RFC 5769 test-vector draft).
    ResponseOrigin = 0x802C,
    /// 0x802D: OTHER-ADDRESS (RFC 5769 test-vector draft).
    OtherAddress = 0x802D,
    /// 0x8032: PADDING (RFC 5769 test-vector draft).
    Padding = 0x8032,
    /// 0x8033: SOURCE-PORT (RFC 5769 test-vector draft).
    SourcePort = 0x8033,
    /// 0x8034: CHANGE-IP (RFC 5769 test-vector draft).
    ChangeIp = 0x8034,
    /// 0x8035: CHANGE-PORT (RFC 5769 test-vector draft).
    ChangePort = 0x8035,
}

impl Attribute {
    /// The raw 16-bit type code.
    pub const fn bits(self) -> u16 {
        self as u16
    }

    /// Look up an attribute by its type code.
    pub const fn try_from_bits(code: u16) -> Result<Attribute, ProtocolError> {
        match Self::known(code) {
            Some(attr) => Ok(attr),
            None => Err(ProtocolError::UnknownAttribute(code)),
        }
    }

    /// The same lookup as an `Option`, for callers that must keep going past
    /// an unrecognised attribute (the codec does this, since unknown
    /// comprehension-optional attributes are simply ignored).
    pub const fn known(code: u16) -> Option<Attribute> {
        Some(match code {
            0x0001 => Self::MappedAddress,
            0x0003 => Self::ChangeRequest,
            0x0006 => Self::Username,
            0x0008 => Self::MessageIntegrity,
            0x0009 => Self::ErrorCode,
            0x000A => Self::UnknownAttributes,
            0x000C => Self::ChannelNumber,
            0x000D => Self::Lifetime,
            0x0012 => Self::XorPeerAddress,
            0x0013 => Self::Data,
            0x0014 => Self::Realm,
            0x0015 => Self::Nonce,
            0x0016 => Self::XorRelayedAddress,
            0x0017 => Self::RequestedAddressFamily,
            0x0018 => Self::EvenPort,
            0x0019 => Self::RequestedTransport,
            0x001A => Self::DontFragment,
            0x0024 => Self::Priority,
            0x001C => Self::MessageIntegritySha256,
            0x001D => Self::PasswordAlgorithm,
            0x001E => Self::UserHash,
            0x0020 => Self::XorMappedAddress,
            0x0022 => Self::ReservationToken,
            0x8002 => Self::PasswordAlgorithms,
            0x8020 => Self::LegacyXorMappedAddress,
            0x8022 => Self::Software,
            0x8023 => Self::AlternateServer,
            0x8028 => Self::Fingerprint,
            0x8029 => Self::IceControlled,
            0x802B => Self::ResponsePort,
            0x802C => Self::ResponseOrigin,
            0x802D => Self::OtherAddress,
            0x8032 => Self::Padding,
            0x8033 => Self::SourcePort,
            0x8034 => Self::ChangeIp,
            0x8035 => Self::ChangePort,
            _ => return None,
        })
    }

    /// Is this attribute comprehension-required (code below `0x8000`)?
    pub const fn comprehension(&self) -> Comprehension {
        Comprehension::of_bits(self.bits())
    }

    /// The attribute name as it appears on the wire and in logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::MappedAddress => "MAPPED-ADDRESS",
            Self::ChangeRequest => "CHANGE-REQUEST",
            Self::Username => "USERNAME",
            Self::MessageIntegrity => "MESSAGE-INTEGRITY",
            Self::ErrorCode => "ERROR-CODE",
            Self::UnknownAttributes => "UNKNOWN-ATTRIBUTES",
            Self::ChannelNumber => "CHANNEL-NUMBER",
            Self::Lifetime => "LIFETIME",
            Self::XorPeerAddress => "XOR-PEER-ADDRESS",
            Self::Data => "DATA",
            Self::Realm => "REALM",
            Self::Nonce => "NONCE",
            Self::XorRelayedAddress => "XOR-RELAYED-ADDRESS",
            Self::RequestedAddressFamily => "REQUESTED-ADDRESS-FAMILY",
            Self::EvenPort => "EVEN-PORT",
            Self::RequestedTransport => "REQUESTED-TRANSPORT",
            Self::DontFragment => "DONT-FRAGMENT",
            Self::Priority => "PRIORITY",
            Self::MessageIntegritySha256 => "MESSAGE-INTEGRITY-SHA256",
            Self::PasswordAlgorithm => "PASSWORD-ALGORITHM",
            Self::UserHash => "USERHASH",
            Self::XorMappedAddress => "XOR-MAPPED-ADDRESS",
            Self::ReservationToken => "RESERVATION-TOKEN",
            Self::PasswordAlgorithms => "PASSWORD-ALGORITHMS",
            Self::LegacyXorMappedAddress => "XOR-MAPPED-ADDRESS (legacy)",
            Self::Software => "SOFTWARE",
            Self::AlternateServer => "ALTERNATE-SERVER",
            Self::Fingerprint => "FINGERPRINT",
            Self::IceControlled => "ICE-CONTROLLED",
            Self::ResponsePort => "RESPONSE-PORT",
            Self::ResponseOrigin => "RESPONSE-ORIGIN",
            Self::OtherAddress => "OTHER-ADDRESS",
            Self::Padding => "PADDING",
            Self::SourcePort => "SOURCE-PORT",
            Self::ChangeIp => "CHANGE-IP",
            Self::ChangePort => "CHANGE-PORT",
        }
    }

    /// Does the attribute carry address-family / port fields?
    pub const fn is_address_attribute(self) -> bool {
        matches!(
            self,
            Self::MappedAddress
                | Self::XorMappedAddress
                | Self::XorRelayedAddress
                | Self::XorPeerAddress
                | Self::OtherAddress
                | Self::ResponsePort
                | Self::SourcePort
                | Self::LegacyXorMappedAddress
        )
    }

    /// Is this attribute allowed to appear only at the end of a message?
    ///
    /// RFC 8489 section 14.5: FINGERPRINT must be the last attribute when
    /// present, and MESSAGE-INTEGRITY may be followed only by FINGERPRINT.
    /// MESSAGE-INTEGRITY-SHA256 follows the same rule.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Fingerprint | Self::MessageIntegrity | Self::MessageIntegritySha256
        )
    }
}

/// The length of the MESSAGE-INTEGRITY value is always 20 bytes (HMAC-SHA1).
pub const MESSAGE_INTEGRITY_LEN: usize = 20;

/// The length of the FINGERPRINT value is always 4 bytes.
pub const FINGERPRINT_LEN: usize = 4;

/// The length of an ERROR-CODE value (RFC 8489, section 14.6).
pub const ERROR_CODE_LEN: usize = 4;

/// The length of a CHANNEL-NUMBER value (RFC 8656, section 18.1).
pub const CHANNEL_NUMBER_LEN: usize = 2;

/// The length of a LIFETIME value (RFC 8656, section 18.2).
pub const LIFETIME_LEN: usize = 4;

/// RESERVATION-TOKEN is always exactly 16 bytes (RFC 8656, section 18.10).
pub const RESERVATION_TOKEN_LEN: usize = 16;

/// EVEN-PORT and DONT-FRAGMENT are valueless: the attribute length field is
/// 0 (RFC 8656, sections 18.7 and 18.9).
pub const DONT_FRAGMENT_LEN: usize = 0;
pub const EVEN_PORT_LEN: usize = 0;

/// A REQUESTED-TRANSPORT value is one byte (RFC 8656, section 18.8).
pub const REQUESTED_TRANSPORT_LEN: usize = 1;

/// A REQUESTED-ADDRESS-FAMILY value is one byte (RFC 8656, section 18.6).
pub const REQUESTED_ADDRESS_FAMILY_LEN: usize = 1;

/// An address attribute value is 12 bytes for IPv4 and 28 bytes for IPv6
/// (RFC 8489, section 14.1).
pub const ADDRESS_ATTR_LEN_V4: usize = 12;
pub const ADDRESS_ATTR_LEN_V6: usize = 28;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_codes_match_rfc_assignments() {
        // RFC 8489 section 18.3
        assert_eq!(Attribute::MappedAddress.bits(), 0x0001);
        assert_eq!(Attribute::Username.bits(), 0x0006);
        assert_eq!(Attribute::MessageIntegrity.bits(), 0x0008);
        assert_eq!(Attribute::ErrorCode.bits(), 0x0009);
        assert_eq!(Attribute::UnknownAttributes.bits(), 0x000A);
        assert_eq!(Attribute::Realm.bits(), 0x0014);
        assert_eq!(Attribute::Nonce.bits(), 0x0015);
        assert_eq!(Attribute::XorMappedAddress.bits(), 0x0020);
        assert_eq!(Attribute::Software.bits(), 0x8022);
        assert_eq!(Attribute::AlternateServer.bits(), 0x8023);
        assert_eq!(Attribute::Fingerprint.bits(), 0x8028);

        // RFC 8656 section 18 -- the drafts used 0x0028/0x0023/0x0024 here.
        assert_eq!(Attribute::ChannelNumber.bits(), 0x000C);
        assert_eq!(Attribute::Lifetime.bits(), 0x000D);
        assert_eq!(Attribute::XorPeerAddress.bits(), 0x0012);
        assert_eq!(Attribute::Data.bits(), 0x0013);
        assert_eq!(Attribute::XorRelayedAddress.bits(), 0x0016);
        assert_eq!(Attribute::RequestedAddressFamily.bits(), 0x0017);
        assert_eq!(Attribute::EvenPort.bits(), 0x0018);
        assert_eq!(Attribute::RequestedTransport.bits(), 0x0019);
        assert_eq!(Attribute::DontFragment.bits(), 0x001A);
        assert_eq!(Attribute::ReservationToken.bits(), 0x0022);

        // RFC 8489 section 18.3.2
        assert_eq!(Attribute::MessageIntegritySha256.bits(), 0x001C);
        assert_eq!(Attribute::PasswordAlgorithm.bits(), 0x001D);
        assert_eq!(Attribute::UserHash.bits(), 0x001E);
        assert_eq!(Attribute::PasswordAlgorithms.bits(), 0x8002);
    }

    #[test]
    fn deprecated_draft_codes_are_not_registered() {
        // 0x0010 (was BANDWIDTH) and 0x0021 (was TIMER-VAL) are Reserved per
        // RFC 8656 section 18; the draft codes for CHANNEL-NUMBER / LIFETIME /
        // XOR-PEER-ADDRESS / DATA / EVEN-PORT / DONT-FRAGMENT are gone too.
        // 0x0024 is *not* in this list: it is PRIORITY from the ICE draft.
        for dead in [
            0x0010u16, 0x0021, 0x0023, 0x0026, 0x0027, 0x0028, 0x002A, 0x0040, 0x0041,
        ] {
            assert!(
                Attribute::known(dead).is_none(),
                "reserved/deprecated code {dead:#06x} must not resolve"
            );
        }
        assert!(matches!(
            Attribute::try_from_bits(0x0010),
            Err(ProtocolError::UnknownAttribute(0x0010))
        ));
    }

    #[test]
    fn comprehension_is_derived_from_the_msb() {
        assert_eq!(
            Attribute::MessageIntegrity.comprehension(),
            Comprehension::Required
        );
        assert_eq!(Attribute::Fingerprint.comprehension(), Comprehension::Optional);
        assert_eq!(Attribute::Software.comprehension(), Comprehension::Optional);
        assert_eq!(
            Attribute::XorMappedAddress.comprehension(),
            Comprehension::Required
        );

        // TURN attributes live below 0x8000 and are comprehension-required.
        assert_eq!(
            Attribute::ChannelNumber.comprehension(),
            Comprehension::Required
        );
        assert_eq!(Attribute::Lifetime.comprehension(), Comprehension::Required);
        assert_eq!(
            Attribute::DontFragment.comprehension(),
            Comprehension::Required
        );
        assert_eq!(
            Attribute::PasswordAlgorithms.comprehension(),
            Comprehension::Optional
        );
    }

    #[test]
    fn unknown_attribute_codes_are_reported() {
        for code in [0x0000u16, 0x0011, 0x0025, 0x7FFE, 0x803F, 0xFFFF] {
            assert!(
                matches!(Attribute::try_from_bits(code), Err(ProtocolError::UnknownAttribute(c)) if c == code),
                "code {code:#06x}"
            );
        }
    }

    #[test]
    fn terminal_attributes_are_the_trailers() {
        assert!(Attribute::Fingerprint.is_terminal());
        assert!(Attribute::MessageIntegrity.is_terminal());
        assert!(Attribute::MessageIntegritySha256.is_terminal());
        assert!(!Attribute::Software.is_terminal());
        assert!(!Attribute::ErrorCode.is_terminal());
    }

    #[test]
    fn address_attributes_round_trip() {
        for code in [
            0x0001u16, 0x0012, 0x0016, 0x0020, 0x8020, 0x802B, 0x802D, 0x8033,
        ] {
            let attr = Attribute::try_from_bits(code).expect("known address code");
            assert!(attr.is_address_attribute(), "code {code:#06x}");
        }
    }

    #[test]
    fn every_variant_has_a_name_and_a_unique_code() {
        let variants = [
            Attribute::MappedAddress,
            Attribute::ChangeRequest,
            Attribute::Username,
            Attribute::MessageIntegrity,
            Attribute::ErrorCode,
            Attribute::UnknownAttributes,
            Attribute::ChannelNumber,
            Attribute::Lifetime,
            Attribute::XorPeerAddress,
            Attribute::Data,
            Attribute::Realm,
            Attribute::Nonce,
            Attribute::XorRelayedAddress,
            Attribute::RequestedAddressFamily,
            Attribute::EvenPort,
            Attribute::RequestedTransport,
            Attribute::DontFragment,
            Attribute::MessageIntegritySha256,
            Attribute::PasswordAlgorithm,
            Attribute::UserHash,
            Attribute::XorMappedAddress,
            Attribute::ReservationToken,
            Attribute::PasswordAlgorithms,
            Attribute::LegacyXorMappedAddress,
            Attribute::Software,
            Attribute::AlternateServer,
            Attribute::Fingerprint,
            Attribute::IceControlled,
            Attribute::ResponsePort,
            Attribute::ResponseOrigin,
            Attribute::OtherAddress,
            Attribute::Padding,
            Attribute::SourcePort,
            Attribute::ChangeIp,
            Attribute::ChangePort,
        ];
        for a in variants {
            assert_eq!(Attribute::known(a.bits()), Some(a), "name lookup failed for {a:?}");
            assert!(a.name().len() > 3, "suspicious name for {a:?}");
        }
        // No two variants share a code.
        for (i, a) in variants.iter().enumerate() {
            for b in &variants[i + 1..] {
                assert_ne!(a.bits(), b.bits(), "duplicate code");
            }
        }
    }
}
