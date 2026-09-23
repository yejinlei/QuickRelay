//! Errors returned by the QuickRelay STUN/TURN codec.
//!
//! `Error` is a `Copy` value carrying an `ErrorKind` plus, when the failure was
//! raised by a specific attribute, the attribute type code. It never carries
//! borrowed message data, so it can be stored in a connection struct without
//! keeping a buffer alive.

/// What went wrong. Every variant corresponds to a normative requirement in
/// RFC 5389, RFC 8489, RFC 6061, RFC 8656, RFC 8326, RFC 8445 or RFC 7635.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The 4-octet magic cookie is not `21 12 A4 42` (RFC 5389 Section 6).
    MagicCookie,
    /// The buffer is shorter than the 20-octet message header.
    TooShort,
    /// `message-length` does not equal the number of octets after the header.
    LengthMismatch,
    /// `message-length` names more than the 65535 octets a header can carry.
    LengthTooLarge,
    /// An attribute's value ran past the end of the message.
    TruncatedAttribute,
    /// The final attribute's padded size does not end the message exactly.
    TrailingOctets,
    /// An attribute value has an impossible length for its type.
    MalformedAttribute,
    /// An address-family/length pair cannot encode a mapped address.
    MalformedAddress,
    /// The address family is neither IPv4 (0x01) nor IPv6 (0x02).
    UnsupportedAddressFamily,
    /// ERROR-CODE class/number are outside the RFC 5389 Section 12 ranges.
    MalformedErrorCode,
    /// A channel number outside the 0x4000-0xBFFF range (RFC 6062).
    MalformedChannelNumber,
    /// ALTERNATE-SERVER or CHANGE-IP is shorter than 12 octets.
    MalformedAlternateServer,
    /// RELAYED-ADDRESS is shorter than 8 octets.
    MalformedRelayedAddress,
    /// A string attribute value is not valid UTF-8.
    InvalidUtf8,
    /// The same attribute appears twice (RFC 3084 Section 5).
    DuplicateAttribute,
    /// An unknown comprehension-required attribute was received. RFC 5389
    /// Section 7.3 checks for those and Section 15.6 answers them with
    /// 420 (Unknown Attribute); requests are retransmitted by the client, so
    /// a reply must be sent rather than the request discarded.
    UnknownRequired,
    /// The message claims to carry MESSAGE-INTEGRITY but does not.
    MissingMessageIntegrity,
    /// MESSAGE-INTEGRITY did not verify against the supplied key.
    MessageIntegrityMismatch,
    /// MESSAGE-INTEGRITY is not the attribute immediately preceding FINGERPRINT.
    MessageIntegrityNotLast,
    /// MESSAGE-INTEGRITY-SHA256 does not have a 32-octet value (RFC 8489).
    MessageIntegritySha256Length,
    /// MESSAGE-INTEGRITY-SHA256 did not verify against the supplied key.
    MessageIntegritySha256Mismatch,
    /// A message that must carry FINGERPRINT does not (RFC 8489 Section 8.4).
    MissingFingerprint,
    /// FINGERPRINT did not verify.
    FingerprintMismatch,
    /// FINGERPRINT is not the final attribute.
    FingerprintNotLast,
    /// USERNAME is absent from an authenticated message.
    MissingUsername,
    /// REALM is absent from an authenticated message.
    MissingRealm,
    /// NONCE is absent from an authenticated message.
    MissingNonce,
    /// USERHASH is absent from a MESSAGE-INTEGRITY-SHA256 message.
    MissingUserHash,
    /// USERHASH is present without a NONCE.
    MissingNonceForUserHash,
    /// PASSWORD-ALGORITHMS is absent while USERHASH is present (RFC 8489
    /// Section 15.5).
    MissingPasswordAlgorithms,
    /// A PASSWORD-ALGORITHMS parameter is unsupported.
    UnsupportedPasswordAlgorithm,
    /// A PASSWORD-ALGORITHMS parameter is duplicated.
    DuplicatePasswordAlgorithm,
    /// An attribute value is longer than its wire format allows.
    ValueTooLong,
    /// Too many entries to accumulate into UNKNOWN-ATTRIBUTES.
    TooManyUnknownAttributes,
    /// CONNECTION-ID is not 1, 4, 8 or 16 octets (RFC 6062).
    MalformedConnectionId,
    /// A PRIORITY / ICE-PRIORITY value was requested but the attribute is absent.
    MissingPriority,
    /// D4-LIMIT is absent from an IPv4 allocate response (RFC 6061).
    MissingD4Limit,
}

/// A codec error: a kind, optionally tied to the attribute that caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    /// Attribute type code that caused the error, when known.
    pub attribute: Option<u16>,
}

impl Error {
    /// Build an error not tied to a specific attribute.
    pub const fn new(kind: ErrorKind) -> Self {
        Error { kind, attribute: None }
    }

    /// Build an error tied to a specific attribute type code.
    pub const fn attr(kind: ErrorKind, attribute: u16) -> Self {
        Error { kind, attribute: Some(attribute) }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "STUN codec error: {}", self.kind)?;
        if let Some(t) = self.attribute {
            write!(f, " (attribute 0x{t:04x})")?;
        }
        Ok(())
    }
}

impl core::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            ErrorKind::MagicCookie => "bad magic cookie",
            ErrorKind::TooShort => "message shorter than the 20-octet header",
            ErrorKind::LengthMismatch => "message-length does not match the payload",
            ErrorKind::LengthTooLarge => "message-length out of range",
            ErrorKind::TruncatedAttribute => "attribute value truncated",
            ErrorKind::TrailingOctets => "trailing octets after the last attribute",
            ErrorKind::MalformedAttribute => "attribute value has an impossible length",
            ErrorKind::MalformedAddress => "address family and length disagree",
            ErrorKind::UnsupportedAddressFamily => "unsupported address family",
            ErrorKind::MalformedErrorCode => "malformed ERROR-CODE",
            ErrorKind::MalformedChannelNumber => "channel number out of range",
            ErrorKind::MalformedAlternateServer => "malformed ALTERNATE-SERVER",
            ErrorKind::MalformedRelayedAddress => "malformed RELAYED-ADDRESS",
            ErrorKind::InvalidUtf8 => "attribute value is not valid UTF-8",
            ErrorKind::DuplicateAttribute => "attribute appears more than once",
            ErrorKind::UnknownRequired => "unknown comprehension-required attribute",
            ErrorKind::MissingMessageIntegrity => "MESSAGE-INTEGRITY is required but absent",
            ErrorKind::MessageIntegrityMismatch => "MESSAGE-INTEGRITY verification failed",
            ErrorKind::MessageIntegrityNotLast => "MESSAGE-INTEGRITY is not last-but-one",
            ErrorKind::MessageIntegritySha256Length => "MESSAGE-INTEGRITY-SHA256 value is not 32 octets",
            ErrorKind::MessageIntegritySha256Mismatch => "MESSAGE-INTEGRITY-SHA256 verification failed",
            ErrorKind::MissingFingerprint => "FINGERPRINT is required but absent",
            ErrorKind::FingerprintMismatch => "FINGERPRINT verification failed",
            ErrorKind::FingerprintNotLast => "FINGERPRINT is not the final attribute",
            ErrorKind::MissingUsername => "USERNAME is required but absent",
            ErrorKind::MissingRealm => "REALM is required but absent",
            ErrorKind::MissingNonce => "NONCE is required but absent",
            ErrorKind::MissingUserHash => "USERHASH is required but absent",
            ErrorKind::MissingNonceForUserHash => "USERHASH without a NONCE",
            ErrorKind::MissingPasswordAlgorithms => "PASSWORD-ALGORITHMS is required but absent",
            ErrorKind::UnsupportedPasswordAlgorithm => "unsupported PASSWORD-ALGORITHMS parameter",
            ErrorKind::DuplicatePasswordAlgorithm => "duplicated PASSWORD-ALGORITHMS parameter",
            ErrorKind::ValueTooLong => "attribute value too long",
            ErrorKind::TooManyUnknownAttributes => "too many unknown attributes",
            ErrorKind::MalformedConnectionId => "malformed CONNECTION-ID",
            ErrorKind::MissingPriority => "PRIORITY is required but absent",
            ErrorKind::MissingD4Limit => "D4-LIMIT is required but absent",
        };
        f.write_str(name)
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
    }
}
