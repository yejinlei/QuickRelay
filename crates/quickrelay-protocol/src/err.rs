//! Protocol-level error types used by the codec and the transport layer.
//!
//! Errors here never panic: the transport layer maps them onto STUN
//! `ERROR-CODE` responses or onto silent drops, which is what the
//! architecture design requires for the hot path (no amplification on
//! malformed input).

/// A STUN/TURN message could not be decoded.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolError {
    /// The message is shorter than the 20-byte STUN header.
    TooShort { len: usize },
    /// The message length field does not fit inside the datagram.
    Truncated {
        /// Datagram length in bytes.
        have: usize,
        /// Length field of the header.
        want: usize,
    },
    /// The reserved high bits of the message-type field are not zero.
    BadMessageClass(u16),
    /// The magic cookie is not `0x2112A442`.
    BadMagicCookie(u32),
    /// The message length is not a multiple of 4.
    BadLengthAlignment(u16),
    /// The message length field is larger than the datagram.
    Oversized(u16),
    /// The method number is outside the 12-bit space.
    BadMethodNumber(u16),
    /// The method is unknown to QuickRelay.
    UnknownMethod(u16),
    /// The message class is not allowed for this method.
    BadClassForMethod(u16),
    /// An attribute type is not in the registry.
    ///
    /// Only ever raised for *comprehension-required* codes (below `0x8000`):
    /// an unknown optional attribute is collected by the codec and answered
    /// with a 420 response, never rejected by the parser itself.
    UnknownAttribute(u16),
    /// An attribute runs past the end of the message.
    AttributeOverrun {
        /// Attribute type code.
        code: u16,
        /// Declared attribute value length.
        length: u16,
    },
    /// An attribute value length is not a multiple of 4.
    BadAttributeAlignment {
        /// Attribute type code.
        code: u16,
        /// Declared attribute value length.
        length: u16,
    },
    /// The trailer layout violates RFC 5389 section 15.5 (FINGERPRINT must
    /// be the last attribute, and only FINGERPRINT may follow
    /// MESSAGE-INTEGRITY).
    BadTrailerOrder,
    /// FINGERPRINT is present but the CRC does not match.
    FingerprintMismatch {
        /// Expected value.
        expected: u32,
        /// Value read from the message.
        actual: u32,
    },
    /// MESSAGE-INTEGRITY is present but the HMAC does not match.
    IntegrityMismatch,
    /// The USERNAME attribute value is not valid UTF-8 / SASLprep input.
    BadUsername,
    /// A required attribute is missing.
    MissingAttribute(u16),
}

impl ProtocolError {
    /// Whether the packet must be dropped without a response.
    ///
    /// Header-level defects (bad magic, oversized, unknown method, bad
    /// trailer order) must not be answered: replying would turn a scanner or
    /// a mixed-protocol port into an amplification channel, and the RFC
    /// tells the receiver to treat such datagrams as *not* STUN traffic.
    pub const fn is_silent(&self) -> bool {
        matches!(
            self,
            Self::TooShort { .. }
                | Self::Truncated { .. }
                | Self::BadMessageClass(_)
                | Self::BadMagicCookie(_)
                | Self::BadLengthAlignment(_)
                | Self::Oversized(_)
                | Self::BadMethodNumber(_)
                | Self::UnknownMethod(_)
                | Self::AttributeOverrun { .. }
                | Self::BadAttributeAlignment { .. }
                | Self::BadTrailerOrder
                | Self::FingerprintMismatch { .. }
        )
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { len } => write!(f, "message shorter than header ({len} bytes)"),
            Self::Truncated { have, want } => {
                write!(f, "message truncated ({have} present, {want} declared)")
            }
            Self::BadMessageClass(bits) => {
                write!(f, "message type {bits:#06x} sets reserved class bits")
            }
            Self::BadMagicCookie(v) => write!(f, "magic cookie {v:#010x} is not 0x2112A442"),
            Self::BadLengthAlignment(v) => write!(f, "message length {v} is not 4-aligned"),
            Self::Oversized(v) => write!(f, "message length {v} exceeds the datagram"),
            Self::BadMethodNumber(v) => write!(f, "method number {v:#06x} is out of range"),
            Self::UnknownMethod(v) => write!(f, "unknown method {v:#06x}"),
            Self::BadClassForMethod(v) => write!(f, "unexpected class for method {v:#06x}"),
            Self::UnknownAttribute(v) => write!(f, "unknown attribute {v:#06x}"),
            Self::AttributeOverrun { code, length } => {
                write!(f, "attribute {code:#06x} overruns the message by {length} bytes")
            }
            Self::BadAttributeAlignment { code, length } => {
                write!(f, "attribute {code:#06x} length {length} is not 4-aligned")
            }
            Self::BadTrailerOrder => write!(f, "FINGERPRINT/MESSAGE-INTEGRITY order violation"),
            Self::FingerprintMismatch { expected, actual } => {
                write!(f, "FINGERPRINT mismatch (expected {expected:#010x}, got {actual:#010x})")
            }
            Self::IntegrityMismatch => write!(f, "MESSAGE-INTEGRITY mismatch"),
            Self::BadUsername => write!(f, "USERNAME is not valid UTF-8"),
            Self::MissingAttribute(code) => write!(f, "missing required attribute {code:#06x}"),
        }
    }
}

impl std::error::Error for ProtocolError {}
