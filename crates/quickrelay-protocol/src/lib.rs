//! # quickrelay-protocol
//!
//! Zero-copy STUN / TURN message codec for QuickRelay.
//!
//! This crate is the Stage 2 protocol layer: it knows message headers,
//! attribute TLVs, XOR-obfuscated addresses, HMAC-SHA1 / HMAC-SHA256 message
//! integrity and the CRC-32 `FINGERPRINT`, and it does no I/O, no session
//! state and no policy. Code points follow the IANA registries; see
//! [`attribute`] for the mapping against the obsoleted RFC 5389 tables.
//!
//! ## Reading
//!
//! [`message::parse`] validates a datagram and decodes its attribute list.
//! [`message::parse_bytes`] and [`message::parse_vec`] are the `bytes::Bytes`
//! and `Vec<u8>` entry points, for callers that own the buffer.
//!
//! ## Writing
//!
//! [`attribute::emit_attribute_value`] appends one attribute, and
//! [`attribute::emit_attribute`] appends a raw value. The `FINGERPRINT` and
//! `MESSAGE-INTEGRITY` trailers are computed in place by
//! [`fingerprint::compute`] and [`integrity::compute`], which follow the RFC
//! 8489 ordering rule: the message length field is patched to the end of the
//! integrity attribute before the HMAC, but left correct and including the
//! `FINGERPRINT` attribute before the CRC-32.
//!
//! ## Errors
//!
//! Every failure is an [`error::Error`] carrying an [`error::ErrorKind`] plus,
//! when the failure came from one attribute, its type code. `Error` is `Copy`
//! and borrows nothing, so it can be stored alongside a connection.

pub mod address;
pub mod attribute;
pub mod error;
pub mod fingerprint;
pub mod integrity;
pub mod message;
pub mod message_type;
pub mod transaction_id;

pub use address::{
    read_alternate_server, read_relayed_address, read_xor_address, write_alternate_server,
    write_relayed_address, write_xor_address, AddressFamily, MappedAddress,
};
pub use attribute::{
    attribute_kind, is_comprehension_optional, is_registered, is_trailer_only,
    pad_len, attr_size, emit_attribute, emit_attribute_value, parse_attribute_value,
    write_attribute_value, Attribute, AttributeKind, AttrCode, ErrorCode,
};
pub use error::{Error, ErrorKind};
pub use fingerprint::Fingerprint;
pub use integrity::{
    compute as compute_integrity, mac_input, verify as verify_integrity,
    IntegrityAlgorithm, IntegrityKey, AttributeLocation,
};
pub use message::{parse, parse_bytes, parse_vec, Header, Message};
pub use message_type::{Class, Method, MessageType};
pub use transaction_id::TransactionId;

/// The magic cookie that identifies a STUN datagram (RFC 8489 Section 5.1).
pub const MAGIC_COOKIE: u32 = 0x21_12_A4_42;

/// The fixed STUN header size in octets (RFC 8489 Section 5.1).
pub const HEADER_LEN: usize = 20;

/// The transaction identifier length in octets (RFC 8489 Section 5.2).
pub const TRANSACTION_ID_LEN: usize = 12;

/// The `MESSAGE-INTEGRITY` value length in octets (RFC 8489 Section 14.5).
pub const MESSAGE_INTEGRITY_LEN: usize = 20;

/// The `MESSAGE-INTEGRITY-SHA256` value length in octets (RFC 8489
/// Section 14.6).
pub const MESSAGE_INTEGRITY_SHA256_LEN: usize = 32;

/// The largest value the `message-length` field can hold (RFC 8489
/// Section 5.1: a 16-bit field starting at octet 2).
pub const MAX_MESSAGE_LENGTH: u16 = 65_535;

/// The largest STUN datagram in octets, header included.
pub const MAX_DATAGRAM: usize = 65_537;
