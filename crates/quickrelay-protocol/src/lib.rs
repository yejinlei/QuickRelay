//! # quickrelay-protocol
//!
//! STUN/TURN message codec for QuickRelay: message header, attribute TLVs,
//! XOR-obfuscated addresses, HMAC message integrity, CRC-32 fingerprint, and
//! the RFC 8489 trailer ordering rules.
//!
//! Zero-copy read path, no I/O, no threads, no locks, no `tokio`/`mio`.
//
//! FROZEN API (F0) — see docs/architecture/workspace-layout.md §4.
//! OWNED BY: YEJ-140. NO OTHER ISSUE MAY EDIT THIS CRATE.
//
//! TODO(YEJ-140): replace this placeholder with the real `pub mod` list
//! (`message`, `attribute`, `message_type`, `address`, `fingerprint`,
//! `integrity`, `error`, `transaction_id`) plus the `pub use` surface in §4.
pub const SKELETON: &str = "quickrelay-protocol skeleton — replaced by YEJ-140";


// ------------------------------------------------------------------------
// YEJ-140 (2026-09-22): the real module list and `pub use` surface required by
// `docs/architecture/workspace-layout.md` §4. Appended after the frozen
// placeholder above, which is preserved verbatim per §0 / §4.11.
// ------------------------------------------------------------------------

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
    attribute_kind, is_comprehension_optional, is_registered, is_trailer_only, pad_len,
    attr_size, emit_attribute, emit_attribute_value, parse_attribute_value,
    write_attribute_value, Attribute, AttributeKind, AttrCode, ErrorCode,
};
pub use error::{Error, ErrorKind};
pub use fingerprint::Fingerprint;
pub use integrity::{
    attribute_offset as integrity_attribute_offset, compute as compute_integrity, mac_input,
    verify as verify_integrity, AttributeLocation, IntegrityAlgorithm, IntegrityKey,
};
pub use message::{build_response, parse, parse_bytes, parse_vec, Header, Message};
pub use message_type::{Class, Method, MessageType};
pub use transaction_id::TransactionId;

/// The magic cookie that identifies a STUN datagram (RFC 8489 §5.1).
pub const MAGIC_COOKIE: u32 = 0x21_12_A4_42;

/// The fixed STUN header size in octets (RFC 8489 §5.1).
pub const HEADER_LEN: usize = 20;

/// The transaction identifier length in octets (RFC 8489 §5.2).
pub const TRANSACTION_ID_LEN: usize = 12;

/// The `MESSAGE-INTEGRITY` value length in octets (RFC 8489 §14.5).
pub const MESSAGE_INTEGRITY_LEN: usize = 20;

/// The `MESSAGE-INTEGRITY-SHA256` value length in octets (RFC 8489 §14.6).
pub const MESSAGE_INTEGRITY_SHA256_LEN: usize = 32;

/// The largest value the `message-length` field can hold (RFC 8489 §5.1).
pub const MAX_MESSAGE_LENGTH: u16 = 65_535;

/// The largest STUN datagram in octets, header included (RFC 8489 §5.1:
/// `message-length` excludes the 20-octet header).
pub const MAX_DATAGRAM: usize = HEADER_LEN + MAX_MESSAGE_LENGTH as usize;
