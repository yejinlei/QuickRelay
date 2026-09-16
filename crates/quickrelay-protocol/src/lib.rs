//! `quickrelay-protocol`: the STUN/TURN wire protocol.
//!
//! Scope (YEJ-141): the identifiers, method numbers, error codes and
//! attribute classification the transport layer needs to recognise STUN
//! traffic, plus the message codec the Binding chain uses to parse a
//! datagram and build a response.
//!
//! YEJ-141 ships its own codec because the codec issue (YEJ-140) is still
//! open; the shapes are deliberately small so they can be replaced later
//! without touching the transport crate.
//!
//! Numbers are transcribed from the RFC text (RFC 5389, RFC 8489, RFC 5766
//! and RFC 8656); nothing here is copied from coturn.

pub mod attr;
pub mod codec;
pub mod err;
pub mod method;
pub mod order;

/// Magic cookie that must appear in every STUN message header (RFC 8489, section 6).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Number of bytes in the fixed part of a STUN message header.
pub const HEADER_LEN: usize = 20;

/// A STUN transaction identifier is 96 bits wide (RFC 8489, section 6).
pub const TRANSACTION_ID_LEN: usize = 12;

/// CRC-32 xor mask used by the FINGERPRINT attribute (RFC 8489, section 14.7).
pub const FINGERPRINT_XOR: u32 = 0x5354_554E;

/// The largest method number expressible in the STUN message-type field.
pub const MAX_METHOD: u32 = 0x0FFF;
