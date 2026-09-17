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
