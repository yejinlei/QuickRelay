//! CHANGE-REQUEST semantics (RFC 8489 Section 13.17, superseding RFC 5780).
//!
//! `CHANGE-REQUEST` is a 32-bit attribute carrying two bits:
//! `A` = change IP, `B` = change port. There is no third flag. The legacy
//! `CHANGE-ADDRESS` (0x0003) and `CHANGED-ADDRESS` (0x0005) are Reserved in
//! the IANA registry and must not be parsed.

/// The two CHANGE-REQUEST bits extracted from a parsed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChangeRequest {
    /// Bit `A` (RFC 8489 Section 13.17): respond from a different IP.
    pub change_ip: bool,
    /// Bit `B` (RFC 8489 Section 13.17): respond on a different port.
    pub change_port: bool,
}

impl ChangeRequest {
    /// Decode the 32-bit CHANGE-REQUEST value. Only the two low-order bits are
    /// defined; the remaining 30 bits are ignored.
    pub const fn from_value(value: u32) -> Self {
        ChangeRequest {
            change_ip: value & 0x0000_0001 != 0,
            change_port: value & 0x0000_0002 != 0,
        }
    }
}

/// What the server should do with the source of the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeResponseAction {
    /// Answer from the same address and port.
    NoChange,
    /// Answer from a different address on the same port.
    ChangeIpOnly,
    /// Answer from the same address on a different port.
    ChangePortOnly,
    /// Answer from a different address on a different port.
    ChangeBoth,
    /// No address is available to satisfy the request: emit an error reply
    /// (see `crate::error_codes::ErrorCode::UnsupportedAddressFamily`).
    Unsatisfiable,
}
