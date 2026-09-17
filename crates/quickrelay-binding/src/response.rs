//! Binding response planning.
//!
//! `quickrelay-binding` never touches the wire: it produces a
//! [`BindingResponsePlan`] and `quickrelay-server` renders it into
//! `quickrelay-protocol` attributes and sends it. That mapping exists in
//! exactly one place: `quickrelay-server`.

/// The identity the server will answer as. Filled in by `quickrelay-server`,
/// which owns the socket set and the multi-address listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerIdentity {
    /// The address the reply is sent from, big-endian.
    pub address: [u8; 16],
    /// Whether `address` holds an IPv4 value (4 bytes, zero-padded big-endian)
    /// or an IPv6 value (16 bytes).
    pub is_ipv4: bool,
    /// The port the reply is sent from.
    pub port: u16,
}

/// The decision produced by this crate for one Binding request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingResponsePlan {
    /// Answer with a success response, or carry an error code.
    pub outcome: Outcome,
    /// Whether to include XOR-MAPPED-ADDRESS (RFC 8489 Section 9.2).
    pub include_xor_mapped: bool,
    /// Which source to answer from (drives the CHANGE-REQUEST outcome).
    pub source: ChangeSource,
    /// When to echo ALTERNATE-SERVER (RFC 5389 Section 15.4).
    pub include_alternate_server: bool,
    /// When to echo SOFTWARE (RFC 5389 Section 15.3).
    pub include_software: bool,
}

/// Success or failure for a [`BindingResponsePlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Reply 100 (Success Response) with the mapped address.
    Success,
    /// Reply with an error code.
    Error(crate::error_codes::ErrorCode),
}

/// Where the reply comes from, as decided by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeSource {
    /// The listener's default source.
    Default,
    /// A specific source, when CHANGE-REQUEST was honored.
    Explicit(ServerIdentity),
}

/// Implemented by the sender. `quickrelay-server` provides the only production
/// implementation. Keeping this a trait is what prevents `quickrelay-binding`
/// from depending on `quickrelay-protocol`.
pub trait ResponseSink {
    /// Render and send `plan` for the request identified by `transaction_id`
    /// (the opaque 12-octet STUN transaction identifier).
    fn send_plan(&mut self, plan: &BindingResponsePlan, transaction_id: [u8; 12]);
}
