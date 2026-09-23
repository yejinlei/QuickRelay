//! Binding response planning.
//!
//! `quickrelay-binding` never touches the wire: it produces a
//! `BindingResponsePlan` and `quickrelay-server` renders it into
//! `quickrelay-protocol` attributes and sends it. That mapping exists in
//! exactly one place: `quickrelay-server`.
//!
//! A plan is the *complete* answer to one Binding request: the outcome, the
//! source the reply leaves from, the address to map, and which echo attributes
//! the peer asked for. Nothing is left for the sender to decide, so every
//! worker answers identically.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error_codes::ErrorCode;
use crate::ChangeResponseAction;

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

impl ServerIdentity {
    /// An IPv4 identity from dotted octets.
    pub fn ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) -> Self {
        let mut address = [0u8; 16];
        address[12..].copy_from_slice(&[a, b, c, d]);
        ServerIdentity {
            address,
            is_ipv4: true,
            port,
        }
    }

    /// An IPv6 identity from 16 octets.
    pub const fn ipv6(address: [u8; 16], port: u16) -> Self {
        ServerIdentity {
            address,
            is_ipv4: false,
            port,
        }
    }

    /// The address as an [`IpAddr`], respecting [`is_ipv4`](Self::is_ipv4).
    pub fn to_ip(self) -> IpAddr {
        if self.is_ipv4 {
            IpAddr::V4(Ipv4Addr::new(
                self.address[12],
                self.address[13],
                self.address[14],
                self.address[15],
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(self.address))
        }
    }

    /// The full `ip:port` this identity answers as.
    pub fn to_socket_addr(self) -> SocketAddr {
        SocketAddr::new(self.to_ip(), self.port)
    }

    /// Whether `self` answers from a different address than `other`.
    pub fn differs_in_ip(self, other: ServerIdentity) -> bool {
        self.to_ip() != other.to_ip()
    }

    /// Whether `self` answers from a different port than `other`.
    pub fn differs_in_port(self, other: ServerIdentity) -> bool {
        self.port != other.port
    }

    /// Whether `self` differs from `other` in the two dimensions
    /// `CHANGE-REQUEST` speaks about, i.e. the address and the port.
    pub fn differs_from(self, other: ServerIdentity, change_ip: bool, change_port: bool) -> bool {
        let ip_ok = if change_ip {
            self.differs_in_ip(other)
        } else {
            !self.differs_in_ip(other)
        };
        let port_ok = if change_port {
            self.differs_in_port(other)
        } else {
            !self.differs_in_port(other)
        };
        ip_ok && port_ok
    }
}

/// Success or failure for a [`BindingResponsePlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Reply 100 (Success Response) with the mapped address.
    Success,
    /// Reply with an error code.
    Error(ErrorCode),
}

impl Outcome {
    /// Whether the reply is a success response.
    pub fn is_success(self) -> bool {
        matches!(self, Outcome::Success)
    }

    /// The error code, when the outcome is an error.
    pub fn error(self) -> Option<ErrorCode> {
        match self {
            Outcome::Error(code) => Some(code),
            Outcome::Success => None,
        }
    }
}

/// Where the reply comes from, as decided by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeSource {
    /// The listener's default source.
    Default,
    /// A specific source, when CHANGE-REQUEST was honored.
    Explicit(ServerIdentity),
}

impl ChangeSource {
    /// The source a [`ChangeResponseAction`] resolves to.
    pub fn from_action(action: ChangeResponseAction, _default: ServerIdentity) -> Self {
        match action.source() {
            Some(explicit) => ChangeSource::Explicit(explicit),
            None => ChangeSource::Default,
        }
    }

    /// The identity this source resolves to.
    pub fn identity(self, default: ServerIdentity) -> ServerIdentity {
        match self {
            ChangeSource::Default => default,
            ChangeSource::Explicit(id) => id,
        }
    }
}

/// The echo attributes a `Binding` request may ask for (RFC 5389 Sections
/// 15.3 and 15.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EchoAttributes {
    /// The request carried `SOFTWARE` (`0x8022`), so the server must echo it.
    pub software: bool,
    /// The server must also send `ALTERNATE-SERVER` (`0x8023`), which is only
    /// sent to the peer that is being told to switch.
    pub alternate_server: bool,
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
    /// The attribute codes to report in `UNKNOWN-ATTRIBUTES` when the outcome
    /// is `Error(UnknownAttribute)`, or `None` when the reply carries none.
    ///
    /// RFC 8489 Section 6.3.1 and Section 14.8 require a 420 to list the
    /// unknown comprehension-required attributes it met; the code alone tells
    /// a peer nothing about which attribute to drop. `decide` names the codes,
    /// `quickrelay-server` renders them. The list is owned rather than a
    /// borrow: the codes are read out of the request's scratch buffer, which
    /// dies before the reply is cached and replayed.
    pub unknown_attributes: Option<Vec<u16>>,
}

impl BindingResponsePlan {
    /// A successful plan answering from `source` with a mapped address.
    pub fn success(source: ChangeSource) -> Self {
        BindingResponsePlan {
            outcome: Outcome::Success,
            include_xor_mapped: true,
            source,
            include_alternate_server: false,
            include_software: false,
            unknown_attributes: None,
        }
    }

    /// An error plan. An error response never maps an address, which is what
    /// keeps a rejected probe from reading as a successful one.
    pub fn error(code: ErrorCode) -> Self {
        BindingResponsePlan {
            outcome: Outcome::Error(code),
            include_xor_mapped: false,
            source: ChangeSource::Default,
            include_alternate_server: false,
            include_software: false,
            unknown_attributes: None,
        }
    }

    /// A successful plan with `ALTERNATE-SERVER` pointing at `alternate`.
    ///
    /// `ALTERNATE-SERVER` replaces the reply address rather than adding to
    /// it, so the plan points its `source` at the alternate identity: the
    /// sender renders `ALTERNATE-SERVER` from `source` and must not also emit
    /// a `XOR-MAPPED-ADDRESS` for the default.
    pub fn redirect(source: ServerIdentity) -> Self {
        BindingResponsePlan {
            outcome: Outcome::Success,
            include_xor_mapped: false,
            source: ChangeSource::Explicit(source),
            include_alternate_server: true,
            include_software: false,
            unknown_attributes: None,
        }
    }

    /// Apply a [`ChangeResponseAction`] to this plan: the source changes on
    /// success, and every error row clears the mapped address.
    pub fn with_change_action(
        mut self,
        action: ChangeResponseAction,
        _default: ServerIdentity,
    ) -> Self {
        match action.source() {
            Some(explicit) => self.source = ChangeSource::Explicit(explicit),
            None => {
                if action.error().is_some() {
                    self.outcome = Outcome::Error(action.error().unwrap());
                    self.include_xor_mapped = false;
                    self.include_alternate_server = false;
                    self.include_software = false;
                    self.source = ChangeSource::Default;
                    self.unknown_attributes = None;
                }
            }
        }
        self
    }

    /// The identity the reply leaves from.
    pub fn reply_identity(&self, default: ServerIdentity) -> ServerIdentity {
        self.source.identity(default)
    }

    /// Set whether the reply echoes `SOFTWARE`. Only ever set on a success
    /// plan: an error response must not carry echo attributes, which would
    /// let a rejected probe read as an answered one.
    pub fn with_software(mut self, include: bool) -> Self {
        self.include_software = include;
        self
    }

    /// Carry the unknown attribute codes a 420 must report. RFC 8489
    /// Section 6.3.1 requires the reply to list them, so the 420 that reaches
    /// a peer says which attribute it rejected rather than only that one
    /// exists. Never called on a non-420 plan: an attribute list on any other
    /// code is noise the peer would have to discard.
    pub fn with_unknown_attributes(mut self, codes: &[u16]) -> Self {
        self.unknown_attributes = Some(codes.to_vec());
        self
    }

    /// Whether this plan carries any echo attribute at all.
    pub fn echoes(&self) -> bool {
        self.include_alternate_server || self.include_software
    }
}

/// Implemented by the sender. `quickrelay-server` provides the only production
/// implementation. Keeping this a trait is what prevents `quickrelay-binding`
/// from depending on `quickrelay-protocol`.
pub trait ResponseSink {
    /// Render and send `plan` for the request identified by `transaction_id`
    /// (the opaque 12-octet STUN transaction identifier).
    fn send_plan(&mut self, plan: &BindingResponsePlan, transaction_id: [u8; 12]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_identity() -> ServerIdentity {
        ServerIdentity::ipv4(127, 0, 0, 1, 3478)
    }

    #[test]
    fn an_ipv4_identity_converts_to_a_socket_addr() {
        let id = ServerIdentity::ipv4(10, 0, 0, 1, 3478);
        assert!(id.is_ipv4);
        assert_eq!(id.to_ip().to_string(), "10.0.0.1");
        assert_eq!(id.to_socket_addr().to_string(), "10.0.0.1:3478");
        assert_eq!(id.port, 3478);
    }

    #[test]
    fn an_ipv6_identity_converts_to_a_socket_addr() {
        let id = ServerIdentity::ipv6(Ipv6Addr::LOCALHOST.octets(), 3478);
        assert!(!id.is_ipv4);
        assert_eq!(id.to_ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn identity_difference_checks_are_per_dimension() {
        let a = ServerIdentity::ipv4(10, 0, 0, 1, 3478);
        let b = ServerIdentity::ipv4(10, 0, 0, 1, 3479);
        let c = ServerIdentity::ipv4(10, 0, 0, 2, 3478);

        assert!(a.differs_in_port(b) && !a.differs_in_ip(b));
        assert!(a.differs_in_ip(c) && !a.differs_in_port(c));

        // The CHANGE-REQUEST sense of "differs": which dimension must change.
        assert!(a.differs_from(b, false, true), "change port only");
        assert!(a.differs_from(c, true, false), "change ip only");
        assert!(!a.differs_from(b, true, false), "ip did not change");
        assert!(!a.differs_from(c, false, true), "port did not change");

        // An identity compared with itself never differs.
        assert!(!a.differs_from(a, true, true));
    }

    #[test]
    fn a_success_plan_maps_the_default_identity() {
        let plan = BindingResponsePlan::success(ChangeSource::Default);
        assert_eq!(plan.outcome, Outcome::Success);
        assert!(plan.include_xor_mapped);
        assert!(plan.reply_identity(default_identity()) == default_identity());
    }

    #[test]
    fn an_error_plan_never_maps_an_address() {
        let plan = BindingResponsePlan::error(ErrorCode::RoleConflict);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::RoleConflict));
        assert!(!plan.include_xor_mapped);
        assert!(!plan.echoes());
        assert!(!plan.outcome.is_success());
        assert_eq!(plan.reply_identity(default_identity()), default_identity());
    }

    #[test]
    fn a_redirect_plan_sends_alternate_server_without_a_mapped_address() {
        let alternate = ServerIdentity::ipv4(10, 0, 0, 9, 3480);
        let plan = BindingResponsePlan::redirect(alternate);
        assert!(plan.include_alternate_server);
        assert!(!plan.include_xor_mapped);
        assert!(plan.echoes());
        assert_eq!(plan.reply_identity(default_identity()), alternate);
    }

    #[test]
    fn a_honored_change_action_moves_the_source() {
        let default = default_identity();
        let other = ServerIdentity::ipv4(10, 0, 0, 2, 3479);
        let action = ChangeResponseAction::ChangeBoth(other);

        let plan =
            BindingResponsePlan::success(ChangeSource::Default).with_change_action(action, default);
        assert_eq!(plan.source, ChangeSource::Explicit(other));
        assert_eq!(plan.reply_identity(default), other);
        assert!(
            plan.include_xor_mapped,
            "a honored change still maps the address"
        );
    }

    #[test]
    fn an_unsatisfiable_change_action_turns_the_plan_into_an_error() {
        let default = default_identity();
        let plan = BindingResponsePlan::success(ChangeSource::Default)
            .with_change_action(ChangeResponseAction::Unsatisfiable, default);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
        assert!(!plan.include_xor_mapped);
        assert_eq!(plan.source, ChangeSource::Default);
    }

    #[test]
    fn change_source_resolves_to_the_default_when_unset() {
        let default = default_identity();
        assert_eq!(
            ChangeSource::from_action(ChangeResponseAction::NoChange, default),
            ChangeSource::Default
        );
        let other = ServerIdentity::ipv4(10, 0, 0, 2, 3479);
        assert_eq!(
            ChangeSource::from_action(ChangeResponseAction::ChangeIpOnly(other), default),
            ChangeSource::Explicit(other)
        );
        assert_eq!(ChangeSource::Explicit(other).identity(default), other);
        assert_eq!(ChangeSource::Default.identity(default), default);
    }

    #[test]
    fn outcome_classification_is_mutually_exclusive() {
        assert!(Outcome::Success.is_success());
        assert!(Outcome::Success.error().is_none());
        assert!(!Outcome::Error(ErrorCode::BadRequest).is_success());
        assert_eq!(
            Outcome::Error(ErrorCode::BadRequest).error(),
            Some(ErrorCode::BadRequest)
        );
    }

    #[test]
    fn the_response_sink_trait_is_object_safe() {
        struct Sink;
        impl ResponseSink for Sink {
            fn send_plan(&mut self, _plan: &BindingResponsePlan, _transaction_id: [u8; 12]) {}
        }
        // A trait object keeps the sender swappable without a protocol dep.
        let mut sink: Box<dyn ResponseSink> = Box::new(Sink);
        sink.send_plan(
            &BindingResponsePlan::success(ChangeSource::Default),
            [0u8; 12],
        );
    }
}
