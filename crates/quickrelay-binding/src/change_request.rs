//! CHANGE-REQUEST semantics (RFC 8489 Section 13.17, updating RFC 5780).
//!
//! `CHANGE-REQUEST` (`0x0003`) is a 32-bit attribute carrying two bits:
//! `A` = change IP, `B` = change port. Only the two low-order bits are defined;
//! the remaining 30 bits MUST be ignored on receipt.
//!
//! The legacy `CHANGE-IP` (`0x0004`), `CHANGE-PORT` (`0x0006`) and
//! `CHANGE-ADDRESS` (`0x0005`) are Reserved in the IANA registry. They are
//! neither synonyms of `A`/`B` nor of each other, so `crate::decision` rejects
//! any of them as an unknown attribute rather than parsing them.
//!
//! # What the table says
//!
//! RFC 5780 Section 6.1 constrains a flag only by the other dimension being
//! held constant across two listening addresses. The flag table (Table 1)
//! carries no address-family restriction on any row:
//!
//! | flags    | requirement              | error if unmet                 |
//! | -------- | ------------------------ | ------------------------------ |
//! | `A`      | same port, other address | 420 Unknown Attribute          |
//! | `B`      | same address, other port | 420 Unknown Attribute          |
//! | `A`|`B`  | both differ              | 420 Unknown Attribute          |
//!
//! RFC 5780 Section 6.1 does not define per-flag error codes: "If the Request
//! contains the CHANGE-REQUEST attribute and the server does not have an
//! alternate address and port as described above, the server MUST generate an
//! error response of type 420."
//!
//! Two consequences, both enforced in this module:
//!
//! * `A` alone is **not** IPv6-only. Nothing in RFC 5780 says so, and an IPv4
//!   host with two local addresses satisfies `A` exactly as an IPv6 one does.
//! * There is no 386 and no 437 to choose between. 386 is not a STUN error
//!   code at all, and 437 is TURN's `Allocation Mismatch` (RFC 8656 Section
//!   19), not a STUN code. Every unsatisfiable row emits 420.

use std::net::{IpAddr, SocketAddr};

use crate::ice::IpFamily;
use crate::response::ServerIdentity;

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
    pub fn from_value(value: u32) -> Self {
        ChangeRequest {
            change_ip: value & 0x0000_0001 != 0,
            change_port: value & 0x0000_0002 != 0,
        }
    }

    /// Re-encode as the 32-bit attribute value.
    pub fn to_value(self) -> u32 {
        (u32::from(self.change_ip) << 0) | (u32::from(self.change_port) << 1)
    }

    /// Neither bit is set: the request asks for nothing.
    pub const fn is_empty(self) -> bool {
        !self.change_ip && !self.change_port
    }

    /// At least one bit is set: the peer actually asked for a changed source.
    pub const fn is_some(self) -> bool {
        !self.is_empty()
    }

    /// Whether the flag set asks for anything at all.
    ///
    /// RFC 5780 Section 6.1 puts no address-family restriction on any flag:
    /// `A` means "answer from the other IP address" and `B` means "answer on
    /// the other port", whichever family the host listens on. The parameter
    /// is kept so callers keep the shape of the check, but it does not filter
    /// anything.
    pub const fn is_actionable_for(self, _family: IpFamily) -> bool {
        !self.is_empty()
    }

    /// Resolve against the server's listening addresses.
    ///
    /// `peer` is the source address the request was read from, kept for the
    /// family of the connection the request arrived on. `default` is the
    /// identity the reply would otherwise leave from, which a candidate must
    /// differ from:
    /// the flag is relative to where the request arrived, not to where the
    /// peer sits. It is included in `addresses` by convention, so a candidate
    /// equal to it is never reported as a change. `addresses` is the full
    /// listen list on this host: every socket the server could send from
    /// (`SO_REUSEADDR` on one address plus the per-worker `SO_REUSEPORT` set).
    ///
    /// A request with no bit set asks for nothing and is answered from the
    /// default source; the listen list is not scanned.
    /// Otherwise the first candidate that satisfies the bits is reported, in
    /// list order. That keeps the decision a pure function of the inputs: no
    /// clock, no load balancer, no tie-breaking by arrival order, so the same
    /// request gets the same answer on every worker.
    pub fn resolve(
        self,
        peer: SocketAddr,
        default: Option<ServerIdentity>,
        addresses: &[ServerIdentity],
    ) -> ChangeResponseAction {
        if self.is_empty() {
            // No flag is set: nothing was asked for, so nothing changes.
            return ChangeResponseAction::NoChange;
        }
        let Some(default) = default else {
            return self.unsatisfiable(family_of(peer));
        };
        let Some(candidate) = self.find_source(peer, default, addresses) else {
            return self.unsatisfiable(family_of(peer));
        };
        match (self.change_ip, self.change_port) {
            (true, false) => ChangeResponseAction::ChangeIpOnly(candidate),
            (false, true) => ChangeResponseAction::ChangePortOnly(candidate),
            (true, true) => ChangeResponseAction::ChangeBoth(candidate),
            (false, false) => unreachable!("handled above"),
        }
    }

    /// The single candidate check, shared by the flag rows.
    ///
    /// `peer` is the source the request came from; it carries no row of its
    /// own, because RFC 5780 Table 1 is keyed by the flag bits only. `default`
    /// is
    /// what a candidate must differ from: `CHANGE-REQUEST` is relative to
    /// where the request arrived, not to where the peer sits, so the peer
    /// address never enters the comparison itself.
    fn find_source(
        &self,
        _peer: SocketAddr,
        default: ServerIdentity,
        addresses: &[ServerIdentity],
    ) -> Option<ServerIdentity> {
        addresses.iter().copied().find(|id| {
            // The default socket is never a change: the request arrived at
            // it, so answering from it answers from the same place.
            if *id == default {
                return false;
            }
            let same_ip_as_default = same_ip(default.to_ip(), id.to_ip());
            let distinct_from_default = if self.change_ip {
                !same_ip_as_default
            } else {
                same_ip_as_default
            };
            let distinct_port = if self.change_port {
                id.port != default.port
            } else {
                id.port == default.port
            };
            distinct_from_default && distinct_port
        })
    }

    /// The error row for any flag set the listen list cannot honor.
    ///
    /// RFC 5780 Section 6.1 defines a single error for an unsatisfiable
    /// `CHANGE-REQUEST`: "the server MUST generate an error response of type
    /// 420". There is no per-flag split, so the family of the peer does not
    /// matter either — the answer is the same whichever row failed.
    fn unsatisfiable(self, _family: IpFamily) -> ChangeResponseAction {
        ChangeResponseAction::Unsatisfiable
    }
}

/// The family of `peer`, as the server sees it from the socket.
pub(crate) fn family_of(peer: SocketAddr) -> IpFamily {
    match peer {
        SocketAddr::V4(_) => IpFamily::V4,
        SocketAddr::V6(_) => IpFamily::V6,
    }
}

/// Whether two `IpAddr`s name the same host. `ServerIdentity` carries the raw
/// 16-octet form and a family flag, so the mapping into `IpAddr` keeps any
/// IPv4-mapped-into-IPv6 comparison out of this function.
fn same_ip(a: IpAddr, b: IpAddr) -> bool {
    a == b
}

/// What the server should do with the source of the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeResponseAction {
    /// Answer from the same address and port.
    NoChange,
    /// Answer from a different address on the same port.
    ///
    /// `target` is the resolved source. It is a [`ServerIdentity`] rather than
    /// a bare `IpAddr` because the reply must also say which port it left
    /// from, and `CHANGE-IP`-only never changes the port.
    ChangeIpOnly(ServerIdentity),
    /// Answer from the same address on a different port.
    ChangePortOnly(ServerIdentity),
    /// Answer from a different address on a different port.
    ChangeBoth(ServerIdentity),
    /// No listen address can satisfy the flag set: emit 420 Unknown Attribute,
    /// the single error RFC 5780 Section 6.1 defines for this case.
    Unsatisfiable,
}

impl ChangeResponseAction {
    /// The identity the reply should leave from, or `None` when the action
    /// keeps the default source (and, for the error rows, when there is no
    /// reply source at all).
    pub fn source(self) -> Option<ServerIdentity> {
        match self {
            ChangeResponseAction::NoChange => None,
            ChangeResponseAction::ChangeIpOnly(id)
            | ChangeResponseAction::ChangePortOnly(id)
            | ChangeResponseAction::ChangeBoth(id) => Some(id),
            ChangeResponseAction::Unsatisfiable => None,
        }
    }

    /// Which error code, if any, this action maps to. RFC 5780 Section 6.1
    /// names one code for every unsatisfiable `CHANGE-REQUEST`: 420.
    pub fn error(self) -> Option<crate::ErrorCode> {
        use crate::ErrorCode;
        match self {
            ChangeResponseAction::Unsatisfiable => Some(ErrorCode::UnknownAttribute),
            _ => None,
        }
    }

    /// Whether the reply may carry `XOR-MAPPED-ADDRESS`. Every error row
    /// must not: an error response with a mapped address would let a peer
    /// treat a rejected request as a successful probe.
    pub fn maps_address(self) -> bool {
        match self {
            ChangeResponseAction::NoChange
            | ChangeResponseAction::ChangeIpOnly(_)
            | ChangeResponseAction::ChangePortOnly(_)
            | ChangeResponseAction::ChangeBoth(_) => true,
            ChangeResponseAction::Unsatisfiable => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an IPv4 [`ServerIdentity`] from octets, big-endian in `address`.
    fn id4(a: u8, b: u8, c: u8, d: u8, port: u16) -> ServerIdentity {
        let mut address = [0u8; 16];
        address[12..].copy_from_slice(&[a, b, c, d]);
        ServerIdentity {
            address,
            is_ipv4: true,
            port,
        }
    }

    /// Build an IPv6 [`ServerIdentity`].
    fn id6(octets: [u8; 16], port: u16) -> ServerIdentity {
        ServerIdentity {
            address: octets,
            is_ipv4: false,
            port,
        }
    }

    const LOOPBACK6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 1];

    /// The `A`|`B` combined row.
    fn change_both() -> ChangeRequest {
        ChangeRequest::from_value(0x0000_0003)
    }

    #[test]
    fn the_bits_round_trip_through_the_wire_value() {
        let cr = ChangeRequest::from_value(0x0000_0003);
        assert!(cr.change_ip && cr.change_port);
        assert_eq!(cr.to_value(), 0x0000_0003);

        let a = ChangeRequest::from_value(0x0000_0001);
        assert!(a.change_ip && !a.change_port);
        assert_eq!(a.to_value(), 0x0000_0001);

        let b = ChangeRequest::from_value(0x0000_0002);
        assert!(!b.change_ip && b.change_port);
        assert_eq!(b.to_value(), 0x0000_0002);

        assert!(ChangeRequest::from_value(0).is_empty());
        assert!(ChangeRequest::from_value(1).is_some());
    }

    #[test]
    fn the_upper_thirty_bits_are_ignored() {
        // RFC 8489 Section 13.17: the top 30 bits are reserved and MUST be
        // ignored on receipt, so a client that sets them is still asking for
        // the same thing as one that does not.
        assert_eq!(
            ChangeRequest::from_value(0xFFFF_FFFF),
            ChangeRequest::from_value(0x0000_0003)
        );
        assert_eq!(
            ChangeRequest::from_value(0x0000_0000),
            ChangeRequest::default()
        );
    }

    #[test]
    fn an_empty_request_answers_no_change() {
        let source = id4(127, 0, 0, 1, 3478);
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();
        let action = ChangeRequest::default().resolve(peer, Some(source), &[source]);
        assert_eq!(action, ChangeResponseAction::NoChange);
        assert!(action.maps_address());
        assert!(action.error().is_none());
    }

    #[test]
    fn combined_flag_changes_ip_and_port_together() {
        let default = id4(10, 0, 0, 1, 3478);
        let other = id4(10, 0, 0, 2, 3479);
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();

        let action = change_both().resolve(peer, Some(default), &[default, other]);
        assert_eq!(action, ChangeResponseAction::ChangeBoth(other));
        assert_eq!(action.source(), Some(other));
    }

    #[test]
    fn combined_flag_ignores_an_equal_candidate() {
        // A candidate identical to the default is not a change at all; the
        // resolution must fall through to the next listening address.
        let default = id4(10, 0, 0, 1, 3478);
        let other = id4(10, 0, 0, 2, 3479);
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();

        let action = change_both().resolve(peer, Some(default), &[other, default]);
        assert_eq!(action, ChangeResponseAction::ChangeBoth(other));

        // Nothing but the default is listening, so there is no alternate
        // address and port at all: RFC 5780 Section 6.1's single 420.
        let action = change_both().resolve(peer, Some(default), &[default]);
        assert_eq!(action, ChangeResponseAction::Unsatisfiable);
        assert_eq!(action.error(), Some(crate::ErrorCode::UnknownAttribute));
    }

    #[test]
    fn change_ip_only_answers_from_the_other_address_on_an_ipv6_host() {
        let peer6: SocketAddr = "[::1]:50000".parse().unwrap();
        let first = id6([0; 16], 3478);
        let second = id6(LOOPBACK6, 3478);

        // Same port, different IPv6 address: Table 1's `A`-only row.
        let action =
            ChangeRequest::from_value(0x0000_0001).resolve(peer6, Some(first), &[first, second]);
        assert_eq!(action, ChangeResponseAction::ChangeIpOnly(second));

        // A different port on the same address is not `A`-only, so the request
        // is unsatisfiable and gets 420.
        let wrong_port = id6(LOOPBACK6, 3479);
        let action = ChangeRequest::from_value(0x0000_0001).resolve(
            peer6,
            Some(first),
            &[first, wrong_port],
        );
        assert_eq!(action, ChangeResponseAction::Unsatisfiable);
        assert_eq!(action.error(), Some(crate::ErrorCode::UnknownAttribute));
    }

    #[test]
    fn change_ip_only_works_for_an_ipv4_host_too() {
        // `A` has no address-family restriction in RFC 5780: an IPv4 host with
        // two local addresses answers from the other one exactly as an IPv6
        // host does.
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();
        let default = id4(10, 0, 0, 1, 3478);
        let other = id4(10, 0, 0, 2, 3478);

        let action =
            ChangeRequest::from_value(0x0000_0001).resolve(peer, Some(default), &[default, other]);
        assert_eq!(action, ChangeResponseAction::ChangeIpOnly(other));
        assert_eq!(action.source(), Some(other));

        // With no second address there is nothing to change to: 420.
        let action = ChangeRequest::from_value(0x0000_0001).resolve(peer, Some(default), &[default]);
        assert_eq!(action, ChangeResponseAction::Unsatisfiable);
        assert_eq!(action.error(), Some(crate::ErrorCode::UnknownAttribute));
        assert!(!action.maps_address());
    }

    #[test]
    fn change_port_only_is_actionable_for_both_families() {
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();
        let default = id4(10, 0, 0, 1, 3478);
        let other = id4(10, 0, 0, 1, 3479);

        // Same address, different port: Table 1's `B`-only row.
        let action =
            ChangeRequest::from_value(0x0000_0002).resolve(peer, Some(default), &[default, other]);
        assert_eq!(action, ChangeResponseAction::ChangePortOnly(other));

        // A different address on the same port is not `B`-only, so it is
        // unsatisfiable and gets 420.
        let wrong_addr = id4(10, 0, 0, 2, 3478);
        let action = ChangeRequest::from_value(0x0000_0002).resolve(
            peer,
            Some(default),
            &[default, wrong_addr],
        );
        assert_eq!(action, ChangeResponseAction::Unsatisfiable);
        assert_eq!(action.error(), Some(crate::ErrorCode::UnknownAttribute));
    }

    #[test]
    fn change_port_only_works_for_an_ipv6_peer_too() {
        // `B` has no family restriction: an IPv6 server with two sockets on
        // the same address can change the port just as an IPv4 one can.
        let peer: SocketAddr = "[::1]:50000".parse().unwrap();
        let default = id6([0; 16], 3478);
        let other = id6([0; 16], 3479);

        let action =
            ChangeRequest::from_value(0x0000_0002).resolve(peer, Some(default), &[default, other]);
        assert_eq!(action, ChangeResponseAction::ChangePortOnly(other));

        // A different address on the same port is not `B`-only, so it is
        // unsatisfiable and gets 420.
        let wrong_addr = id6(LOOPBACK6, 3478);
        let action = ChangeRequest::from_value(0x0000_0002).resolve(
            peer,
            Some(default),
            &[default, wrong_addr],
        );
        assert_eq!(action, ChangeResponseAction::Unsatisfiable);
        assert_eq!(action.error(), Some(crate::ErrorCode::UnknownAttribute));
    }

    #[test]
    fn no_flag_row_is_address_family_specific() {
        // RFC 5780 Table 1 carries no family restriction, so every flag set
        // asks for something on either family.
        for family in [IpFamily::V4, IpFamily::V6] {
            assert!(
                ChangeRequest::from_value(0x0000_0001).is_actionable_for(family),
                "`A` is actionable for {family:?}"
            );
            assert!(
                ChangeRequest::from_value(0x0000_0002).is_actionable_for(family),
                "`B` is actionable for {family:?}"
            );
            assert!(
                change_both().is_actionable_for(family),
                "`A`|`B` is actionable for {family:?}"
            );
            assert!(
                !ChangeRequest::default().is_actionable_for(family),
                "no flag set asks for nothing"
            );
        }
    }

    #[test]
    fn no_listen_address_honoring_the_bits_is_unsatisfiable() {
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();
        let only = id4(10, 0, 0, 1, 3478);

        let action = change_both().resolve(peer, Some(only), &[only]);
        assert_eq!(action, ChangeResponseAction::Unsatisfiable);
        assert_eq!(action.source(), None);
        assert!(!action.maps_address());
        assert_eq!(action.error(), Some(crate::ErrorCode::UnknownAttribute));

        // An empty listen list is the same story, not a special case.
        let action = change_both().resolve(peer, None, &[]);
        assert_eq!(action, ChangeResponseAction::Unsatisfiable);
    }

    #[test]
    fn the_default_source_is_not_itself_a_change() {
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();
        let default = id4(10, 0, 0, 1, 3478);

        // The default is the only listener, so there is no address to change
        // to. It is still not a change: `CHANGE-REQUEST` is relative to where
        // the request arrived, not to the peer address.
        let action = change_both().resolve(peer, Some(default), &[default]);
        assert_eq!(action, ChangeResponseAction::Unsatisfiable);
        assert_eq!(action.source(), None);
        assert!(!action.maps_address());

        // The same bits against an IPv6 peer are the same error: RFC 5780
        // Section 6.1 defines one code for every unsatisfiable request.
        let peer6: SocketAddr = "[::1]:50000".parse().unwrap();
        let only6 = id6([0; 16], 3478);
        let action = change_both().resolve(peer6, Some(only6), &[only6]);
        assert_eq!(action, ChangeResponseAction::Unsatisfiable);
        assert_eq!(action.error(), Some(crate::ErrorCode::UnknownAttribute));
    }

    #[test]
    fn a_second_listener_becomes_the_source() {
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();
        let default = id4(10, 0, 0, 1, 3478);
        let other = id4(10, 0, 0, 2, 3479);

        let action = change_both().resolve(peer, Some(default), &[default, other]);
        assert_eq!(action, ChangeResponseAction::ChangeBoth(other));
        assert_eq!(action.source(), Some(other));
        assert!(action.maps_address());
    }

    #[test]
    fn the_family_of_a_peer_is_read_from_the_socket_addr() {
        assert_eq!(family_of("1.2.3.4:1".parse().unwrap()), IpFamily::V4);
        assert_eq!(family_of("[::1]:1".parse().unwrap()), IpFamily::V6);
    }
}
