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
//! RFC 5780 Section 6.1 constrains a flag by the other dimension being held
//! constant across two listening addresses, and by address family:
//!
//! | flags    | peer family | requirement              | error row if unmet            |
//! | -------- | ----------- | ------------------------ | ----------------------------- |
//! | `A`      | IPv6 only   | same port, other address | 437 Unsupported Address Family |
//! | `B`      | either      | same address, other port | 437 Unsupported Address Family |
//! | `A`|`B`  | IPv6        | both differ              | 437 Unsupported Address Family |
//! | `A`|`B`  | IPv4        | both differ              | 386 Change-Address Unassigned  |
//!
//! `A` alone is IPv6-only because the flag means "another local unicast address
//! in the same scope", and IPv4 has no scopes. The IPv4 form of the combined bit
//! is what the legacy `CHANGE-ADDRESS` meant, which is why only that row is 386.

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

    /// Whether the flag set is even meaningful for `family` (RFC 5780
    /// Section 6.1 Table 1). `A` alone is IPv6-only: the flag means "another
    /// IPv6 address in the same scope", and IPv4 has no scopes. `B` and the
    /// combined bit have no family restriction.
    pub const fn is_actionable_for(self, family: IpFamily) -> bool {
        match (self.change_ip, self.change_port) {
            (false, false) => false,
            (true, false) => matches!(family, IpFamily::V6),
            _ => true,
        }
    }

    /// Resolve against the server's listening addresses.
    ///
    /// `peer` is the source address the request was read from — its family
    /// selects the row of RFC 5780 Table 1. `default` is the identity the
    /// reply would otherwise leave from, which a candidate must differ from:
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
    /// `peer` selects the row of RFC 5780 Table 1 by its family. `default` is
    /// what a candidate must differ from: `CHANGE-REQUEST` is relative to
    /// where the request arrived, not to where the peer sits, so the peer
    /// address never enters the comparison itself.
    fn find_source(
        &self,
        peer: SocketAddr,
        default: ServerIdentity,
        addresses: &[ServerIdentity],
    ) -> Option<ServerIdentity> {
        // `A` without `B` is the IPv6-only row of the table: the flag means
        // "another address in the same scope", and IPv4 has no scopes, so no
        // IPv4 listen address can ever satisfy it.
        if self.change_ip && !self.change_port && family_of(peer) != IpFamily::V6 {
            return None;
        }
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

    /// The error row of the table, chosen by which flag the peer asked for.
    ///
    /// RFC 5780 Section 6.1 assigns `Change-Address Unassigned` (386) only to
    /// `CHANGE-ADDRESS`, which is the IPv4 form of the combined bit. Every
    /// other flag that cannot be honored is `Unsupported Address Family`
    /// (437), including `A` alone against an IPv4 peer, where the IPv6 scope
    /// the flag refers to does not exist.
    fn unsatisfiable(self, family: IpFamily) -> ChangeResponseAction {
        match (self.change_ip, self.change_port) {
            // `CHANGE-ADDRESS` = `A`|`B` over IPv4.
            (true, true) if family == IpFamily::V4 => ChangeResponseAction::ChangeAddressOnly,
            _ => ChangeResponseAction::UnsupportedFamily,
        }
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
    /// No address is available to satisfy the request: emit an error reply
    /// (see `crate::error_codes::ErrorCode::UnsupportedAddressFamily`).
    ///
    /// Reserved for the `CHANGE-IP`|`CHANGE-PORT` row that cannot be met: the
    /// reply must differ in *both* dimensions at once and no listen address
    /// differs in both. The pure-flag rows use [`ChangeAddressOnly`] and
    /// [`UnsupportedFamily`] below so the peer can tell them apart.
    Unsatisfiable,
    /// The IPv4 combined-bit row could not be met: this is
    /// `CHANGE-ADDRESS`, whose error is `Change-Address Unassigned` (386)
    /// rather than 437.
    ChangeAddressOnly,
    /// Any other flag the server could not honor, including `A` alone from an
    /// IPv4 peer, where the IPv6 scope the flag refers to does not exist.
    /// RFC 5780 Section 6.1's `Unsupported Address Family` (437).
    UnsupportedFamily,
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
            ChangeResponseAction::Unsatisfiable
            | ChangeResponseAction::ChangeAddressOnly
            | ChangeResponseAction::UnsupportedFamily => None,
        }
    }

    /// Which error code, if any, this action maps to.
    pub fn error(self) -> Option<crate::ErrorCode> {
        use crate::ErrorCode;
        match self {
            ChangeResponseAction::ChangeAddressOnly => Some(ErrorCode::ChangeAddress),
            ChangeResponseAction::UnsupportedFamily | ChangeResponseAction::Unsatisfiable => {
                Some(ErrorCode::UnsupportedAddressFamily)
            }
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
            ChangeResponseAction::Unsatisfiable
            | ChangeResponseAction::ChangeAddressOnly
            | ChangeResponseAction::UnsupportedFamily => false,
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

        // Nothing but the default is listening: the combined row over IPv4 is
        // `CHANGE-ADDRESS`, so 386 rather than 437.
        let action = change_both().resolve(peer, Some(default), &[default]);
        assert_eq!(action, ChangeResponseAction::ChangeAddressOnly);
        assert_eq!(action.error(), Some(crate::ErrorCode::ChangeAddress));
    }

    #[test]
    fn change_ip_only_is_actionable_only_for_ipv6() {
        let peer6: SocketAddr = "[::1]:50000".parse().unwrap();
        let first = id6([0; 16], 3478);
        let second = id6(LOOPBACK6, 3478);

        // Same port, different IPv6 address: Table 1's `A`-only row.
        let action =
            ChangeRequest::from_value(0x0000_0001).resolve(peer6, Some(first), &[first, second]);
        assert_eq!(action, ChangeResponseAction::ChangeIpOnly(second));

        // A different port on the same address is not `A`-only: the row still
        // cannot be met, so it is 437.
        let wrong_port = id6(LOOPBACK6, 3479);
        let action = ChangeRequest::from_value(0x0000_0001).resolve(
            peer6,
            Some(first),
            &[first, wrong_port],
        );
        assert_eq!(action, ChangeResponseAction::UnsupportedFamily);
    }

    #[test]
    fn change_ip_only_from_an_ipv4_peer_is_unsupported_family() {
        // RFC 5780 Section 6.1: `A` alone means "another IPv6 address in the
        // same scope". IPv4 has no scopes, so no IPv4 listen address can
        // ever satisfy it and the error is 437, not the 386 that
        // `CHANGE-ADDRESS` carries.
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();
        let default = id4(10, 0, 0, 1, 3478);
        let other = id4(10, 0, 0, 2, 3478);

        let action =
            ChangeRequest::from_value(0x0000_0001).resolve(peer, Some(default), &[default, other]);
        assert_eq!(action, ChangeResponseAction::UnsupportedFamily);
        assert_eq!(
            action.error(),
            Some(crate::ErrorCode::UnsupportedAddressFamily)
        );
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

        // A different address on the same port is not `B`-only.
        let wrong_addr = id4(10, 0, 0, 2, 3478);
        let action = ChangeRequest::from_value(0x0000_0002).resolve(
            peer,
            Some(default),
            &[default, wrong_addr],
        );
        assert_eq!(action, ChangeResponseAction::UnsupportedFamily);
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

        // A different address on the same port is not `B`-only.
        let wrong_addr = id6(LOOPBACK6, 3478);
        let action = ChangeRequest::from_value(0x0000_0002).resolve(
            peer,
            Some(default),
            &[default, wrong_addr],
        );
        assert_eq!(action, ChangeResponseAction::UnsupportedFamily);
    }

    #[test]
    fn the_table_rows_are_selected_by_the_peer_family() {
        assert_eq!(
            ChangeRequest::from_value(0x0000_0001).is_actionable_for(IpFamily::V6),
            true
        );
        assert_eq!(
            ChangeRequest::from_value(0x0000_0001).is_actionable_for(IpFamily::V4),
            false
        );
        assert_eq!(
            ChangeRequest::from_value(0x0000_0002).is_actionable_for(IpFamily::V4),
            true
        );
        assert_eq!(
            ChangeRequest::from_value(0x0000_0002).is_actionable_for(IpFamily::V6),
            true
        );
        assert_eq!(change_both().is_actionable_for(IpFamily::V4), true);
        assert_eq!(change_both().is_actionable_for(IpFamily::V6), true);
        assert_eq!(
            ChangeRequest::default().is_actionable_for(IpFamily::V4),
            false
        );
    }

    #[test]
    fn no_listen_address_honoring_the_bits_is_unsatisfiable() {
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();
        let only = id4(10, 0, 0, 1, 3478);

        let action = change_both().resolve(peer, Some(only), &[only]);
        assert_eq!(action, ChangeResponseAction::ChangeAddressOnly);
        assert_eq!(action.source(), None);
        assert!(!action.maps_address());

        // An empty listen list is the same story, not a special case.
        let action = change_both().resolve(peer, None, &[]);
        assert_eq!(action, ChangeResponseAction::ChangeAddressOnly);
    }

    #[test]
    fn the_default_source_is_not_itself_a_change() {
        let peer: SocketAddr = "10.0.0.7:50000".parse().unwrap();
        let default = id4(10, 0, 0, 1, 3478);

        // The default is the only listener, so there is no address to change
        // to. It is still not a change: `CHANGE-REQUEST` is relative to where
        // the request arrived, not to the peer address.
        let action = change_both().resolve(peer, Some(default), &[default]);
        assert_eq!(action, ChangeResponseAction::ChangeAddressOnly);
        assert_eq!(action.source(), None);
        assert!(!action.maps_address());

        // The same bits against an IPv6 peer are 437 instead: the combined
        // row is only `CHANGE-ADDRESS` over IPv4.
        let peer6: SocketAddr = "[::1]:50000".parse().unwrap();
        let only6 = id6([0; 16], 3478);
        let action = change_both().resolve(peer6, Some(only6), &[only6]);
        assert_eq!(action, ChangeResponseAction::UnsupportedFamily);
        assert_eq!(
            action.error(),
            Some(crate::ErrorCode::UnsupportedAddressFamily)
        );
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
