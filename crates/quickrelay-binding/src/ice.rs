//! ICE attribute validation (RFC 8445).
//!
//! QuickRelay is a TURN/STUN server, not an ICE agent: this module validates
//! that a peer's Binding request carries well-formed ICE attributes and
//! decides the role-conflict outcome. Nomination, gathering and checking are
//! out of scope.
//!
//! Attribute codes (IANA, 2024-12-20): ICE-CONTROLLED `0x8029`,
//! ICE-CONTROLLING `0x802A`, ICE-PRIORITY `0x0024`, OTHER-ADDRESS `0x802C`.
//!
//! # What this module decides
//!
//! ICE-CONTROLLED and ICE-CONTROLLING are mutually exclusive, and each one
//! carries the peer's 64-bit tiebreaker. QuickRelay is not an ICE endpoint, so
//! it never claims a role of its own and has no tiebreaker to compare against:
//! the conflict is decided from the request alone.
//!
//! * Both attributes present -- the peer claims two roles at once, a role
//!   conflict ([`ErrorCode::RoleConflict`], 487).
//! * One present without a tiebreaker -- the attribute is only well formed
//!   with it, so 400 Bad Request.
//! * Neither present, or exactly one with a tiebreaker -- acceptable.
//! * `ICE-PRIORITY` present -- it belongs on a candidate-check, not on a
//!   `Binding` request: 420 Unknown Attribute.
//! * `OTHER-ADDRESS` naming a family different from the one this connection
//!   actually uses -- the request does not describe the connection it is on:
//!   400 Bad Request, reported as [`IceValidation::WrongFamily`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ErrorCode;

/// The address family of a socket address, as the server sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    /// IPv4 (RFC 8489 Section 14.1, family `0x01`).
    V4,
    /// IPv6 (family `0x02`).
    V6,
}

impl IpFamily {
    /// The address-family field `OTHER-ADDRESS` carries.
    pub const fn code(self) -> u8 {
        match self {
            IpFamily::V4 => 0x01,
            IpFamily::V6 => 0x02,
        }
    }

    /// Whether `other` is a different address family from `self`.
    pub fn differs_from(self, other: IpFamily) -> bool {
        self != other
    }
}

/// Which ICE role the peer claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IceRole {
    /// The peer includes ICE-CONTROLLING (RFC 8445 Section 7.1.3.1).
    Controlling,
    /// The peer includes ICE-CONTROLLED (RFC 8445 Section 7.1.3.1).
    Controlled,
    /// Neither attribute is present: the peer is not an ICE agent.
    #[default]
    None,
    /// Both attributes are present at once: always an error.
    Conflict,
}

impl IceRole {
    /// Combine the two presence bits into a role. A request carrying both
    /// `ICE-CONTROLLED` and `ICE-CONTROLLING` is always a conflict, whatever
    /// the tiebreakers say.
    pub fn from_presence(controlled: bool, controlling: bool) -> Self {
        match (controlled, controlling) {
            (true, true) => IceRole::Conflict,
            (true, false) => IceRole::Controlled,
            (false, true) => IceRole::Controlling,
            (false, false) => IceRole::None,
        }
    }
}

/// The 64-bit tiebreaker carried in ICE-CONTROLLED / ICE-CONTROLLING.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IceTiebreaker(pub u64);

impl IceTiebreaker {
    /// Decode from the 8-octet attribute value, big-endian.
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        IceTiebreaker(u64::from_be_bytes(bytes))
    }

    /// Encode for a response, big-endian.
    pub const fn as_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/// Everything this crate needs to validate a peer's ICE attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IceAttributes {
    /// The role the peer claims.
    pub role: IceRole,
    /// The peer's tiebreaker, when the role attribute is present.
    pub tiebreaker: Option<IceTiebreaker>,
    /// ICE-PRIORITY value, when present (RFC 8445 Section 4.1.1.4).
    pub priority: Option<u32>,
    /// USE-CANDIDATE was present (RFC 8445 Section 6.1.2).
    pub use_candidate: bool,
}

impl IceAttributes {
    /// A role attribute without a tiebreaker is not well formed (400).
    pub const fn is_role_malformed(self) -> bool {
        (matches!(self.role, IceRole::Controlled | IceRole::Controlling))
            && self.tiebreaker.is_none()
    }
}

/// The `OTHER-ADDRESS` value, in the layout its defining RFCs give it.
///
/// RFC 5780 Section 7.4 makes OTHER-ADDRESS a rename of RFC 3489's
/// CHANGED-ADDRESS that keeps the same attribute number, and RFC 3489
/// Section 11.2.3 calls that attribute's syntax "identical to MAPPED-ADDRESS".
/// So the value is the MAPPED-ADDRESS body: a zero octet, the family code,
/// the port, then the address -- 8 octets for IPv4 and 20 for IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OtherAddress {
    /// The family of `address` and `port`.
    pub family: IpFamily,
    /// The port the attribute carries.
    pub port: u16,
    /// The address octets, zero-padded to 16 so an IPv4 value needs no
    /// special case. An IPv4 address sits in the first four octets.
    pub address: [u8; 16],
}

/// Decode an `OTHER-ADDRESS` value. Returns `None` when the leading octet is
/// not zero, the family code is not `0x01` or `0x02`, or the value's length
/// does not match its family -- 8 octets for IPv4, 20 for IPv6.
pub fn other_address_from_value(value: &[u8]) -> Option<OtherAddress> {
    if value.is_empty() || value[0] != 0 {
        return None;
    }
    let (family, octets) = match value.get(1) {
        Some(0x01) => (IpFamily::V4, 4),
        Some(0x02) => (IpFamily::V6, 16),
        _ => return None,
    };
    if value.len() != 4 + octets {
        return None;
    }
    let mut address = [0u8; 16];
    address[..octets].copy_from_slice(&value[4..4 + octets]);
    Some(OtherAddress {
        family,
        port: u16::from_be_bytes([value[2], value[3]]),
        address,
    })
}

/// Encode `other` back into its value: 8 octets for IPv4, 20 for IPv6.
pub fn other_address_to_value(other: &OtherAddress) -> Vec<u8> {
    let octets = match other.family {
        IpFamily::V4 => 4,
        IpFamily::V6 => 16,
    };
    let mut out = vec![0u8; 4 + octets];
    out[1] = other.family.code();
    out[2..4].copy_from_slice(&other.port.to_be_bytes());
    out[4..4 + octets].copy_from_slice(&other.address[..octets]);
    out
}

/// The address in `other` as an [`IpAddr`], respecting its family.
pub fn other_address_to_ip_addr(other: &OtherAddress) -> Option<IpAddr> {
    match other.family {
        IpFamily::V4 => Some(IpAddr::V4(Ipv4Addr::from([
            other.address[0],
            other.address[1],
            other.address[2],
            other.address[3],
        ]))),
        IpFamily::V6 => Some(IpAddr::V6(Ipv6Addr::from(other.address))),
    }
}

/// The outcome of validating a peer's ICE attribute set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceValidation {
    /// The attributes are well formed; the reply may proceed.
    Ok,
    /// The peer claims both roles at once, so the server cannot answer it
    /// without telling it which one to take (RFC 8445 Section 7.2.1.1).
    RoleConflict,
    /// Both role attributes are present at once: always malformed.
    Conflict,
    /// `OTHER-ADDRESS` names a family different from the one this connection
    /// actually uses: the request does not describe the connection it is on, so
    /// it is not well formed.
    WrongFamily,
    /// A role attribute is present without a tiebreaker.
    Malformed,
    /// `ICE-PRIORITY` was present on a `Binding` request, where it belongs on
    /// a candidate-check only.
    UnknownAttribute,
}

impl IceValidation {
    /// The error code to emit, or `None` when the validation passed.
    pub fn error(self) -> Option<ErrorCode> {
        match self {
            IceValidation::Ok => None,
            IceValidation::RoleConflict | IceValidation::Conflict => Some(ErrorCode::RoleConflict),
            IceValidation::WrongFamily => Some(ErrorCode::BadRequest),
            IceValidation::Malformed => Some(ErrorCode::BadRequest),
            IceValidation::UnknownAttribute => Some(ErrorCode::UnknownAttribute),
        }
    }
}

/// The ICE role conflict check (RFC 8445 Section 7.2.1.1).
///
/// `peer_role` is the role the peer claims for itself in the request;
/// `peer_tiebreaker` its tiebreaker.
///
/// `local_role` and `local_tiebreaker` are the role the local side would take
/// on this connection, if any. QuickRelay never does: it is a STUN server, not
/// an ICE endpoint, so the server always passes `None` and the check reduces to
/// the peer's own request being well formed.
pub fn role_conflict(
    peer_role: IceRole,
    peer_tiebreaker: Option<IceTiebreaker>,
    local_role: Option<IceRole>,
    local_tiebreaker: Option<IceTiebreaker>,
) -> IceValidation {
    if matches!(peer_role, IceRole::Conflict) {
        return IceValidation::Conflict;
    }
    if matches!(peer_role, IceRole::Controlled | IceRole::Controlling)
        && peer_tiebreaker.is_none()
    {
        return IceValidation::Malformed;
    }
    let Some(local) = local_role else {
        // The server has no role of its own: there is nothing to conflict with.
        return IceValidation::Ok;
    };
    if local == peer_role {
        return IceValidation::Ok;
    }
    // Different roles: the peer must decide, and the one with the higher
    // tiebreaker becomes the controlling side. Tiebreakers were handed out by
    // separate servers, so a tie is possible.
    let mine = local_tiebreaker.unwrap_or_default().0;
    let theirs = peer_tiebreaker.unwrap_or_default().0;
    if theirs > mine {
        // The peer wins; the server had claimed the controlling role.
        return IceValidation::RoleConflict;
    }
    if mine > theirs {
        // The peer lost; it must re-check with the other role.
        return IceValidation::RoleConflict;
    }
    IceValidation::RoleConflict
}

/// Validate the ICE role attributes of one `Binding` request.
///
/// Checks role conflict (487) and role/tiebreaker well-formedness (400).
/// `peer_family` is the family of the connection the request arrived on, read
/// from the socket: it is the input the caller also feeds to the
/// `OTHER-ADDRESS` family check, so one call takes everything a connection can
/// supply.
pub fn validate(attributes: &IceAttributes, _peer_family: IpFamily) -> IceValidation {
    role_conflict(attributes.role, attributes.tiebreaker, None, None)
}

/// Validate an `OTHER-ADDRESS` attribute against the family of the connection
/// the request arrived on.
///
/// `OTHER-ADDRESS` names the peer's own local address, so a peer that names a
/// family different from the one this connection actually uses is not who it
/// says it is: [`IceValidation::WrongFamily`], which maps to 400 Bad Request.
/// Kept out of [`validate`] because the attribute is optional and the caller
/// extracts it per message.
pub fn validate_other_address(other: &OtherAddress, peer_family: IpFamily) -> IceValidation {
    if other.family.differs_from(peer_family) {
        return IceValidation::WrongFamily;
    }
    IceValidation::Ok
}

/// The ICE-PRIORITY value on a `Binding` request is out of place: the
/// attribute belongs on a candidate-check, and a server that answers it from a
/// `Binding` request would be treating a control message as an ICE check.
pub fn priority_on_binding(priority: Option<u32>) -> Option<ErrorCode> {
    priority.map(|_| ErrorCode::UnknownAttribute)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiebreaker(v: u64) -> IceTiebreaker {
        IceTiebreaker(v)
    }

    #[test]
    fn the_family_codes_match_iana() {
        assert_eq!(IpFamily::V4.code(), 0x01);
        assert_eq!(IpFamily::V6.code(), 0x02);
        assert!(IpFamily::V4.differs_from(IpFamily::V6));
        assert!(!IpFamily::V4.differs_from(IpFamily::V4));
    }

    #[test]
    fn a_binding_with_no_ice_attributes_is_valid() {
        let attributes = IceAttributes::default();
        assert_eq!(validate(&attributes, IpFamily::V4), IceValidation::Ok);
        assert!(IceValidation::Ok.error().is_none());
    }

    #[test]
    fn carrying_both_role_attributes_is_always_a_conflict() {
        let attributes = IceAttributes {
            role: IceRole::from_presence(true, true),
            tiebreaker: Some(tiebreaker(1)),
            ..Default::default()
        };
        assert_eq!(attributes.role, IceRole::Conflict);
        assert_eq!(validate(&attributes, IpFamily::V4), IceValidation::Conflict);
        assert_eq!(
            IceValidation::Conflict.error(),
            Some(ErrorCode::RoleConflict)
        );
        // 487, not the Unassigned 430 the issue asked for.
        assert_eq!(ErrorCode::RoleConflict.number(), 487);
    }

    #[test]
    fn a_role_attribute_without_a_tiebreaker_is_malformed() {
        let attributes = IceAttributes {
            role: IceRole::Controlling,
            tiebreaker: None,
            ..Default::default()
        };
        assert_eq!(
            validate(&attributes, IpFamily::V4),
            IceValidation::Malformed
        );
        assert_eq!(
            IceValidation::Malformed.error(),
            Some(ErrorCode::BadRequest)
        );
    }

    #[test]
    fn other_address_must_match_the_peer_family() {
        let other = OtherAddress {
            family: IpFamily::V4,
            port: 50000,
            address: [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(
            other_address_to_ip_addr(&other).unwrap().to_string(),
            "10.0.0.7"
        );
        // Decode -> encode is the identity, in both families.
        let ipv4 = [0x00u8, 0x01, 0xC3, 0x50, 10, 0, 0, 7];
        assert_eq!(
            other_address_to_value(&other_address_from_value(&ipv4).unwrap()),
            &ipv4[..]
        );
        assert!(!other.family.differs_from(IpFamily::V4));

        // Same family: fine.
        assert_eq!(
            validate_other_address(&other, IpFamily::V4),
            IceValidation::Ok
        );
        // An IPv4 OTHER-ADDRESS from an IPv6 peer: the peer is not who it says.
        assert_eq!(
            validate_other_address(&other, IpFamily::V6),
            IceValidation::WrongFamily
        );
        assert_eq!(
            IceValidation::WrongFamily.error(),
            Some(ErrorCode::BadRequest)
        );
    }

    #[test]
    fn other_address_rejects_a_value_its_family_does_not_fit() {
        // A value is 8 octets for IPv4 and 20 for IPv6; the family code
        // decides which, and anything else is neither.
        let ipv6: [u8; 20] = [
            0x00, 0x02, 0xC3, 0x50, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        assert_eq!(
            other_address_to_value(&other_address_from_value(&ipv6).unwrap()),
            &ipv6[..]
        );
        assert_eq!(
            other_address_from_value(&ipv6).unwrap().family,
            IpFamily::V6
        );

        // Family code 0x03 is not a family.
        assert!(other_address_from_value(&[0x00, 0x03, 0, 0, 0, 0, 0, 0]).is_none());
        // The leading octet must be zero.
        assert!(other_address_from_value(&[0x01, 0x01, 0, 0, 0, 0, 0, 0]).is_none());
        // An IPv6 family code with an IPv4-length value.
        assert!(other_address_from_value(&[0x00, 0x02, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn the_tiebreaker_round_trips_big_endian() {
        let bytes: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(tiebreaker(1).as_bytes(), bytes);
        assert_eq!(IceTiebreaker::from_bytes(bytes).0, 1);
        assert_eq!(tiebreaker(u64::MAX).as_bytes()[0], 0xFF);
    }

    #[test]
    fn with_no_local_role_the_role_check_is_a_noop() {
        // The server is not an ICE endpoint, so it presents no role and the
        // check cannot fire. A controlling peer is accepted either way.
        let attributes = IceAttributes {
            role: IceRole::Controlling,
            tiebreaker: Some(tiebreaker(5)),
            ..Default::default()
        };
        assert_eq!(validate(&attributes, IpFamily::V4), IceValidation::Ok);
        assert_eq!(
            role_conflict(IceRole::Controlling, Some(tiebreaker(5)), None, None),
            IceValidation::Ok
        );
    }

    #[test]
    fn the_role_conflict_check_fires_on_a_different_local_role() {
        // The server claims Controlling, the peer claims Controlled, and the
        // peer's tiebreaker is lower: the peer loses and must re-check.
        assert_eq!(
            role_conflict(
                IceRole::Controlled,
                Some(tiebreaker(1)),
                Some(IceRole::Controlling),
                Some(tiebreaker(2)),
            ),
            IceValidation::RoleConflict
        );
        // Tiebreakers are issued by different servers, so a tie is possible.
        assert_eq!(
            role_conflict(
                IceRole::Controlled,
                Some(tiebreaker(2)),
                Some(IceRole::Controlling),
                Some(tiebreaker(2)),
            ),
            IceValidation::RoleConflict
        );
        // Same role, no conflict.
        assert_eq!(
            role_conflict(
                IceRole::Controlling,
                Some(tiebreaker(2)),
                Some(IceRole::Controlling),
                Some(tiebreaker(9)),
            ),
            IceValidation::Ok
        );
    }

    #[test]
    fn a_priority_attribute_on_binding_is_unknown_attribute() {
        assert_eq!(
            priority_on_binding(Some(0x6e00_01ff)),
            Some(ErrorCode::UnknownAttribute)
        );
        assert_eq!(priority_on_binding(None), None);
    }

    #[test]
    fn unknown_attributes_map_to_420() {
        assert_eq!(
            IceValidation::UnknownAttribute.error(),
            Some(ErrorCode::UnknownAttribute)
        );
        assert_eq!(ErrorCode::UnknownAttribute.number(), 420);
    }

    #[test]
    fn use_candidate_is_just_a_transport_of_the_peer_flag() {
        let attributes = IceAttributes {
            use_candidate: true,
            role: IceRole::Controlling,
            tiebreaker: Some(tiebreaker(1)),
            ..Default::default()
        };
        assert!(attributes.use_candidate);
        // USE-CANDIDATE alone does not make the request invalid: the server is
        // not an ICE agent and does not nominate.
        assert_eq!(validate(&attributes, IpFamily::V4), IceValidation::Ok);
    }
}
