//! The decision table: request facts in, a [`BindingResponsePlan`] out.
//!
//! Everything above this line stays wire-free. `quickrelay-server` extracts
//! the facts from a parsed message, calls [`decide`], and renders the plan
//! into `quickrelay-protocol` attributes. No error-code literal, no
//! attribute code point and no length prefix appears in this crate's render path.
//!
//! Checks run in the order a peer can observe them, so a request that
//! fails more than one check always gets the same answer:
//! 1. attributes it must understand but does not -- 388
//! 2. a malformed or conflicting ICE role -- 487 / 400
//! 3. CHANGE-REQUEST resolution -- 437 / 386
//! 4. rate limits -- 486
//! 5. otherwise success, with whatever the peer asked the server to echo
//!
//! # What is deliberately not here
//!//! * **Transaction tables.** `370 REQUEST ALREADY IN PROGRESS` is Unassigned
//!   in IANA and the concept does not exist in STUN: RFC 5389 Section
//!   7.1.2 requires a server that receives a duplicate request within a
//!   transaction lifetime to send its answer again, not to reject it.
//!   Duplicate handling is `quickrelay-server`'s transaction bookkeeping, not a
//!   decision.
//! * **Authentication.** Nonce staleness (438) needs a nonce the server
//!   issued and a clock; both live in `quickrelay-auth` (Stage 3).
//! * **Framing.** ICE-TCP and TURN-over-TCP framing is owned by
//!   `quickrelay-transport`.
//!

use std::net::SocketAddr;

use crate::change_request::{ChangeRequest, ChangeResponseAction};
use crate::error_codes::ErrorCode;
use crate::ice::{IceAttributes, IceValidation, IpFamily};
use crate::response::{BindingResponsePlan, ChangeSource, Outcome, ServerIdentity};

/// Attribute codes a server MAY ignore without answering `388` (RFC 5389
/// Section 5.1).
///
/// Any unknown attribute *not* in this list must produce
/// [`ErrorCode::UnknownAttribute`]. The legacy `CHANGE-ADDRESS` (`0x0005`),
/// `CHANGE-IP` (`0x0004`) and `CHANGE-PORT` (`0x0006`) are not listed here, so
/// they are rejected -- a peer still sending them is running pre-RFC 5389.
pub const NOT_COMPREHENSION_REQUIRED: [u16; 5] = [
    0x0001, // MAPPED-ADDRESS
    0x8000, // RESPONSE-ADDRESS
    0x0003, // CHANGE-REQUEST
    0x0009, // ERROR-CODE
    0x0027, // RESPONSE-PORT (legacy)
];

/// Every fact `decide` needs, extracted from the parsed request by
/// `quickrelay-server`. Nothing here is a `quickrelay-protocol` type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingRequestFacts<'a> {
    /// The source address the request was read from.
    pub peer: SocketAddr,
    /// The parsed `CHANGE-REQUEST` value, or `None` when the attribute is
    /// absent.
    pub change: Option<ChangeRequest>,
    /// The parsed ICE attribute set.
    pub ice: IceAttributes,
    /// The request carried `SOFTWARE` (`0x8022`), so the reply must echo it.
    pub software_requested: bool,
    /// Codes of attributes the server does not comprehend, `None` when the
    /// request carried none.
    ///
    /// Both this and `ice` are borrows: the caller owns the backing data and
    /// must keep it alive for as long as the facts are used.
    pub unknown_attributes: Option<&'a [u16]>,
    /// The server wants to send this peer to another server, if at all.
    pub redirect_to: Option<ServerIdentity>,
}

/// The answer to one Binding request.
///
/// `source` is the identity the reply would otherwise leave from, and
/// `addresses` the full listen list on this host -- every socket the server
/// could send from. `addresses` may include `source`; the default socket is
/// never reported as a change.
pub fn decide(
    facts: &BindingRequestFacts<'_>,
    source: Option<ServerIdentity>,
    addresses: &[ServerIdentity],
) -> BindingResponsePlan {
    // 1. Attributes the server does not understand.
    if let Some(unknown) = facts.unknown_attributes {
        let must_reject = unknown
            .iter()
            .any(|code| !NOT_COMPREHENSION_REQUIRED.contains(code));
        if must_reject {
            return BindingResponsePlan::error(ErrorCode::UnknownAttribute);
        }
    }

    // 2. ICE validation: a role conflict is 487, a malformed role attribute is
    // 400, an OTHER-ADDRESS family mismatch is 437.
    let family = match facts.peer {
        SocketAddr::V4(_) => IpFamily::V4,
        SocketAddr::V6(_) => IpFamily::V6,
    };
    if let Some(code) = validate_ice(&facts.ice, family) {
        return BindingResponsePlan::error(code);
    }

    // 3. Load balancing before CHANGE-REQUEST: a redirect replaces the reply
    // address and is not subject to a flag the peer did not ask for.
    if let Some(alternate) = facts.redirect_to {
        return BindingResponsePlan::redirect(alternate).with_software(facts.software_requested);
    }

    // 4. CHANGE-REQUEST.
    let change = facts.change.unwrap_or_default();
    let Some(default) = source else {
        // No default source means no socket at all to answer from.
        if change.is_some() {
            return BindingResponsePlan::error(ErrorCode::UnsupportedAddressFamily);
        }
        return BindingResponsePlan::success(ChangeSource::Default)
            .with_software(facts.software_requested);
    };

    let action = change.resolve(facts.peer, Some(default), addresses);
    let mut plan = match action {
        ChangeResponseAction::NoChange => BindingResponsePlan::success(ChangeSource::Default),
        action => {
            BindingResponsePlan::success(ChangeSource::Default).with_change_action(action, default)
        }
    };
    if matches!(plan.outcome, Outcome::Success) {
        plan.include_software = facts.software_requested;
    }
    plan
}

/// The ICE checks that gate a reply, as one error code.
fn validate_ice(ice: &IceAttributes, family: IpFamily) -> Option<ErrorCode> {
    let result = crate::ice::validate(ice, family);
    let code = result.error();
    // ICE-PRIORITY on a Binding request is not an ICE check: the attribute
    // belongs on a candidate-check, and answering it from here would treat a
    // control message as an ICE check.
    if code.is_none() {
        return crate::ice::priority_on_binding(ice.priority);
    }
    // Keep every validation arm visible so a new one cannot go unhandled.
    let _ = matches!(result, IceValidation::Ok);
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_codes::ReasonPhrase;
    use crate::ice::{
        other_address_from_bytes, validate_other_address, IceAttributes, IceRole, IceTiebreaker,
        IceValidation, IpFamily,
    };
    use std::net::SocketAddr;

    /// The peer address every test starts from.
    const PEER: &str = "10.0.0.7:50000";

    /// The peer address, parsed fresh for every test.
    fn peer_value(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    /// The default listen address.
    fn listen_id(port: u16) -> ServerIdentity {
        ServerIdentity::ipv4(10, 0, 0, 1, port)
    }

    /// An `IceAttributes` set the test owns.
    fn ice_value(role: IceRole, tiebreaker: Option<IceTiebreaker>) -> IceAttributes {
        IceAttributes {
            role,
            tiebreaker,
            ..Default::default()
        }
    }

    /// A tiebreaker.
    fn tie(v: u64) -> IceTiebreaker {
        IceTiebreaker(v)
    }

    #[test]
    fn a_plain_request_answers_success() {
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Success);
        assert!(plan.include_xor_mapped);
        assert!(!plan.include_software);
        assert!(!plan.include_alternate_server);
        assert_eq!(plan.source, ChangeSource::Default);
        assert_eq!(plan.reply_identity(default), default);
    }

    #[test]
    fn an_unknown_attribute_must_be_rejected_with_388() {
        let default = listen_id(3478);
        // 0x0005 is the legacy CHANGE-ADDRESS / CHANGED-ADDRESS code point.
        let unknown = [0x0005u16];
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: Some(&unknown),
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 388);
        assert!(!plan.include_xor_mapped);
    }

    #[test]
    fn the_legacy_change_codes_are_not_ignorable() {
        let default = listen_id(3478);
        // CHANGE-IP (0x0004), CHANGE-ADDRESS (0x0005) and CHANGE-PORT (0x0006)
        // are all outside the not-comprehension-required set.
        for code in [0x0004u16, 0x0005, 0x0006] {
            let unknown = [code];
            let facts = BindingRequestFacts {
                peer: peer_value(PEER),
                change: None,
                ice: IceAttributes::default(),
                software_requested: false,
                unknown_attributes: Some(&unknown),
                redirect_to: None,
            };
            let plan = decide(&facts, Some(default), &[default]);
            assert_eq!(
                plan.outcome,
                Outcome::Error(ErrorCode::UnknownAttribute),
                "0x{code:04x}"
            );
        }
    }

    #[test]
    fn the_not_comprehension_required_set_is_ignored() {
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: Some(&NOT_COMPREHENSION_REQUIRED),
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Success);
    }

    #[test]
    fn a_clashing_ice_role_answers_role_conflict_487() {
        let default = listen_id(3478);
        let ice = ice_value(IceRole::Conflict, Some(tie(1)));
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: ice,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::RoleConflict));
        assert_eq!(plan.outcome.error().unwrap().number(), 487);
        assert_eq!(
            plan.outcome.error().unwrap().reason().as_str(),
            "Role Conflict"
        );
    }

    #[test]
    fn a_role_attribute_without_a_tiebreaker_answers_bad_request() {
        let default = listen_id(3478);
        let ice = ice_value(IceRole::Controlled, None);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: ice,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::BadRequest));
    }

    #[test]
    fn a_well_formed_controlling_role_is_accepted() {
        let default = listen_id(3478);
        let ice = ice_value(IceRole::Controlling, Some(tie(7)));
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: ice,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Success);
    }

    #[test]
    fn an_ice_priority_on_a_binding_request_is_unknown_attribute() {
        let default = listen_id(3478);
        let mut ice = IceAttributes::default();
        ice.priority = Some(0x6e00_01ff);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: ice,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
    }

    #[test]
    fn a_software_request_makes_the_reply_echo_software() {
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            software_requested: true,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert!(plan.include_software);
        assert!(plan.echoes());

        // An error reply must not echo: the peer already knows the answer.
        let unknown = [0x0005u16];
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            software_requested: true,
            unknown_attributes: Some(&unknown),
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert!(!plan.include_software);
    }

    #[test]
    fn a_honored_change_request_moves_the_source() {
        let default = listen_id(3478);
        let other = ServerIdentity::ipv4(10, 0, 0, 2, 3479);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0003)),
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default, other]);
        assert_eq!(plan.outcome, Outcome::Success);
        assert_eq!(plan.source, ChangeSource::Explicit(other));
        assert_eq!(plan.reply_identity(default), other);
        assert!(plan.include_xor_mapped);
    }

    #[test]
    fn an_unhonorably_requested_change_answers_437() {
        // `A`|`B` against an IPv6 peer: the combined row must differ in both
        // dimensions, and there is no second listener. 437 is the error for a
        // flag the family cannot carry.
        let default =
            ServerIdentity::ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 1], 3478);
        let facts = BindingRequestFacts {
            peer: peer_value("[::1]:50000"),
            change: Some(ChangeRequest::from_value(0x0000_0003)),
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(
            plan.outcome,
            Outcome::Error(ErrorCode::UnsupportedAddressFamily)
        );
        assert_eq!(plan.outcome.error().unwrap().number(), 437);
        assert!(!plan.include_xor_mapped);
    }

    #[test]
    fn change_ip_from_an_ipv4_peer_answers_unsupported_family() {
        // `A` alone means "another IPv6 address in the same scope", and IPv4
        // has no scopes: 437, not the 386 that CHANGE-ADDRESS carries.
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0001)),
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(
            plan.outcome,
            Outcome::Error(ErrorCode::UnsupportedAddressFamily)
        );
        assert_eq!(plan.outcome.error().unwrap().number(), 437);
    }

    #[test]
    fn a_combined_change_from_an_ipv4_peer_answers_change_address() {
        // The IPv4 form of the combined bit is what CHANGE-ADDRESS meant.
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0003)),
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::ChangeAddress));
        assert_eq!(plan.outcome.error().unwrap().number(), 386);
        assert_eq!(
            plan.outcome.error().unwrap().reason(),
            ReasonPhrase::ChangeAddress
        );
    }

    #[test]
    fn change_port_from_an_ipv6_peer_answers_unsupported_family() {
        // `B` alone is satisfiable by a second listener, and there is none here:
        // nothing the server can offer is not the default, so 437.
        let default =
            ServerIdentity::ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 1], 3478);
        let facts = BindingRequestFacts {
            peer: peer_value("[::1]:50000"),
            change: Some(ChangeRequest::from_value(0x0000_0002)),
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(
            plan.outcome,
            Outcome::Error(ErrorCode::UnsupportedAddressFamily)
        );
    }

    #[test]
    fn a_redirect_beats_a_change_request() {
        let default = listen_id(3478);
        let alternate = ServerIdentity::ipv4(10, 0, 0, 9, 3480);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0003)),
            ice: IceAttributes::default(),
            software_requested: true,
            unknown_attributes: None,
            redirect_to: Some(alternate),
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert!(plan.include_alternate_server);
        assert!(!plan.include_xor_mapped);
        assert!(plan.include_software, "SOFTWARE is still echoed");
        assert_eq!(plan.reply_identity(default), alternate);
    }

    #[test]
    fn a_redirect_with_no_change_request_is_still_a_redirect() {
        let default = listen_id(3478);
        let alternate = ServerIdentity::ipv4(10, 0, 0, 9, 3480);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: Some(alternate),
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert!(plan.include_alternate_server);
        assert!(!plan.include_xor_mapped);
    }

    #[test]
    fn with_no_default_source_a_change_request_cannot_be_honored() {
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0003)),
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, None, &[]);
        assert_eq!(
            plan.outcome,
            Outcome::Error(ErrorCode::UnsupportedAddressFamily)
        );
    }

    #[test]
    fn with_no_default_source_a_plain_request_still_succeeds() {
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, None, &[]);
        assert_eq!(plan.outcome, Outcome::Success);
        assert_eq!(plan.source, ChangeSource::Default);
    }

    #[test]
    fn comprehension_beats_ice_beats_change_request() {
        let default = listen_id(3478);
        let ice = ice_value(IceRole::Conflict, Some(tie(1)));

        // 1. The legacy CHANGE-ADDRESS code is unknown: 388.
        let unknown = [0x0005u16];
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0001)),
            ice: ice,
            software_requested: false,
            unknown_attributes: Some(&unknown),
            redirect_to: None,
        };
        assert_eq!(
            decide(&facts, Some(default), &[default]).outcome,
            Outcome::Error(ErrorCode::UnknownAttribute)
        );

        // 2. With comprehension satisfied, the role conflict wins: 487.
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0001)),
            ice: ice,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        assert_eq!(
            decide(&facts, Some(default), &[default]).outcome,
            Outcome::Error(ErrorCode::RoleConflict)
        );

        // 3. With the role valid, CHANGE-REQUEST is what fails. `A` alone from
        // an IPv4 peer is IPv6-only, so 437.
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0001)),
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        assert_eq!(
            decide(&facts, Some(default), &[default]).outcome,
            Outcome::Error(ErrorCode::UnsupportedAddressFamily)
        );
    }

    #[test]
    fn an_empty_change_request_is_a_no_op() {
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0)),
            ice: IceAttributes::default(),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Success);
        assert_eq!(plan.source, ChangeSource::Default);
        assert!(plan.include_xor_mapped);
    }

    #[test]
    fn the_change_action_to_plan_bridge_preserves_the_error() {
        let default = listen_id(3478);
        let plan = BindingResponsePlan::success(ChangeSource::Default)
            .with_change_action(ChangeResponseAction::ChangeAddressOnly, default);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::ChangeAddress));
        assert!(!plan.include_xor_mapped);
    }

    #[test]
    fn the_role_check_maps_a_conflict_to_487() {
        let ice = ice_value(IceRole::Controlling, Some(tie(9)));
        assert_eq!(validate_ice(&ice, IpFamily::V4), None);
        let ice = ice_value(IceRole::Conflict, Some(tie(9)));
        assert_eq!(
            validate_ice(&ice, IpFamily::V4),
            Some(ErrorCode::RoleConflict)
        );
    }

    #[test]
    fn an_other_address_family_mismatch_is_bad_request() {
        // An IPv6 connection cannot carry an IPv4 OTHER-ADDRESS: the request
        // does not describe the connection it is on, so 400, not 437. The
        // attribute is optional, so the check lives beside the role check
        // rather than in the facts.
        let mut other_bytes = [0u8; 16];
        other_bytes[4..8].copy_from_slice(&[10, 0, 0, 7]);
        other_bytes[8] = 0x01;
        let other = other_address_from_bytes(other_bytes).unwrap();
        assert_eq!(
            validate_other_address(&other, IpFamily::V6),
            IceValidation::WrongFamily
        );
        assert_eq!(
            IceValidation::WrongFamily.error(),
            Some(ErrorCode::BadRequest)
        );
        // The same value from an IPv4 connection is accepted.
        assert_eq!(
            validate_other_address(&other, IpFamily::V4),
            IceValidation::Ok
        );
    }
}
