//! The decision table: request facts in, a [`BindingResponsePlan`] out.
//!
//! Everything above this line stays wire-free. `quickrelay-server` extracts
//! the facts from a parsed message, calls [`decide`], and renders the plan
//! into `quickrelay-protocol` attributes. No error-code literal, no
//! attribute code point and no length prefix appears in this crate's render path.
//!
//! Checks run in the order a peer can observe them, so a request that
//! fails more than one check always gets the same answer:
//! 1. attributes it must understand but does not -- 420
//! 2. a malformed or conflicting ICE role -- 487 / 400
//! 3. CHANGE-REQUEST resolution -- 420
//! 4. otherwise success, with whatever the peer asked the server to echo
//!
//! # What is deliberately not here
//! * **Transaction tables.** There is no "request already in progress" error
//!   to decide here, and none of 370, 390 or 430 has a row in any STUN
//!   error-code table. RFC 5389 Section 7.3.1 requires a server that receives
//!   a duplicate request within a transaction lifetime to send its answer
//!   again, not to reject it, so a duplicate is a cache hit and not a decision:
//!   it is `quickrelay-server`'s transaction cache, not a plan.
//! * **Authentication.** Nonce staleness (438) needs a nonce the server
//!   issued and a clock; both live in `quickrelay-auth` (Stage 3).
//! * **Framing.** ICE-TCP and TURN-over-TCP framing is owned by
//!   `quickrelay-transport`.
//!

use std::net::SocketAddr;

use crate::change_request::{ChangeRequest, ChangeResponseAction};
use crate::error_codes::ErrorCode;
use crate::ice::{IceAttributes, IceValidation, OtherAddress, IpFamily};
use crate::response::{BindingResponsePlan, ChangeSource, Outcome, ServerIdentity};

/// Attribute codes the server may ignore without answering 420, because the
/// server has no use for them: they describe the connection or the request
/// itself rather than something the server must act on.
///
/// The list is deliberately conservative. RFC 5389 Section 7.3 does not
/// publish a global allowlist; it says comprehension-*optional* attributes
/// (`0x8000-0xFFFF`) may be ignored, and that a server *should* ignore a
/// comprehension-*required* attribute it does not expect. What a Binding
/// server ignores, therefore, is a property of this server and is stated here
/// next to the 420 decision it gates, rather than derived from a registry
/// constant.
///
/// Everything not listed here must produce [`ErrorCode::UnknownAttribute`]
/// (420) and be named in the reply's `UNKNOWN-ATTRIBUTES` attribute
/// (RFC 8489 Section 14.8). That includes the legacy `CHANGE-ADDRESS`
/// (`0x0005`), `CHANGE-IP` (`0x0004`) and `CHANGE-PORT` (`0x0006`) and the
/// `CHANGE-REQUEST` slot itself: RFC 8489 Section 18.3.1 records `0x0003` as
/// `Reserved; was CHANGE-REQUEST prior to [RFC5389]`, so under 8489 a peer
/// that still sends it is out of date and gets 420. `quickrelay-server`
/// supplies the codes, so whether `0x0003` is honored is a decision the caller
/// makes by omitting it from the unknown list, not a constant here.
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
    /// The request named its own address in `OTHER-ADDRESS`, when present.
    ///
    /// Carried as the parsed value rather than the wire body: the family
    /// mismatch that 400 answers is a property of the address, and
    /// `quickrelay-server` is the side that reads it off the message.
    pub other_address: Option<OtherAddress>,
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
        // RFC 8489 Section 6.3.1: the 420 must list the unknown
        // comprehension-required attributes it met. Only the codes that
        // actually rejected the request are named here, so a comprehension-
        // optional code the server ignores is never reported as unknown.
        let rejecting: Vec<u16> = unknown
            .iter()
            .copied()
            .filter(|code| !NOT_COMPREHENSION_REQUIRED.contains(code))
            .collect();
        if !rejecting.is_empty() {
            return BindingResponsePlan::error(ErrorCode::UnknownAttribute)
                .with_unknown_attributes(&rejecting);
        }
    }

    // 2. ICE validation: a role conflict is 487, a malformed role attribute
    // or an OTHER-ADDRESS family mismatch is 400. The family is the socket the
    // request arrived on, so it is read once and shared by both checks.
    let family = match facts.peer {
        SocketAddr::V4(_) => IpFamily::V4,
        SocketAddr::V6(_) => IpFamily::V6,
    };
    // OTHER-ADDRESS names the peer's own address on this connection, so a
    // family it names different from the one the request arrived on means the
    // request does not describe the connection it is on: 400. It is a 400 and
    // not a 420 because the server does comprehend the attribute -- it reads
    // the family field and compares it with the socket, so the check is on the
    // value, not on the code point.
    if let Some(other) = facts.other_address {
        let check = crate::ice::validate_other_address(&other, family);
        if !matches!(check, IceValidation::Ok) {
            // `WrongFamily` is the only arm that check can return, and the
            // error table already pairs it with 400.
            return BindingResponsePlan::error(check.error().expect("non-Ok carries a code"));
        }
    }
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
        // No default source means no socket at all to answer from, so there
        // is no alternate address and port either: 420 (RFC 5780 Section 6.1).
        if change.is_some() {
            return BindingResponsePlan::error(ErrorCode::UnknownAttribute);
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
        other_address_from_value, validate_other_address, IceAttributes, IceRole, IceTiebreaker,
        IceValidation, IpFamily, OtherAddress,
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
            other_address: None,
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
    fn an_unknown_attribute_must_be_rejected_with_420() {
        let default = listen_id(3478);
        // 0x0005 is the legacy CHANGE-ADDRESS / CHANGED-ADDRESS code point.
        let unknown = [0x0005u16];
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            other_address: None,
            software_requested: false,
            unknown_attributes: Some(&unknown),
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
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
                other_address: None,
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
            other_address: None,
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
            other_address: None,
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
            other_address: None,
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
            other_address: None,
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
            other_address: None,
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
            other_address: None,
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
            other_address: None,
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
            other_address: None,
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
    fn an_unhonorably_requested_change_answers_420() {
        // `A`|`B` with only one listener: both dimensions must differ and no
        // second address exists. RFC 5780 Section 6.1 defines a single error
        // for this, and it is 420.
        let default =
            ServerIdentity::ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 1], 3478);
        let facts = BindingRequestFacts {
            peer: peer_value("[::1]:50000"),
            change: Some(ChangeRequest::from_value(0x0000_0003)),
            ice: IceAttributes::default(),
            other_address: None,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(
            plan.outcome,
            Outcome::Error(ErrorCode::UnknownAttribute)
        );
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
        assert!(!plan.include_xor_mapped);
    }

    #[test]
    fn change_ip_from_an_ipv4_peer_answers_420() {
        // `A` has no address-family restriction, but the host has no second
        // address to answer from, so there is no alternate address and port.
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0001)),
            ice: IceAttributes::default(),
            other_address: None,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
    }

    #[test]
    fn a_combined_change_from_an_ipv4_peer_answers_420() {
        // The same request answers 420 over either family: RFC 5780 Section 6.1
        // defines one error for every unsatisfiable CHANGE-REQUEST.
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0003)),
            ice: IceAttributes::default(),
            other_address: None,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
        assert_eq!(
            plan.outcome.error().unwrap().reason(),
            ReasonPhrase::UnknownAttribute
        );
    }

    #[test]
    fn change_port_from_an_ipv6_peer_answers_420() {
        // `B` alone needs a second listener, and there is none here: nothing
        // the server can offer is not the default.
        let default =
            ServerIdentity::ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 1], 3478);
        let facts = BindingRequestFacts {
            peer: peer_value("[::1]:50000"),
            change: Some(ChangeRequest::from_value(0x0000_0002)),
            ice: IceAttributes::default(),
            other_address: None,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
    }

    #[test]
    fn a_redirect_beats_a_change_request() {
        let default = listen_id(3478);
        let alternate = ServerIdentity::ipv4(10, 0, 0, 9, 3480);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0003)),
            ice: IceAttributes::default(),
            other_address: None,
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
            other_address: None,
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
            other_address: None,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, None, &[]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
    }

    #[test]
    fn with_no_default_source_a_plain_request_still_succeeds() {
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            other_address: None,
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

        // 1. The legacy CHANGE-ADDRESS code is unknown: 420.
        let unknown = [0x0005u16];
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0001)),
            ice: ice,
            other_address: None,
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
            other_address: None,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        assert_eq!(
            decide(&facts, Some(default), &[default]).outcome,
            Outcome::Error(ErrorCode::RoleConflict)
        );

        // 3. With the role valid, CHANGE-REQUEST is what fails: no second
        // address exists, so 420.
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0001)),
            ice: IceAttributes::default(),
            other_address: None,
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        assert_eq!(
            decide(&facts, Some(default), &[default]).outcome,
            Outcome::Error(ErrorCode::UnknownAttribute)
        );
    }

    #[test]
    fn an_other_address_of_the_wrong_family_is_a_400() {
        // The peer arrived on an IPv4 socket but named an IPv6 address: the
        // request does not describe the connection it is on. This is 400, not
        // the 420 the unknown-attribute arm answers, because OTHER-ADDRESS is
        // an attribute the server does comprehend.
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            other_address: Some(other_value(IpFamily::V6, [0xff; 16], 50000)
                .expect("family code 0x02 is valid")),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::BadRequest));
        assert_eq!(plan.outcome.error().unwrap().number(), 400);
        assert!(plan.unknown_attributes.is_none(), "a 400 carries no attribute list");
    }

    #[test]
    fn an_other_address_that_names_the_connection_is_not_an_error() {
        // The same family as the socket the request arrived on is fine: the
        // check is on the family, not on whether the peer echoed the value it
        // was told about.
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            other_address: Some(other_value(IpFamily::V4,
                [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 50000)
                .expect("family code 0x01 is valid")),
            software_requested: false,
            unknown_attributes: None,
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Success);
    }

    #[test]
    fn comprehension_beats_the_other_address_family_check() {
        // Step order is observable: a request that is both unknown and
        // malformed answers 420, because the comprehension check runs first.
        let default = listen_id(3478);
        let unknown = [0x0006u16];
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: None,
            ice: IceAttributes::default(),
            other_address: Some(other_value(IpFamily::V6, [0xff; 16], 50000).unwrap()),
            software_requested: false,
            unknown_attributes: Some(&unknown),
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
    }

    #[test]
    fn an_empty_change_request_is_a_no_op() {
        let default = listen_id(3478);
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0)),
            ice: IceAttributes::default(),
            other_address: None,
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
            .with_change_action(ChangeResponseAction::Unsatisfiable, default);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
        assert!(!plan.include_xor_mapped);
    }

    #[test]
    fn an_unhonorably_requested_change_names_the_attribute() {
        // RFC 8489 Section 14.8 requires a 420 to carry the unknown code in an
        // UNKNOWN-ATTRIBUTES attribute. The decision names the code point; the
        // reply renders it.
        let default = listen_id(3478);
        let unknown = [0x0003u16];
        let facts = BindingRequestFacts {
            peer: peer_value(PEER),
            change: Some(ChangeRequest::from_value(0x0000_0003)),
            ice: IceAttributes::default(),
            other_address: None,
            software_requested: false,
            unknown_attributes: Some(&unknown),
            redirect_to: None,
        };
        let plan = decide(&facts, Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
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

    /// Build an `OTHER-ADDRESS` value in the on-wire layout: a zero octet,
    /// the family code, the port, then the address.
    fn other_value(family: IpFamily, address: [u8; 16], port: u16) -> Option<OtherAddress> {
        let octets = match family {
            IpFamily::V4 => 4,
            IpFamily::V6 => 16,
        };
        let mut value = vec![0u8; 4 + octets];
        value[1] = family.code();
        value[2..4].copy_from_slice(&port.to_be_bytes());
        value[4..4 + octets].copy_from_slice(&address[..octets]);
        other_address_from_value(&value)
    }

    #[test]
    fn an_other_address_family_mismatch_is_bad_request() {
        // An IPv6 connection cannot carry an IPv4 OTHER-ADDRESS: the request
        // does not describe the connection it is on, so 400. The
        // attribute is optional, so the check lives beside the role check
        // rather than in the facts.
        let other = other_value(IpFamily::V4, [10, 0, 0, 7, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0], 50000)
            .unwrap();
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
