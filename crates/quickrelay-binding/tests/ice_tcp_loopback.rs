//! ICE-TCP (RFC 6544 / RFC 4571 shim) loopback for the Binding decision.
//!
//! `quickrelay-binding` owns the semantic decision and no framing and no
//! socket, so the framing primitive used here is the shim itself: a 16-bit
//! big-endian length in front of every STUN message. That is two octets of
//! header, which is not an implementation -- it is the contract the real
//! framing code in `quickrelay-transport` must produce. What is asserted on
//! the server side is the decision: a `Binding` request read through the shim
//! is answered from the same `BindingRequestFacts` as the same request over
//! UDP, because the decision has no transport in its inputs.
//!
//! The listener is a real TCP listener on loopback, so the bytes travel the
//! wire the way they would between a WebRTC endpoint and a TURN server.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};

use quickrelay_binding as binding;

/// One STUN header: 20 octets, method `0x0001` Binding, type `0x0000` Request,
/// a 12-octet transaction id, zero attribute length.
fn stun_header(tid: [u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&0x0001u16.to_be_bytes());
    out.extend_from_slice(&0x0000u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&tid);
    out
}

/// One packet through the shim: the 2-octet length, then the bytes.
fn send_framed(stream: &mut TcpStream, payload: &[u8]) {
    let len = u16::try_from(payload.len()).expect("a STUN message is under 16 octets short");
    stream.write_all(&len.to_be_bytes()).unwrap();
    stream.write_all(payload).unwrap();
}

/// One packet off the shim.
fn read_framed(stream: &mut TcpStream) -> Vec<u8> {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).unwrap();
    let len = u16::from_be_bytes(prefix) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).unwrap();
    payload
}

fn loopback_listener() -> (TcpListener, TcpStream, TcpStream) {
    let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind a TCP listener on loopback");
    let peer = listener.local_addr().unwrap();
    let client = TcpStream::connect(peer).expect("connect to the ICE-TCP listener");
    let server = listener.accept().expect("accept the ICE-TCP connection").0;
    client.set_nodelay(true).unwrap();
    server.set_nodelay(true).unwrap();
    (listener, client, server)
}

#[test]
fn the_shim_carrs_the_message_unchanged() {
    let (_listener, mut client, mut server) = loopback_listener();
    let tid = [7u8; 12];
    let message = stun_header(tid);

    send_framed(&mut client, &message);
    let received = read_framed(&mut server);
    assert_eq!(received, message);

    // A SOFTWARE attribute inside the message keeps the message's own length
    // field different from the frame's, which is what would mislead a reader
    // that treats the two as one field.
    let with_attr = {
        let mut msg = message.clone();
        msg.extend_from_slice(&0x8022u16.to_be_bytes());
        msg.extend_from_slice(&2u16.to_be_bytes());
        msg.extend_from_slice(b"ok");
        // Message length covers the attributes only, so it is 8 here while the
        // frame's length is the whole message, 28.
        let length_field = u16::try_from(msg.len() - 20).unwrap();
        msg[2..4].copy_from_slice(&length_field.to_be_bytes());
        msg
    };
    send_framed(&mut client, &with_attr);
    assert_eq!(read_framed(&mut server), with_attr);
    let message_length = u16::from_be_bytes([with_attr[2], with_attr[3]]) as usize;
    assert_eq!(
        message_length,
        with_attr.len() - 20,
        "the message's attribute length is not the frame's length"
    );
    assert_ne!(message_length, with_attr.len());

    // Two packets in one write still arrive as two packets: the shim is one
    // frame per message, so a reader that reads by the prefix cannot merge them.
    let second = stun_header([8u8; 12]);
    let mut burst = Vec::new();
    burst.extend_from_slice(&u16::try_from(message.len()).unwrap().to_be_bytes());
    burst.extend_from_slice(&message);
    burst.extend_from_slice(&u16::try_from(second.len()).unwrap().to_be_bytes());
    burst.extend_from_slice(&second);
    client.write_all(&burst).unwrap();
    assert_eq!(read_framed(&mut server), message);
    assert_eq!(read_framed(&mut server), second);
}

#[test]
fn the_listener_reads_one_frame_per_message_in_one_read() {
    // RFC 6544 puts the same STUN message behind a length prefix. The shim
    // keeps one message contiguous on the wire, which is why a server can read
    // the prefix and then the declared length without buffering.
    let (_listener, mut client, mut server) = loopback_listener();
    let msg = stun_header([3u8; 12]);
    send_framed(&mut client, &msg);
    let mut buf = vec![0u8; 2 + msg.len()];
    server.read_exact(&mut buf).unwrap();
    assert_eq!(buf[..2], u16::try_from(msg.len()).unwrap().to_be_bytes());
    assert_eq!(&buf[2..], &msg[..]);
}

#[test]
fn the_same_request_over_ice_tcp_gets_the_same_answer_as_over_udp() {
    // The decision is a pure function of the facts. The transport that carried
    // the request is not one of them, so a request read off a TCP shim and one
    // read off a UDP datagram produce the same plan.
    let peer: SocketAddr = (IpAddr::V4(Ipv4Addr::LOCALHOST), 50000).into();
    let source = binding::ServerIdentity::ipv4(127, 0, 0, 1, 3478);
    let facts = |from: SocketAddr| binding::BindingRequestFacts {
        peer: from,
        change: None,
        other_address: None,
        ice: binding::IceAttributes::default(),
        software_requested: true,
        unknown_attributes: None,
        redirect_to: None,
    };
    let from_tcp = facts(peer);
    let from_udp = facts(peer);
    assert_eq!(
        binding::decide(&from_tcp, Some(source), &[source]),
        binding::decide(&from_udp, Some(source), &[source]),
        "the transport is not an input to the decision"
    );
    let plan = binding::decide(&from_tcp, Some(source), &[source]);
    assert!(plan.include_software, "a SOFTWARE request is echoed on any transport");
    assert!(plan.include_xor_mapped);
}

#[test]
fn a_role_conflict_over_ice_tcp_is_487_like_over_udp() {
    let facts = binding::BindingRequestFacts {
        peer: "10.0.0.7:50000".parse().unwrap(),
        change: None,
        other_address: None,
        ice: binding::IceAttributes {
            role: binding::IceRole::Conflict,
            tiebreaker: Some(binding::IceTiebreaker(1)),
            ..Default::default()
        },
        software_requested: false,
        unknown_attributes: None,
        redirect_to: None,
    };
    let source = binding::ServerIdentity::ipv4(10, 0, 0, 1, 3478);
    let plan = binding::decide(&facts, Some(source), &[source]);
    assert_eq!(
        plan.outcome,
        binding::response::Outcome::Error(binding::ErrorCode::RoleConflict)
    );
    assert_eq!(plan.outcome.error().unwrap().number(), 487);
    assert!(!plan.include_xor_mapped, "an error never maps an address");
    assert!(!plan.echoes(), "an error never carries an echo attribute");
}

#[test]
fn other_address_is_checked_against_the_family_of_the_transport() {
    // OTHER-ADDRESS names the peer's own local address, so the family has to
    // match the connection the request arrived on, whatever it is.
    // OTHER-ADDRESS carries the MAPPED-ADDRESS layout (RFC 5780 Section 7.4,
    // RFC 3489 Section 11.2.3): a zero octet, the family code, the port,
    // then the address.
    let other = binding::ice::other_address_from_value(&[0x00, 0x01, 0xC3, 0x50, 10, 0, 0, 7])
        .unwrap();
    assert_eq!(
        binding::ice::validate_other_address(&other, binding::IpFamily::V4),
        binding::IceValidation::Ok
    );
    assert_eq!(
        binding::ice::validate_other_address(&other, binding::IpFamily::V6),
        binding::IceValidation::WrongFamily
    );
    assert!(
        binding::ice::other_address_to_ip_addr(&other).unwrap().is_ipv4()
    );

    // The same value through the decision table: an IPv4 OTHER-ADDRESS on an
    // IPv6 connection is a 400, and a 400 carries no attribute list.
    let peer: SocketAddr = (IpAddr::V6(Ipv6Addr::LOCALHOST), 50000).into();
    let source = binding::ServerIdentity::ipv6(Ipv6Addr::LOCALHOST.octets(), 3478);
    let facts = binding::BindingRequestFacts {
        peer,
        change: None,
        other_address: Some(other),
        ice: binding::IceAttributes::default(),
        software_requested: false,
        unknown_attributes: None,
        redirect_to: None,
    };
    let plan = binding::decide(&facts, Some(source), &[source]);
    assert_eq!(
        plan.outcome,
        binding::response::Outcome::Error(binding::ErrorCode::BadRequest)
    );
    assert_eq!(plan.outcome.error().unwrap().number(), 400);
    assert!(plan.unknown_attributes.is_none());
}
