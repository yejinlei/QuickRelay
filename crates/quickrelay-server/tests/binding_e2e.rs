//! End-to-end: a real worker, a real socket pair, a real Binding request.
//!
//! These are the only tests in the workspace that walk the path a client
//! actually takes — `transport` handing a datagram to `binding` through
//! `quickrelay-server`. The unit tests in `binding_chain` prove the same
//! logic without sockets; these prove the sockets carry it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use mio::event::Events;
use quickrelay_protocol::{Attribute, MessageType, TransactionId, build_response, parse};
use quickrelay_transport::worker::{Worker, WorkerConfig, EVENT_CAPACITY};
use quickrelay_transport::{FRAME_PREFIX_LEN, MAX_UDP_DATAGRAM};
use quickrelay_server::binding_chain::{identity_of_socket, reply_socket, BindingHandler};

fn binding_chain_identity(addr: SocketAddr) -> quickrelay_binding::ServerIdentity {
    identity_of_socket(addr)
}

const READ_TIMEOUT: Duration = Duration::from_secs(8);
const QUIET: Duration = Duration::from_millis(300);
const TXID: [u8; 12] = [
    0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
];

fn txid() -> TransactionId {
    TransactionId::from(TXID)
}

/// Write one framed packet, the way TURN-over-TCP and ICE-TCP both do.
fn write_frame(stream: &mut TcpStream, payload: &[u8]) {
    let len = u16::try_from(payload.len()).expect("payload is within the 16-bit field");
    stream.write_all(&len.to_be_bytes()).unwrap();
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
}

/// Read one framed packet, assuming the peer framed correctly.
fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = [0u8; FRAME_PREFIX_LEN];
    let mut got = 0usize;
    while got < head.len() {
        let n = match stream.read(&mut head[got..]) {
            Ok(n) => n,
            Err(e) => panic!("the server failed the read: {e}"),
        };
        if n == 0 {
            panic!("the server closed the connection mid-header");
        }
        got += n;
    }
    let len = u16::from_be_bytes(head) as usize;
    let mut body = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        let n = stream.read(&mut body[got..]).unwrap_or(0);
        assert!(n > 0, "the server closed the connection mid-payload");
        got += n;
    }
    body
}

/// A Binding request with no attributes: the smallest one a client sends.
fn binding_request() -> Vec<u8> {
    build_response(MessageType::BINDING_REQUEST.bits(), &txid(), &[], None, false).unwrap()
}

/// A worker under test: bound and running on its own thread.
fn start_worker(config: WorkerConfig) -> (quickrelay_transport::worker::WorkerWake, SocketAddr, SocketAddr) {
    let listening = SocketAddr::from(([127, 0, 0, 1], 0));
    let (mut worker, wake) = Worker::new(config, BindingHandler::new()).unwrap();
    worker.new_udp(listening, 0).unwrap();
    worker.new_tcp(listening).unwrap();
    let udp = worker.udp_local_addr().unwrap();
    let tcp = worker.listener_local_addr().unwrap();
    // Each path answers as the address it actually leaves from: a UDP reply
    // from the datagram socket, a TCP reply from the listener. The listen list
    // is what a CHANGE-REQUEST is resolved against, so it must name both.
    worker.handler_mut().set_udp(reply_socket(udp).unwrap());
    worker.handler_mut().set_tcp_identity(binding_chain_identity(tcp));
    worker.handler_mut().set_addresses(vec![
        binding_chain_identity(udp),
        binding_chain_identity(tcp),
    ]);

    std::thread::spawn(move || {
        let events = &mut Events::with_capacity(EVENT_CAPACITY);
        let _ = worker.run(events);
    });
    (wake, udp, tcp)
}

fn quiet_config() -> WorkerConfig {
    WorkerConfig {
        poll_timeout: Duration::from_millis(5),
        max_ticks: Some(400),
        ..WorkerConfig::default()
    }
}

#[test]
fn binding_over_tcp_connects_frames_and_replies() {
    let (wake, _udp, tcp) = start_worker(quiet_config());

    let mut peer = TcpStream::connect(tcp).unwrap();
    peer.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    write_frame(&mut peer, &binding_request());

    let reply = read_frame(&mut peer);
    let msg = parse(&reply).unwrap();
    assert_eq!(msg.msg_type(), MessageType::BINDING_SUCCESS);
    assert_eq!(msg.transaction_id(), txid());
    let mapped = msg.xor_mapped_address().expect("XOR-MAPPED-ADDRESS");
    assert_eq!(mapped.port, tcp.port(), "the reply reports the real address");
    assert_eq!(mapped.ipv4(), Some((127, 0, 0, 1)));

    wake.wake();
}

#[test]
fn binding_over_udp_answers_from_the_listening_address() {
    let (wake, udp, _tcp) = start_worker(quiet_config());

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let request = binding_request();
    client.send_to(&request, udp).unwrap();

    let mut buffer = vec![0u8; MAX_UDP_DATAGRAM];
    let (n, from) = client.recv_from(&mut buffer).unwrap();
    assert_eq!(from, udp, "the reply leaves the listening address");

    let msg = parse(&buffer[..n]).unwrap();
    assert_eq!(msg.msg_type(), MessageType::BINDING_SUCCESS);
    assert_eq!(msg.transaction_id(), txid());
    assert!(msg.xor_mapped_address().is_some());

    wake.wake();
}

#[test]
fn two_requests_on_one_connection_get_two_replies() {
    let (wake, _udp, tcp) = start_worker(quiet_config());

    let mut peer = TcpStream::connect(tcp).unwrap();
    peer.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let request = binding_request();
    write_frame(&mut peer, &request);
    write_frame(&mut peer, &request);

    for _ in 0..2 {
        let reply = read_frame(&mut peer);
        let msg = parse(&reply).unwrap();
        assert_eq!(msg.msg_type(), MessageType::BINDING_SUCCESS);
    }

    wake.wake();
}

#[test]
fn a_request_that_cannot_be_honored_gets_an_error_reply() {
    let (wake, _udp, tcp) = start_worker(quiet_config());

    let mut peer = TcpStream::connect(tcp).unwrap();
    peer.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    // CHANGE-REQUEST asks for an address the server cannot switch to.
    let request = build_response(
        MessageType::BINDING_REQUEST.bits(),
        &txid(),
        &[Attribute::ChangeRequest(0x0000_0001)],
        None,
        false,
    )
    .unwrap();
    write_frame(&mut peer, &request);

    let reply = read_frame(&mut peer);
    let msg = parse(&reply).unwrap();
    assert_eq!(msg.msg_type(), MessageType::BINDING_ERROR);
    assert_eq!(msg.transaction_id(), txid());
    let code = msg.error().expect("ERROR-CODE");
    assert_eq!(
        code.as_u16(),
        quickrelay_binding::ErrorCode::UnknownAttribute.number()
    );

    wake.wake();
}

#[test]
fn a_software_request_is_echoed_back_over_tcp() {
    let (wake, _udp, tcp) = start_worker(quiet_config());

    let mut peer = TcpStream::connect(tcp).unwrap();
    peer.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let request = build_response(
        MessageType::BINDING_REQUEST.bits(),
        &txid(),
        &[Attribute::Software("turnutils 4.99".to_string())],
        None,
        false,
    )
    .unwrap();
    write_frame(&mut peer, &request);

    let reply = read_frame(&mut peer);
    let msg = parse(&reply).unwrap();
    assert_eq!(msg.msg_type(), MessageType::BINDING_SUCCESS);
    assert!(msg.software().is_some(), "SOFTWARE must be echoed");

    wake.wake();
}

#[test]
fn a_combined_change_request_answers_420() {
    let (wake, _udp, tcp) = start_worker(quiet_config());

    let mut peer = TcpStream::connect(tcp).unwrap();
    peer.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    // `A`|`B` needs both dimensions to differ and there is no second
    // listener: RFC 5780 Section 6.1 answers 420 for every unsatisfiable
    // CHANGE-REQUEST, whichever family the peer uses.
    let request = build_response(
        MessageType::BINDING_REQUEST.bits(),
        &txid(),
        &[Attribute::ChangeRequest(0x0000_0003)],
        None,
        false,
    )
    .unwrap();
    write_frame(&mut peer, &request);

    let reply = read_frame(&mut peer);
    let msg = parse(&reply).unwrap();
    assert_eq!(msg.msg_type(), MessageType::BINDING_ERROR);
    assert!(msg.xor_mapped_address().is_none(), "an error must not map");
    assert_eq!(
        msg.error().expect("ERROR-CODE").as_u16(),
        quickrelay_binding::ErrorCode::UnknownAttribute.number()
    );

    wake.wake();
}

#[test]
fn both_ice_roles_answer_role_conflict_487() {
    let (wake, _udp, tcp) = start_worker(quiet_config());

    let mut peer = TcpStream::connect(tcp).unwrap();
    peer.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    // RFC 8445 §16.2 registers 487 (Role Conflict): a peer claiming both
    // roles is a conflict. It is not 430, which no STUN error-code table
    // assigns.
    let request = build_response(
        MessageType::BINDING_REQUEST.bits(),
        &txid(),
        &[
            Attribute::IceControlled([0, 0, 0, 0, 0, 0, 0, 1]),
            Attribute::IceControlling([0, 0, 0, 0, 0, 0, 0, 2]),
        ],
        None,
        false,
    )
    .unwrap();
    write_frame(&mut peer, &request);

    let reply = read_frame(&mut peer);
    let msg = parse(&reply).unwrap();
    assert_eq!(msg.msg_type(), MessageType::BINDING_ERROR);
    assert!(msg.xor_mapped_address().is_none(), "an error must not map");
    let error = msg.error().expect("ERROR-CODE");
    assert_eq!(error.as_u16(), quickrelay_binding::ErrorCode::RoleConflict.number());
    assert_eq!(error.as_u16(), 487, "the role conflict is 487, not 430");
    assert_eq!(
        &error.reason,
        quickrelay_binding::ErrorCode::RoleConflict.reason().as_str().as_bytes()
    );

    wake.wake();
}

#[test]
fn the_same_ice_roles_over_udp_also_answer_487() {
    let (wake, udp, _tcp) = start_worker(quiet_config());

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let request = build_response(
        MessageType::BINDING_REQUEST.bits(),
        &txid(),
        &[
            Attribute::IceControlled([0, 0, 0, 0, 0, 0, 0, 1]),
            Attribute::IceControlling([0, 0, 0, 0, 0, 0, 0, 2]),
        ],
        None,
        false,
    )
    .unwrap();
    client.send_to(&request, udp).unwrap();

    let mut buffer = vec![0u8; MAX_UDP_DATAGRAM];
    let (n, _from) = client.recv_from(&mut buffer).unwrap();
    let msg = parse(&buffer[..n]).unwrap();
    assert_eq!(msg.msg_type(), MessageType::BINDING_ERROR);
    assert_eq!(msg.error().expect("ERROR-CODE").as_u16(), 487);

    wake.wake();
}

#[test]
fn a_change_request_against_a_second_listener_is_honored() {
    // A worker that listens on two addresses can honor the `B` bit: same
    // address, different port. Before this worker received the address list
    // the same request answered 420, so this is the wiring test.
    let listening = SocketAddr::from(([127, 0, 0, 1], 0));
    let config = quiet_config();
    let (mut worker, wake) = Worker::new(config, BindingHandler::new()).unwrap();
    worker.new_udp(listening, 0).unwrap();
    let udp = worker.udp_local_addr().unwrap();
    worker.new_tcp(listening).unwrap();
    let tcp = worker.listener_local_addr().unwrap();
    worker.handler_mut().set_udp(reply_socket(udp).unwrap());
    worker.handler_mut().set_tcp_identity(binding_chain_identity(tcp));
    let other = SocketAddr::new(tcp.ip(), udp.port());
    worker.handler_mut().set_addresses(vec![
        binding_chain_identity(udp),
        binding_chain_identity(tcp),
        binding_chain_identity(other),
    ]);

    std::thread::spawn(move || {
        let events = &mut Events::with_capacity(EVENT_CAPACITY);
        let _ = worker.run(events);
    });

    let mut peer = TcpStream::connect(tcp).unwrap();
    peer.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let request = build_response(
        MessageType::BINDING_REQUEST.bits(),
        &txid(),
        &[Attribute::ChangeRequest(0x0000_0002)],
        None,
        false,
    )
    .unwrap();
    write_frame(&mut peer, &request);

    let reply = read_frame(&mut peer);
    let msg = parse(&reply).unwrap();
    assert_eq!(msg.msg_type(), MessageType::BINDING_SUCCESS);
    let mapped = msg.xor_mapped_address().expect("XOR-MAPPED-ADDRESS");
    assert_eq!(mapped.ipv4(), Some((127, 0, 0, 1)));
    assert_ne!(
        mapped.port,
        tcp.port(),
        "the B bit must change the port the reply reports"
    );
    // The resolved candidate must be an address the worker knows.
    let known = [tcp.port(), udp.port(), other.port()];
    assert!(known.contains(&mapped.port), "not in the listen list");

    wake.wake();
}

#[test]
fn a_non_binding_message_is_left_alone() {
    let (wake, _udp, tcp) = start_worker(quiet_config());

    let mut peer = TcpStream::connect(tcp).unwrap();
    peer.set_read_timeout(Some(QUIET)).unwrap();
    // An indication: valid STUN, nothing to answer.
    let request = build_response(
        MessageType::DATA_INDICATION.bits(),
        &txid(),
        &[Attribute::Data(vec![0u8; 8])],
        None,
        false,
    )
    .unwrap();
    write_frame(&mut peer, &request);

    let mut head = [0u8; FRAME_PREFIX_LEN];
    match peer.read(&mut head) {
        Ok(0) => {} // the server closed its write side
        Ok(_) => panic!("an indication must not be answered"),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
        Err(e) => panic!("unexpected: {e}"),
    }

    wake.wake();
}

#[test]
fn a_half_open_connection_is_cut_without_leaking_a_handle() {
    let config = WorkerConfig {
        poll_timeout: Duration::from_millis(1),
        conn_idle_timeout: Duration::from_secs(300),
        half_open_timeout: Duration::from_millis(400),
        max_ticks: Some(4000),
        ..WorkerConfig::default()
    };
    let (wake, _udp, tcp) = start_worker(config);

    // Connect and send nothing: the half-open timer is the only thing that can
    // reclaim this connection, and the worker must not keep it open.
    let mut peer = TcpStream::connect(tcp).unwrap();
    peer.set_read_timeout(Some(QUIET)).unwrap();
    let mut head = [0u8; FRAME_PREFIX_LEN];
    let mut closed = false;
    for _ in 0..600 {
        match peer.read(&mut head) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(_) => panic!("the server wrote to a half-open connection"),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                std::thread::sleep(Duration::from_millis(30));
            }
            Err(_) => {
                closed = true;
                break;
            }
        }
    }
    assert!(closed, "the half-open connection was never reclaimed");

    wake.wake();
}

#[test]
fn an_idle_connection_is_cut_after_it_has_sent_traffic() {
    let config = WorkerConfig {
        poll_timeout: Duration::from_millis(1),
        conn_idle_timeout: Duration::from_millis(400),
        half_open_timeout: Duration::from_secs(300),
        max_ticks: Some(4000),
        ..WorkerConfig::default()
    };
    let (wake, _udp, tcp) = start_worker(config);

    // Send one packet so the connection leaves the half-open state, then go
    // quiet: only the idle timer can end it.
    let mut peer = TcpStream::connect(tcp).unwrap();
    peer.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    write_frame(&mut peer, &binding_request());
    read_frame(&mut peer);

    peer.set_read_timeout(Some(QUIET)).unwrap();
    let mut head = [0u8; FRAME_PREFIX_LEN];
    let mut closed = false;
    for _ in 0..600 {
        match peer.read(&mut head) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(_) => panic!("the server kept writing to an idle connection"),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                std::thread::sleep(Duration::from_millis(30));
            }
            Err(_) => {
                closed = true;
                break;
            }
        }
    }
    assert!(closed, "the idle connection was never reclaimed");

    wake.wake();
}
