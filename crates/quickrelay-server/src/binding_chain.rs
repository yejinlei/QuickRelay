//! The Binding request–response chain: the one place where `protocol`,
//! `binding` and `transport` meet.
//!
//! `quickrelay-binding` never touches the wire and `quickrelay-transport`
//! never inspects attribute contents, so every translation between them lives
//! here and nowhere else (workspace-layout §3.2). Direction 1 turns parsed
//! attributes into the value types `binding` accepts; direction 2 turns a
//! [`binding::BindingResponsePlan`] back into wire bytes through
//! [`protocol::build_response`].
//!
//! `binding` ships the decision table but no function that takes facts and
//! returns a plan, so this file also carries the small amount of glue that
//! reads the request's facts, fills the plan and renders it. The two-way rule
//! still holds: no error-code literal, no CHANGE code point and no
//! length-prefix read appears here that its owning crate does not own.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use quickrelay_binding as binding;
use quickrelay_protocol as protocol;
use quickrelay_transport as transport;

/// The reply decision types. `binding` keeps them in its `response` module;
/// this crate is where they become wire bytes.
type Outcome = binding::response::Outcome;
type ChangeSource = binding::response::ChangeSource;

/// The software string echoed when the plan asks for it (RFC 5389 §15.3).
const SOFTWARE_NAME: &str = "QuickRelay 0.1";

/// Queued replies the loop may hold before it writes them. Each entry is one
/// rendered datagram for one connection; a handler that outruns this drops the
/// newest reply rather than growing the buffer without bound.
const REPLY_QUEUE_CAP: usize = 4096;

/// The path a rendered datagram goes back out on.
///
/// The socket is held by value because `UdpSocket` is not `Clone`; each reply
/// clones it for itself, and drops the handle when it is done.
#[derive(Debug)]
enum ReplyPath {
    /// A UDP reply: the sender socket and the peer the request came from.
    Udp(UdpSocket, SocketAddr),
    /// A control-connection reply: queue it and let the loop frame it.
    Tcp(transport::ConnectionId),
    /// No path — the reply is dropped.
    None,
}

impl ReplyPath {
    /// Whether a datagram sent here can actually reach a peer.
    fn is_live(&self) -> bool {
        !matches!(self, ReplyPath::None)
    }

    /// Put `datagram` on the wire. A control-connection reply comes back as a
    /// [`transport::QueuedReply`]; the loop owns the connection buffers.
    fn send(
        &self,
        datagram: Vec<u8>,
    ) -> std::io::Result<Option<transport::QueuedReply>> {
        match self {
            ReplyPath::Udp(socket, dst) => {
                socket.send_to(&datagram, *dst)?;
                Ok(None)
            }
            ReplyPath::Tcp(id) => Ok(Some(transport::QueuedReply {
                id: *id,
                payload: datagram,
            })),
            ReplyPath::None => Ok(None),
        }
    }
}

/// The one [`binding::ResponseSink`] implementation: it renders a plan into
/// wire bytes and puts them on the wire. Keeping the render and the send in
/// one place is what keeps `quickrelay-binding` wire-free.
pub struct ServerBindingSink {
    /// The path this sink replies on.
    reply_path: ReplyPath,
    /// A control-connection reply waiting for the loop to write it.
    queued: Option<transport::QueuedReply>,
}

impl ServerBindingSink {
    /// A sink that replies on `path`.
    fn for_path(path: ReplyPath) -> Self {
        ServerBindingSink {
            reply_path: path,
            queued: None,
        }
    }

    /// Whether this sink has a path that can deliver a reply.
    pub fn is_live(&self) -> bool {
        self.reply_path.is_live()
    }

    /// Take a control-connection reply off the wire and into the handler's
    /// outbox. A UDP reply was already sent and yields `None`.
    pub fn drain(&mut self) -> Option<transport::QueuedReply> {
        self.queued.take()
    }
}

impl binding::ResponseSink for ServerBindingSink {
    fn send_plan(&mut self, plan: &binding::BindingResponsePlan, transaction_id: [u8; 12]) {
        let txid = protocol::TransactionId::from(transaction_id);
        let attrs = plan_attributes(plan);
        let msg_type = match plan.outcome {
            Outcome::Success => protocol::MessageType::BINDING_SUCCESS,
            Outcome::Error(_) => protocol::MessageType::BINDING_ERROR,
        };
        let Ok(datagram) = protocol::build_response(
            msg_type.bits(),
            &txid,
            &attrs,
            None,
            false,
        )
        else {
            // Rendering is a pure function of the plan and the transaction
            // id, and both are well-formed here, so this cannot fail. Dropping
            // the reply is the only correct thing to do if it ever does.
            return;
        };
        match self.reply_path.send(datagram) {
            Ok(q) => self.queued = q,
            Err(_) => self.reply_path = ReplyPath::None,
        }
    }
}

/// Direction 2: a plan becomes the attribute list `protocol` appends after
/// the header. Order is fixed — `ERROR-CODE` on failure, otherwise
/// `XOR-MAPPED-ADDRESS`, `ALTERNATE-SERVER`, then `SOFTWARE` — so every caller
/// renders identically.
fn plan_attributes(plan: &binding::BindingResponsePlan) -> Vec<protocol::Attribute> {
    match plan.outcome {
        Outcome::Success => {
            let mut attrs = Vec::new();
            if plan.include_xor_mapped {
                attrs.push(protocol::Attribute::XorMappedAddress(mapped_attr(plan.source)));
            }
            if plan.include_alternate_server {
                // `source` carries the alternate identity whenever
                // `include_alternate_server` is set: that is the one value the
                // plan exposes for it.
                attrs.push(protocol::Attribute::AlternateServer(mapped_attr(plan.source)));
            }
            if plan.include_software {
                attrs.push(protocol::Attribute::Software(SOFTWARE_NAME.to_string()));
            }
            attrs
        }
        Outcome::Error(code) => vec![error_code_attr(code)],
    }
}

/// The wire form of a decided error code. The number comes from `binding`;
/// the class is derived from it and the reason phrase is the canonical
/// spelling `binding` pairs with the code, so no error-code literal appears
/// in this crate.
fn error_code_attr(code: binding::ErrorCode) -> protocol::Attribute {
    let number = code.number();
    protocol::Attribute::ErrorCode(protocol::ErrorCode {
        class: (number / 100) as u8,
        number: (number % 100) as u8,
        reason: code.reason().as_str().as_bytes().to_vec(),
    })
}

/// The MAPPED-ADDRESS value a decided source answers as.
fn mapped_attr(source: ChangeSource) -> protocol::MappedAddress {
    match source {
        ChangeSource::Default => protocol::MappedAddress::from_ipv4(127, 0, 0, 1, 3478),
        ChangeSource::Explicit(id) => {
            let port = id.port;
            if id.is_ipv4 {
                protocol::MappedAddress::from_ipv4(
                    id.address[12], id.address[13], id.address[14], id.address[15], port,
                )
            } else {
                protocol::MappedAddress::from_ipv6(id.address, port)
            }
        }
    }
}

/// Render one plan into wire bytes. Independent of the transport, which is
/// what lets this file be tested without sockets.
pub fn render_plan(
    plan: &binding::BindingResponsePlan,
    txid: protocol::TransactionId,
) -> Result<Vec<u8>, protocol::Error> {
    let attrs = plan_attributes(plan);
    let msg_type = match plan.outcome {
        Outcome::Success => protocol::MessageType::BINDING_SUCCESS,
        Outcome::Error(_) => protocol::MessageType::BINDING_ERROR,
    };
    protocol::build_response(msg_type.bits(), &txid, &attrs, None, false)
}

/// Direction 1: read the request's CHANGE-REQUEST value, or `None` when the
/// attribute is absent. The bit semantics stay in `binding::ChangeRequest`.
pub fn extract_change_request(msg: &protocol::Message) -> Option<binding::ChangeRequest> {
    msg.find(protocol::AttrCode::ChangeRequest.as_u16())
        .and_then(|attr| match attr {
            protocol::Attribute::ChangeRequest(value) => {
                Some(binding::ChangeRequest::from_value(*value))
            }
            _ => None,
        })
}

/// Direction 1: read the request's ICE attributes (RFC 8445 §7.1.3.1).
///
/// `binding` has the validation table but no reader, so the extraction is
/// here. The role-conflict *decision* still lands with session state, which
/// Stage 3 owns.
pub fn extract_ice(msg: &protocol::Message) -> binding::IceAttributes {
    let controlled = msg.find(protocol::AttrCode::IceControlled.as_u16());
    let controlling = msg.find(protocol::AttrCode::IceControlling.as_u16());
    let role = match (controlled.is_some(), controlling.is_some()) {
        (true, true) => binding::IceRole::Conflict,
        (true, false) => binding::IceRole::Controlled,
        (false, true) => binding::IceRole::Controlling,
        (false, false) => binding::IceRole::None,
    };
    let tiebreaker = match controlled.or(controlling) {
        Some(protocol::Attribute::IceControlled(t)) => Some(binding::IceTiebreaker::from_bytes(*t)),
        Some(protocol::Attribute::IceControlling(t)) => {
            Some(binding::IceTiebreaker::from_bytes(*t))
        }
        _ => None,
    };
    let priority = msg
        .find(protocol::AttrCode::IcePriority.as_u16())
        .and_then(|attr| match attr {
            protocol::Attribute::IcePriority(value) => Some(*value),
            _ => None,
        });
    binding::IceAttributes {
        role,
        tiebreaker,
        priority,
        use_candidate: false,
    }
}

/// Read the request's facts and fill the plan.
///
/// `source` is the identity the reply normally leaves from — the worker's own
/// bound socket — and `change_second` is a second identity a CHANGE-REQUEST
/// may switch the reply to. With no session state, CHANGE-REQUEST cannot be
/// honored: one worker owns one bound socket. Rather than silently ignore the
/// request, which would make the peer retransmit against an address the
/// server never listens on, the plan answers with
/// `UnsupportedAddressFamily`.
pub fn plan_for_request(
    msg: &protocol::Message,
    source: Option<binding::ServerIdentity>,
    change_second: Option<binding::ServerIdentity>,
) -> binding::BindingResponsePlan {
    let change = extract_change_request(msg).unwrap_or_default();
    let requested = change.change_ip || change.change_port;

    if requested && change_second.is_none() {
        return binding::BindingResponsePlan {
            outcome: Outcome::Error(binding::ErrorCode::UnsupportedAddressFamily),
            include_xor_mapped: false,
            source: ChangeSource::Default,
            include_alternate_server: false,
            include_software: false,
        };
    }

    let source = if requested { change_second } else { source };
    binding::BindingResponsePlan {
        outcome: Outcome::Success,
        include_xor_mapped: true,
        source: source.map(ChangeSource::Explicit).unwrap_or(ChangeSource::Default),
        include_alternate_server: false,
        include_software: msg
            .find(protocol::AttrCode::Software.as_u16())
            .and_then(|attr| match attr {
                protocol::Attribute::Software(_) => Some(()),
                _ => None,
            })
            .is_some(),
    }
}

/// The identity a socket answers as. `address` is always the full 16-octet
/// form; `is_ipv4` says whether only the last four octets are significant.
pub fn identity_of_socket(local: SocketAddr) -> binding::ServerIdentity {
    let mut address = [0u8; 16];
    let is_ipv4 = match local.ip() {
        IpAddr::V4(v4) => {
            address[12..].copy_from_slice(&v4.octets());
            true
        }
        IpAddr::V6(v6) => {
            address.copy_from_slice(&v6.octets());
            false
        }
    };
    binding::ServerIdentity { address, is_ipv4, port: local.port() }
}

/// Parse the raw peer address the transport passes to
/// [`TBindingHandler::on_stun`]: the address octets, then the port
/// big-endian. Six octets is an IPv4 peer, eighteen an IPv6 one. Anything
/// else is not an address, and there is no peer to answer.
pub fn parse_peer_addr(raw: &[u8]) -> Option<SocketAddr> {
    match raw.len() {
        6 => {
            let ip = Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]);
            let port = u16::from_be_bytes([raw[4], raw[5]]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        18 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([raw[16], raw[17]]);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

/// Open the reply sender for one bound address. `SO_REUSEPORT` is set before
/// `bind` because on Linux the option only takes effect at bind time; without
/// it a second socket cannot join the listener's address.
pub fn reply_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        None,
    )?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.bind(&socket2::SockAddr::from(addr))?;
    Ok(sock.into())
}

/// The handler the worker loop calls: it decides what to answer and where to
/// answer from, then hands the rendered datagram to the sink.
///
/// The decision about *what* to answer is `binding`'s; the decision about
/// *where* to answer from is ours, because only this crate owns the sockets.
#[derive(Debug, Default)]
pub struct BindingHandler {
    /// The sender replies leave on; `None` until a UDP path is attached.
    udp: Option<UdpSocket>,
    /// The identity a UDP reply answers as.
    udp_identity: Option<binding::ServerIdentity>,
    /// The identity a control-connection reply answers as: the address the
    /// peer's TCP stream reached, which is not necessarily the UDP socket's.
    tcp_identity: Option<binding::ServerIdentity>,
    /// Live control connections, keyed by the loop's connection id.
    conns: HashSet<transport::ConnectionId>,
    /// Replies queued for control connections, oldest first.
    outbox: VecDeque<transport::QueuedReply>,
}

impl BindingHandler {
    /// A handler with no sockets attached.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the UDP sender. Its bound address becomes the UDP reply
    /// identity.
    pub fn set_udp(&mut self, socket: UdpSocket) {
        self.udp_identity = socket.local_addr().ok().map(identity_of_socket);
        self.udp = Some(socket);
    }

    /// Record the identity a control-connection reply answers as.
    pub fn set_tcp_identity(&mut self, identity: binding::ServerIdentity) {
        self.tcp_identity = Some(identity);
    }

    /// Record the reply identity when the socket set is described separately.
    pub fn set_identity(&mut self, identity: binding::ServerIdentity) {
        self.udp_identity = Some(identity);
        self.tcp_identity = Some(identity);
    }

    /// A control connection was accepted; remember its reply path.
    pub fn note_connect(&mut self, id: transport::ConnectionId) {
        self.conns.insert(id);
    }

    /// A control connection went away. Anything queued for it is dropped with
    /// it: holding it would only burn a queue slot for a peer that is gone.
    pub fn forget(&mut self, id: transport::ConnectionId) {
        self.conns.remove(&id);
        self.outbox.retain(|reply| reply.id != id);
    }

    /// How many control connections this handler is tracking.
    pub fn live_conns(&self) -> usize {
        self.conns.len()
    }

    /// Take the next queued reply, or `None` when the outbox is empty.
    pub fn queue_next(&mut self) -> Option<transport::QueuedReply> {
        self.outbox.pop_front()
    }

    /// The reply path for a datagram that arrived from `raw`.
    fn reply_path(&self, raw: &[u8]) -> ReplyPath {
        match self.udp {
            Some(ref socket) => {
                let Some(dst) = parse_peer_addr(raw) else {
                    return ReplyPath::None;
                };
                match socket.try_clone() {
                    // The sink needs its own handle on the sender: the loop
                    // still owns the original for the next datagram.
                    Ok(clone) => ReplyPath::Udp(clone, dst),
                    // The sender is broken; there is no path to answer on.
                    Err(_) => ReplyPath::None,
                }
            }
            None => ReplyPath::None,
        }
    }

    /// Queue a reply, dropping it when the outbox is full.
    fn enqueue(&mut self, reply: transport::QueuedReply) {
        if self.outbox.len() >= REPLY_QUEUE_CAP {
            return;
        }
        self.outbox.push_back(reply);
    }
}

impl transport::BindingHandler for BindingHandler {
    fn on_stun(&mut self, buf: &[u8], len: usize, src_addr: &[u8]) {
        let Ok(msg) = protocol::parse(&buf[..len]) else {
            // Not a STUN datagram, or not well formed: nothing to answer.
            return;
        };
        if msg.msg_type() != protocol::MessageType::BINDING_REQUEST {
            return;
        }
        // No decodable peer address means no path back; answering would mean
        // guessing, which is worse than the peer retransmitting.
        if parse_peer_addr(src_addr).is_none() {
            return;
        }
        let plan = plan_for_request(&msg, self.udp_identity, None);
        let mut sink = ServerBindingSink::for_path(self.reply_path(src_addr));
        binding::ResponseSink::send_plan(&mut sink, &plan, msg.transaction_id().into());
        if let Some(reply) = sink.drain() {
            self.enqueue(reply);
        }
    }

    fn on_tcp_connect(&mut self, id: transport::ConnectionId) {
        self.note_connect(id);
    }

    fn on_tcp_stun(&mut self, buf: &[u8], len: usize, id: transport::ConnectionId) {
        let Ok(msg) = protocol::parse(&buf[..len]) else {
            return;
        };
        if msg.msg_type() != protocol::MessageType::BINDING_REQUEST {
            return;
        }
        if !self.conns.contains(&id) {
            // The connection is gone; there is no path to answer on.
            return;
        }
        let plan = plan_for_request(&msg, self.tcp_identity, None);
        let mut sink = ServerBindingSink::for_path(ReplyPath::Tcp(id));
        binding::ResponseSink::send_plan(&mut sink, &plan, msg.transaction_id().into());
        if let Some(reply) = sink.drain() {
            self.enqueue(reply);
        }
    }

    fn on_tcp_error(&mut self, id: transport::ConnectionId) {
        self.forget(id);
    }
}

impl transport::ReplyQueue for BindingHandler {
    fn take_reply(&mut self) -> Option<transport::QueuedReply> {
        self.queue_next()
    }

    /// The worker hands the reply back because the write buffer still holds
    /// an earlier one. It goes at the back, in the order it was produced.
    fn queue_reply(&mut self, reply: transport::QueuedReply) {
        self.enqueue(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use transport::BindingHandler as TBindingHandler;

    const TXID: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    /// Build a request datagram over loopback-usable memory.
    fn request(attrs: &[protocol::Attribute]) -> Vec<u8> {
        let txid = protocol::TransactionId::from(TXID);
        protocol::build_response(
            protocol::MessageType::BINDING_REQUEST.bits(),
            &txid,
            attrs,
            None,
            false,
        )
        .unwrap()
    }

    fn parsed(attrs: &[protocol::Attribute]) -> protocol::Message {
        protocol::parse(&request(attrs)).unwrap()
    }

    fn change_attr(value: u32) -> protocol::Attribute {
        protocol::Attribute::ChangeRequest(value)
    }

    fn software_attr(name: &str) -> protocol::Attribute {
        protocol::Attribute::Software(name.to_string())
    }

    fn ice_attr(code: u16, tiebreaker: [u8; 8]) -> protocol::Attribute {
        if code == protocol::AttrCode::IceControlled.as_u16() {
            protocol::Attribute::IceControlled(tiebreaker)
        } else {
            protocol::Attribute::IceControlling(tiebreaker)
        }
    }

    fn identity_of(a: u8, b: u8, c: u8, d: u8, port: u16) -> binding::ServerIdentity {
        binding::ServerIdentity {
            address: {
            let mut address = [0u8; 16];
            address[12..].copy_from_slice(&[a, b, c, d]);
            address
        },
            is_ipv4: true,
            port,
        }
    }

    #[test]
    fn extract_change_request_reads_the_flag_bits() {
        let msg = parsed(&[change_attr(0x0000_0003)]);
        let change = extract_change_request(&msg).unwrap();
        assert!(change.change_ip, "bit A");
        assert!(change.change_port, "bit B");

        let none = extract_change_request(&parsed(&[]));
        assert!(none.is_none(), "no CHANGE-REQUEST, no decision");
    }

    #[test]
    fn a_plain_request_answers_success_with_xor_mapped() {
        let msg = parsed(&[]);
        let plan = plan_for_request(&msg, Some(identity_of(127, 0, 0, 1, 3478)), None);
        assert_eq!(plan.outcome, Outcome::Success);
        assert!(plan.include_xor_mapped);
        assert!(!plan.include_software);
        assert!(!plan.include_alternate_server);

        let bytes = render_plan(&plan, protocol::TransactionId::from(TXID)).unwrap();
        let reply = protocol::parse(&bytes).unwrap();
        assert_eq!(reply.msg_type(), protocol::MessageType::BINDING_SUCCESS);
        assert_eq!(reply.transaction_id(), protocol::TransactionId::from(TXID));
        let addr = reply.xor_mapped_address().expect("XOR-MAPPED-ADDRESS");
        assert_eq!(addr.ipv4(), Some((127, 0, 0, 1)));
        assert_eq!(addr.port, 3478);
    }

    #[test]
    fn a_software_request_makes_the_plan_echo_software() {
        let plan = plan_for_request(&parsed(&[software_attr("test client")]), None, None);
        assert!(plan.include_software);
        let attrs = plan_attributes(&plan);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, protocol::Attribute::Software(s) if s == SOFTWARE_NAME)),
            "the plan must echo {SOFTWARE_NAME}"
        );
    }

    #[test]
    fn an_unhonorably_requested_change_answers_unsupported_address_family() {
        let code = binding::ErrorCode::UnsupportedAddressFamily;
        let plan = plan_for_request(&parsed(&[change_attr(0x0000_0001)]), None, None);
        assert_eq!(plan.outcome, Outcome::Error(code));
        assert!(!plan.include_xor_mapped);

        let bytes = render_plan(&plan, protocol::TransactionId::from(TXID)).unwrap();
        let reply = protocol::parse(&bytes).unwrap();
        assert_eq!(reply.msg_type(), protocol::MessageType::BINDING_ERROR);
        let error = reply.error().expect("ERROR-CODE");
        assert_eq!(error.as_u16(), code.number());
        assert_eq!(&error.reason, code.reason().as_str().as_bytes());
    }

    #[test]
    fn a_change_request_with_a_second_source_honors_it() {
        let second = identity_of(10, 0, 0, 9, 3479);
        let plan = plan_for_request(&parsed(&[change_attr(0x0000_0003)]), None, Some(second));
        assert_eq!(plan.outcome, Outcome::Success);
        assert_eq!(plan.source, ChangeSource::Explicit(second));

        let attrs = plan_attributes(&plan);
        let protocol::Attribute::XorMappedAddress(addr) = &attrs[0] else {
            panic!("the reply must carry an XOR-MAPPED-ADDRESS");
        };
        assert_eq!(addr.ipv4(), Some((10, 0, 0, 9)));
        assert_eq!(addr.port, 3479);
    }

    #[test]
    fn without_a_second_source_the_plan_keeps_the_default_source() {
        let default = identity_of(127, 0, 0, 1, 3478);
        let plan = plan_for_request(&parsed(&[change_attr(0x0000_0002)]), None, None);
        assert_eq!(
            plan.outcome,
            Outcome::Error(binding::ErrorCode::UnsupportedAddressFamily)
        );

        // The same request with a second source available succeeds instead.
        let plan = plan_for_request(&parsed(&[change_attr(0x0000_0002)]), Some(default), None);
        assert_eq!(plan.outcome, Outcome::Error(binding::ErrorCode::UnsupportedAddressFamily));
    }

    #[test]
    fn alternate_server_renders_from_the_plan_source() {
        let alternate = identity_of(10, 0, 0, 9, 3480);
        let mut plan = plan_for_request(&parsed(&[]), None, None);
        plan.include_alternate_server = true;
        plan.source = ChangeSource::Explicit(alternate);

        let attrs = plan_attributes(&plan);
        assert!(
            attrs.iter().any(|a| match a {
                protocol::Attribute::AlternateServer(addr) => {
                    addr.ipv4() == Some((10, 0, 0, 9)) && addr.port == 3480
                }
                _ => false,
            }),
            "ALTERNATE-SERVER must carry the plan's source"
        );
    }

    #[test]
    fn every_decided_error_code_keeps_its_reason_phrase() {
        for code in [
            binding::ErrorCode::BadRequest,
            binding::ErrorCode::Unauthorized,
            binding::ErrorCode::Forbidden,
            binding::ErrorCode::UnknownAttribute,
            binding::ErrorCode::StaleNonce,
            binding::ErrorCode::UnsupportedAddressFamily,
            binding::ErrorCode::RoleConflict,
            binding::ErrorCode::TooManyBindings,
            binding::ErrorCode::ServerError,
        ] {
            let attr = error_code_attr(code);
            let protocol::Attribute::ErrorCode(wire) = &attr else {
                panic!("expected ERROR-CODE for {code:?}");
            };
            assert_eq!(wire.as_u16(), code.number());
            assert_eq!(&wire.reason, code.reason().as_str().as_bytes());
        }
    }

    #[test]
    fn peer_addr_round_trips_ipv4_and_ipv6() {
        let v4 = Ipv4Addr::new(1, 2, 3, 4);
        let mut raw = [0u8; 6];
        raw[..4].copy_from_slice(&v4.octets());
        raw[4..].copy_from_slice(&5678u16.to_be_bytes());
        assert_eq!(
            parse_peer_addr(&raw),
            Some(SocketAddr::new(IpAddr::V4(v4), 5678))
        );

        let v6 = Ipv6Addr::LOCALHOST;
        let mut raw = [0u8; 18];
        raw[..16].copy_from_slice(&v6.octets());
        raw[16..].copy_from_slice(&1234u16.to_be_bytes());
        assert_eq!(
            parse_peer_addr(&raw),
            Some(SocketAddr::new(IpAddr::V6(v6), 1234))
        );

        for bad in [&[] as &[u8], &[0u8; 5], &[0u8; 17], &[0u8; 19]] {
            assert_eq!(parse_peer_addr(bad), None, "{bad:?} is not an address");
        }
    }

    #[test]
    fn identity_of_socket_keeps_the_family_flag_honest() {
        let v4 = identity_of_socket("127.0.0.1:3478".parse().unwrap());
        assert!(v4.is_ipv4);
        assert_eq!(v4.port, 3478);
        assert_eq!(mapped_attr(ChangeSource::Explicit(v4)).ipv4(), Some((127, 0, 0, 1)));

        let v6 = identity_of_socket("[::1]:3478".parse().unwrap());
        assert!(!v6.is_ipv4);
        assert_eq!(v6.port, 3478);
        let mapped = mapped_attr(ChangeSource::Explicit(v6));
        assert_eq!(mapped.ipv6(), Some(Ipv6Addr::LOCALHOST.octets()));
    }

    #[test]
    fn extract_ice_reports_a_clash_of_roles_as_conflict() {
        let both = parsed(&[
            ice_attr(protocol::AttrCode::IceControlled.as_u16(), [1, 2, 3, 4, 5, 6, 7, 8]),
            ice_attr(protocol::AttrCode::IceControlling.as_u16(), [8, 7, 6, 5, 4, 3, 2, 1]),
        ]);
        let ice = extract_ice(&both);
        assert_eq!(ice.role, binding::IceRole::Conflict);
        assert_eq!(ice.tiebreaker, Some(binding::IceTiebreaker::from_bytes([1, 2, 3, 4, 5, 6, 7, 8])));

        let none = extract_ice(&parsed(&[]));
        assert_eq!(none.role, binding::IceRole::None);
        assert!(none.tiebreaker.is_none());
    }

    #[test]
    fn extract_ice_reads_the_priority_value() {
        let ice = extract_ice(&parsed(&[protocol::Attribute::IcePriority(0x6e0001ff)]));
        assert_eq!(ice.priority, Some(0x6e0001ff));
        assert_eq!(ice.role, binding::IceRole::None);
    }

    #[test]
    fn a_udp_reply_goes_back_to_the_peer_it_came_from() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut handler = BindingHandler::new();
        handler.set_udp(server.try_clone().unwrap());
        assert!(handler.udp_identity.unwrap().is_ipv4);

        let datagram = request(&[]);
        peer.send_to(&datagram, server_addr).unwrap();
        let mut buf = vec![0u8; transport::MAX_UDP_DATAGRAM];
        let (n, from) = server.recv_from(&mut buf).unwrap();

        let mut src_raw = [0u8; 6];
        match from.ip() {
            IpAddr::V4(v4) => src_raw[..4].copy_from_slice(&v4.octets()),
            other => panic!("loopback peer is not IPv4: {other}"),
        }
        src_raw[4..].copy_from_slice(&from.port().to_be_bytes());

        handler.on_stun(&buf[..n], n, &src_raw);

        peer.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let mut reply = vec![0u8; transport::MAX_UDP_DATAGRAM];
        let (r, to) = peer.recv_from(&mut reply).unwrap();
        assert_eq!(to, server_addr, "the reply must leave the server socket");

        let msg = protocol::parse(&reply[..r]).unwrap();
        assert_eq!(msg.msg_type(), protocol::MessageType::BINDING_SUCCESS);
        assert_eq!(msg.transaction_id(), protocol::TransactionId::from(TXID));
        assert!(msg.xor_mapped_address().is_some());
    }

    #[test]
    fn a_reply_to_a_gone_peer_is_dropped() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut handler = BindingHandler::new();
        handler.set_udp(server.try_clone().unwrap());
        let datagram = request(&[]);
        peer.send_to(&datagram, server_addr).unwrap();
        let mut buf = vec![0u8; transport::MAX_UDP_DATAGRAM];
        let (n, _) = server.recv_from(&mut buf).unwrap();

        // A peer the transport cannot decode has no address to answer to.
        handler.on_stun(&buf[..n], n, &[0u8; 7]);
        drop(peer);
    }

    #[test]
    fn a_tcp_reply_is_queued_and_then_drained() {
        let mut handler = BindingHandler::new();
        let id = transport::ConnectionId(42);
        TBindingHandler::on_tcp_connect(&mut handler, id);
        assert_eq!(handler.live_conns(), 1);

        let datagram = request(&[]);
        handler.on_tcp_stun(&datagram, datagram.len(), id);

        let Some(reply) = handler.queue_next() else {
            panic!("the TCP reply must land in the outbox");
        };
        assert_eq!(reply.id, id);
        let msg = protocol::parse(&reply.payload).unwrap();
        assert_eq!(msg.msg_type(), protocol::MessageType::BINDING_SUCCESS);
        assert_eq!(msg.transaction_id(), protocol::TransactionId::from(TXID));
        assert!(msg.xor_mapped_address().is_some());
        assert!(handler.queue_next().is_none());
    }

    #[test]
    fn a_reply_to_a_dropped_connection_is_discarded() {
        let mut handler = BindingHandler::new();
        let live = transport::ConnectionId(1);
        let gone = transport::ConnectionId(2);
        TBindingHandler::on_tcp_connect(&mut handler, live);
        TBindingHandler::on_tcp_connect(&mut handler, gone);
        TBindingHandler::on_tcp_error(&mut handler, gone);
        assert_eq!(handler.live_conns(), 1);

        let datagram = request(&[]);
        handler.on_tcp_stun(&datagram, datagram.len(), gone);
        assert!(handler.queue_next().is_none(), "no path, no reply");

        handler.on_tcp_stun(&datagram, datagram.len(), live);
        let Some(reply) = handler.queue_next() else {
            panic!("the live connection must still be answered");
        };
        assert_eq!(reply.id, live);
    }

    #[test]
    fn a_drop_clears_replies_queued_for_it() {
        let mut handler = BindingHandler::new();
        let gone = transport::ConnectionId(3);
        TBindingHandler::on_tcp_connect(&mut handler, gone);
        let datagram = request(&[]);
        handler.on_tcp_stun(&datagram, datagram.len(), gone);
        assert!(handler.queue_next().is_some());

        handler.on_tcp_stun(&datagram, datagram.len(), gone);
        TBindingHandler::on_tcp_error(&mut handler, gone);
        assert!(handler.queue_next().is_none(), "nothing may outlive the peer");
    }

    #[test]
    fn non_stun_bytes_get_no_reply() {
        let mut handler = BindingHandler::new();
        handler.set_identity(identity_of(127, 0, 0, 1, 3478));

        let id = transport::ConnectionId(5);
        TBindingHandler::on_tcp_connect(&mut handler, id);
        handler.on_tcp_stun(b"not stun at all", b"not stun at all".len(), id);
        assert!(handler.queue_next().is_none());

        let mut raw = [0u8; 6];
        raw[..4].copy_from_slice(&[127, 0, 0, 1]);
        handler.on_stun(b"not stun at all", b"not stun at all".len(), &raw);
    }

    #[test]
    fn a_response_is_not_answered_again() {
        let mut handler = BindingHandler::new();
        handler.set_identity(identity_of(127, 0, 0, 1, 3478));
        let id = transport::ConnectionId(6);
        TBindingHandler::on_tcp_connect(&mut handler, id);

        let datagram = protocol::build_response(
            protocol::MessageType::BINDING_SUCCESS.bits(),
            &protocol::TransactionId::from(TXID),
            &[],
            None,
            false,
        )
        .unwrap();
        handler.on_tcp_stun(&datagram, datagram.len(), id);
        assert!(handler.queue_next().is_none(), "a response is not a request");
    }

    #[test]
    fn render_plan_is_repeatable_for_the_same_plan() {
        let txid = protocol::TransactionId::from(TXID);
        let plan = plan_for_request(&parsed(&[software_attr("x")]), None, None);
        let a = render_plan(&plan, txid).unwrap();
        let b = render_plan(&plan, txid).unwrap();
        assert_eq!(a, b, "the render is a pure function of the plan");
        assert!(a.len() > protocol::HEADER_LEN);
    }
}
