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
//! The decision itself lives in `binding::decide`, which takes a
//! [`binding::BindingRequestFacts`] and returns a plan with no wire types.
//! This file owns the two things `binding` deliberately does not: reading the
//! facts out of a parsed message (direction 1) and rendering a plan into
//! attribute bytes (direction 2). The two-way rule still holds: no
//! error-code literal and no length-prefix read appears here that its owning
//! crate does not own.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

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

/// How long a rendered Binding reply is kept so a retransmission can be
/// answered with the identical datagram (RFC 5389 §7.3.1).
///
/// The value is a deployment choice, not an RFC-mandated one: RFC 5389
/// §7.2.1 defines no server-side timeout at all, and the 500 ms RTO example
/// it gives times a transaction out at 39 500 ms. 55 s sits past that, so a
/// peer that has sent its whole retry schedule still finds the cache.
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(55);

/// The largest replay cache the handler keeps. Binding replies are small, so
/// this is a ceiling on state, not a target.
const TRANSACTION_CACHE_CAP: usize = 4096;

/// The transaction key: source address plus transaction identifier.
///
/// The RFC scopes a transaction to the peer it came from (RFC 5389 §5.2), so
/// two peers that happen to pick the same transaction id must not collide here.
/// `None` for a datagram peer, the control connection for ICE-TCP — two
/// streams on one listener are distinct peers for this purpose.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TransactionKey {
    peer: SocketAddr,
    txid: [u8; 12],
    connection: Option<transport::ConnectionId>,
}

/// One rendered reply kept for a transaction, so a retransmission is answered
/// with the datagram that went out before.
#[derive(Debug, Clone)]
struct TransactionEntry {
    datagram: Vec<u8>,
    until: Instant,
}

/// Rendered replies indexed by their transaction. STUN has no request
/// "in progress" state a server can reject against, so this map is where the
/// idempotency RFC 5389 §7.3.1 requires lives: same request, same datagram.
#[derive(Debug, Default)]
struct TransactionCache {
    entries: Vec<(TransactionKey, TransactionEntry)>,
}

impl TransactionCache {
    /// The reply kept for `key`, if one is still valid. Not removed: a client
    /// may retransmit several times before it sees an answer.
    fn lookup(&mut self, key: &TransactionKey) -> Option<Vec<u8>> {
        self.reap();
        self.entries
            .iter()
            .find(|(stored, _)| stored == key)
            .map(|(_, entry)| entry.datagram.clone())
    }

    /// Record a rendered reply under its transaction key.
    fn insert(&mut self, key: TransactionKey, datagram: Vec<u8>) {
        self.reap();
        if let Some(entry) = self.entries.iter_mut().find(|(stored, _)| stored == &key) {
            entry.1 = TransactionEntry {
                datagram,
                until: Instant::now() + TRANSACTION_TIMEOUT,
            };
            return;
        }
        if self.entries.len() >= TRANSACTION_CACHE_CAP {
            self.reap_oldest();
        }
        self.entries.push((
            key,
            TransactionEntry {
                datagram,
                until: Instant::now() + TRANSACTION_TIMEOUT,
            },
        ));
    }

    /// How many transactions are cached, including the expired ones not yet
    /// reaped. Tests use this to see the eviction cap.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is cached, expired or not.
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop entries past their expiry. Cheap enough to run per request: the
    /// cache is bounded by [`TRANSACTION_CACHE_CAP`] and Binding traffic is
    /// the only source of entries.
    fn reap(&mut self) {
        let now = Instant::now();
        self.entries.retain(|(_, entry)| entry.until > now);
    }

    /// Evict the earliest-expiring entry: the cache is full and a new
    /// transaction has to fit.
    fn reap_oldest(&mut self) {
        let Some(pos) = (0..self.entries.len()).min_by_key(|&i| self.entries[i].1.until) else {
            return;
        };
        self.entries.remove(pos);
    }
}

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
    /// The identity a `ChangeSource::Default` answer reports: the socket this
    /// reply actually leaves from.
    default_identity: binding::ServerIdentity,
    /// The datagram the last plan rendered to, kept so the handler can file
    /// it under the transaction for a retransmission.
    rendered: Option<Vec<u8>>,
    /// A control-connection reply waiting for the loop to write it.
    queued: Option<transport::QueuedReply>,
}

impl ServerBindingSink {
    /// A sink that replies on `path` and reports `default_identity`.
    fn for_path(path: ReplyPath, default_identity: binding::ServerIdentity) -> Self {
        ServerBindingSink {
            reply_path: path,
            default_identity,
            rendered: None,
            queued: None,
        }
    }

    /// Whether this sink has a path that can deliver a reply.
    pub fn is_live(&self) -> bool {
        self.reply_path.is_live()
    }

    /// The datagram the plan rendered to, whether or not it was sent. `None`
    /// when the reply could not be rendered.
    pub fn rendered(&self) -> Option<&[u8]> {
        self.rendered.as_deref()
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
        let attrs = plan_attributes(plan, self.default_identity);
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
        self.rendered = Some(datagram.clone());
        match self.reply_path.send(datagram) {
            Ok(queue) => self.queued = queue,
            Err(_) => {
                self.reply_path = ReplyPath::None
            }
        }
    }
}

/// Direction 2: a plan becomes the attribute list `protocol` appends after
/// the header. Order is fixed — `ERROR-CODE` on failure, otherwise
/// `XOR-MAPPED-ADDRESS`, `ALTERNATE-SERVER`, then `SOFTWARE` — so every caller
/// renders identically.
///
/// `default` is the identity a `ChangeSource::Default` answer leaves from:
/// the plan names the default only relatively, and only this crate knows what
/// the socket is actually bound to.
fn plan_attributes(
    plan: &binding::BindingResponsePlan,
    default: binding::ServerIdentity,
) -> Vec<protocol::Attribute> {
    match plan.outcome {
        Outcome::Success => {
            let mut attrs = Vec::new();
            if plan.include_xor_mapped {
                attrs.push(protocol::Attribute::XorMappedAddress(
                    mapped_attr(plan.source, default),
                ));
            }
            if plan.include_alternate_server {
                // `source` carries the alternate identity whenever
                // `include_alternate_server` is set: that is the one value the
                // plan exposes for it.
                attrs.push(protocol::Attribute::AlternateServer(
                    mapped_attr(plan.source, default),
                ));
            }
            if plan.include_software {
                attrs.push(protocol::Attribute::Software(SOFTWARE_NAME.to_string()));
            }
            attrs
        }
        Outcome::Error(code) => {
            let mut attrs = vec![error_code_attr(code)];
            // RFC 8489 Section 6.3.1: a 420 must name the attributes it
            // rejected. Only 420 carries a list; `plan_attributes` is the one
            // place that decides, so no other error code can grow it.
            if matches!(plan.outcome, Outcome::Error(binding::ErrorCode::UnknownAttribute))
                {
                if let Some(codes) = &plan.unknown_attributes {
                    attrs.push(protocol::Attribute::UnknownAttributes(codes.clone()));
                }
            }
            attrs
        }
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
fn mapped_attr(source: ChangeSource, default: binding::ServerIdentity) -> protocol::MappedAddress {
    match source {
        ChangeSource::Default => identity_attr(default),
        ChangeSource::Explicit(id) => identity_attr(id),
    }
}

/// The MAPPED-ADDRESS value for one identity.
fn identity_attr(id: binding::ServerIdentity) -> protocol::MappedAddress {
    let port = id.port;
    if id.is_ipv4 {
        protocol::MappedAddress::from_ipv4(
            id.address[12], id.address[13], id.address[14], id.address[15], port,
        )
    } else {
        protocol::MappedAddress::from_ipv6(id.address, port)
    }
}

/// Render one plan into wire bytes. Independent of the transport, which is
/// what lets this file be tested without sockets.
pub fn render_plan(
    plan: &binding::BindingResponsePlan,
    txid: protocol::TransactionId,
    default: binding::ServerIdentity,
) -> Result<Vec<u8>, protocol::Error> {
    let attrs = plan_attributes(plan, default);
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
/// here. Carrying both role attributes is a conflict the decision turns into
/// 487; a role attribute that would not parse at all never reaches the
/// decision, because the message would have failed to parse first.
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

/// Direction 1: read `OTHER-ADDRESS` as its own fact. It is not part of
/// [`binding::IceAttributes`] because the attribute is optional and the family
/// check compares it against the socket the request arrived on, which only the
/// OTHER-ADDRESS carries the MAPPED-ADDRESS layout (RFC 5780 Section 7.4,
/// RFC 3489 Section 11.2.3), so the parsed value maps onto the decision's
/// carrier field for field. Returns `None` when the peer sent none: the
/// attribute is optional, so its absence is not an error.
pub fn extract_other_address(msg: &protocol::Message) -> Option<binding::OtherAddress> {
    let protocol::Attribute::OtherAddress(addr) = msg.find(protocol::AttrCode::OtherAddress.as_u16())?
    else {
        return None;
    };
    Some(binding::OtherAddress {
        family: match addr.family {
            protocol::AddressFamily::Ipv4 => binding::IpFamily::V4,
            protocol::AddressFamily::Ipv6 => binding::IpFamily::V6,
        },
        port: addr.port,
        address: addr.ip,
    })
}

/// Direction 1: the attribute codes a Binding server must comprehend but
/// cannot find here, as a list [`binding::decide`] turns into 420.
///
/// A Binding server knows `binding::NOT_COMPREHENSION_REQUIRED` — the set it
/// may ignore silently — plus `BINDING_KNOWN`, the echo, ICE and
/// OTHER-ADDRESS attributes it reads and decides on. Every other attribute in
/// a Binding request is a 420. `BINDING_KNOWN` is a separate constant rather
/// than a field of the decision crate so the comprehension table stays exactly
/// the one a Binding server may keep and still reject the rest. `codes` is
/// the caller's scratch, so the result borrows it rather than the message,
/// and the buffer stays on the stack.
const BINDING_KNOWN: [u16; 4] = [
    protocol::AttrCode::Software.as_u16(),       // 0x8022, echoed
    protocol::AttrCode::IceControlled.as_u16(),  // 0x8029, the role
    protocol::AttrCode::IceControlling.as_u16(), // 0x802A, the role
    // 0x802C, comprehension-optional (RFC 5780 §7): a server may ignore it,
    // but this one reads it, so it is known rather than unknown.
    protocol::AttrCode::OtherAddress.as_u16(),
];

fn unknown_attribute_codes<'buf>(
    msg: &protocol::Message,
    codes: &'buf mut [u16; 64],
) -> Option<&'buf [u16]> {
    let mut n = 0;
    for attr in msg.attributes() {
        let code = protocol::attribute_kind(attr).as_u16();
        if !binding::NOT_COMPREHENSION_REQUIRED.contains(&code)
            && !BINDING_KNOWN.contains(&code)
        {
            if n < codes.len() {
                codes[n] = code;
            }
            n += 1;
        }
    }
    for attr in &msg.unknown {
        if n < codes.len() {
            codes[n] = attr.code;
        }
        n += 1;
    }
    if n == 0 {
        None
    } else {
        Some(&codes[..n.min(codes.len())])
    }
}

/// Read the request's facts and decide the plan.
///
/// `peer` is the source the request was read from, `source` the identity the
/// reply normally leaves from, and `addresses` every address this worker can
/// send from — the full listen list `CHANGE-REQUEST` is resolved against.
/// Without `addresses` a combined flag would always fail, so a worker that
/// only knows its own socket answers 420 where the flag cannot be met (RFC
/// 5780 §6.1 gives one error for every unsatisfiable CHANGE-REQUEST).
pub fn plan_for_request(
    msg: &protocol::Message,
    peer: SocketAddr,
    source: Option<binding::ServerIdentity>,
    addresses: &[binding::ServerIdentity],
) -> binding::BindingResponsePlan {
    let mut codes = [0u16; 64];
    let facts = binding::BindingRequestFacts {
        peer,
        change: extract_change_request(msg),
        ice: extract_ice(msg),
        other_address: extract_other_address(msg),
        software_requested: msg
            .find(protocol::AttrCode::Software.as_u16())
            .is_some(),
        unknown_attributes: unknown_attribute_codes(msg, &mut codes),
        redirect_to: None,
    };
    binding::decide(&facts, source, addresses)
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
    /// Every address this worker can send from, the list
    /// `CHANGE-REQUEST` is resolved against. Populated by the control plane
    /// from the sockets it actually bound.
    addresses: Vec<binding::ServerIdentity>,
    /// Live control connections, keyed by the loop's connection id.
    conns: HashSet<transport::ConnectionId>,
    /// Replies queued for control connections, oldest first.
    outbox: VecDeque<transport::QueuedReply>,
    /// Rendered replies kept so a retransmission answers with the same
    /// datagram (RFC 5389 §7.3.1).
    transactions: TransactionCache,
}

impl BindingHandler {
    /// A handler with no sockets attached.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the UDP sender. Its bound address becomes the UDP reply
    /// identity and joins the listen list.
    pub fn set_udp(&mut self, socket: UdpSocket) {
        self.udp_identity = socket.local_addr().ok().map(identity_of_socket);
        if let Some(identity) = self.udp_identity {
            self.add_address(identity);
        }
        self.udp = Some(socket);
    }

    /// Record the identity a control-connection reply answers as.
    pub fn set_tcp_identity(&mut self, identity: binding::ServerIdentity) {
        self.tcp_identity = Some(identity);
        self.add_address(identity);
    }

    /// Record the reply identity when the socket set is described separately.
    pub fn set_identity(&mut self, identity: binding::ServerIdentity) {
        self.udp_identity = Some(identity);
        self.tcp_identity = Some(identity);
        self.add_address(identity);
    }

    /// Describe every address this worker can send from. Called with the
    /// process's full listen list so a `CHANGE-REQUEST` that names a second
    /// address is resolved against what the server really binds, not just the
    /// one socket this request came in on.
    pub fn set_addresses<I>(&mut self, addresses: I)
    where
        I: IntoIterator<Item = binding::ServerIdentity>,
    {
        self.addresses = addresses.into_iter().collect();
    }

    /// Add one address to the listen list, keeping it free of duplicates.
    fn add_address(&mut self, identity: binding::ServerIdentity) {
        if !self.addresses.contains(&identity) {
            self.addresses.push(identity);
        }
    }

    /// The address list `CHANGE-REQUEST` resolves against.
    fn addresses(&self) -> &[binding::ServerIdentity] {
        &self.addresses
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

    /// The transaction key for one UDP datagram: the peer it came from plus
    /// its transaction identifier.
    fn transaction_key(&self, raw: &[u8], txid: [u8; 12]) -> Option<TransactionKey> {
        parse_peer_addr(raw).map(|peer| TransactionKey {
            peer,
            txid,
            connection: None,
        })
    }

    /// Deliver one datagram for a transaction and keep the exact bytes under
    /// that transaction, so a retransmission is answered with the datagram
    /// the peer already saw — a mapped address cannot change between answers.
    fn deliver_reply(&mut self, path: &ReplyPath, key: &TransactionKey, datagram: Vec<u8>) {
        if !path.is_live() {
            return;
        }
        let Ok(sent) = path.send(datagram.clone()) else {
            // The write failed; nothing reached the peer, so nothing is kept.
            return;
        };
        // A control-connection reply has no wire yet: queue it for the loop.
        if let Some(payload) = sent {
            self.enqueue(payload);
        }
        self.transactions.insert(key.clone(), datagram);
    }

    /// File a rendered reply under its transaction: the sink has already put
    /// it on the wire, so this only remembers the bytes.
    fn filed(&mut self, sink: &ServerBindingSink, key: &TransactionKey) {
        if let Some(rendered) = sink.rendered() {
            self.transactions.insert(key.clone(), rendered.to_vec());
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
        let Some(peer) = parse_peer_addr(src_addr) else {
            return;
        };
        let Some(default_identity) = self.udp_identity else {
            // No bound socket means no address to report and nowhere to send.
            return;
        };
        let plan = plan_for_request(&msg, peer, Some(default_identity), self.addresses());
        let txid = msg.transaction_id().into();
        let Some(key) = self.transaction_key(src_addr, txid) else {
            unreachable!("the peer was already parsed above")
        };
        let path = self.reply_path(src_addr);
        // RFC 5389 §7.3.1: a request is either the first of a transaction or
        // a retransmission, and the server MUST answer so that getting the
        // retransmission's reply is equivalent to getting the original's. A
        // cached reply is the exact bytes the peer already saw, which is the
        // only way a different mapped address cannot leak between the two.
        if path.is_live() {
            if let Some(replay) = self.transactions.lookup(&key) {
                self.deliver_reply(&path, &key, replay);
                return;
            }
        }
        let mut sink = ServerBindingSink::for_path(path, default_identity);
        binding::ResponseSink::send_plan(&mut sink, &plan, txid);
        // The sink already sent; file the exact bytes under the transaction
        // so a retransmission is answered with this same datagram.
        self.filed(&sink, &key);
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
        let Some(default_identity) = self.tcp_identity else {
            // A control path with no identity has no address to report.
            return;
        };
        // The peer the TCP stream reached is the listener's address: a
        // Binding request over ICE-TCP reports the address the connection
        // was made to, which is where the reply leaves from.
        let peer = default_identity.to_socket_addr();
        let plan = plan_for_request(&msg, peer, Some(default_identity), self.addresses());
        // The connection id is part of the key: two streams on the same
        // listener must not share a transaction cache entry.
        let key = TransactionKey {
            peer,
            txid: msg.transaction_id().into(),
            connection: Some(id),
        };
        if let Some(replay) = self.transactions.lookup(&key) {
            self.deliver_reply(&ReplyPath::Tcp(id), &key, replay);
            return;
        }
        let mut sink = ServerBindingSink::for_path(ReplyPath::Tcp(id), default_identity);
        binding::ResponseSink::send_plan(&mut sink, &plan, msg.transaction_id().into());
        if let Some(reply) = sink.drain() {
            self.enqueue(reply);
        }
        self.filed(&sink, &key);
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

    /// An `OTHER-ADDRESS`, which carries the MAPPED-ADDRESS layout: an IPv4
    /// address sits in the first four address octets, an IPv6 one in all
    /// sixteen.
    fn other_addr(is_ipv4: bool, address: [u8; 16], port: u16) -> protocol::Attribute {
        if is_ipv4 {
            protocol::Attribute::OtherAddress(protocol::MappedAddress::from_ipv4(
                address[0],
                address[1],
                address[2],
                address[3],
                port,
            ))
        } else {
            protocol::Attribute::OtherAddress(protocol::MappedAddress::from_ipv6(
                address, port,
            ))
        }
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

    /// The peer every test request comes from.
    const PEER: &str = "10.0.0.7:50000";

    /// The peer, parsed fresh for each test.
    fn peer() -> SocketAddr {
        PEER.parse().unwrap()
    }

    /// The worker's default listen identity.
    fn default_identity() -> binding::ServerIdentity {
        identity_of(10, 0, 0, 1, 3478)
    }

    /// The peer the transport hands the handler, encoded the way it comes
    /// off the wire: four or sixteen address octets plus a big-endian port.
    fn src_raw_of(addr: SocketAddr) -> Vec<u8> {
        let mut raw = Vec::with_capacity(6);
        match addr.ip() {
            IpAddr::V4(v4) => raw.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => raw.extend_from_slice(&v6.octets()),
        }
        raw.extend_from_slice(&addr.port().to_be_bytes());
        raw
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
        let default = identity_of(127, 0, 0, 1, 3478);
        let plan = plan_for_request(&msg, peer(), Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Success);
        assert!(plan.include_xor_mapped);
        assert!(!plan.include_software);
        assert!(!plan.include_alternate_server);

        let bytes = render_plan(&plan, protocol::TransactionId::from(TXID), default).unwrap();
        let reply = protocol::parse(&bytes).unwrap();
        assert_eq!(reply.msg_type(), protocol::MessageType::BINDING_SUCCESS);
        assert_eq!(reply.transaction_id(), protocol::TransactionId::from(TXID));
        let addr = reply.xor_mapped_address().expect("XOR-MAPPED-ADDRESS");
        assert_eq!(addr.ipv4(), Some((127, 0, 0, 1)));
        assert_eq!(addr.port, 3478);
    }

    #[test]
    fn a_software_request_makes_the_plan_echo_software() {
        let default = default_identity();
        let msg = parsed(&[software_attr("test client")]);
        let plan = plan_for_request(&msg, peer(), Some(default), &[default]);
        assert!(plan.include_software);
        let attrs = plan_attributes(&plan, default);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, protocol::Attribute::Software(s) if s == SOFTWARE_NAME)),
            "the plan must echo {SOFTWARE_NAME}"
        );
    }

    #[test]
    fn an_ice_priority_on_a_binding_request_answers_420() {
        // ICE-PRIORITY belongs on a candidate check, not a control message:
        // the attribute is unknown to a Binding server.
        let default = default_identity();
        let msg = parsed(&[protocol::Attribute::IcePriority(0x6e00_01ff)]);
        let plan = plan_for_request(&msg, peer(), Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(binding::ErrorCode::UnknownAttribute));
        assert_eq!(
            plan.outcome.error().unwrap().number(),
            420
        );
    }

    #[test]
    fn an_attribute_the_binding_server_does_not_comprehend_answers_420() {
        // USERNAME is a TURN attribute: a Binding server that meets it must
        // reject rather than ignore.
        let default = default_identity();
        let msg = parsed(&[protocol::Attribute::Username("alice".to_string())]);
        let plan = plan_for_request(&msg, peer(), Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(binding::ErrorCode::UnknownAttribute));
        assert!(!plan.include_xor_mapped);

        // RFC 8489 Section 6.3.1 names the offending attribute, so a peer that
        // keeps sending USERNAME learns which code to stop sending.
        let unknowns = plan_attributes(&plan, default);
        let protocol::Attribute::UnknownAttributes(codes) = unknowns.last().expect("list") else {
            panic!("a 420 must carry UNKNOWN-ATTRIBUTES")
        };
        assert_eq!(codes, &[protocol::AttrCode::Username.as_u16()]);
        let reply = protocol::parse(
            &render_plan(&plan, protocol::TransactionId::from(TXID), default).unwrap(),
        )
        .unwrap();
        let listed = reply
            .find(protocol::AttrCode::UnknownAttributes.as_u16())
            .and_then(|a| match a {
                protocol::Attribute::UnknownAttributes(c) => Some(c.to_vec()),
                _ => None,
            })
            .expect("the reply must carry UNKNOWN-ATTRIBUTES");
        assert_eq!(listed, [protocol::AttrCode::Username.as_u16()]);

        // Every other error code carries no attribute list: the 400 an
        // OTHER-ADDRESS of the wrong family raises must stay a bare
        // ERROR-CODE.
        let other = other_addr(false, [0xffu8; 16], 50000);
        let plan = plan_for_request(
            &parsed(&[other]),
            peer(),
            Some(default),
            &[default],
        );
        assert_eq!(plan.outcome.error().unwrap().number(), 400, "{plan:?}");
        assert!(plan.unknown_attributes.is_none(), "{plan:?}");
        assert!(
            !plan_attributes(&plan, default)
                .iter()
                .any(|a| matches!(a, protocol::Attribute::UnknownAttributes(_)))
        );
    }

    #[test]
    fn an_other_address_of_the_connection_family_is_not_an_error() {
        // The check is on the family only: a peer that names the family it is
        // actually on is answered normally, not with the 400 the mismatch gets.
        let default = default_identity();
        let other = other_addr(true, [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 50000);
        let plan = plan_for_request(&parsed(&[other]), peer(), Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Success, "{plan:?}");
    }

    #[test]
    fn a_clashing_ice_role_answers_role_conflict_487() {
        // RFC 8445 §16.2: 487 Role Conflict, not the unassigned 430.
        let default = default_identity();
        let msg = parsed(&[
            ice_attr(protocol::AttrCode::IceControlled.as_u16(), [0, 0, 0, 0, 0, 0, 0, 1]),
            ice_attr(protocol::AttrCode::IceControlling.as_u16(), [0, 0, 0, 0, 0, 0, 0, 2]),
        ]);
        let plan = plan_for_request(&msg, peer(), Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(binding::ErrorCode::RoleConflict));
        assert_eq!(plan.outcome.error().unwrap().number(), 487);
        assert!(!plan.include_xor_mapped);

        // A single well-formed role is accepted.
        let msg = parsed(&[ice_attr(
            protocol::AttrCode::IceControlling.as_u16(),
            [0, 0, 0, 0, 0, 0, 0, 2],
        )]);
        let plan = plan_for_request(&msg, peer(), Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Success);
    }

    #[test]
    fn a_change_request_no_candidate_satisfies_answers_420() {
        // `B` alone asks for the same address on a different port, and the
        // listen list holds only the default: no alternate address and port,
        // so RFC 5780 Section 6.1's 420, with no mapped address.
        let default = default_identity();
        let msg = parsed(&[change_attr(0x0000_0002)]);
        let plan = plan_for_request(&msg, peer(), Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(binding::ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
        assert!(!plan.include_xor_mapped);

        let bytes = render_plan(&plan, protocol::TransactionId::from(TXID), default).unwrap();
        let reply = protocol::parse(&bytes).unwrap();
        assert_eq!(reply.msg_type(), protocol::MessageType::BINDING_ERROR);
        let error = reply.error().expect("ERROR-CODE");
        assert_eq!(error.as_u16(), binding::ErrorCode::UnknownAttribute.number());
        assert_eq!(
            &error.reason,
            binding::ErrorCode::UnknownAttribute.reason().as_str().as_bytes()
        );
    }

    #[test]
    fn a_combined_change_request_with_no_candidate_answers_420() {
        // `A`|`B` asks for both dimensions to change; with one listener neither
        // does, so the answer is the same 420 the port-only request got.
        let default = default_identity();
        let msg = parsed(&[change_attr(0x0000_0003)]);
        let plan = plan_for_request(&msg, peer(), Some(default), &[default]);
        assert_eq!(plan.outcome, Outcome::Error(binding::ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);
    }

    #[test]
    fn a_change_request_resolved_against_the_listen_list_is_honored() {
        let default = default_identity();
        let second = identity_of(10, 0, 0, 9, 3479);
        let msg = parsed(&[change_attr(0x0000_0003)]);
        let plan = plan_for_request(&msg, peer(), Some(default), &[default, second]);
        assert_eq!(plan.outcome, Outcome::Success);
        assert_eq!(plan.source, ChangeSource::Explicit(second));

        let attrs = plan_attributes(&plan, default);
        let protocol::Attribute::XorMappedAddress(addr) = attrs.first().expect("XOR-MAPPED-ADDRESS")
        else {
            panic!("the reply must carry an XOR-MAPPED-ADDRESS");
        };
        assert_eq!(addr.ipv4(), Some((10, 0, 0, 9)));
        assert_eq!(addr.port, 3479);
    }

    #[test]
    fn a_change_request_without_any_source_answers_420() {
        // No default source and no listen list: a `B` request cannot be met,
        // and there is no socket at all to answer from, so no alternate.
        let msg = parsed(&[change_attr(0x0000_0002)]);
        let plan = plan_for_request(&msg, peer(), None, &[]);
        assert_eq!(plan.outcome, Outcome::Error(binding::ErrorCode::UnknownAttribute));
        assert_eq!(plan.outcome.error().unwrap().number(), 420);

        // A plain request still succeeds: there is no address to report, but
        // the sink supplies the socket it sends from.
        let plan = plan_for_request(&parsed(&[]), peer(), None, &[]);
        assert_eq!(plan.outcome, Outcome::Success);
        assert_eq!(plan.source, ChangeSource::Default);
    }

    #[test]
    fn alternate_server_renders_from_the_plan_source() {
        let alternate = identity_of(10, 0, 0, 9, 3480);
        let default = default_identity();
        let mut plan = plan_for_request(&parsed(&[]), peer(), Some(default), &[default]);
        plan.include_alternate_server = true;
        plan.source = ChangeSource::Explicit(alternate);

        let attrs = plan_attributes(&plan, default);
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
            binding::ErrorCode::TryAlternate,
            binding::ErrorCode::BadRequest,
            binding::ErrorCode::Unauthorized,
            binding::ErrorCode::UnknownAttribute,
            binding::ErrorCode::StaleNonce,
            binding::ErrorCode::RoleConflict,
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
        assert_eq!(identity_attr(v4).ipv4(), Some((127, 0, 0, 1)));

        let v6 = identity_of_socket("[::1]:3478".parse().unwrap());
        assert!(!v6.is_ipv4);
        assert_eq!(v6.port, 3478);
        let mapped = mapped_attr(ChangeSource::Explicit(v6), v4);
        assert_eq!(mapped.ipv6(), Some(Ipv6Addr::LOCALHOST.octets()));

        // A default source answers as the socket it is attached to, not a
        // hardcoded loopback: the render must report the real bound address.
        let default = identity_of_socket("[::1]:3478".parse().unwrap());
        let default_mapped = mapped_attr(ChangeSource::Default, default);
        assert_eq!(default_mapped.ipv6(), Some(Ipv6Addr::LOCALHOST.octets()));
        assert_eq!(default_mapped.port, 3478);
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
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut handler = BindingHandler::new();
        handler.set_udp(server.try_clone().unwrap());
        assert!(handler.udp_identity.unwrap().is_ipv4);

        let datagram = request(&[]);
        client.send_to(&datagram, server_addr).unwrap();
        let mut buf = vec![0u8; transport::MAX_UDP_DATAGRAM];
        let (n, from) = server.recv_from(&mut buf).unwrap();

        let mut src_raw = [0u8; 6];
        match from.ip() {
            IpAddr::V4(v4) => src_raw[..4].copy_from_slice(&v4.octets()),
            other => panic!("loopback peer is not IPv4: {other}"),
        }
        src_raw[4..].copy_from_slice(&from.port().to_be_bytes());

        handler.on_stun(&buf[..n], n, &src_raw);

        client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let mut reply = vec![0u8; transport::MAX_UDP_DATAGRAM];
        let (r, to) = client.recv_from(&mut reply).unwrap();
        assert_eq!(to, server_addr, "the reply must leave the server socket");

        let msg = protocol::parse(&reply[..r]).unwrap();
        assert_eq!(msg.msg_type(), protocol::MessageType::BINDING_SUCCESS);
        assert_eq!(msg.transaction_id(), protocol::TransactionId::from(TXID));
        // The mapped address must name the socket the reply left from, not a
        // hardcoded loopback: that is what a client decides its local port from.
        let mapped = msg.xor_mapped_address().expect("XOR-MAPPED-ADDRESS");
        assert_eq!(mapped.ipv4(), Some((127, 0, 0, 1)));
        assert_eq!(mapped.port, server_addr.port());
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
        handler.set_tcp_identity(identity_of(127, 0, 0, 1, 3478));
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
        handler.set_tcp_identity(identity_of(127, 0, 0, 1, 3478));
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
        handler.set_tcp_identity(identity_of(127, 0, 0, 1, 3478));
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
    fn a_role_conflict_over_udp_and_tcp_answers_487() {
        // RFC 8445 §7.2.1.1: both role attributes present is a conflict, and
        // the error must not carry a mapped address.
        let mut handler = BindingHandler::new();
        handler.set_identity(identity_of(127, 0, 0, 1, 3478));
        let live = transport::ConnectionId(7);
        TBindingHandler::on_tcp_connect(&mut handler, live);

        let conflicting = request(&[
            ice_attr(protocol::AttrCode::IceControlled.as_u16(), [0, 0, 0, 0, 0, 0, 0, 1]),
            ice_attr(protocol::AttrCode::IceControlling.as_u16(), [0, 0, 0, 0, 0, 0, 0, 2]),
        ]);
        handler.on_tcp_stun(&conflicting, conflicting.len(), live);

        let Some(reply) = handler.queue_next() else {
            panic!("a conflict must be answered, not dropped");
        };
        let msg = protocol::parse(&reply.payload).unwrap();
        assert_eq!(msg.msg_type(), protocol::MessageType::BINDING_ERROR);
        assert!(msg.xor_mapped_address().is_none(), "an error must not map");
        assert_eq!(
            msg.error().expect("ERROR-CODE").as_u16(),
            binding::ErrorCode::RoleConflict.number()
        );
    }

    #[test]
    fn render_plan_is_repeatable_for_the_same_plan() {
        let txid = protocol::TransactionId::from(TXID);
        let default = default_identity();
        let plan = plan_for_request(&parsed(&[software_attr("x")]), peer(), Some(default), &[default]);
        let a = render_plan(&plan, txid, default).unwrap();
        let b = render_plan(&plan, txid, default).unwrap();
        assert_eq!(a, b, "the render is a pure function of the plan");
        assert!(a.len() > protocol::HEADER_LEN);
    }

    #[test]
    fn the_listen_list_deduplicates_and_grows_from_the_sockets() {
        let mut handler = BindingHandler::new();
        handler.set_addresses(vec![
            identity_of(10, 0, 0, 1, 3478),
            identity_of(10, 0, 0, 9, 3479),
        ]);
        handler.set_udp(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let bound = handler.udp_identity.expect("the socket is bound");

        // The listener list is what a CHANGE-REQUEST resolves against, and it
        // must now hold the socket the handler actually sends from.
        assert!(handler.addresses().contains(&identity_of(10, 0, 0, 1, 3478)));
        assert!(handler.addresses().contains(&identity_of(10, 0, 0, 9, 3479)));
        assert!(handler.addresses().contains(&bound));

        // Adding the same address twice must not double it.
        handler.set_tcp_identity(identity_of(10, 0, 0, 9, 3479));
        assert_eq!(
            handler.addresses().iter().filter(|id| **id == identity_of(10, 0, 0, 9, 3479)).count(),
            1
        );
        assert_eq!(handler.addresses().len(), 3);
    }

    #[test]
    fn an_address_list_of_two_honors_a_change_request_over_tcp() {
        let mut handler = BindingHandler::new();
        let live = transport::ConnectionId(9);
        TBindingHandler::on_tcp_connect(&mut handler, live);

        let listener = identity_of(127, 0, 0, 1, 3480);
        let second = identity_of(127, 0, 0, 2, 3481);
        handler.set_tcp_identity(listener);
        handler.set_addresses(vec![listener, second]);

        let datagram = request(&[change_attr(0x0000_0003)]);
        handler.on_tcp_stun(&datagram, datagram.len(), live);

        let Some(reply) = handler.queue_next() else {
            panic!("a change request the listen list can satisfy must be answered");
        };
        let msg = protocol::parse(&reply.payload).unwrap();
        assert_eq!(msg.msg_type(), protocol::MessageType::BINDING_SUCCESS);
        let addr = msg.xor_mapped_address().expect("XOR-MAPPED-ADDRESS");
        assert_eq!(addr.ipv4(), Some((127, 0, 0, 2)));
        assert_eq!(addr.port, 3481);
    }

    /// A request the handler has already answered, delivered from the same
    /// peer with the same transaction id.
    #[test]
    fn a_retransmission_gets_the_same_datagram_over_udp() {
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut handler = BindingHandler::new();
        handler.set_udp(server.try_clone().unwrap());

        let datagram = request(&[software_attr("replay me")]);
        let src_raw = src_raw_of(client.local_addr().unwrap());
        for _ in 0..3 {
            client.send_to(&datagram, server_addr).unwrap();
            let mut buf = vec![0u8; transport::MAX_UDP_DATAGRAM];
            let (n, _) = server.recv_from(&mut buf).unwrap();
            handler.on_stun(&buf[..n], n, &src_raw);
        }

        let mut first = vec![0u8; transport::MAX_UDP_DATAGRAM];
        let (len, from) = client.recv_from(&mut first).unwrap();
        assert_eq!(from, server_addr);
        assert_eq!(handler.transactions.len(), 1, "one transaction, three replies");

        let mut second = vec![0u8; transport::MAX_UDP_DATAGRAM];
        let (len2, _) = client.recv_from(&mut second).unwrap();
        let mut third = vec![0u8; transport::MAX_UDP_DATAGRAM];
        let (len3, _) = client.recv_from(&mut third).unwrap();

        // RFC 5389 §7.3.1: the reply to a retransmission must be equivalent to
        // the original's, and the replay cache answers with the same bytes.
        assert_eq!(first[..len], second[..len2], "second reply differs");
        assert_eq!(second[..len2], third[..len3], "third reply differs");
        let msg = protocol::parse(&first[..len]).unwrap();
        assert_eq!(msg.msg_type(), protocol::MessageType::BINDING_SUCCESS);
        assert!(
            msg.find(protocol::AttrCode::Software.as_u16()).is_some(),
            "the replayed reply keeps every attribute"
        );
    }

    /// A retransmission over a control connection replays the queued datagram.
    #[test]
    fn a_retransmission_gets_the_same_datagram_over_tcp() {
        let mut handler = BindingHandler::new();
        handler.set_tcp_identity(identity_of(127, 0, 0, 1, 3478));
        let id = transport::ConnectionId(21);
        TBindingHandler::on_tcp_connect(&mut handler, id);

        let datagram = request(&[]);
        handler.on_tcp_stun(&datagram, datagram.len(), id);
        let Some(first) = handler.queue_next() else {
            panic!("the first request must be answered");
        };
        handler.on_tcp_stun(&datagram, datagram.len(), id);
        let Some(second) = handler.queue_next() else {
            panic!("a retransmission must be answered");
        };
        assert_eq!(first.payload, second.payload, "the retransmission is replayed");

        handler.on_tcp_stun(&datagram, datagram.len(), id);
        let Some(third) = handler.queue_next() else {
            panic!("every retransmission is answered");
        };
        assert_eq!(first.payload, third.payload);
        assert_eq!(handler.transactions.len(), 1);
    }

    /// Two streams on one listener never share a cache entry, even for the
    /// same transaction id: the connection id is part of the key.
    #[test]
    fn two_streams_with_the_same_transaction_id_do_not_replay_each_others() {
        let mut handler = BindingHandler::new();
        handler.set_tcp_identity(identity_of(127, 0, 0, 1, 3478));
        let a = transport::ConnectionId(30);
        let b = transport::ConnectionId(31);
        TBindingHandler::on_tcp_connect(&mut handler, a);
        TBindingHandler::on_tcp_connect(&mut handler, b);

        let same_txid = request(&[software_attr("a")]);
        let mut diff_txid = same_txid.clone();
        diff_txid[14] ^= 0xff;
        diff_txid[15] ^= 0xff;

        handler.on_tcp_stun(&same_txid, same_txid.len(), a);
        handler.on_tcp_stun(&diff_txid, diff_txid.len(), b);
        let ra = handler.queue_next().unwrap().payload;
        let rb = handler.queue_next().unwrap().payload;
        assert_ne!(ra, rb, "different streams, different replies");
        assert_eq!(handler.transactions.len(), 2);

        handler.on_tcp_stun(&same_txid, same_txid.len(), a);
        handler.on_tcp_stun(&diff_txid, diff_txid.len(), b);
        assert_eq!(handler.queue_next().unwrap().payload, ra);
        assert_eq!(handler.queue_next().unwrap().payload, rb);
    }

    /// Expired and evicted entries are not replayed: the cache holds state,
    /// and the state has a lifetime.
    #[test]
    fn expired_entries_are_not_replayed() {
        let mut cache = TransactionCache::default();
        let key = TransactionKey {
            peer: "127.0.0.1:3478".parse().unwrap(),
            txid: TXID,
            connection: None,
        };
        cache.insert(key.clone(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(cache.lookup(&key).is_some(), "a fresh entry lives");

        // Age the entry past the transaction timeout: after that the server is
        // no longer answering for that transaction.
        let mut entry = cache.entries.remove(0).1;
        entry.until = Instant::now() - Duration::from_secs(1);
        cache.entries.push((key.clone(), entry));
        assert!(
            cache.lookup(&key).is_none(),
            "an expired entry is reaped, not replayed"
        );
        assert!(cache.is_empty(), "the reap dropped it");
    }

    /// A full cache evicts the earliest-expiring entry rather than growing.
    #[test]
    fn a_full_cache_evicts_the_oldest_entry() {
        let mut cache = TransactionCache::default();
        let key = |i: u64| TransactionKey {
            peer: "127.0.0.1:3478".parse().unwrap(),
            txid: {
                let mut txid = [0u8; 12];
                txid[..8].copy_from_slice(&i.to_le_bytes());
                txid
            },
            connection: None,
        };

        for i in 0..TRANSACTION_CACHE_CAP as u64 {
            cache.insert(key(i), vec![i as u8]);
        }
        assert_eq!(cache.len(), TRANSACTION_CACHE_CAP, "the cache fills");
        assert!(cache.lookup(&key(0)).is_some(), "the first entry fits");

        // Spread the expiries so the eviction target is unambiguous: the
        // entry inserted first expires first.
        for (n, entry) in cache.entries.iter_mut().enumerate() {
            entry.1.until = Instant::now() + Duration::from_secs(n as u64 + 1);
        }

        // One more transaction evicts the earliest-expiring entry.
        cache.insert(key(9000), vec![0xff]);
        assert_eq!(cache.len(), TRANSACTION_CACHE_CAP, "the cap holds");
        assert!(cache.lookup(&key(9000)).is_some(), "the newcomer is kept");
        assert!(cache.lookup(&key(0)).is_none(), "the oldest is evicted");
    }
}

