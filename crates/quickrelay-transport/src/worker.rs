//! The per-worker event loop: one thread, one `mio::Poll`, no channel, no spawn.
//!
//! A worker owns its sockets outright (architecture.md §2.3): `SO_REUSEPORT`
//! already pins every five-tuple to exactly one worker, so nothing is shared
//! and there is no lock anywhere in this loop. One tick is
//!
//! 1. reclaim every connection past its deadline — the time-wheel work, folded
//!    into the poll deadline so nothing is scanned more often than the next
//!    expiry (architecture.md §5.2),
//! 2. `poll` until the sooner of that expiry and the tick budget,
//! 3. drain every ready source.
//!
//! The worker decides nothing about STUN semantics: a datagram goes up to the
//! [`BindingHandler`]. Whether the reply is sent, and to whom, is the handler's
//! business — that is what keeps `quickrelay-binding` out of this crate.

use std::net::{Shutdown, SocketAddr};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use std::time::{Duration, Instant};

use mio::event::Events;
use mio::net::{TcpListener, UdpSocket};
use mio::{Interest, Poll, Token, Waker};

use crate::connmgr::{
    accept_all, bind_tcp, bind_udp, deregister_id, modify_id, register_id, Conn, ConnMgr,
    EVENT_TCP_LISTEN, EVENT_UDP, EVENT_WAKE,
};
use crate::{BindingHandler, ConnectionId, MAX_UDP_DATAGRAM};

/// How many datagrams one tick drains off the UDP socket before re-arming.
pub const UDP_DRAIN_BATCH: usize = 128;
/// How many connections one tick accepts before re-arming the listener.
pub const ACCEPT_BATCH: usize = 128;
/// How many frames one tick decodes off one connection. A peer that sends more
/// than this in one tick is answered late by one tick, which is invisible.
pub const DECODE_BATCH: usize = 64;
/// A read fills a stack frame, not the heap. A peer that sends more than this
/// is drained on the next tick, which the poll re-arms immediately.
const READ_WINDOW: usize = 16 * 1024;
/// The event list must hold every source in the worker: one UDP, one listener,
/// one wake socket, and one arm per connection.
pub const EVENT_CAPACITY: usize = 256;

/// The configuration of one worker. Only the socket set and the timers matter:
/// a worker has no cross-worker state to share.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// This worker's index, which is also its shard index
    /// (`shard_idx = worker_idx`, architecture.md §2.2).
    pub index: usize,
    /// How many workers the process started.
    pub count: usize,
    /// The UDP listening address; `None` disables the datagram path.
    pub udp_addr: Option<SocketAddr>,
    /// Per-worker receive buffer (architecture.md §2.3, `--udp-rbuf-size`,
    /// default 4 MB). 0 leaves the system default in place.
    pub udp_rcvbuf: usize,
    /// The TCP listening address; `None` disables the control path.
    pub tcp_addr: Option<SocketAddr>,
    /// Idle timeout: a connection that has sent at least one byte but nothing
    /// for this long is cut.
    pub conn_idle_timeout: Duration,
    /// Half-open timeout: a connection that completed the handshake but never
    /// sent a byte is cut after this long (RFC 6062 §2.1 — the TCP shim sends
    /// nothing until the peer has been proven alive).
    pub half_open_timeout: Duration,
    /// How long one tick may wait for a ready event.
    pub poll_timeout: Duration,
    /// Stop after this many ticks; `None` runs until [`WorkerWake`] is tripped.
    pub max_ticks: Option<u64>,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        WorkerConfig {
            index: 0,
            count: 1,
            udp_addr: None,
            udp_rcvbuf: 4 * 1024 * 1024,
            tcp_addr: None,
            conn_idle_timeout: Duration::from_secs(300),
            half_open_timeout: Duration::from_secs(5),
            poll_timeout: Duration::from_secs(1),
            max_ticks: None,
        }
    }
}

/// Why a TCP control connection was cut. Delivered to the handler through
/// [`BindingHandler::on_tcp_error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// The peer closed or reset the stream.
    Eof,
    /// A read or write failed.
    Io,
    /// A frame declared a length above the 16-bit field's reach.
    BadFrame,
    /// The peer said nothing for [`WorkerConfig::conn_idle_timeout`].
    Idle,
    /// The peer completed the handshake but never sent a packet
    /// ([`WorkerConfig::half_open_timeout`]).
    HalfOpen,
}

impl DropReason {
    /// One-word form, for the handler's logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            DropReason::Eof => "eof",
            DropReason::Io => "io",
            DropReason::BadFrame => "bad-frame",
            DropReason::Idle => "idle",
            DropReason::HalfOpen => "half-open",
        }
    }
}

/// A drop in the bucket that lets another thread end this worker's loop.
///
/// The waker alone is not enough to stop a worker, and sharing it is not
/// enough either. `mio` wakes are level-triggered: a wake posted while every
/// other interest is still registered is coalesced with the pending interest
/// and never reported on its own, so the poll parks until its deadline. And
/// Windows batches completion-port posts even harder, so a post that loses the
/// race can be dropped for good.
///
/// The handle therefore does two things: it raises a flag the loop checks
/// before *and* after every poll, so a lost wake is noticed within one poll
/// timeout no matter what the selector decided to do, and it asks the waker to
/// break the poll early when one is in flight. `wake` takes `&self` because
/// the control thread must not borrow the waker just to end the run.
pub struct WorkerWake {
    handle: Arc<StopRequest>,
}

/// The worker's stop signal: a flag the control plane raises and the loop
/// checks before and after every poll.
struct StopRequest {
    /// `wake()` is being called somewhere. The flag is only read by the
    /// worker, which is why `Relaxed` is enough.
    pending: AtomicBool,
    /// Posting this breaks the poll in flight.
    waker: Arc<Waker>,
}

impl StopRequest {
    /// Raise the stop request. Call twice to be safe: a wake can be lost to
    /// the selector, and the flag is what catches that.
    fn stop(&self) {
        self.pending.store(true, Ordering::Relaxed);
        let _ = self.waker.wake();
    }
}

impl WorkerWake {
    /// Ask the worker to end its loop.
    pub fn wake(&self) {
        self.handle.stop();
        self.handle.stop();
    }
}

/// What the loop did before it stopped.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WorkerStats {
    /// How many poll rounds ran.
    pub ticks: u64,
    /// Datagrams handed to the handler.
    pub udp_packets: u64,
    /// Connections that were accepted.
    pub accepts: u64,
    /// Connections that were cut.
    pub dropped: u64,
    /// Packets handed to the handler over TCP control connections.
    pub tcp_packets: u64,
}

/// One worker. Build it, attach sockets with [`Worker::new_udp`] and
/// [`Worker::new_tcp`], then call [`Worker::run`].
pub struct Worker<H> {
    config: WorkerConfig,
    poll: Poll,
    handler: H,
    udp: Option<UdpSocket>,
    listener: Option<TcpListener>,
    conns: ConnMgr,
    wake: Arc<StopRequest>,
    stats: WorkerStats,
}

impl<H> Worker<H>
where
    H: BindingHandler + crate::ReplyQueue,
{
    /// Build a worker with no sockets attached. The returned wake handle is
    /// the only way another thread can end the loop.
    pub fn new(config: WorkerConfig, handler: H) -> Result<(Self, WorkerWake), std::io::Error> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), Token(EVENT_WAKE as usize))?);
        let wake = Arc::new(StopRequest {
            pending: AtomicBool::new(false),
            waker,
        });
        let handle = Arc::clone(&wake);
        Ok((
            Worker {
                config,
                poll,
                handler,
                udp: None,
                listener: None,
                conns: ConnMgr::new(),
                wake,
                stats: WorkerStats::default(),
            },
            WorkerWake { handle },
        ))
    }

    /// Attach the UDP datagram socket, bound and drained into `BindingHandler`.
    pub fn new_udp(&mut self, addr: SocketAddr, rcvbuf: usize) -> Result<(), std::io::Error> {
        let mut sock = bind_udp(addr, rcvbuf)?;
        self.poll.registry().register(&mut sock, Token(EVENT_UDP as usize), Interest::READABLE)?;
        self.udp = Some(sock);
        Ok(())
    }

    /// Attach the TCP control listener.
    pub fn new_tcp(&mut self, addr: SocketAddr) -> Result<(), std::io::Error> {
        let mut listener = bind_tcp(addr)?;
        self.poll
            .registry()
            .register(&mut listener, Token(EVENT_TCP_LISTEN as usize), Interest::READABLE)?;
        self.listener = Some(listener);
        Ok(())
    }

    /// The UDP socket's bound address, when attached.
    pub fn udp_local_addr(&self) -> Option<SocketAddr> {
        self.udp.as_ref().and_then(|s| s.local_addr().ok())
    }

    /// The address the listener is bound to. A reply on a control connection
    /// leaves from this address, not from the UDP sender's, so a handler must
    /// learn it from here.
    pub fn listener_identity(&self) -> Option<SocketAddr> {
        self.listener
            .as_ref()
            .and_then(|listener| listener.local_addr().ok())
    }

    /// The listener's bound address, when attached.
    pub fn listener_local_addr(&self) -> Option<SocketAddr> {
        self.listener.as_ref().and_then(|s| s.local_addr().ok())
    }

    /// The handler, so the control plane can attach a reply sender once the
    /// sockets are bound.
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    /// How many control connections are open.
    pub fn live_conns(&self) -> usize {
        self.conns.live()
    }

    /// Whether the control plane has asked this worker to stop.
    fn stop_requested(&self) -> bool {
        self.wake.pending.load(Ordering::Relaxed)
    }

    /// The soonest time a connection will be reclaimed.
    fn next_deadline(&mut self) -> Option<Instant> {
        let mut soonest: Option<Instant> = None;
        self.conns.for_each(|_id, c| {
            if let Some(d) = c.deadline(self.config.conn_idle_timeout) {
                soonest = Some(match soonest {
                    Some(s) => s.min(d),
                    None => d,
                });
            }
        });
        soonest
    }

    /// The poll deadline: the sooner of the next expiry and the tick budget.
    fn poll_deadline(&mut self) -> Duration {
        let now = Instant::now();
        match self.next_deadline() {
            Some(d) => d.saturating_duration_since(now).min(self.config.poll_timeout),
            None => self.config.poll_timeout,
        }
    }

    /// Reclaim every connection past its deadline. Runs before each poll, so
    /// the poll deadline can never overshoot an expiry.
    fn reclaim(&mut self) {
        let now = Instant::now();
        let mut doomed = Vec::new();
        self.conns.for_each(|id, c| {
            if let Some(d) = c.deadline(self.config.conn_idle_timeout) {
                if d <= now {
                    doomed.push((
                        id,
                        if c.ever_received() {
                            DropReason::Idle
                        } else {
                            DropReason::HalfOpen
                        },
                    ));
                }
            }
        });
        for (id, reason) in doomed {
            self.drop(id, reason);
        }
    }

    /// Cut a connection and tell the handler why.
    pub fn drop(&mut self, id: ConnectionId, _reason: DropReason) {
        let Some(mut conn) = self.conns.remove(id) else {
            return;
        };
        deregister_id(&self.poll, &mut conn);
        let _ = conn.stream.shutdown(Shutdown::Both);
        self.stats.dropped += 1;
        self.handler.on_tcp_error(id);
    }

    /// Drain the UDP socket until it would block.
    fn drain_udp(&mut self) {
        let Some(sock) = self.udp.as_mut() else {
            return;
        };
        let mut buf = [0u8; MAX_UDP_DATAGRAM];
        for _ in 0..UDP_DRAIN_BATCH {
            match sock.recv_from(&mut buf) {
                Ok((n, addr)) if n > 0 => {
                    self.stats.udp_packets += 1;
                    // The handler decodes the address itself; the transport
                    // passes raw octets so it stays address-family blind.
                    // Layout: the address octets, then the port big-endian.
                    // That keeps this encoding identical to a `sockaddr` tail
                    // and gives the handler everything it needs to send a
                    // reply back, which is the whole point of the field.
                    let mut raw = [0u8; 18];
                    let src = match addr.ip() {
                        std::net::IpAddr::V4(v) => {
                            let o = v.octets();
                            raw[..4].copy_from_slice(&o);
                            raw[4..6].copy_from_slice(&addr.port().to_be_bytes());
                            &raw[..6]
                        }
                        std::net::IpAddr::V6(v) => {
                            raw[..16].copy_from_slice(&v.octets());
                            raw[16..].copy_from_slice(&addr.port().to_be_bytes());
                            &raw[..18]
                        }
                    };
                    self.handler.on_stun(&buf[..n], n, src);
                }
                Ok(_) => continue,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    let _ = e;
                    break;
                }
            }
        }
    }

    /// Accept until the listener would block.
    fn drain_accepts(&mut self) {
        let Some(listener) = self.listener.as_ref() else {
            return;
        };
        let Ok(Some(batch)) = accept_all(listener, ACCEPT_BATCH) else {
            return;
        };
        for (stream, peer) in batch {
            let Some(id) = self.conns.alloc() else {
                let _ = stream.shutdown(Shutdown::Both);
                continue;
            };
            let mut conn = Conn::new(stream, peer);
            conn.stream.set_nodelay(true).ok();
            conn.half_open_deadline = Some(Instant::now() + self.config.half_open_timeout);
            if register_id(&self.poll, id, &mut conn).is_err() {
                let _ = conn.stream.shutdown(Shutdown::Both);
                self.conns.remove(id);
                continue;
            }
            self.conns.insert(id, conn);
            self.stats.accepts += 1;
            self.handler.on_tcp_connect(id);
        }
    }

    /// Read one connection's bytes, then decode whatever the read produced.
    fn drain_read(&mut self, id: ConnectionId) {
        {
            let Some(conn) = self.conns.get(id) else {
                return;
            };
            let mut chunk = [0u8; READ_WINDOW];
            match crate::connmgr::try_read(&mut conn.stream, &mut chunk) {
                Ok(None) => return,
                Err(e) => {
                    let reason = if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        DropReason::Eof
                    } else {
                        DropReason::Io
                    };
                    let _ = conn;
                    self.drop(id, reason);
                    return;
                }
                Ok(Some(n)) => {
                    // The window holds one frame plus slack, so a read that
                    // overflows it is refused: the peer would see its data
                    // dropped, which is worse than one more round trip.
                    let take = n.min(conn.read_buf.len() - conn.read_len);
                    let tail = &mut conn.read_buf[conn.read_len..];
                    tail[..take].copy_from_slice(&chunk[..take]);
                    conn.read_len += take;
                    conn.note_active();
                    conn.mark_received();
                }
            }
        }
        self.decode(id);
    }

    /// Decode buffered bytes into packets for the handler.
    ///
    /// Frames are bounded, so they are copied into a small vector before the
    /// handler sees them: that keeps the connection's read window borrowed for
    /// as short a stretch as possible. The transport still parses nothing — it
    /// only counts frames (workspace-layout §2.3).
    fn decode(&mut self, id: ConnectionId) {
        let mut frames = Vec::new();
        {
            let Some(conn) = self.conns.get(id) else {
                return;
            };
            let n = conn.read_len.min(conn.read_buf.len());
            let outcome = crate::framing::decode_with(&conn.read_buf[..n], false, |payload, _need| {
                if frames.len() < DECODE_BATCH {
                    frames.push(payload.to_vec());
                }
                Ok(())
            });
            if outcome.consumed > 0 {
                conn.set_readable(outcome.consumed);
                conn.compact_read();
            }
        }
        for payload in frames {
            self.stats.tcp_packets += 1;
            if self.conns.get(id).is_none() {
                break;
            }
            self.handler.on_tcp_stun(&payload, payload.len(), id);
        }
    }

    /// Write back the replies a handler queued during this tick.
    ///
    /// The handler cannot write itself: the frozen [`BindingHandler`] has no
    /// send callback, and writing here would pin the connection's read borrow
    /// across the callback. Queuing keeps the replies safe until this call,
    /// which is the next thing the loop does. A reply that no longer fits is
    /// dropped rather than held against a half-used buffer -- dropping one
    /// reply is harmless, a partial frame would not be.
    fn drain_replies(&mut self) {
        while let Some(reply) = self.handler.take_reply() {
            let Some(conn) = self.conns.get(reply.id) else {
                // The connection went away between the reply and now.
                continue;
            };
            if conn.can_write(reply.payload.len()) {
                conn.take_write(&reply.payload);
                let _ = modify_id(&self.poll, reply.id, conn);
            } else {
                // The write buffer is still holding the previous reply. Put
                // this one back so it is not lost: `take_reply` is
                // destructive, and a dropped reply means a peer that
                // retransmits forever. The buffer arms the writable edge, so
                // the next tick empties it and this reply follows it out.
                self.handler.queue_reply(reply);
                break;
            }
        }
    }

    /// Write whatever the connection is holding, or re-arm for the writable edge.
    fn drain_write(&mut self, id: ConnectionId) {
        let Some(conn) = self.conns.get(id) else {
            return;
        };
        if !conn.has_write() {
            conn.pending_write = false;
            let _ = modify_id(&self.poll, id, conn);
            return;
        }
        let remaining = conn.write_len;
        match crate::connmgr::try_write(&mut conn.stream, &conn.write_buf[..remaining]) {
            Ok(None) => {
                conn.pending_write = true;
                let _ = modify_id(&self.poll, id, conn);
            }
            Ok(Some(w)) => {
                conn.advance_write(w);
                conn.note_active();
                conn.pending_write = conn.has_write();
                let _ = modify_id(&self.poll, id, conn);
            }
            Err(_) => {
                let _ = conn;
                self.drop(id, DropReason::Io);
            }
        }
    }

    /// The loop. Returns when a wake arrives, the tick budget is spent, or the
    /// poll itself fails.
    pub fn run(mut self, events: &mut Events) -> WorkerStats {
        loop {
            // A wake can lose the race with the selector, so the flag is the
            // authority and the wake is only the fast path.
            if self.stop_requested() {
                break;
            }
            self.reclaim();
            let deadline = self.poll_deadline();
            if self.poll.poll(events, Some(deadline)).is_err() {
                break;
            }
            if self.stop_requested() {
                break;
            }
            if events.is_empty() {
                self.stats.ticks += 1;
                if matches!(self.config.max_ticks, Some(n) if self.stats.ticks >= n) {
                    break;
                }
                continue;
            }
            let mut woken = false;
            let mut ready = Vec::new();
            for e in events.iter() {
                match e.token() {
                    Token(val) if val == EVENT_WAKE as usize => {
                        // The fast path. Nothing to consume: the flag is what
                        // says stop, and it is re-checked below.
                        woken = true;
                    }
                    Token(val) if val == EVENT_UDP as usize => self.drain_udp(),
                    Token(val) if val == EVENT_TCP_LISTEN as usize => self.drain_accepts(),
                    other => {
                        if let Some(id) = crate::connmgr::token_conn(other) {
                            if e.is_error() || e.is_read_closed() || e.is_write_closed() {
                                self.drop(id, DropReason::Io);
                            } else {
                                ready.push((id, e.is_readable(), e.is_writable()));
                            }
                        }
                    }
                }
            }
            if woken {
                break;
            }
            for (id, readable, writable) in ready {
                if !self.conns.get(id).is_some() {
                    continue;
                }
                if readable {
                    self.drain_read(id);
                }
                if writable && self.conns.get(id).is_some() {
                    self.drain_write(id);
                }
            }
            self.drain_replies();
            self.stats.ticks += 1;
            if matches!(self.config.max_ticks, Some(n) if self.stats.ticks >= n) {
                break;
            }
        }
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Records what a handler was told, so the loop can be asserted on.
    #[derive(Default)]
    struct Rec {
        udp: Vec<usize>,
        /// The bytes each datagram arrived with.
        udp_payload: Vec<Vec<u8>>,
        /// The raw peer address each datagram arrived with.
        udp_src: Vec<Vec<u8>>,
        connects: Vec<u64>,
        stuns: Vec<(usize, u64)>,
        errors: Vec<u64>,
    }

    // No outbox: the loop's `take_reply` default keeps this double honest.
    impl crate::ReplyQueue for Rec {}

    impl BindingHandler for Rec {
        fn on_stun(&mut self, buf: &[u8], len: usize, src_addr: &[u8]) {
            self.udp.push(len);
            self.udp_payload.push(buf[..len].to_vec());
            self.udp_src.push(src_addr.to_vec());
        }
        fn on_tcp_connect(&mut self, id: ConnectionId) {
            self.connects.push(id.0);
        }
        fn on_tcp_stun(&mut self, _buf: &[u8], len: usize, id: ConnectionId) {
            self.stuns.push((len, id.0));
        }
        fn on_tcp_error(&mut self, id: ConnectionId) {
            self.errors.push(id.0);
        }
    }

    #[test]
    fn wake_ends_the_loop() {
        let config = WorkerConfig {
            max_ticks: None,
            poll_timeout: Duration::from_millis(20),
            ..WorkerConfig::default()
        };
        let (w, wake) = Worker::new(config, Rec::default()).unwrap();
        wake.wake();
        let before = Instant::now();
        let stats = w.run(&mut Events::with_capacity(EVENT_CAPACITY));
        // The byte ends the loop on the very first round: no tick is counted,
        // and no poll timeout is waited for.
        assert_eq!(stats.ticks, 0);
        assert!(before.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn max_ticks_stops_the_loop() {
        let config = WorkerConfig {
            max_ticks: Some(3),
            poll_timeout: Duration::from_millis(1),
            ..WorkerConfig::default()
        };
        let (w, _wake) = Worker::new(config, Rec::default()).unwrap();
        let stats = w.run(&mut Events::with_capacity(EVENT_CAPACITY));
        assert_eq!(stats.ticks, 3);
    }

    /// A handler whose records outlive the worker that consumed them.
    ///
    /// `run` takes the worker by value, so a test that inspects the records
    /// afterwards hands the worker and the test clones of the same recorder.
    #[derive(Default)]
    struct SharedRecorder(Arc<Mutex<Rec>>);

    impl SharedRecorder {
        fn new(rec: Arc<Mutex<Rec>>) -> Self {
            SharedRecorder(rec)
        }
    }

    impl crate::ReplyQueue for SharedRecorder {}

    impl BindingHandler for SharedRecorder {
        fn on_stun(&mut self, buf: &[u8], len: usize, src_addr: &[u8]) {
            let mut rec = self.0.lock().unwrap();
            rec.udp.push(len);
            rec.udp_payload.push(buf[..len].to_vec());
            rec.udp_src.push(src_addr.to_vec());
        }
        fn on_tcp_connect(&mut self, id: ConnectionId) {
            self.0.lock().unwrap().connects.push(id.0);
        }
        fn on_tcp_stun(&mut self, _buf: &[u8], len: usize, id: ConnectionId) {
            self.0.lock().unwrap().stuns.push((len, id.0));
        }
        fn on_tcp_error(&mut self, id: ConnectionId) {
            self.0.lock().unwrap().errors.push(id.0);
        }
    }

    #[test]
    fn udp_datagram_reaches_the_handler() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = WorkerConfig {
            max_ticks: Some(20),
            poll_timeout: Duration::from_millis(5),
            udp_rcvbuf: 0,
            ..WorkerConfig::default()
        };
        let rec = Arc::new(Mutex::new(Rec::default()));
        let (mut w, _wake) =
            Worker::new(config.clone(), SharedRecorder::new(rec.clone())).unwrap();
        w.new_udp(addr, 0).unwrap();
        let bound = w.udp_local_addr().unwrap();

        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"stun", bound).unwrap();

        let stats = w.run(&mut Events::with_capacity(EVENT_CAPACITY));
        assert_eq!(stats.udp_packets, 1);
        // The datagram and the peer address reach the handler intact: the
        // payload is the raw octets, and the address is the peer octets plus
        // the port big-endian (6 octets for an IPv4 peer).
        let from = sender.local_addr().unwrap();
        let rec = rec.lock().unwrap();
        assert_eq!(rec.udp, vec![4]);
        assert_eq!(rec.udp_payload, vec![b"stun".to_vec()]);
        assert_eq!(rec.udp_src.len(), 1);
        assert_eq!(rec.udp_src[0].len(), 6);
        match from.ip() {
            std::net::IpAddr::V4(v4) => assert_eq!(rec.udp_src[0][..4], v4.octets()),
            other => panic!("loopback peer is not IPv4: {other}"),
        }
        assert_eq!(&rec.udp_src[0][4..], from.port().to_be_bytes());
    }

    /// A handler that queues one reply per control-connection packet.
    #[derive(Default)]
    struct Replier {
        queued: Vec<Vec<u8>>,
        delivered: usize,
        packets: usize,
    }

    impl crate::ReplyQueue for Replier {
        fn take_reply(&mut self) -> Option<crate::QueuedReply> {
            if self.queued.is_empty() {
                return None;
            }
            self.delivered += 1;
            Some(crate::QueuedReply {
                id: ConnectionId(0),
                payload: self.queued.remove(0),
            })
        }
    }

    impl BindingHandler for Replier {
        fn on_stun(&mut self, _buf: &[u8], _len: usize, _src_addr: &[u8]) {}
        fn on_tcp_connect(&mut self, _id: ConnectionId) {}
        fn on_tcp_stun(&mut self, _buf: &[u8], _len: usize, id: ConnectionId) {
            self.packets += 1;
            if self.packets == 1 {
                // Queued for the connection the packet came in on; the loop
                // writes it back on the same tick.
                self.queued.push(vec![id.0 as u8, 0xAA, 0xBB, 0xCC]);
            }
        }
        fn on_tcp_error(&mut self, _id: ConnectionId) {}
    }

    #[test]
    fn a_queued_reply_is_framed_back_onto_the_connection() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = WorkerConfig {
            max_ticks: Some(30),
            poll_timeout: Duration::from_millis(5),
            half_open_timeout: Duration::from_secs(300),
            ..WorkerConfig::default()
        };
        let (mut w, _wake) = Worker::new(config.clone(), Replier::default()).unwrap();
        w.new_tcp(addr).unwrap();
        let bound = w.listener_local_addr().unwrap();

        let mut peer = std::net::TcpStream::connect(bound).unwrap();
        let mut req = Vec::new();
        req.extend_from_slice(&u16::to_be_bytes(4));
        req.extend_from_slice(b"abcd");
        peer.write_all(&req).unwrap();

        let stats = w.run(&mut Events::with_capacity(EVENT_CAPACITY));
        assert!(stats.tcp_packets >= 1);

        // The reply is one framed datagram: the 16-bit big-endian length, then
        // the bytes the handler queued. Read the frame length first, then take
        // exactly that many payload octets.
        let mut head = [0u8; 2];
        let mut got = 0usize;
        for _ in 0..1024 {
            if got >= 2 {
                break;
            }
            if let Ok(n) = peer.read(&mut head[got..]) {
                got += n;
            } else {
                break;
            }
        }
        assert_eq!(got, 2);
        let len = u16::from_be_bytes(head) as usize;
        assert!(len >= 1, "the reply must carry the queued payload");

        let mut body = vec![0u8; len];
        let mut got = 0usize;
        for _ in 0..1024 {
            if got >= len {
                break;
            }
            if let Ok(n) = peer.read(&mut body[got..]) {
                got += n;
            } else {
                break;
            }
        }
        assert_eq!(got, len, "the framed payload did not arrive in full");
        assert_eq!(&body[..4], &[0, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn a_framed_packet_on_tcp_reaches_the_handler() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = WorkerConfig {
            max_ticks: Some(30),
            poll_timeout: Duration::from_millis(5),
            half_open_timeout: Duration::from_secs(300),
            ..WorkerConfig::default()
        };
        let (mut w, _wake) = Worker::new(config.clone(), Rec::default()).unwrap();
        w.new_tcp(addr).unwrap();
        let bound = w.listener_local_addr().unwrap();

        // The peer: two frames in one write, to prove a partial header is held
        // back and the second frame is still decoded from the same read.
        let mut peer = std::net::TcpStream::connect(bound).unwrap();
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x0004u16.to_be_bytes());
        raw.extend_from_slice(b"abcd");
        raw.extend_from_slice(&u16::to_be_bytes(3));
        raw.extend_from_slice(b"xyz");
        peer.write_all(&raw).unwrap();

        let stats = w.run(&mut Events::with_capacity(EVENT_CAPACITY));
        assert!(stats.accepts >= 1);
        assert!(stats.tcp_packets >= 2);
    }

    #[test]
    fn a_half_open_connection_is_reclaimed() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = WorkerConfig {
            max_ticks: Some(200),
            poll_timeout: Duration::from_millis(1),
            half_open_timeout: Duration::from_millis(2),
            ..WorkerConfig::default()
        };
        let (mut w, _wake) = Worker::new(config, Rec::default()).unwrap();
        w.new_tcp(addr).unwrap();
        let bound = w.listener_local_addr().unwrap();

        // Connect and stay silent: the half-open deadline must fire.
        let _peer = std::net::TcpStream::connect(bound).unwrap();

        let stats = w.run(&mut Events::with_capacity(EVENT_CAPACITY));
        assert!(stats.accepts >= 1);
        assert!(stats.dropped >= 1);
    }
}
