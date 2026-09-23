//! Socket lifecycle, token management and per-connection buffers for one worker.
//!
//! A worker owns its sockets outright: there is no shared mutable state, no
//! channel and no spawn (architecture.md §2.3 — `SO_REUSEPORT` already pins
//! each five-tuple to exactly one worker, so no routing is needed). This module
//! is the map between the `mio::Token` the poller hands back and the
//! [`ConnectionId`] the rest of the crate uses.
//!
//! Token space: the fixed sources take the low tokens
//! ([`EVENT_UDP`], [`EVENT_WAKE`], [`EVENT_TCP_LISTEN`]); TCP connections take
//! [`EVENT_TCP_BASE`] and up. The two halves are far apart enough that no
//! connection can ever be confused with a listener.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mio::net::{TcpListener as MioTcpListener, TcpStream as MioTcpStream};
use mio::{Interest, Poll, Token};
use socket2::{SockAddr, Socket};

use crate::{ConnectionId, MAX_FRAME_PAYLOAD, MAX_UDP_DATAGRAM};

/// Token for the UDP datagram socket.
pub const EVENT_UDP: u64 = 0;
/// Token for the wake socket used to stop the event loop.
pub const EVENT_WAKE: u64 = 1;
/// Token for the TCP listener.
pub const EVENT_TCP_LISTEN: u64 = 2;
/// Token base for TCP connections: `ConnectionId(n) -> Token(BASE + n)`.
pub const EVENT_TCP_BASE: u64 = 1 << 48;

/// The token used by connection `id` with the poller.
pub const fn conn_token(id: ConnectionId) -> Token {
    Token((EVENT_TCP_BASE + id.0) as usize)
}

/// The connection id behind a token, when the token is a connection token.
pub const fn token_conn(token: Token) -> Option<ConnectionId> {
    if token.0 as u64 >= EVENT_TCP_BASE {
        Some(ConnectionId(token.0 as u64 - EVENT_TCP_BASE))
    } else {
        None
    }
}

/// The largest connection id this token space can express.
pub const fn max_conns() -> u64 {
    u64::MAX - EVENT_TCP_BASE
}

/// Capacity of the per-connection read window: one full `MAX_FRAME_PAYLOAD`
/// packet plus slack, so a complete packet plus the next one's head always fit
/// without an allocation.
pub const FRAME_CAP: usize = MAX_FRAME_PAYLOAD + 64;

/// One accepted TCP control connection and its I/O buffers.
///
/// The buffers live for the whole connection rather than being allocated per
/// packet — that is what keeps per-packet heap traffic low on the read path
/// (workspace-layout §2.3).
pub struct Conn {
    /// The socket, in non-blocking mode.
    pub stream: MioTcpStream,
    /// The peer as seen by the kernel.
    pub peer: Option<SocketAddr>,
    /// Incoming framed bytes.
    pub read_buf: Vec<u8>,
    /// How many bytes of `read_buf` hold a partially decoded frame.
    pub read_len: usize,
    /// The next packet to frame and send.
    pub write_buf: Vec<u8>,
    /// How much of `write_buf` is framed and not yet written to the kernel.
    pub write_len: usize,
    /// Set while there is something left to write; drives the re-arm.
    pub pending_write: bool,
    /// Last time this connection read or wrote anything.
    pub last_active: Instant,
    /// Half-open: the handshake finished but nothing has been received yet.
    pub half_open: bool,
    /// Half-open retransmit deadline: RFC 6062 §2.1 says the TCP shim sends
    /// nothing until the peer is alive, and a peer that never does so must be
    /// cut rather than held.
    pub half_open_deadline: Option<Instant>,
}

impl Conn {
    /// Build a connection around an accepted stream.
    pub fn new(stream: MioTcpStream, peer: Option<SocketAddr>) -> Self {
        Conn::with_capacity(stream, peer, FRAME_CAP)
    }

    /// A connection with the given read window capacity, for tests that want a
    /// deliberately small buffer.
    pub fn with_capacity(stream: MioTcpStream, peer: Option<SocketAddr>, cap: usize) -> Self {
        Conn {
            stream,
            peer,
            read_buf: vec![0u8; cap],
            read_len: 0,
            write_buf: vec![0u8; cap],
            write_len: 0,
            pending_write: false,
            last_active: Instant::now(),
            half_open: true,
            half_open_deadline: None,
        }
    }

    /// Whether the write buffer holds a complete framed packet ready to send.
    pub const fn has_write(&self) -> bool {
        self.write_len > 0
    }

    /// How much of `read_buf` holds a partially decoded frame.
    pub const fn readable(&self) -> usize {
        self.read_len
    }

    /// Whether `read_buf` can still grow by `n` octets.
    pub const fn read_has_room(&self, n: usize) -> bool {
        self.read_len + n <= self.read_buf.len()
    }

    /// The tail of `read_buf`, where the next bytes will be appended.
    pub fn read_tail(&mut self) -> &mut [u8] {
        &mut self.read_buf[self.read_len..]
    }

    /// Record that `n` octets of the read window are now in use.
    pub fn set_readable(&mut self, n: usize) {
        self.read_len = n.min(self.read_buf.len());
    }

    /// Compact: move the leftover tail to the front so the next `read` fills
    /// behind it. Called after each decode pass.
    pub fn compact_read(&mut self) {
        let n = self.read_len;
        if n > 0 {
            self.read_buf.copy_within(n.., 0);
        }
        self.read_len = 0;
    }

    /// Whether the framed form of `payload` fits in the write buffer.
    pub const fn can_write(&self, payload_len: usize) -> bool {
        !self.has_write()
            && crate::framing::frame_wire_size(payload_len) <= self.write_buf.len()
    }

    /// Fill `write_buf` with the framed form of `payload`. Returns whether the
    /// buffer was armed; it refuses a partial frame so a peer can never see a
    /// truncated one.
    pub fn take_write(&mut self, payload: &[u8]) -> bool {
        let need = crate::framing::frame_wire_size(payload.len());
        if self.write_buf.len() < need {
            return false;
        }
        self.write_len = crate::framing::encode(payload, &mut self.write_buf).unwrap_or(0);
        self.pending_write = true;
        true
    }

    /// Drop the write buffer and go back to reading only.
    pub fn clear_write(&mut self) {
        self.write_len = 0;
        self.pending_write = false;
    }

    /// The framed bytes pending a write.
    pub fn write_slice(&self) -> &[u8] {
        &self.write_buf[..self.write_len]
    }

    /// Advance past the first `n` written octets.
    pub fn advance_write(&mut self, n: usize) {
        let n = n.min(self.write_len);
        self.write_buf.copy_within(n.., 0);
        self.write_len -= n;
        if self.write_len == 0 {
            self.pending_write = false;
        }
    }

    /// The bytes left to write.
    pub fn write_remaining(&self) -> &[u8] {
        &self.write_buf[..self.write_len]
    }

    /// A read or write just happened.
    pub fn note_active(&mut self) {
        self.last_active = Instant::now();
    }

    /// Mark the first byte received: the half-open deadline goes away and the
    /// idle timeout takes over from this instant.
    pub fn mark_received(&mut self) {
        self.half_open = false;
        self.half_open_deadline = None;
        self.last_active = Instant::now();
    }

    /// Whether this connection has ever received a byte.
    pub const fn ever_received(&self) -> bool {
        !self.half_open
    }

    /// The next time this connection should be reclaimed. The worker folds the
    /// minimum of these into its poll deadline, so reclaiming never outpaces
    /// expiry.
    pub fn deadline(&self, idle_timeout: Duration) -> Option<Instant> {
        if self.half_open {
            self.half_open_deadline
        } else {
            Some(self.last_active + idle_timeout)
        }
    }
}

/// Owns the connection table and the next free connection id.
pub struct ConnMgr {
    next_id: u64,
    conns: Vec<Option<Conn>>,
}

impl ConnMgr {
    pub fn new() -> Self {
        ConnMgr { next_id: 0, conns: Vec::new() }
    }

    /// Allocate the next connection id. Fails when the token space is exhausted.
    pub fn alloc(&mut self) -> Option<ConnectionId> {
        if self.next_id > max_conns() {
            return None;
        }
        let id = ConnectionId(self.next_id);
        self.next_id += 1;
        self.conns.push(None);
        Some(id)
    }

    /// Insert a live connection under `id`.
    pub fn insert(&mut self, id: ConnectionId, conn: Conn) {
        let slot = self.conns.get_mut(id.0 as usize);
        debug_assert!(slot.is_some(), "id {:?} was not allocated", id);
        if let Some(slot) = slot {
            *slot = Some(conn);
        }
    }

    /// A mutable handle to a live connection.
    pub fn get(&mut self, id: ConnectionId) -> Option<&mut Conn> {
        self.conns.get_mut(id.0 as usize).and_then(Option::as_mut)
    }

    /// Take a connection out of the table. The socket is dropped with it, which
    /// closes it; call [`deregister_id`] first when the token is still armed.
    pub fn remove(&mut self, id: ConnectionId) -> Option<Conn> {
        self.conns.get_mut(id.0 as usize).and_then(|c| c.take())
    }

    /// The number of live connections.
    pub fn live(&self) -> usize {
        self.conns.iter().filter(|c| c.is_some()).count()
    }

    /// Walk every live connection and call `f`.
    pub fn for_each<F>(&mut self, mut f: F)
    where
        F: FnMut(ConnectionId, &mut Conn),
    {
        for i in 0..self.conns.len() {
            if let Some(c) = self.conns.get_mut(i).and_then(Option::as_mut) {
                f(ConnectionId(i as u64), c);
            }
        }
    }
}

impl Default for ConnMgr {
    fn default() -> Self {
        Self::new()
    }
}

/// The interests a connection wants right now.
pub fn conn_interests(c: &Conn) -> Interest {
    let mut i = Interest::READABLE;
    if c.pending_write {
        i = i.add(Interest::WRITABLE);
    }
    i
}

/// Register `conn` with the poller under `id`. Called once at accept time.
pub fn register_id(poll: &Poll, id: ConnectionId, c: &mut Conn) -> std::io::Result<()> {
    let interest = conn_interests(c);
    poll.registry().register(&mut c.stream, conn_token(id), interest)
}

/// Re-register after the write interest changed.
pub fn modify_id(poll: &Poll, id: ConnectionId, c: &mut Conn) -> std::io::Result<()> {
    let interest = conn_interests(c);
    poll.registry().reregister(&mut c.stream, conn_token(id), interest)
}

/// Drop the poll registration. The socket is closed separately.
pub fn deregister_id(poll: &Poll, c: &mut Conn) {
    let _ = poll.registry().deregister(&mut c.stream);
}

/// Read up to `buf.len()` bytes into `buf`. `Ok(None)` means the socket was not
/// ready (would-block), the normal exit path for a non-blocking read.
pub fn try_read(
    stream: &mut MioTcpStream,
    buf: &mut [u8],
) -> Result<Option<usize>, std::io::Error> {
    match stream.read(buf) {
        Ok(0) => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer closed the connection",
        )),
        Ok(n) => Ok(Some(n)),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write as much of `buf` as the kernel will take.
pub fn try_write(stream: &mut MioTcpStream, buf: &[u8]) -> Result<Option<usize>, std::io::Error> {
    match stream.write(buf) {
        Ok(n) => Ok(Some(n)),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Set `SO_REUSEPORT` on `sock` the way the platform wants it.
///
/// `socket2` only exposes `set_reuse_port` on Unix; Windows 10 1709+ supports
/// the option natively but `socket2` does not surface it. Rather than add a
/// `windows-sys` dependency for one constant, the option is skipped there —
/// which is correct, because on Windows a single worker is enough and `SO_REUSEADDR`
/// already lets one socket hold the address (architecture.md §2.2).
#[cfg(unix)]
fn set_reuse_port(sock: &Socket) -> std::io::Result<()> {
    sock.set_reuse_port(true)
}

/// No-op outside Unix; see [`set_reuse_port`].
#[cfg(not(unix))]
fn set_reuse_port(_sock: &Socket) -> std::io::Result<()> {
    Ok(())
}

/// Create one UDP socket, bound and ready to be handed to `mio`.
///
/// `SO_REUSEPORT` is what makes every worker's socket land on the same
/// address:port, with the kernel doing the four-tuple dispatch
/// (architecture.md §2.2). It is set before `bind`, because on Linux the
/// option only takes effect at bind time.
pub fn bind_udp(addr: SocketAddr, rcvbuf: usize) -> std::io::Result<mio::net::UdpSocket> {
    let sock = Socket::new(socket2::Domain::for_address(addr), socket2::Type::DGRAM, None)?;
    sock.set_reuse_address(true)?;
    set_reuse_port(&sock)?;
    if rcvbuf > 0 {
        // Bumping the buffer can be refused by the system limit; the worker
        // must still come up, so the failure is recorded and not fatal.
        let _ = sock.set_recv_buffer_size(rcvbuf);
    }
    sock.bind(&SockAddr::from(addr))?;
    sock.set_nonblocking(true)?;
    Ok(mio::net::UdpSocket::from_std(sock.into()))
}

/// Create one TCP listener socket, bound and ready to be handed to `mio`.
pub fn bind_tcp(addr: SocketAddr) -> std::io::Result<MioTcpListener> {
    let sock = Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        None,
    )?;
    sock.set_reuse_address(true)?;
    set_reuse_port(&sock)?;
    sock.bind(&SockAddr::from(addr))?;
    sock.listen(1024)?;
    sock.set_nonblocking(true)?;
    Ok(MioTcpListener::from_std(sock.into()))
}

/// Create a pair of connected sockets for the wake channel.
///
/// The wake channel is the one way another thread ends a worker's loop. A
/// `mio::Waker` needs a shared `Arc` around a single active waker; a connected
/// socket pair has the same effect for one control byte and keeps the worker
/// single-threaded. On Unix it is `socketpair(AF_UNIX, SOCK_STREAM)`; on
/// Windows `socketpair` does not exist, so a loopback pair is used instead.
pub fn wake_pair() -> std::io::Result<(MioTcpStream, MioTcpStream)> {
    #[cfg(unix)]
    {
        let a = Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
        a.set_nonblocking(true)?;
        a.set_nodelay(true)?;
        let b = a.try_clone()?;
        b.set_nonblocking(true)?;
        b.set_nodelay(true)?;
        Ok((MioTcpStream::from_std(a.into()), MioTcpStream::from_std(b.into())))
    }
    #[cfg(windows)]
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let a = TcpStream::connect(addr)?;
        a.set_nodelay(true)?;
        a.set_nonblocking(true)?;
        let (b, _) = listener.accept()?;
        b.set_nodelay(true)?;
        b.set_nonblocking(true)?;
        Ok((MioTcpStream::from_std(a), MioTcpStream::from_std(b)))
    }
}

/// One accepted control connection: the stream and the peer it claims.
pub type Accepted = (MioTcpStream, Option<SocketAddr>);

/// Accept pending connections, up to `max` of them. `Ok(None)` means no more
/// are ready right now (would-block), the normal exit path.
pub fn accept_all(listener: &MioTcpListener, max: usize) -> Result<Option<Vec<Accepted>>, std::io::Error> {
    let mut out = Vec::new();
    for _ in 0..max {
        match listener.accept() {
            Ok((stream, addr)) => out.push((stream, Some(addr))),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(Some(out)),
            Err(e) => return Err(e),
        }
    }
    Ok(Some(out))
}

/// Close a stream without blocking the worker. The socket is non-blocking so
/// `shutdown` returns immediately; dropping the handle frees the fd.
pub fn close_stream(stream: MioTcpStream) {
    let _ = stream.shutdown(Shutdown::Both);
}

/// The maximum payload size a worker will accept on a framed connection.
pub const UDP_MAX: usize = MAX_UDP_DATAGRAM;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_token_and_back() {
        let id = ConnectionId(0);
        let t = conn_token(id);
        assert_eq!(t.0, EVENT_TCP_BASE as usize);
        assert_eq!(token_conn(t), Some(id));

        let id = ConnectionId(1 << 40);
        assert_eq!(token_conn(conn_token(id)), Some(id));
    }

    #[test]
    fn fixed_tokens_are_not_connection_tokens() {
        assert!(token_conn(Token(EVENT_UDP as usize)).is_none());
        assert!(token_conn(Token(EVENT_WAKE as usize)).is_none());
        assert!(token_conn(Token(EVENT_TCP_LISTEN as usize)).is_none());
        assert!(token_conn(Token(EVENT_TCP_BASE as usize - 1)).is_none());
    }

    #[test]
    fn connmgr_allocates_inserts_and_removes() {
        let mut m = ConnMgr::new();
        let a = m.alloc().unwrap();
        let b = m.alloc().unwrap();
        assert!(a.0 < b.0);
        assert_eq!(m.live(), 0);

        let (sa, sb) = wake_pair().unwrap();
        m.insert(a, Conn::new(sa, None));
        let (sc, _sd) = wake_pair().unwrap();
        m.insert(b, Conn::new(sc, None));
        assert_eq!(m.live(), 2);
        assert!(m.get(a).is_some());

        m.remove(a);
        m.remove(b);
        assert_eq!(m.live(), 0);
        let _ = sb;
    }

    #[test]
    fn conn_take_write_sets_pending() {
        let (stream, _peer) = wake_pair().unwrap();
        let mut c = Conn::new(stream, None);
        assert!(!c.has_write());
        assert!(c.take_write(&[1, 2, 3]));
        assert!(c.has_write());
        assert!(c.pending_write);
        assert_eq!(c.write_len, 5);
        assert_eq!(c.write_slice(), &[0x00, 0x03, 0x01, 0x02, 0x03]);
        c.clear_write();
        assert!(!c.has_write());
        assert!(!c.pending_write);
    }

    #[test]
    fn conn_refuses_an_overlarge_write() {
        let (stream, _peer) = wake_pair().unwrap();
        let mut c = Conn::with_capacity(stream, None, 10);
        let payload = vec![0u8; 64];
        assert!(!c.can_write(payload.len()));
        assert!(!c.take_write(&payload));
        assert!(!c.has_write(), "must not arm a partial write");
    }

    #[test]
    fn conn_advance_write_drains() {
        let (stream, _peer) = wake_pair().unwrap();
        let mut c = Conn::new(stream, None);
        c.take_write(&[1, 2, 3, 4]);
        assert_eq!(c.write_len, 6);
        c.advance_write(4);
        assert_eq!(c.write_len, 2);
        assert!(c.pending_write, "still has bytes left");
        c.advance_write(2);
        assert!(!c.has_write());
        assert!(!c.pending_write);
    }

    #[test]
    fn conn_read_tail_then_compact() {
        let (stream, _peer) = wake_pair().unwrap();
        let mut c = Conn::new(stream, None);
        assert!(c.read_has_room(FRAME_CAP));
        c.set_readable(500);
        assert_eq!(c.readable(), 500);
        c.compact_read();
        assert_eq!(c.readable(), 0);
        assert!(c.read_has_room(FRAME_CAP), "capacity restored");
    }

    #[test]
    fn conn_reads_do_not_overlap_the_frame() {
        let (mut a, b) = wake_pair().unwrap();
        let mut c = Conn::new(b, None);
        a.write_all(&[0u8; 128]).unwrap();
        let mut chunk = [0u8; 128];
        let mut n = 0;
        for _ in 0..1024 {
            if let Some(k) = try_read(&mut c.stream, &mut chunk[..128 - n]).unwrap() {
                n += k;
            }
            if n == 128 {
                break;
            }
        }
        assert_eq!(n, 128);
        c.set_readable(n);
        c.note_active();
        c.mark_received();
        assert!(!c.half_open);
        assert!(c.readable() == 128);
    }

    #[test]
    fn conn_deadline_follows_the_half_open_state() {
        let (stream, _peer) = wake_pair().unwrap();
        let mut c = Conn::new(stream, None);
        let before = Instant::now();
        c.half_open_deadline = Some(before + Duration::from_secs(5));
        assert_eq!(c.deadline(Duration::from_secs(300)).unwrap(), before + Duration::from_secs(5));
        c.mark_received();
        let d = c.deadline(Duration::from_secs(300)).unwrap();
        assert!(d > before);
        assert!(d <= before + Duration::from_secs(301));
    }

    #[test]
    fn conn_interests_match_pending_write() {
        let (stream, _peer) = wake_pair().unwrap();
        let mut c = Conn::new(stream, None);
        let i = conn_interests(&c);
        assert!(i.is_readable());
        assert!(!i.is_writable());
        c.take_write(&[1]);
        let i = conn_interests(&c);
        assert!(i.is_readable());
        assert!(i.is_writable());
    }

    #[test]
    fn max_conns_matches_the_token_space() {
        assert_eq!(max_conns(), u64::MAX - EVENT_TCP_BASE);
        assert!(max_conns() > 1 << 40);
    }

    #[test]
    fn udp_max_covers_a_full_datagram() {
        assert_eq!(UDP_MAX, MAX_UDP_DATAGRAM);
        // Compile-time: a full datagram plus its length prefix fits the frame.
        const { assert!(UDP_MAX + 2 <= FRAME_CAP); }
    }
}
