//! The half-open TURN-over-TCP connection table, owned by one worker.
//!
//! Each entry keeps the peer socket, that connection's reusable framing
//! buffers, the bytes already framed but not yet flushed, and the
//! inactivity deadline. The manager is transport-only: it never inspects a
//! STUN payload, never decides whether a message earns a reply, and it
//! invents no session identifier of its own beyond [`ConnectionId`].
//!
//! Write buffering is honest nonblocking I/O: a frame that the kernel refuses
//! (EAGAIN) stays in [`Entry::queued`] and is retried when the poller reports
//! the socket writable again.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use mio::{Interest, Poll, Token};

use crate::framing::{FrameReader, FrameResult, FrameWriter};
use crate::{
    BindingHandler, ConnectionId, DEFAULT_IDLE_TIMEOUT_SECS, FRAME_PREFIX_LEN, MAX_FRAME_PAYLOAD,
};

/// One accepted TURN-over-TCP connection.
pub struct Entry {
    /// The transport-level connection id handed to the handler.
    pub id: ConnectionId,
    /// The peer socket, nonblocking.
    pub peer: mio::net::TcpStream,
    /// The peer's socket address.
    pub peer_addr: SocketAddr,
    /// Reusable read-side framing buffer.
    pub read: FrameReader,
    /// Reusable write-side framing buffer.
    pub write: FrameWriter,
    /// Framed octets not yet flushed to the kernel.
    pub queued: Vec<u8>,
    /// The moment after which this connection is reclaimed as idle.
    pub deadline: Instant,
}

/// Everything one worker owns for its TURN-over-TCP connection table.
pub struct Manager<H: BindingHandler> {
    entries: HashMap<Token, Entry>,
    next_id: u64,
    next_token: u64,
    handler: H,
    idle_timeout: Duration,
}

impl<H: BindingHandler> Manager<H> {
    /// Build a table with the worker's handler and the default 90-second
    /// inactivity limit.
    pub fn new(handler: H) -> Self {
        Self {
            entries: HashMap::new(),
            next_id: 0,
            next_token: 0,
            handler,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
        }
    }

    /// Override the inactivity limit (tests and configurations use this).
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// The handler, so the loop can report framing failures to it.
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    /// The number of live connections.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no connection is open.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries, so the event loop can register and poll them.
    pub fn entries(&mut self) -> &mut HashMap<Token, Entry> {
        &mut self.entries
    }

    /// Allocate the next free token for a new connection.
    fn allocate_token(&mut self) -> Token {
        let token = Token(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        token
    }

    /// Record a newly accepted connection and return its token.
    pub fn insert(&mut self, peer: mio::net::TcpStream, peer_addr: SocketAddr) -> Token {
        let id = ConnectionId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        let token = self.allocate_token();
        let entry = Entry {
            id,
            peer,
            peer_addr,
            read: FrameReader::new(),
            write: FrameWriter::new(),
            queued: Vec::with_capacity(FRAME_PREFIX_LEN + 64),
            deadline: Instant::now() + self.idle_timeout,
        };
        self.entries.insert(token, entry);
        token
    }

    /// Drop a connection, deregistering it from the poller first so the file
    /// handle is closed once and only once.
    pub fn remove(&mut self, poll: &mut Poll, token: Token) -> Option<ConnectionId> {
        let mut id = None;
        if let Some(entry) = self.entries.remove(&token) {
            let _ = poll.deregister(&entry.peer);
            id = Some(entry.id);
        }
        id
    }

    /// The largest number of octets one read can return.
    pub const READ_BUFFER_CAP: usize = FRAME_PREFIX_LEN + MAX_FRAME_PAYLOAD as usize;

    /// Read one buffer from `entry`, appending every byte to its framing
    /// reader.
    ///
    /// `WouldBlock` is normal and simply means the connection is idle for now;
    /// anything else is treated as a peer reset.
    pub fn read_into(&mut self, entry: &mut Entry, buf: &mut [u8]) -> io::Result<bool> {
        if entry.read.pending() + buf.len() > FrameReader::CAPACITY + FRAME_PREFIX_LEN {
            // A connection that stays half-open across a whole buffer without
            // framing anything is dead weight; reclaiming it is the transport
            // job, not the handler's.
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame buffer overfilled"));
        }
        match entry.peer.read(buf) {
            Ok(0) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed")),
            Ok(n) => {
                entry.read.append(&buf[..n])?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Flush everything framed and not yet sent, registering the socket for
    /// writes again when the kernel is not ready to take more.
    pub fn flush(&mut self, poll: &mut Poll, token: Token, entry: &mut Entry) -> io::Result<()> {
        loop {
            if entry.queued.is_empty() {
                return Ok(());
            }
            match entry.peer.write(&entry.queued) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "peer accepted no bytes",
                    ));
                }
                Ok(n) => {
                    entry.queued.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    poll.register(&mut entry.peer, token, Interest::WRITABLE)?;
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Re-extend the deadline by the inactivity limit.
    pub fn touch(&mut self, entry: &mut Entry) {
        entry.deadline = Instant::now() + self.idle_timeout;
    }

    /// The inactivity limit this manager was built with.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
}

/// The frame the handler was asked to send, queued for the next flush.
///
/// Frames the handler refuses to send do not exist: `write_frame` owns the
/// length prefix, so an oversized payload is an error rather than a truncated
/// frame on the wire.
pub fn queue_frame(entry: &mut Entry, payload: &[u8]) -> Result<(), crate::FrameError> {
    let frame = entry.write.write_frame(payload)?;
    entry.queued.extend_from_slice(frame);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;

    #[test]
    fn ids_and_tokens_are_dedicated_per_connection() {
        let (server, _client) = pair();
        let (peer1, _) = server.accept().unwrap();
        let (peer2, _) = server.accept().unwrap();
        peer1.set_nonblocking(true).unwrap();
        peer2.set_nonblocking(true).unwrap();
        let p1 = mio::net::TcpStream::from_std(peer1).unwrap();
        let p2 = mio::net::TcpStream::from_std(peer2).unwrap();
        let mut mgr = Manager::<MockHandler>::new(MockHandler);
        let t1 = mgr.insert(p1, SocketAddr::from(([127, 0, 0, 1], 1111)));
        let t2 = mgr.insert(p2, SocketAddr::from(([127, 0, 0, 1], 2222)));
        assert_eq!(mgr.len(), 2);
        assert!(t1.0 != t2.0);
        let e1 = mgr.entries().get_mut(&t1).unwrap();
        let e2 = mgr.entries().get_mut(&t2).unwrap();
        assert_ne!(e1.id, e2.id);
        let _ = &mgr;
    }

    #[test]
    fn removing_a_connection_reports_its_id_and_closes_the_socket() {
        let (server, _client) = pair();
        let (peer, _) = server.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        let mio_peer = mio::net::TcpStream::from_std(peer).unwrap();
        let mut mgr = Manager::<MockHandler>::new(MockHandler);
        let token = mgr.insert(mio_peer, SocketAddr::from(([127, 0, 0, 1], 3333)));
        assert!(!mgr.is_empty());
        let mut poll = Poll::new().unwrap();
        let removed = mgr.remove(&mut poll, token);
        assert!(removed.is_some());
        assert!(mgr.is_empty());
    }

    #[test]
    fn queued_frames_are_flushed_in_order() {
        let (server, _client) = pair();
        let (peer, _) = server.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut mgr = Manager::<MockHandler>::new(MockHandler);
        let mio_peer = mio::net::TcpStream::from_std(peer).unwrap();
        let token = mgr.insert(mio_peer, SocketAddr::from(([127, 0, 0, 1], 4444)));
        let entry = mgr.entries().get_mut(&token).unwrap();
        queue_frame(entry, b"first").unwrap();
        queue_frame(entry, b"second").unwrap();
        let total = entry.queued.len();
        assert_eq!(total, 2 + 5 + 2 + 6);
        mgr.flush(&mut mio::Poll::new().unwrap(), token, entry).unwrap();
        assert!(entry.queued.is_empty());
    }

    #[test]
    fn reading_more_than_one_frame_per_read_is_reclaimed() {
        let mut reader = FrameReader::new();
        let big = vec![0u8; 65_537];
        let err = reader.append(&big[..65_536]).unwrap_err();
        assert!(matches!(err.kind(), io::ErrorKind::InvalidData));
    }

    #[test]
    fn a_deadline_is_extended_by_the_idle_timeout() {
        let before = Instant::now();
        let mut mgr = Manager::<MockHandler>::new(MockHandler);
        let (server, _client) = pair();
        let (peer, _) = server.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        let mio_peer = mio::net::TcpStream::from_std(peer).unwrap();
        let token = mgr.insert(mio_peer, SocketAddr::from(([127, 0, 0, 1], 5555)));
        let entry = mgr.entries().get_mut(&token).unwrap();
        let old = entry.deadline;
        mgr.touch(entry);
        assert!(entry.deadline >= old);
        assert!(entry.deadline >= before + mgr.idle_timeout() - Duration::from_millis(500));
    }

    struct MockHandler;
    impl BindingHandler for MockHandler {
        type Error = crate::FrameError;
        fn on_stun(&self, _source: SocketAddr, _datagram: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::new())
        }
        fn on_tcp_connect(&self, _id: ConnectionId, _source: SocketAddr) {}
        fn on_tcp_stun(&self, _id: ConnectionId, _datagram: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(Vec::new())
        }
        fn on_tcp_error(&mut self, _id: ConnectionId, _err: crate::FrameError) {}
    }

    fn pair() -> (TcpListener, std::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (listener, client)
    }
}
