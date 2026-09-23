//! # quickrelay-transport
//!
//! Data-plane transport for QuickRelay: per-core `SO_REUSEPORT` workers, UDP
//! send/recv, the TCP listener, and the single shared
//! [length-prefix framing](self::FRAME_PREFIX_LEN) used by both TURN over TCP
//! (RFC 6062) and ICE-TCP (RFC 4571 / RFC 6544).
//!
//! This crate decides nothing about protocol semantics: a received datagram is
//! handed up to a [`BindingHandler`], and `quickrelay-binding` is not a
//! dependency of this crate.
//
//! FROZEN API (F1) — see docs/architecture/workspace-layout.md section 2.3.
//! OWNED BY: YEJ-141. DO NOT DEPEND ON quickrelay-binding.

/// Length of the TCP length prefix, in octets: a 16-bit big-endian field per
/// RFC 4571 Section 2. Zero is a valid value and codes the null packet.
pub const FRAME_PREFIX_LEN: usize = 2;

/// Maximum payload size for a framed TCP packet. `u16::MAX` minus nothing:
/// the prefix is outside the length field, so the payload may span the whole
/// STUN datagram limit.
pub const MAX_FRAME_PAYLOAD: usize = 65_535;

/// Maximum size of a received UDP datagram. A datagram of this size is the
/// RFC 768 ceiling for UDP over IPv4; STUN datagrams in practice stay far
/// below it. `read` must be given a window this large or the kernel drops the
/// datagram before the worker ever sees it.
pub const MAX_UDP_DATAGRAM: usize = MAX_FRAME_PAYLOAD;

/// Errors produced while decoding or encoding a framed TCP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The buffer holds fewer than [`FRAME_PREFIX_LEN`] octets.
    IncompleteHeader,
    /// The declared length exceeds [`MAX_FRAME_PAYLOAD`].
    LengthTooLarge,
    /// The declared length exceeds the bytes available after the header.
    IncompletePayload,
    /// The length prefix was written to a buffer that cannot hold the payload.
    BufferTooSmall,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::IncompleteHeader => write!(f, "fewer than {FRAME_PREFIX_LEN} octets"),
            FrameError::LengthTooLarge => write!(f, "declared length exceeds {MAX_FRAME_PAYLOAD}"),
            FrameError::IncompletePayload => write!(f, "declared length exceeds available bytes"),
            FrameError::BufferTooSmall => write!(f, "buffer too small for the framed packet"),
        }
    }
}

impl std::error::Error for FrameError {}

/// The transport hands received STUN traffic up to this handler. Implemented
/// once, in `quickrelay-server`; the transport never inspects attribute
/// contents.
///
/// `buf[..len]` borrows from the caller and is valid only for the duration of
/// the call. `src_addr` is the raw socket address of the peer; the handler
/// owns its decoding.
pub trait BindingHandler {
    /// Handle one received STUN datagram arriving from `src_addr`. The handler
    /// owns the reply path.
    fn on_stun(&mut self, buf: &[u8], len: usize, src_addr: &[u8]);

    /// Called once when a TCP control connection is established.
    fn on_tcp_connect(&mut self, id: ConnectionId);

    /// Called when a framed packet is read off a TCP control connection.
    fn on_tcp_stun(&mut self, buf: &[u8], len: usize, id: ConnectionId);

    /// Called when a write back onto a TCP control connection fails.
    fn on_tcp_error(&mut self, id: ConnectionId);
}

/// An opaque identifier for one TCP control connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ConnectionId(pub u64);

// ---------------------------------------------------------------------------
// Unfrozen additions (workspace-layout §2.3). The block above is F1 and stays
// byte-for-byte; everything below may only be appended to.
// ---------------------------------------------------------------------------

/// One reply a handler queued for a control connection, unframed.
#[derive(Debug, Clone)]
pub struct QueuedReply {
    /// The connection the reply goes back on.
    pub id: ConnectionId,
    /// The datagram, not yet framed.
    pub payload: Vec<u8>,
}

/// Optional outbox for a [`BindingHandler`].
///
/// The frozen [`BindingHandler`] has no send callback, and the worker owns
/// the connection buffers, so a handler that must answer a
/// control-connection packet queues the rendered datagram here and the
/// worker writes it back on the next tick. The default answers nothing,
/// which keeps a handler that only counts packets free of any obligation.
pub trait ReplyQueue {
    /// Take the next queued reply, oldest first, or `None` when there is none.
    ///
    /// A reply that is taken must either be delivered or handed back through
    /// [`queue_reply`]: the worker owns the connection buffers and cannot
    /// deliver one that does not fit.
    fn take_reply(&mut self) -> Option<QueuedReply> {
        None
    }

    /// Put a reply back when the worker could not write it yet. Called when the
    /// connection's write buffer still holds an earlier reply; that one goes out
    /// first, so this one is re-queued after it. The default drops the reply,
    /// which is wrong for a handler that must answer — a dropped reply means a
    /// peer that retransmits forever — so a handler that queues replies must
    /// override it.
    fn queue_reply(&mut self, reply: QueuedReply) {
        drop(reply);
    }
}

/// Socket lifecycle, token space and the per-connection buffers of one worker.
pub mod connmgr;
/// Transport errors.
pub mod error;
/// The shared 16-bit big-endian framing.
pub mod framing;
/// The per-worker event loop.
pub mod worker;

/// Errors surfaced by a worker while running.
pub use error::{TransportError, TransportResult};
/// Results of the incremental framing decoder.
pub use framing::DecodeOutcome;
