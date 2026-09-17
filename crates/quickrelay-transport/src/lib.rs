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
