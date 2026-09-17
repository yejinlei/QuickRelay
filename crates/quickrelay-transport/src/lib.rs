//! QuickRelay UDP/TCP data-plane transport.
//!
//! This crate owns everything between the network and the STUN message codec:
//! per-listening-address sockets, the `SO_REUSEPORT` multi-worker pattern,
//! the nonblocking event loops that drive them, the fixed-size packet buffers
//! and the 16-bit big-endian length-prefix framing required by TURN-over-TCP
//! (RFC 8656 §3.2 / §4.3) and ICE-TCP (RFC 6544).
//!
//! This crate deliberately contains **no** STUN/TURN semantics: it never
//! decides whether a request deserves a response, it never writes a CHANGE
//! bit and it never picks an error code. Those decisions live in
//! `quickrelay-binding` (YEJ-142) and are routed to it by the
//! `BindingHandler` trait below, which the server crate implements.
//!
//! Framing is owned here: `FrameReader` / `FrameWriter` /
//! [`frame_payload_too_large`] are the only framing code in the workspace.
//!
//! ## FROZEN API (F1) — owned by YEJ-141, reviewed against YEJ-177
//!
//! The following items are frozen by the workspace contract and must not be
//! renamed or re-signed without a change request on YEJ-177:
//!
//! - [`BindingHandler`] with `on_stun`, `on_tcp_connect`, `on_tcp_stun` and
//!   `on_tcp_error`
//! - [`ConnectionId`]
//! - [`FrameError`]
//! - [`FRAME_PREFIX_LEN`]
//! - [`MAX_FRAME_PAYLOAD`]
//!
//! Everything else in this crate is internal to Stage 2 / Stage 4.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod cli;
pub mod connmgr;
pub mod evloop;
pub mod framing;
pub mod wake;
pub mod workers;

use std::fmt;

/// Size of the TURN-over-TCP length prefix in octets (RFC 8656 §3.2).
///
/// Frozen by YEJ-177 as `FRAME_PREFIX_LEN`.
pub const FRAME_PREFIX_LEN: usize = 2;

/// Largest TURN-over-TCP payload this stack will accept, in octets (RFC 8656
/// §3.2 caps a frame payload at 65 535 octets).
///
/// Frozen by YEJ-177 as `MAX_FRAME_PAYLOAD`.
pub const MAX_FRAME_PAYLOAD: u16 = 65_535;

/// Default per-connection inactivity limit.
///
/// RFC 6051 §14.3.2 asks a client to re-verify its connection after 90
/// seconds, so a connection idle longer than that is treated as dead and is
/// closed by the worker.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 90;

/// Errors a TCP frame reader can report.
///
/// Only [`FrameError::OversizedPayload`] is a *protocol* error that must be
/// reported back through [`BindingHandler::on_tcp_error`];
/// [`FrameError::PeerReset`] covers the peer tearing the connection down.
/// The manager never closes a connection on read failure alone: the inactivity
/// timer is the reclamation mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The length prefix claimed more than [`MAX_FRAME_PAYLOAD`] octets.
    OversizedPayload {
        /// The payload length the peer claimed.
        declared: u32,
    },
    /// The peer closed the connection, or the read syscall failed.
    PeerReset,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::OversizedPayload { declared } => {
                write!(
                    f,
                    "oversized TURN-over-TCP frame: {declared} octets claimed, max {MAX_FRAME_PAYLOAD}"
                )
            }
            FrameError::PeerReset => write!(f, "peer reset or read error"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Identifier of one TURN-over-TCP connection.
///
/// Frozen by YEJ-177 as `ConnectionId`. It is a plain non-negative integer and
/// carries no transport flavour: the transport layer that handed it to the
/// handler already knows which socket it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ConnectionId(pub u64);

impl ConnectionId {
    /// The connection id with no particular meaning; reserved.
    pub const NONE: Self = Self(0);

    /// The id's numeric value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "conn#{}", self.0)
    }
}

/// Callbacks the transport layer invokes for everything that arrives on the
/// wire.
///
/// Frozen by YEJ-177 as `BindingHandler`. A value implementing this trait is
/// the *only* object the transport crate talks to: it decides nothing
/// protocol-wise itself, it just reports datagrams, frames and errors and
/// sends back the bytes it is handed.
///
/// [`Error`](Error) is the boxed error type of the handler, so a handler
/// implementation can be any concrete error type the caller owns.
pub trait BindingHandler: Send + Sync + 'static {
    /// The error type reported by this handler's callbacks.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Handle one inbound STUN datagram received on a UDP socket.
    ///
    /// `source` is the peer address and `datagram` is the raw, unparsed
    /// datagram. Returning `Ok(bytes)` asks the transport to send `bytes`
    /// straight back to `source` on the same socket; returning an error or
    /// `Ok(Vec::new())` drops the datagram.
    fn on_stun(&self, source: std::net::SocketAddr, datagram: &[u8])
        -> Result<Vec<u8>, Self::Error>;

    /// A new TURN-over-TCP connection was accepted on `source`.
    fn on_tcp_connect(&self, id: ConnectionId, source: std::net::SocketAddr);

    /// Handle one STUN message read off a TURN-over-TCP frame.
    ///
    /// `datagram` is the frame payload exactly as the peer framed it (the
    /// length prefix has already been stripped). Returning `Ok(bytes)` asks
    /// the transport to send `bytes` back as one new frame.
    fn on_tcp_stun(&self, id: ConnectionId, datagram: &[u8])
        -> Result<Vec<u8>, Self::Error>;

    /// Report a framing or transport error on an already-open connection.
    ///
    /// The transport closes the connection after this returns; the handler
    /// only observes the failure.
    fn on_tcp_error(&mut self, id: ConnectionId, err: FrameError);
}
