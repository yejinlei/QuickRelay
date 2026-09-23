//! Errors the transport layer can produce.
//!
//! Protocol errors stay in `quickrelay-protocol::Error` — the transport never
//! names a protocol error here, it just knows the handler rejected a datagram.
//! Everything in this file is about sockets, framing and timeouts.

use crate::FrameError;

/// Convenience alias for fallible transport calls.
pub type TransportResult<T> = std::result::Result<T, TransportError>;

/// Errors produced while running a worker or moving datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// A system call on a socket failed. The message carries the OS error kind.
    Io(std::io::ErrorKind),
    /// A TCP frame could not be decoded.
    Frame(FrameError),
    /// A packet was not a STUN datagram at all (bad magic cookie or too short).
    NotStun,
    /// A STUN datagram was well formed but could not be parsed.
    InvalidStun,
    /// The worker was asked to stop while it was still draining.
    ShuttingDown,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(kind) => write!(f, "socket error: {kind}"),
            TransportError::Frame(e) => write!(f, "framing error: {e}"),
            TransportError::NotStun => write!(f, "datagram is not STUN"),
            TransportError::InvalidStun => write!(f, "datagram is not valid STUN"),
            TransportError::ShuttingDown => write!(f, "worker is shutting down"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(error: std::io::Error) -> Self {
        TransportError::Io(error.kind())
    }
}

impl From<FrameError> for TransportError {
    fn from(error: FrameError) -> Self {
        TransportError::Frame(error)
    }
}
