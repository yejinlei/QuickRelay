//! # quickrelay-binding
//!
//! STUN Binding full semantics, ICE candidate attribute validation, and ICE-TCP framing.
//! This crate is the Binding semantics layer of QuickRelay: given a parsed request
//! (supplied as plain values, not a codec type), it decides what the server should answer.
//!
//! CHANGE-REQUEST bit layout (RFC 5780 Section 5):
//! ```text
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//! A = change IP, B = change port. Only these two bits exist.
//!
//! CHANGE-REQUEST (RFC 5780) is legacy: IANA marks 0x0003 as reserved since
//! RFC 5389. We decode it but never emit it.
//!
//! Not in scope: ICE agent / nomination (QuickRelay is middleware), TURN data
//! channel (Stage 3), message codec (YEJ-140), sockets (YEJ-141).

pub mod change_request;
pub mod error_codes;
pub mod ice;
pub mod ice_tcp;
pub mod response;

pub use change_request::{ChangeRequest, ChangeResponseAction};
pub use error_codes::{ErrorCode, ReasonPhrase};
pub use ice::{IceAttributes, IceTiebreaker, Role};
pub use ice_tcp::{FrameError, FrameRead, FrameTransport};
pub use response::{BindingResponsePlan, ResponseSink, ServerIdentity};
