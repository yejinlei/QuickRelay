//! # quickrelay-binding
//!
//! STUN Binding *semantics* for QuickRelay. Given the facts of an
//! already-parsed Binding request, this crate decides what the server should
//! answer: which address family to reply from, whether to honor
//! CHANGE-REQUEST, whether the peer's ICE role is acceptable, and which error
//! code to emit on rejection.
//!
//! It owns no sockets, no framing, no clock and no session state, and it does
//! **not** depend on `quickrelay-protocol`: every input is a plain value type
//! declared in this crate, and `quickrelay-server` does the two-way mapping.
//! ICE-TCP / TURN-over-TCP framing lives in `quickrelay-transport`.
//
//! FROZEN API (F1) — see docs/architecture/workspace-layout.md section 3.2.
//! OWNED BY: YEJ-142. NO I/O, NO I/O DEPENDENCIES, NO PROTOCOL DEPENDENCY.
//! The four module names and the four `pub use` groups below are fixed; new
//! modules and `pub use` items may be appended, existing signatures may not be
//! renamed or removed.

pub mod change_request;
pub mod error_codes;
pub mod ice;
pub mod response;

pub use change_request::{ChangeRequest, ChangeResponseAction};
pub use error_codes::{ErrorCode, ReasonPhrase};
pub use ice::{IceAttributes, IceRole, IceTiebreaker};
pub use response::{BindingResponsePlan, ResponseSink, ServerIdentity};
