//! `quickrelay`: the QuickRelay binary.
//!
//! Assembly only — worker construction, `BindingHandler` wiring, signal
//! handling, CLI and config parsing. No protocol parsing, no semantics, no I/O
//! primitives: those live in `quickrelay-protocol`, `quickrelay-binding` and
//! `quickrelay-transport`.

fn main() {
    // TODO(YEJ-141): construct the worker pool, wire the BindingHandler, and
    // start the event loop. This placeholder exists so the workspace builds.
    println!("quickrelay: skeleton build — wire up the workers (YEJ-141)");
}
