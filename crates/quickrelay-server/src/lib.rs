//! # quickrelay-server
//!
//! Assembly for QuickRelay: this crate is the only place where
//! `quickrelay-protocol`, `quickrelay-binding` and `quickrelay-transport`
//! meet. It also owns the `quickrelay` binary, CLI and config parsing.
//
//! UNFROZEN (F2) — see docs/architecture/workspace-layout.md section 2.4.
//! OWNED BY: YEJ-141.
//
//! The `BindingHandler` implementation must live in `src/binding_chain.rs`;
//! the two-way mapping between `protocol` attributes and `binding` value
//! types is allowed in exactly that one file.

pub mod binding_chain;
