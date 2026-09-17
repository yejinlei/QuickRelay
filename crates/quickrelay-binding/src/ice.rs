//! ICE attribute validation (RFC 8445).
//!
//! QuickRelay is a TURN/STUN server, not an ICE agent: this module validates
//! that a peer's Binding request carries well-formed ICE attributes and
//! decides the role-conflict outcome. Nomination, gathering and checking are
//! out of scope.
//!
//! Attribute codes (IANA, 2024-12-20): ICE-CONTROLLED `0x8029`,
//! ICE-CONTROLLING `0x802A`, ICE-PRIORITY `0x0024`.

/// Which ICE role the peer claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IceRole {
    /// The peer includes ICE-CONTROLLING (RFC 8445 Section 7.1.3.1).
    Controlling,
    /// The peer includes ICE-CONTROLLED (RFC 8445 Section 7.1.3.1).
    Controlled,
    /// Neither attribute is present: the peer is not an ICE agent.
    #[default]
    None,
    /// Both attributes are present at once: always an error.
    Conflict,
}

/// The 64-bit tiebreaker carried in ICE-CONTROLLED / ICE-CONTROLLING.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IceTiebreaker(pub u64);

impl IceTiebreaker {
    /// Decode from the 8-octet attribute value, big-endian.
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        IceTiebreaker(u64::from_be_bytes(bytes))
    }

    /// Encode for a response, big-endian.
    pub const fn as_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/// Everything this crate needs to validate a peer's ICE attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IceAttributes {
    /// The role the peer claims.
    pub role: IceRole,
    /// The peer's tiebreaker, when the role attribute is present.
    pub tiebreaker: Option<IceTiebreaker>,
    /// ICE-PRIORITY value, when present (RFC 8445 Section 4.1.1.4).
    pub priority: Option<u32>,
    /// USE-CANDIDATE was present (RFC 8445 Section 6.1.2).
    pub use_candidate: bool,
}
