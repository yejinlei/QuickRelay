//! The 96-bit STUN transaction identifier (RFC 5389 Section 6).

/// A 12-octet STUN transaction identifier.
///
/// It is the correlation key that lets a response be matched to the request
/// that produced it, and it also participates in the XOR-MAPPED-ADDRESS and
/// XOR-RELAYED-ADDRESS keys for IPv6 (RFC 5389 Section 15.2).
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionId([u8; 12]);

impl TransactionId {
    pub const LEN: usize = 12;

    /// Construct from an exact-length octet slice.
    pub const fn from_bytes(bytes: [u8; 12]) -> Self {
        TransactionId(bytes)
    }

    /// The identifier's octets, little-endian-free: wire order, unchanged.
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// The last 8 octets. Retained for callers that need a shorter key tail;
    /// the codec uses the full 12 octets via [`TransactionId::as_bytes`].
    #[inline]
    pub const fn key_tail(&self) -> [u8; 8] {
        [self.0[4], self.0[5], self.0[6], self.0[7], self.0[8], self.0[9], self.0[10], self.0[11]]
    }

    /// Generate a fresh identifier from the process RNG.
    ///
    /// Enabled with the `rand` feature. The RFC requires only that identifiers
    /// be locally unique over the 200 ms retransmission window.
    #[cfg(feature = "rand")]
    pub fn random() -> Self {
        use rand::Rng;
        let mut bytes = [0u8; 12];
        rand::rng().fill(&mut bytes);
        TransactionId(bytes)
    }
}

impl AsRef<[u8]> for TransactionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 12]> for TransactionId {
    fn from(bytes: [u8; 12]) -> Self {
        TransactionId(bytes)
    }
}

impl From<TransactionId> for [u8; 12] {
    fn from(id: TransactionId) -> Self {
        id.0
    }
}

impl core::fmt::Display for TransactionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for TransactionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TransactionId(\"{self}\")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5769_transaction_id_roundtrip() {
        // RFC 5769 Section 2.1/2.2/2.3 all use the same identifier.
        let id = TransactionId::from_bytes([
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ]);
        assert_eq!(
            id.as_bytes(),
            &[
                0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae
            ]
        );
        assert_eq!(id.to_string(), "b7e7a701bc34d686fa87dfae");
        assert_eq!(
            id.key_tail(),
            [0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae]
        );
    }

    #[test]
    fn rfc5769_section24_transaction_id_roundtrip() {
        let id = TransactionId::from_bytes([
            0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e,
        ]);
        assert_eq!(id.to_string(), "78ad3433c6ad72c029da412e");
        let back = TransactionId::from_bytes([
            0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e,
        ]);
        assert_eq!(back, id);
        assert_eq!(
            id.as_bytes(),
            &[
                0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e
            ]
        );
    }

    #[test]
    fn default_is_all_zero() {
        assert_eq!(TransactionId::default().as_bytes(), &[0u8; 12]);
        assert_eq!(TransactionId::default(), TransactionId::from_bytes([0; 12]));
    }

    #[test]
    fn as_ref_is_wire_order() {
        let id = TransactionId::from_bytes([0x01; 12]);
        let ref_as_slice: &[u8] = id.as_ref();
        assert_eq!(ref_as_slice.len(), TransactionId::LEN);
        assert!(ref_as_slice.iter().all(|b| *b == 0x01));
    }
}
