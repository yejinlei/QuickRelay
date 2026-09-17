//! The `FINGERPRINT` attribute (RFC 8489 Section 14.7, obsoletes RFC 5389
//! Section 15.5).
//!
//! The value is `CRC-32(message) ^ 0x5354554E`, where the message is everything
//! from the message type field through the last attribute before
//! `FINGERPRINT` itself, with the **correct** `message-length` in place.
//!
//! Three points that trips implementers up:
//!
//! * The CRC-32 here is the ITU-T V.42 / RFC 1952 CRC-32 (Ethernet, PNG, ZIP):
//!   reflected polynomial `0xEDB88320`, initial register `0xFFFFFFFF`, with the
//!   complement applied. That is exactly what `crc32fast::hash` computes. There
//!   is no special initial value and no missing final complement.
//! * The `message-length` field is **not** zeroed before the CRC — the opposite
//!   of what is done for MESSAGE-INTEGRITY. RFC 8489 Section 14.7: "prior to
//!   computation of the CRC, this value must be correct and include the CRC
//!   attribute as part of the message length".
//! * The `FINGERPRINT` value is replaced, not zeroed, before the CRC: the
//!   attribute is inserted with a dummy value, the CRC is computed, then the
//!   value is written. Since the CRC is XOR'ed with a constant, a dummy value
//!   gives the wrong CRC, so the four value octets must be patched out of the
//!   input in practice — which is why this module hashes
//!   `message[..fingerprint_offset]` (header + preceding attributes) with the
//!   length patched up to include the whole FINGERPRINT attribute.

use crate::attribute::{attr_size, pad_len};
use crate::error::{Error, ErrorKind};

/// The XOR mask applied to the CRC-32 (RFC 8489 Section 14.7).
pub const FINGERPRINT_XOR: u32 = 0x53_54_55_4E;

/// The `FINGERPRINT` attribute code (RFC 8489 Section 14.7).
pub const FINGERPRINT_ATTR: u16 = 0x8028;
/// The value length of a `FINGERPRINT` attribute.
pub const FINGERPRINT_VALUE_LEN: usize = 4;
/// The fixed STUN header size in octets.
pub const HEADER_LEN: usize = 20;

/// The largest STUN datagram in octets, header included
/// (RFC 8489 Section 5.1: `message-length` excludes the 20-octet header, so
/// the largest datagram is 20 + 65535 = 65555).
pub const MAX_DATAGRAM: usize = 65_555;

/// The maximum value the `message-length` field can hold (RFC 8489
/// Section 5.1).
pub const MAX_MESSAGE_LENGTH: u16 = 65_535;

/// `FINGERPRINT` covers the message length field, so the attribute count is
/// capped by it as well (RFC 8489 Section 5.1).
pub const MAX_ATTRIBUTE_COUNT: usize = 32_767;

/// A `FINGERPRINT` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(u32);

impl Fingerprint {
    /// The raw 32-bit value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Build a fingerprint from its raw value.
    pub const fn from_bits(value: u32) -> Self {
        Fingerprint(value)
    }

    /// The 4 network-order octets of the attribute value.
    pub fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    /// Parse the 4-octet attribute value.
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Fingerprint(u32::from_be_bytes(bytes))
    }

    /// Parse a slice, returning `None` when it is not exactly 4 octets.
    pub fn from_bytes_opt(bytes: &[u8]) -> Option<Self> {
        Some(Self::from_bytes(bytes.try_into().ok()?))
    }

    /// Compute `CRC-32(bytes) ^ 0x5354554E` (RFC 8489 Section 14.7).
    pub fn over(bytes: &[u8]) -> Self {
        Fingerprint(crc32fast::hash(bytes) ^ FINGERPRINT_XOR)
    }

    /// The CRC-32 alone, without the mask, for tests and callers that need the
    /// underlying checksum.
    pub const fn crc32_of(v: u32) -> u32 {
        v ^ FINGERPRINT_XOR
    }
}

impl core::fmt::LowerHex for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl core::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:08X}", self.0)
    }
}

/// Compute a `FINGERPRINT` over a message whose `FINGERPRINT` attribute is the
/// final attribute, at `fp_off` octets from the start of the datagram.
///
/// `datagram` must already carry the correct `message-length`, including the
/// whole `FINGERPRINT` attribute. Returns the fingerprint and, on success,
/// writes it into the value octets of the attribute in place.
pub fn compute(datagram: &mut [u8], fp_off: usize) -> Result<Fingerprint, Error> {
    if datagram.len() < 20 {
        return Err(Error::new(ErrorKind::TooShort));
    }
    if fp_off < 20 || fp_off + 4 + 4 > datagram.len() {
        return Err(Error::attr(ErrorKind::MalformedAttribute, 0x8028));
    }
    let len = u16::from_be_bytes([datagram[2], datagram[3]]);
    if usize::from(len) + 20 != datagram.len() {
        return Err(Error::new(ErrorKind::LengthMismatch));
    }
    let fingerprint = Fingerprint::over(&datagram[..fp_off]);
    datagram[fp_off + 4..fp_off + 8].copy_from_slice(&fingerprint.to_bytes());
    Ok(fingerprint)
}

/// Verify the `FINGERPRINT` at `fp_off` against the message.
///
/// Constant-time comparison, so a forged fingerprint does not leak whether the
/// prefix matched.
pub fn verify(datagram: &[u8], fp_off: usize) -> Result<(), Error> {
    if datagram.len() < HEADER_LEN {
        return Err(Error::new(ErrorKind::TooShort));
    }
    // The attribute is a 4-octet header plus a 4-octet value.
    if fp_off < HEADER_LEN || fp_off + 8 > datagram.len() {
        return Err(Error::attr(ErrorKind::MalformedAttribute, FINGERPRINT_ATTR));
    }
    // The bound check above guarantees this is exactly 4 octets.
    let stored = Fingerprint::from_bytes(datagram[fp_off + 4..fp_off + 8].try_into().unwrap());
    let expected = Fingerprint::over(&datagram[..fp_off]);
    use subtle::ConstantTimeEq;
    let expected_bits = expected.bits();
    let stored_bits = stored.bits();
    let equal = Into::<bool>::into(expected_bits.ct_eq(&stored_bits));
    if !equal {
        return Err(Error::new(ErrorKind::FingerprintMismatch));
    }
    Ok(())
}

/// Find the offset of the `FINGERPRINT` attribute header in a datagram by
/// walking the attribute list. Returns `None` when it is absent.
///
/// This is a length-only walk: it does not parse or validate any attribute
/// value, so it is safe to run on untrusted input before the message is
/// validated.
pub fn attribute_offset(datagram: &[u8]) -> Option<usize> {
    let len = datagram.len();
    if len < 20 {
        return None;
    }
    let payload = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if payload + 20 != len {
        return None;
    }
    let mut off = 20usize;
    while off + 4 <= len {
        let code = u16::from_be_bytes([datagram[off], datagram[off + 1]]);
        let value_len = usize::from(u16::from_be_bytes([datagram[off + 2], datagram[off + 3]]));
        let end = off + attr_size(value_len);
        if end > len {
            return None;
        }
        if code == 0x8028 && value_len == 4 {
            return Some(off);
        }
        off = end;
    }
    None
}

/// The octets a `FINGERPRINT` attribute occupies, header included: a 4-octet
/// header plus its 4-octet value, with no padding because the value length is
/// already a multiple of four.
pub const fn fingerprint_attribute_size() -> usize {
    attr_size(4) - pad_len(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_is_the_standard_reflected_crc32() {
        // RFC 1952 Section 8: crc32("123456789") == 0xCBF43926
        assert_eq!(crc32fast::hash(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32fast::hash(b""), 0);
        assert_eq!(crc32fast::hash(b"A"), 0xD3D9_9E8B);
    }

    #[test]
    fn xor_mask_and_conversion() {
        assert_eq!(Fingerprint::from_bits(0).bits(), 0);
        assert_eq!(Fingerprint::over(b"").bits(), FINGERPRINT_XOR);
        assert_eq!(Fingerprint::from_bytes([0x00, 0x00, 0x00, 0x00]).bits(), 0);
        assert_eq!(Fingerprint::from_bits(0xAABB_CCDD).to_bytes(), [0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(Fingerprint::over(b"123456789").bits(), 0xCBF4_3926 ^ 0x5354_554E);
        assert_eq!(Fingerprint::from_bytes_opt(&[]), None);
        assert_eq!(Fingerprint::from_bytes_opt(&[1, 2, 3]), None);
        assert_eq!(Fingerprint::from_bytes_opt(&[1, 2, 3, 4, 5]), None);
        assert_eq!(Fingerprint::from_bytes_opt(&[1, 2, 3, 4]), Some(Fingerprint::from_bits(0x01020304)));
        assert_eq!(Fingerprint::crc32_of(FINGERPRINT_XOR), 0);
        assert_eq!(format!("{}", Fingerprint::from_bits(0x01020304)), "01020304");
        assert_eq!(format!("{:x}", Fingerprint::from_bits(0x01020304)), "01020304");
        assert_eq!(
            format!("{:?}", Fingerprint::from_bits(0x01020304)),
            "Fingerprint(01020304)"
        );
    }

    /// RFC 5769 Section 2.2 — 80-octet Binding response, with a
    /// `FINGERPRINT` of `c0 7d 4c 96`.
    const RFC5769_2_2: [u8; 80] = [
        0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01,
        0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b,
        0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
        0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
        0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
        0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7,
        0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96
    ];

    #[test]
    fn rfc5769_2_2_fingerprint() {
        // fp_off = 72: SOFTWARE ends at 36, CHANNEL-NUMBER at 48, the 20-octet
        // MESSAGE-INTEGRITY at 48 ends at 72, so FINGERPRINT is the 61st octet.
        // length 0x003c already correct.
        assert_eq!(attribute_offset(&RFC5769_2_2), Some(72));
        assert_eq!(verify(&RFC5769_2_2, 72).is_ok(), true);
        assert_eq!(Fingerprint::over(&RFC5769_2_2[..72]), Fingerprint::from_bytes([0xc0, 0x7d, 0x4c, 0x96]));
        // compute() into a copy must reproduce the stored value byte for byte
        let mut msg = RFC5769_2_2;
        msg[72..76].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(compute(&mut msg, 72).unwrap().bits(), 0xc07d4c96);
        assert_eq!(msg, RFC5769_2_2);
        assert_eq!(fingerprint_attribute_size(), 8);
    }

    #[test]
    fn verify_rejects_a_corrupt_fingerprint() {
        let mut msg = RFC5769_2_2;
        msg[73] ^= 0x01;
        assert_eq!(verify(&msg, 72).unwrap_err().kind, ErrorKind::FingerprintMismatch);
        let mut msg2 = RFC5769_2_2;
        msg2[0] = 0x02;
        assert_eq!(verify(&msg2, 72).unwrap_err().kind, ErrorKind::FingerprintMismatch);
    }

    #[test]
    fn verify_rejects_a_corrupt_body() {
        let mut msg = RFC5769_2_2;
        msg[30] ^= 0x20;
        assert_eq!(verify(&msg, 72).unwrap_err().kind, ErrorKind::FingerprintMismatch);
    }

    #[test]
    fn length_field_must_be_correct_not_zeroed() {
        // Zeroing the length field — the MESSAGE-INTEGRITY rule — breaks the
        // check, which proves the two rules are different.
        let mut msg = RFC5769_2_2;
        msg[2..4].fill(0);
        assert_eq!(verify(&msg, 72).unwrap_err().kind, ErrorKind::FingerprintMismatch);
    }

    #[test]
    fn short_and_mismatched_datagrams_are_rejected() {
        let short = [0u8; 12];
        assert_eq!(verify(&short, 0).unwrap_err().kind, ErrorKind::MalformedAttribute);
        assert_eq!(compute(&mut [0u8; 12], 0).unwrap_err().kind, ErrorKind::TooShort);
        let mut msg = RFC5769_2_2;
        msg[3] = 0x3d;
        assert_eq!(verify(&msg, 72).unwrap_err().kind, ErrorKind::FingerprintMismatch);
        assert_eq!(compute(&mut msg, 72).unwrap_err().kind, ErrorKind::LengthMismatch);
    }

    /// RFC 5769 Section 2.4 — no FINGERPRINT attribute.
    const RFC5769_2_4: [u8; 116] = [
        0x00, 0x01, 0x00, 0x60, 0x21, 0x12, 0xa4, 0x42, 0x78, 0xad, 0x34, 0x33,
        0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e, 0x00, 0x06, 0x00, 0x12,
        0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88, 0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83,
        0xe3, 0x82, 0xaf, 0xe3, 0x82, 0xb9, 0x00, 0x00, 0x00, 0x15, 0x00, 0x1c,
        0x66, 0x2f, 0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36,
        0x4f, 0x4c, 0x33, 0x34, 0x6f, 0x4c, 0x39, 0x46, 0x53, 0x54, 0x76, 0x79,
        0x36, 0x34, 0x73, 0x41, 0x00, 0x14, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d,
        0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x08, 0x00, 0x14,
        0xf6, 0x70, 0x24, 0x65, 0x6d, 0xd6, 0x4a, 0x3e, 0x02, 0xb8, 0xe0, 0x71,
        0x2e, 0x85, 0xc9, 0xa2, 0x8c, 0xa8, 0x96, 0x66
    ];

    #[test]
    fn absent_fingerprint_is_none() {
        assert_eq!(attribute_offset(&RFC5769_2_4), None);
        assert_eq!(attribute_offset(&RFC5769_2_2), Some(72));
        assert!(attribute_offset(&[0u8; 4]).is_none());
        let mut bad = RFC5769_2_2;
        bad[3] = 0x3e;
        assert!(attribute_offset(&bad).is_none());
    }

    #[test]
    fn constants_match_rfc8489_section_5_1() {
        assert_eq!(MAX_MESSAGE_LENGTH, 65_535);
        assert_eq!(MAX_DATAGRAM, 65_555);
        assert_eq!(MAX_ATTRIBUTE_COUNT, 32_767);
        assert_eq!(FINGERPRINT_XOR, 0x5354_554e);
    }
}
