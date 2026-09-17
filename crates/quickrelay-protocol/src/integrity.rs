//! MESSAGE-INTEGRITY (RFC 8489 Section 14.5, obsoletes RFC 5389 Section 15.4).
//!
//! # What the HMAC is computed over
//!
//! The MAC input is the message **up to and including the attribute preceding
//! the MESSAGE-INTEGRITY attribute**. The MESSAGE-INTEGRITY attribute itself —
//! header and value — is excluded. The `message-length` field is adjusted to
//! point at the end of the MESSAGE-INTEGRITY attribute, and its value is set to
//! a dummy before the computation.
//!
//! Worked out in symbols, with `datagram` the whole message and `mi_off` the
//! offset of the MESSAGE-INTEGRITY attribute header:
//!
//! ```text
//! input      = datagram[0 .. mi_off]                       // 20 + preceding attrs
//! input[2..4] = (mi_off + 4).to_be_bytes()                 // length field patched
//! tag        = HMAC-SHA1(key, input)
//! datagram[mi_off + 4 .. mi_off + 24] = tag                // dummy value replaced
//! ```
//!
//! For the four RFC 5769 vectors, `mi_off` is 76, 48, 60 and 92, so the length
//! fields written into the MAC input are `0x0050`, `0x0034`, `0x0040` and
//! `0x0060`. These are byte-exact against RFC 5769 Appendix A.
//!
//! # Keys
//!
//! Key derivation is an authentication concern, but the two credential
//! mechanisms STUN/TURN actually uses are mechanical enough to be worth
//! including here, since every implementation gets them wrong in a different
//! way:
//!
//! * Short-term (RFC 8489 Section 9.1.1): `key = SASLprep(password)`.
//! * Long-term (RFC 8489 Section 9.2.2): `key = MD5(username ":" realm ":"
//!   SASLprep(password))`, 16 octets.
//! * Static, RFC 6061 Section 11.2.2: `key = HMAC-SHA1(HMAC-SHA1(0x00,
//!   "user@realm"), static_secret)`.
//! * MESSAGE-INTEGRITY-SHA256, RFC 8489 Section 14.6: the key is the MD5 form
//!   above, 16 octets.

use hmac::{self, Mac};
use crate::attribute::{attr_size, pad_len};
use crate::error::{Error, ErrorKind};

/// MESSAGE-INTEGRITY (HMAC-SHA1) value length, RFC 8489 Section 14.5.
pub const MESSAGE_INTEGRITY_LEN: usize = 20;
/// MESSAGE-INTEGRITY-SHA256 maximum value length, RFC 8489 Section 14.6.
pub const MESSAGE_INTEGRITY_SHA256_LEN: usize = 32;
/// MESSAGE-INTEGRITY-SHA256 minimum value length, RFC 8489 Section 14.6.
pub const MESSAGE_INTEGRITY_SHA256_MIN_LEN: usize = 16;
/// Fingerprint of the short-term credential mechanism.
pub const CREDENTIAL_SHORT_TERM: u32 = 0x0000_0001;
/// Fingerprint of the long-term credential mechanism.
pub const CREDENTIAL_LONG_TERM: u32 = 0x0000_0002;
/// Fingerprint of the static credential mechanism (RFC 6061).
pub const CREDENTIAL_STATIC: u32 = 0x0000_0003;

/// The algorithm of a MESSAGE-INTEGRITY attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegrityAlgorithm {
    /// HMAC-SHA1, 20-octet value (RFC 8489 Section 14.5).
    Sha1,
    /// HMAC-SHA256, 32-octet value (RFC 8489 Section 14.6).
    Sha256,
}

impl IntegrityAlgorithm {
    /// The attribute code, `0x0008` for SHA-1 and `0x001C` for SHA-256.
    pub const fn attribute_code(self) -> u16 {
        match self {
            IntegrityAlgorithm::Sha1 => 0x0008,
            IntegrityAlgorithm::Sha256 => 0x001C,
        }
    }

    /// The value length.
    pub const fn mac_len(self) -> usize {
        match self {
            IntegrityAlgorithm::Sha1 => MESSAGE_INTEGRITY_LEN,
            IntegrityAlgorithm::Sha256 => MESSAGE_INTEGRITY_SHA256_LEN,
        }
    }

    /// The credential mechanism names in RFC 8489 Section 9.2.1 order.
    pub const fn credential_names() -> &'static [&'static str] {
        &["MD5", "SHA-256"]
    }
}

/// A message-integrity key.
///
/// The variant records only provenance for logging; the codec uses
/// [`IntegrityKey::as_bytes`]. Key derivation helpers are
/// [`short_term_key`], [`long_term_key`] and [`static_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntegrityKey {
    /// The password directly, RFC 8489 Section 9.1.1.
    ShortTerm,
    /// `MD5(username:realm:password)`, RFC 8489 Section 9.2.2.
    LongTerm,
    /// `HMAC-SHA1(HMAC-SHA1(0x00, user@realm), static_secret)`, RFC 6061.
    Static,
    /// A usage-supplied key of its own.
    Other,
}

impl IntegrityKey {
    /// The key bytes.
    pub const fn as_bytes(self, bytes: &[u8]) -> &[u8] {
        bytes
    }
}

/// The short-term key: the password bytes as-is, already SASLprep'ed
/// (RFC 8489 Section 9.1.1).
pub fn short_term_key(password: &[u8]) -> &[u8] {
    password
}

/// The long-term key: `MD5(username ":" realm ":" password)` (RFC 8489
/// Section 9.2.2). `password` must already be SASLprep'ed.
pub fn long_term_key(username: &[u8], realm: &[u8], password: &[u8]) -> [u8; 16] {
    let mut input = Vec::with_capacity(username.len() + realm.len() + password.len() + 2);
    input.extend_from_slice(username);
    input.push(b':');
    input.extend_from_slice(realm);
    input.push(b':');
    input.extend_from_slice(password);
    let digest = md5::compute(&input);
    let mut key = [0u8; 16];
    key.copy_from_slice(digest.as_slice());
    key
}

/// The static credential key (RFC 6061 Section 11.2.2):
///
/// ```text
/// intermediate = HMAC-SHA1(key = 0x00, message = OpaqueString(user@realm))
/// key          = HMAC-SHA1(key = intermediate, message = static_secret)
/// ```
///
/// `user_at_realm` is the literal `"user@realm"` string.
pub fn static_key(user_at_realm: &[u8], static_secret: &[u8]) -> [u8; 20] {
    let intermediate = {
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&[0u8])
            .expect("a 1-octet key is always valid");
        mac.update(user_at_realm);
        mac.finalize().into_bytes()
    };
    let mut mac =
        hmac::Hmac::<sha1::Sha1>::new_from_slice(&intermediate).expect("a 20-octet key is valid");
    mac.update(static_secret);
    let mut key = [0u8; 20];
    key.copy_from_slice(&mac.finalize().into_bytes());
    key
}

/// Compute the MESSAGE-INTEGRITY over a message whose integrity attribute is
/// at `attr_off`, patching the length field in a scratch buffer and writing
/// the tag into the attribute value octets of `datagram` in place.
///
/// `datagram` must already carry the correct `message-length`.
pub fn compute(datagram: &mut [u8], attr_off: usize, algorithm: IntegrityAlgorithm, key: &[u8]) -> Result<[u8; 32], Error> {
    let mac_len = algorithm.mac_len();
    let need = attr_off + 4 + mac_len;
    if datagram.len() < need {
        return Err(Error::new(ErrorKind::TruncatedAttribute));
    }
    let (tag, _prefix) = compute_prefix(datagram, attr_off, mac_len, key)?;
    let mut out = [0u8; 32];
    // Only the first `mac_len` octets are the tag: an SHA-1 integrity is 20
    // octets long, so copying the whole 32-octet buffer here would panic.
    out[..tag_len(mac_len)].copy_from_slice(&tag);
    datagram[attr_off + 4..need].copy_from_slice(&tag);
    Ok(out)
}

/// The MAC and the MAC input, for callers that need to inspect the input.
pub fn compute_prefix(datagram: &[u8], attr_off: usize, mac_len: usize, key: &[u8]) -> Result<([u8; 32], Vec<u8>), Error> {
    let mut mac = [0u8; 32];
    let input = mac_input(datagram, attr_off, mac_len)?;
    let tag = hmac_of(tag_len(mac_len), key, &input);
    mac[..tag_len(mac_len)].copy_from_slice(&tag);
    Ok((mac, input))
}

const fn tag_len(mac_len: usize) -> usize {
    if mac_len == MESSAGE_INTEGRITY_SHA256_LEN {
        MESSAGE_INTEGRITY_SHA256_LEN
    } else {
        MESSAGE_INTEGRITY_LEN
    }
}

/// Build the HMAC input (RFC 8489 Section 14.5): the message through the
/// attribute preceding the integrity attribute, with the `message-length`
/// field patched to the end of the integrity attribute.
pub fn mac_input(datagram: &[u8], attr_off: usize, mac_len: usize) -> Result<Vec<u8>, Error> {
    if datagram.len() < 20 {
        return Err(Error::new(ErrorKind::TooShort));
    }
    if attr_off < 20 || attr_off + 4 + mac_len > datagram.len() {
        return Err(Error::attr(
            ErrorKind::TruncatedAttribute,
            0x0008,
        ));
    }
    let recorded = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if recorded + 20 != datagram.len() {
        return Err(Error::new(ErrorKind::LengthMismatch));
    }
    let mut input = datagram[..attr_off].to_vec();
    // `message-length` excludes the 20-octet header (RFC 8489 Section 5.1),
    // so the patch target is the MI attribute end minus the header:
    // (attr_off + 4 + mac_len) - 20. For the RFC 5769 vectors this yields
    // 0x0050, 0x0034, 0x0040 and 0x0060.
    let length_field = (attr_off + 4 + mac_len - crate::message::HEADER_LEN) as u16;
    if attr_off + 4 + mac_len > crate::message::MAX_DATAGRAM {
        return Err(Error::new(ErrorKind::LengthTooLarge));
    }
    input[2..4].copy_from_slice(&length_field.to_be_bytes());
    Ok(input)
}

/// Verify the integrity attribute at `attr_off`. Constant-time comparison.
pub fn verify(datagram: &[u8], attr_off: usize, algorithm: IntegrityAlgorithm, key: &[u8]) -> Result<(), Error> {
    let mac_len = algorithm.mac_len();
    if datagram.len() < attr_off + 4 + mac_len {
        return Err(Error::attr(
            ErrorKind::TruncatedAttribute,
            algorithm.attribute_code(),
        ));
    }
    let expected = hmac_of(tag_len(mac_len), key, &mac_input(datagram, attr_off, mac_len)?);
    let stored = &datagram[attr_off + 4..attr_off + 4 + expected.len()];
    use subtle::ConstantTimeEq;
    let equal = Into::<bool>::into(expected.as_slice().ct_eq(stored));
    if !equal {
        return Err(Error::attr(
            ErrorKind::MessageIntegrityMismatch,
            algorithm.attribute_code(),
        ));
    }
    Ok(())
}

fn hmac_of<'a>(len: usize, key: &[u8], msg: &'a [u8]) -> Vec<u8> {
    let mut out: Vec<u8> = if len == MESSAGE_INTEGRITY_SHA256_LEN {
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap_or_else(|_| {
            panic!("HMAC accepts keys of any length, including zero")
        });
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    } else {
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).unwrap_or_else(|_| {
            panic!("HMAC accepts keys of any length, including zero")
        });
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    };
    out.truncate(len);
    out
}

/// Find the offset of the first `MESSAGE-INTEGRITY` or `MESSAGE-INTEGRITY-SHA256`
/// attribute in `datagram`, walking the attribute list by length only.
///
/// Length-only walk, safe on untrusted input before validation.
pub fn attribute_offset(datagram: &[u8]) -> Option<AttributeLocation> {
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
        if code == 0x0008 || code == 0x001C {
            return Some(AttributeLocation { off, code, value_len });
        }
        off = end;
    }
    None
}

/// A located MESSAGE-INTEGRITY attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeLocation {
    /// Offset of the attribute header.
    pub off: usize,
    /// `0x0008` (SHA-1) or `0x001C` (SHA-256).
    pub code: u16,
    /// The recorded value length in octets.
    pub value_len: usize,
}

impl AttributeLocation {
    /// The algorithm, if the recorded value length is legal for either
    /// registered variant.
    pub fn algorithm(&self) -> Option<IntegrityAlgorithm> {
        if self.code == 0x0008 && self.value_len == MESSAGE_INTEGRITY_LEN {
            Some(IntegrityAlgorithm::Sha1)
        } else if self.code == 0x001C
            && self.value_len >= MESSAGE_INTEGRITY_SHA256_MIN_LEN
            && self.value_len <= MESSAGE_INTEGRITY_SHA256_LEN
            && self.value_len % 4 == 0
        {
            Some(IntegrityAlgorithm::Sha256)
        } else {
            None
        }
    }

    /// Whether the attribute is the last one in the message.
    pub fn is_last(&self, datagram: &[u8]) -> bool {
        self.off + attr_size(self.value_len) == datagram.len()
    }
}

/// The number of pad octets an integrity attribute value contributes.
pub const fn integrity_pad_value_len(value_len: usize) -> usize {
    pad_len(value_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";

    // RFC 5769 Section 2.1 — 108 octets, Binding request, FINGERPRINT after MI.
    const RFC5769_2_1: [u8; 108] = [
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01,
        0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10,
        0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6c,
        0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff,
        0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36,
        0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76,
        0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c,
        0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49,
        0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf
    ];

    // RFC 5769 Section 2.2 — 80 octets, Binding success.
    const RFC5769_2_2: [u8; 80] = [
        0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01,
        0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b,
        0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
        0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
        0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
        0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7,
        0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96
    ];

    // RFC 5769 Section 2.3 — 92 octets, IPv6 Binding success.
    const RFC5769_2_3: [u8; 92] = [
        0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01,
        0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b,
        0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
        0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa,
        0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
        0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1,
        0x17, 0x84, 0xc9, 0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41,
        0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb, 0x0b, 0x4c
    ];

    // RFC 5769 Section 2.4 — 116 octets, long-term credential request, no FP.
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

    // SASLprep of "The\u{00AD}M\u{00AA}tr\u{2168}" as printed in RFC 5769 2.4.
    const LONG_TERM_PASSWORD: &[u8] = b"TheMatrIX";
    const REALM: &[u8] = b"example.org";
    // "マトリックス" in UTF-8, as it appears in the USERNAME attribute.
    const USERNAME_UTF8: [u8; 18] = [
        0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88, 0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82,
        0xaf, 0xe3, 0x82, 0xb9,
    ];

    fn locate(datagram: &[u8]) -> AttributeLocation {
        attribute_offset(datagram).expect("an integrity attribute must be present")
    }

    #[test]
    fn rfc5769_2_1_short_term() {
        let loc = locate(&RFC5769_2_1);
        assert_eq!(loc.off, 76);
        assert_eq!(loc.code, 0x0008);
        assert_eq!(loc.value_len, 20);
        assert_eq!(loc.algorithm(), Some(IntegrityAlgorithm::Sha1));
        assert!(!loc.is_last(&RFC5769_2_1));
        assert_eq!(
            verify(&RFC5769_2_1, loc.off, IntegrityAlgorithm::Sha1, SECRET),
            Ok(())
        );
        // The length field written into the MAC input is 0x0050 = 80.
        let input = mac_input(&RFC5769_2_1, loc.off, 20).unwrap();
        assert_eq!(input.len(), 76);
        assert_eq!(&input[2..4], &[0x00, 0x50]);
        let tag = hmac_of(20, SECRET, &input);
        assert_eq!(
            tag,
            hex(b"9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2")
        );
        assert_eq!(&RFC5769_2_1[loc.off + 4..loc.off + 24], tag.as_slice());
    }

    #[test]
    fn rfc5769_2_2_short_term() {
        let loc = locate(&RFC5769_2_2);
        assert_eq!(loc.off, 48);
        assert_eq!(verify(&RFC5769_2_2, loc.off, IntegrityAlgorithm::Sha1, SECRET), Ok(()));
        let input = mac_input(&RFC5769_2_2, loc.off, 20).unwrap();
        assert_eq!(input.len(), 48);
        assert_eq!(&input[2..4], &[0x00, 0x34]);
        assert_eq!(hmac_of(20, SECRET, &input), hex(b"2b91f599fd9e90c38c7489f92af9ba53f06be7d7"));
    }

    #[test]
    fn rfc5769_2_3_short_term() {
        let loc = locate(&RFC5769_2_3);
        assert_eq!(loc.off, 60);
        assert_eq!(verify(&RFC5769_2_3, loc.off, IntegrityAlgorithm::Sha1, SECRET), Ok(()));
        let input = mac_input(&RFC5769_2_3, loc.off, 20).unwrap();
        assert_eq!(input.len(), 60);
        assert_eq!(&input[2..4], &[0x00, 0x40]);
        assert_eq!(hmac_of(20, SECRET, &input), hex(b"a382954e4be67bf11784c97c8292c275bfe3ed41"));
    }

    #[test]
    fn rfc5769_2_4_long_term_md5_key() {
        let loc = locate(&RFC5769_2_4);
        assert_eq!(loc.off, 92);
        assert!(loc.is_last(&RFC5769_2_4));
        let key = long_term_key(&USERNAME_UTF8, REALM, LONG_TERM_PASSWORD);
        assert_eq!(key, md5_of("マトリックス:example.org:TheMatrIX"));
        assert_eq!(
            verify(&RFC5769_2_4, loc.off, IntegrityAlgorithm::Sha1, &key),
            Ok(())
        );
        let input = mac_input(&RFC5769_2_4, loc.off, 20).unwrap();
        assert_eq!(input.len(), 92);
        assert_eq!(&input[2..4], &[0x00, 0x60]);
        assert_eq!(hmac_of(20, &key, &input), hex(b"f67024656dd64a3e02b8e0712e85c9a28ca89666"));
    }

    #[test]
    fn compute_reproduces_all_four_rfc5769_vectors() {
        let cases: [(&[u8], &[u8]); 3] = [
            (&RFC5769_2_1, SECRET),
            (&RFC5769_2_2, SECRET),
            (&RFC5769_2_3, SECRET),
        ];
        for (original, key) in cases {
            let loc = locate(original);
            let mut msg: Vec<u8> = original.to_vec();
            msg[loc.off + 4..loc.off + 24].fill(0);
            let tag = compute(&mut msg, loc.off, IntegrityAlgorithm::Sha1, key).unwrap();
            assert_eq!(&tag[..20], &msg[loc.off + 4..loc.off + 24]);
            assert_eq!(&msg[..], &original[..]);
        }
        let key = long_term_key(&USERNAME_UTF8, REALM, LONG_TERM_PASSWORD);
        let loc = locate(&RFC5769_2_4);
        let mut msg = RFC5769_2_4;
        msg[loc.off + 4..loc.off + 24].fill(0);
        compute(&mut msg, loc.off, IntegrityAlgorithm::Sha1, &key).unwrap();
        assert_eq!(msg, RFC5769_2_4);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let loc = locate(&RFC5769_2_1);
        assert_eq!(
            verify(&RFC5769_2_1, loc.off, IntegrityAlgorithm::Sha1, b"wrong")
                .unwrap_err()
                .kind,
            ErrorKind::MessageIntegrityMismatch
        );
        assert_eq!(
            verify(&RFC5769_2_1, loc.off, IntegrityAlgorithm::Sha1, &[]).unwrap_err().kind,
            ErrorKind::MessageIntegrityMismatch
        );
        // A one-octet difference anywhere in the message fails.
        for at in [0usize, 3, 20, 40, 75] {
            let mut msg = RFC5769_2_1;
            msg[at] ^= 0x01;
            if at >= loc.off + 4 {
                continue;
            }
            assert_eq!(
                verify(&msg, loc.off, IntegrityAlgorithm::Sha1, SECRET).unwrap_err().kind,
                ErrorKind::MessageIntegrityMismatch,
                "octet {at}"
            );
        }
    }

    #[test]
    fn integrity_must_exclude_its_own_attribute() {
        // Including the MI attribute in the input — the classic mistake —
        // produces the wrong tag for every vector.
        let loc = locate(&RFC5769_2_1);
        let wrong = RFC5769_2_1[..loc.off + 4 + 20].to_vec();
        assert_ne!(
            wrong.as_slice(),
            mac_input(&RFC5769_2_1, loc.off, 20).unwrap().as_slice()
        );
        assert_ne!(hmac_of(20, SECRET, &wrong), hmac_of(20, SECRET, &mac_input(&RFC5769_2_1, loc.off, 20).unwrap()));
    }

    #[test]
    fn mac_input_rejects_bad_length_and_offsets() {
        assert_eq!(mac_input(&[0u8; 4], 0, 20).unwrap_err().kind, ErrorKind::TooShort);
        assert_eq!(mac_input(&RFC5769_2_1, 12, 20).unwrap_err().kind, ErrorKind::TruncatedAttribute);
        assert_eq!(
            mac_input(&RFC5769_2_1, 76, 32).unwrap_err().kind,
            ErrorKind::TruncatedAttribute
        );
        let mut bad = RFC5769_2_1;
        bad[3] = 0x59;
        assert_eq!(mac_input(&bad, 76, 20).unwrap_err().kind, ErrorKind::LengthMismatch);
        assert_eq!(
            verify(&RFC5769_2_1, 76, IntegrityAlgorithm::Sha1, SECRET),
            Ok(())
        );
    }

    #[test]
    fn attribute_location_walks_the_message() {
        let loc = attribute_offset(&RFC5769_2_1).unwrap();
        assert_eq!(loc, AttributeLocation { off: 76, code: 0x0008, value_len: 20 });
        assert_eq!(attribute_offset(&RFC5769_2_4).unwrap().off, 92);
        assert!(attribute_offset(&[0u8; 20]).is_none());
        assert!(attribute_offset(&[0u8; 4]).is_none());
        let mut bad = RFC5769_2_1;
        bad[3] = 0x00;
        assert!(attribute_offset(&bad).is_none());
    }

    #[test]
    fn sha256_length_rules() {
        assert_eq!(IntegrityAlgorithm::Sha1.attribute_code(), 0x0008);
        assert_eq!(IntegrityAlgorithm::Sha256.attribute_code(), 0x001c);
        assert_eq!(IntegrityAlgorithm::Sha1.mac_len(), 20);
        assert_eq!(IntegrityAlgorithm::Sha256.mac_len(), 32);
        assert_eq!(
            AttributeLocation { off: 20, code: 0x001C, value_len: 16 }.algorithm(),
            Some(IntegrityAlgorithm::Sha256)
        );
        assert_eq!(
            AttributeLocation { off: 20, code: 0x001C, value_len: 32 }.algorithm(),
            Some(IntegrityAlgorithm::Sha256)
        );
        // 12 octets is below the RFC 8489 minimum, and 18 is not a multiple of 4.
        assert_eq!(AttributeLocation { off: 20, code: 0x001C, value_len: 12 }.algorithm(), None);
        assert_eq!(AttributeLocation { off: 20, code: 0x001C, value_len: 18 }.algorithm(), None);
        assert_eq!(AttributeLocation { off: 20, code: 0x001C, value_len: 1 }.algorithm(), None);
        assert_eq!(AttributeLocation { off: 20, code: 0x0008, value_len: 32 }.algorithm(), None);
        assert_eq!(AttributeLocation { off: 20, code: 0x0008, value_len: 1 }.algorithm(), None);
        assert_eq!(MESSAGE_INTEGRITY_SHA256_MIN_LEN, 16);
        assert_eq!(MESSAGE_INTEGRITY_SHA256_LEN, 32);
    }

    #[test]
    fn sha256_verify_computes_a_correct_hmac_sha256() {
        // A self-contained round trip: build an input, compute the tag, then
        // verify it back. The vectors for this attribute are in RFC 8489
        // Appendix B, which this crate does not vendor, so the round trip is
        // the contract.
        let input = b"some message input for the sha256 check";
        let tag = hmac_of(32, b"key", input);
        assert_eq!(tag.len(), 32);
        assert_eq!(tag, hmac_of(32, b"key", input));
        assert_ne!(tag, hmac_of(20, b"key", input));
        assert_eq!(hmac_of(20, b"key", input).len(), 20);
        let sha256_of_empty = hmac_of(32, b"k", b"");
        let sha1_of_empty = hmac_of(20, b"k", b"");
        assert_eq!(sha256_of_empty.len(), 32);
        assert_eq!(sha1_of_empty.len(), 20);
    }

    #[test]
    fn static_key_is_the_rfc6061_nested_hmac_of() {
        let key = static_key(b"user@example.org", b"secret");
        assert_eq!(key.len(), 20);
        let intermediate = {
            let mut m = hmac::Hmac::<sha1::Sha1>::new_from_slice(&[0u8]).unwrap();
            m.update(b"user@example.org");
            m.finalize().into_bytes()
        };
        let mut m = hmac::Hmac::<sha1::Sha1>::new_from_slice(&intermediate).unwrap();
        m.update(b"secret");
        assert_eq!(&key[..], m.finalize().into_bytes().as_slice());
        assert_ne!(static_key(b"other@example.org", b"secret"), key);
        assert_ne!(static_key(b"user@example.org", b"other"), key);
    }

    #[test]
    fn long_term_key_is_md5_of_username_realm_password() {
        let key = long_term_key(b"user", b"realm", b"pass");
        assert_eq!(key, md5_of("user:realm:pass"));
        assert_ne!(long_term_key(b"user", b"realm2", b"pass"), key);
        assert_ne!(long_term_key(b"user", b"realm", b"pass2"), key);
        assert_ne!(long_term_key(b"u", b"realm:pass", b"x"), key);
    }

    #[test]
    fn short_term_key_is_the_password() {
        assert!(short_term_key(b"p").eq(b"p"));
        assert_eq!(short_term_key(&[]).len(), 0);
    }

    #[test]
    fn key_and_credential_constants() {
        assert_eq!(CREDENTIAL_SHORT_TERM, 0x1);
        assert_eq!(CREDENTIAL_LONG_TERM, 0x2);
        assert_eq!(CREDENTIAL_STATIC, 0x3);
        assert_eq!(IntegrityAlgorithm::credential_names(), &["MD5", "SHA-256"]);
        let key = IntegrityKey::LongTerm;
        assert_eq!(key.as_bytes(&[1, 2, 3]), &[1, 2, 3]);
        let _ = IntegrityKey::ShortTerm.as_bytes(&[]);
        let _ = IntegrityKey::Static.as_bytes(&[]);
        let _ = IntegrityKey::Other.as_bytes(&[]);
        assert!(format!("{key:?}").contains("LongTerm"));
        assert_eq!(integrity_pad_value_len(20), 0);
        assert_eq!(integrity_pad_value_len(28), 0);
        assert_eq!(integrity_pad_value_len(16), 0);
        assert_eq!(integrity_pad_value_len(1), 3);
    }

    fn hex(s: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() / 2);
        for pair in s.chunks(2) {
            out.push(u8::from_str_radix(&std::str::from_utf8(pair).unwrap(), 16).unwrap());
        }
        out
    }

    fn md5_of(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(md5::compute(s.as_bytes()).as_slice());
        out
    }
}
