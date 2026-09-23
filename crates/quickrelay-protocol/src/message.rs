//! STUN / TURN message framing and attribute list parsing (RFC 8489 Sections
//! 5, 7.2 and 11.1).
//!
//! A datagram is validated, not mutated: the message length field must agree
//! with the buffer, every attribute value must fit its type, the
//! `FINGERPRINT` must be the final attribute, and a `MESSAGE-INTEGRITY-SHA256`
//! value must obey the RFC 8489 Section 14.6 length rule.
//!
//! Unknown attribute handling follows RFC 8489 Section 6.3.1 (RFC 5389
//! Section 7.3): a comprehension-required code (high bit clear) is an error
//! the caller must answer with error code `420 Unknown Attribute` carrying an
//! `UNKNOWN-ATTRIBUTES` attribute; a comprehension-optional code (high bit
//! set) is preserved in [`Message::unknown`] so the caller can echo it.
//!
//! Note on message types: this crate follows the RFC 8489 method numbering,
//! where Binding is `0x001` (RFC 8489 §18.2), so a Binding request encodes as
//! `0x0001` and a Binding success response as `0x0101` — exactly the headers
//! RFC 5769 prints. The RFC 5769 datagrams parse byte for byte.

use bytes::Bytes;

use crate::attribute::{
    attribute_kind, emit_attribute, is_comprehension_optional,
    is_trailer_only, parse_attribute_value, Attribute, AttrCode, AttributeKind,
};
use crate::error::{Error, ErrorKind};
use crate::fingerprint::MAX_ATTRIBUTE_COUNT;
use crate::integrity::{compute as compute_integrity, AttributeLocation, IntegrityAlgorithm};
use crate::message_type::MessageType;
use crate::transaction_id::TransactionId;

/// The magic cookie that identifies a STUN datagram (RFC 8489 Section 5.1).
pub const MAGIC_COOKIE: u32 = 0x21_12_A4_42;
/// The fixed STUN header size in octets (RFC 8489 Section 5.1).
pub const HEADER_LEN: usize = 20;
/// The transaction identifier length in octets (RFC 8489 Section 5.2).
pub const TRANSACTION_ID_LEN: usize = 12;
/// The largest value the `message-length` field can hold (RFC 8489 Section
/// 5.1: a 16-bit field starting at octet 2).
pub const MAX_MESSAGE_LENGTH: u16 = 65_535;
/// The largest STUN datagram in octets, header included.
pub const MAX_DATAGRAM: usize = HEADER_LEN + MAX_MESSAGE_LENGTH as usize;
/// The offset of the `message-length` field in a datagram.
pub const LENGTH_OFFSET: usize = 2;
/// The offset of the magic cookie field in a datagram.
pub const MAGIC_COOKIE_OFFSET: usize = 4;
/// The offset of the transaction identifier field in a datagram.
pub const TRANSACTION_ID_OFFSET: usize = 8;
/// The `FINGERPRINT` attribute code (RFC 8489 Section 14.7).
pub const FINGERPRINT_CODE: u16 = 0x8028;
/// The `MESSAGE-INTEGRITY` attribute code (RFC 8489 Section 14.5).
pub const MESSAGE_INTEGRITY_CODE: u16 = 0x0008;
/// The `MESSAGE-INTEGRITY-SHA256` attribute code (RFC 8489 Section 14.6).
pub const MESSAGE_INTEGRITY_SHA256_CODE: u16 = 0x001C;
/// The `UNKNOWN-ATTRIBUTES` attribute code (RFC 8489 Section 14.13).
pub const UNKNOWN_ATTRIBUTES_CODE: u16 = 0x000A;

/// The `MESSAGE-INTEGRITY-SHA256` minimum value length, RFC 8489
/// Section 14.6.
pub const MESSAGE_INTEGRITY_SHA256_MIN_LEN: usize = 16;

/// A parsed STUN / TURN message.
///
/// [`Message::attributes`] holds every decodable attribute in wire order,
/// trailers included; [`Message::unknown`] holds the unrecognised
/// comprehension-optional attributes, preserved verbatim so an
/// `UNKNOWN-ATTRIBUTES` reply can be built from it (RFC 8489 Section 14.13).
/// Values are owned, so a parsed message can outlive the buffer it was read
/// from.
#[derive(Debug, Clone)]
pub struct Message {
    /// The decoded header.
    pub header: Header,
    /// The transaction identifier, repeated from the header for convenience.
    pub txid: TransactionId,
    /// The datagram this message was parsed from, header included.
    pub datagram_bytes: Bytes,
    /// The parsed attributes, in wire order.
    pub attributes: Vec<Attribute>,
    /// Unrecognised comprehension-optional attributes, in wire order.
    pub unknown: Vec<UnknownAttribute>,
    /// The located `MESSAGE-INTEGRITY` / `MESSAGE-INTEGRITY-SHA256` trailer,
    /// when present.
    pub integrity_location: Option<AttributeLocation>,
    /// The offset of the `FINGERPRINT` attribute header, when present.
    pub fingerprint_offset: Option<usize>,
}

/// An unrecognised comprehension-optional attribute, kept verbatim
/// (RFC 8489 Section 6.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAttribute {
    /// The attribute type code, which is not in the registry.
    pub code: u16,
    /// The attribute kind the wire code maps to, always `Unknown`.
    pub kind: AttributeKind,
    /// The value octets, trimmed to the declared length, with no padding.
    pub value: Bytes,
}

impl Message {
    /// The parsed attribute list, in wire order.
    pub fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }

    /// The number of parsed attributes.
    pub fn len(&self) -> usize {
        self.attributes.len()
    }

    /// Whether the message carries no parsed attributes.
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// The `i`th parsed attribute, in wire order.
    pub fn get(&self, i: usize) -> Option<&Attribute> {
        self.attributes.get(i)
    }

    /// The first parsed attribute with this code.
    pub fn find(&self, code: u16) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|a| attribute_kind(a).as_u16() == code)
    }

    /// Whether any attribute with this code is present, registered or not.
    pub fn has(&self, code: u16) -> bool {
        self.attributes.iter().any(|a| attribute_kind(a).as_u16() == code)
            || self.unknown.iter().any(|u| u.code == code)
    }

    /// The datagram this message was parsed from, header included.
    pub fn datagram_bytes(&self) -> &[u8] {
        &self.datagram_bytes
    }

    /// The total datagram size in octets, header included.
    pub fn datagram_len(&self) -> usize {
        self.datagram_bytes.len()
    }

    /// The parsed header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The STUN Message Type field.
    pub fn msg_type(&self) -> MessageType {
        self.header.msg_type
    }

    /// The STUN Transaction Identifier.
    pub fn transaction_id(&self) -> TransactionId {
        self.txid
    }

    /// The unrecognised comprehension-optional attributes, in wire order.
    /// Their codes are exactly the list that belongs in an
    /// `UNKNOWN-ATTRIBUTES` reply (RFC 8489 Section 14.13).
    pub fn unknown_optional(&self) -> &[UnknownAttribute] {
        &self.unknown
    }

    /// The codes of the unrecognised comprehension-optional attributes.
    pub fn unknown_optional_codes(&self) -> impl Iterator<Item = u16> + '_ {
        self.unknown.iter().map(|u| u.code)
    }

    /// The located `MESSAGE-INTEGRITY` trailer, when present.
    pub fn integrity(&self) -> Option<&AttributeLocation> {
        self.integrity_location.as_ref()
    }

    /// Whether a `MESSAGE-INTEGRITY` attribute is present.
    pub fn has_message_integrity(&self) -> bool {
        self.integrity_location.is_some()
    }

    /// Whether a `MESSAGE-INTEGRITY` attribute is present. Alias of
    /// [`Message::has_message_integrity`].
    pub fn has_integrity(&self) -> bool {
        self.has_message_integrity()
    }

    /// Whether a `FINGERPRINT` attribute is present.
    pub fn has_fingerprint(&self) -> bool {
        self.fingerprint_offset.is_some()
    }

    /// The offset of the `FINGERPRINT` attribute header, when present.
    pub fn fingerprint_offset(&self) -> Option<usize> {
        self.fingerprint_offset
    }

    /// The `FINGERPRINT` value, if present.
    pub fn fingerprint(&self) -> Option<u32> {
        match self.find(FINGERPRINT_CODE) {
            Some(Attribute::Fingerprint(v)) => Some(*v),
            _ => None,
        }
    }

    /// The `USERNAME` value, if present.
    pub fn username(&self) -> Option<&str> {
        match self.find(0x0006) {
            Some(Attribute::Username(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The `REALM` value, if present.
    pub fn realm(&self) -> Option<&str> {
        match self.find(0x0014) {
            Some(Attribute::Realm(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The `NONCE` value, if present.
    pub fn nonce(&self) -> Option<&str> {
        match self.find(0x0015) {
            Some(Attribute::Nonce(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The `SOFTWARE` value, if present.
    pub fn software(&self) -> Option<&str> {
        match self.find(0x8022) {
            Some(Attribute::Software(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The `XOR-MAPPED-ADDRESS` value, if present.
    pub fn xor_mapped_address(&self) -> Option<&crate::address::MappedAddress> {
        match self.find(0x0020) {
            Some(Attribute::XorMappedAddress(a)) => Some(a),
            _ => None,
        }
    }

    /// The `XOR-RELAYED-ADDRESS` value, if present.
    pub fn xor_relayed_address(&self) -> Option<&crate::address::MappedAddress> {
        match self.find(0x0016) {
            Some(Attribute::XorRelayedAddress(a)) => Some(a),
            _ => None,
        }
    }

    /// The `ERROR-CODE` value, if present.
    pub fn error(&self) -> Option<&crate::attribute::ErrorCode> {
        match self.find(0x0009) {
            Some(Attribute::ErrorCode(e)) => Some(e),
            _ => None,
        }
    }

    /// The `LIFETIME` value in seconds, if present.
    pub fn lifetime_secs(&self) -> Option<u32> {
        match self.find(0x000D) {
            Some(Attribute::Lifetime(v)) => Some(*v),
            _ => None,
        }
    }

    /// The `DATA` payload, if present.
    pub fn data_bytes(&self) -> Option<&[u8]> {
        match self.find(0x0013) {
            Some(Attribute::Data(v)) => Some(v),
            _ => None,
        }
    }

    /// The `CHANNEL-NUMBER` value, if present.
    pub fn channel_number(&self) -> Option<u16> {
        match self.find(0x000C) {
            Some(Attribute::ChannelNumber(v)) => Some(*v),
            _ => None,
        }
    }

    /// The `ICE-PRIORITY` value, if present.
    pub fn ice_priority(&self) -> Option<u32> {
        match self.find(0x0024) {
            Some(Attribute::IcePriority(v)) => Some(*v),
            _ => None,
        }
    }
}

/// The fixed 20-octet STUN header, decoded from a datagram (RFC 8489
/// Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    /// The STUN Message Type field.
    pub msg_type: MessageType,
    /// The Message Length field, in octets, excluding the 20-octet header.
    pub message_length: u16,
    /// The STUN Transaction Identifier.
    pub txid: TransactionId,
}

impl Header {
    /// Decode a header from the first 20 octets of a datagram.
    ///
    /// Checks the magic cookie, the message length field and the message type,
    /// but not the attribute list: use [`parse`] for that.
    pub fn parse(datagram: &[u8]) -> Result<Self, Error> {
        if datagram.len() < HEADER_LEN {
            return Err(Error::new(ErrorKind::TooShort));
        }
        let msg_type_bits = u16::from_be_bytes([datagram[0], datagram[1]]);
        let message_length = u16::from_be_bytes([datagram[LENGTH_OFFSET], datagram[3]]);
        let cookie = u32::from_be_bytes([
            datagram[MAGIC_COOKIE_OFFSET],
            datagram[MAGIC_COOKIE_OFFSET + 1],
            datagram[MAGIC_COOKIE_OFFSET + 2],
            datagram[MAGIC_COOKIE_OFFSET + 3],
        ]);
        if cookie != MAGIC_COOKIE {
            return Err(Error::new(ErrorKind::MagicCookie));
        }
        let mut txid = [0u8; TRANSACTION_ID_LEN];
        txid.copy_from_slice(&datagram[TRANSACTION_ID_OFFSET..HEADER_LEN]);
        let msg_type = MessageType::from_bits(msg_type_bits)
            .ok_or_else(|| Error::new(ErrorKind::MalformedAttribute))?;
        Ok(Header {
            msg_type,
            message_length,
            txid: TransactionId::from_bytes(txid),
        })
    }

    /// The datagram length this header implies, header included.
    pub const fn total_len(self) -> usize {
        HEADER_LEN + self.message_length as usize
    }

    /// The STUN Message Type field.
    pub const fn msg_type(self) -> MessageType {
        self.msg_type
    }

    /// The Message Length field.
    pub const fn message_length(self) -> u16 {
        self.message_length
    }

    /// The STUN Transaction Identifier.
    pub const fn transaction_id(self) -> TransactionId {
        self.txid
    }
}

/// Validate and parse a datagram.
///
/// The message length field is checked against the buffer, every attribute
/// value is decoded and range-checked, `FINGERPRINT` must be the final
/// attribute, and an unknown comprehension-required attribute is rejected.
/// Unrecognised comprehension-optional attributes are preserved in
/// [`Message::unknown_optional`].
#[inline]
pub fn parse(datagram: &[u8]) -> Result<Message, Error> {
    let header = Header::parse(datagram)?;
    if datagram.len() != header.total_len() {
        return Err(Error::new(ErrorKind::LengthMismatch));
    }
    let txid = header.txid;
    let txid_bytes = *txid.as_bytes();
    let mut attributes = Vec::new();
    let mut unknown: Vec<UnknownAttribute> = Vec::new();
    let mut fingerprint_offset: Option<usize> = None;
    let mut integrity_location: Option<AttributeLocation> = None;
    let mut off = HEADER_LEN;
    let mut count = 0usize;
    while off < datagram.len() {
        if count >= MAX_ATTRIBUTE_COUNT {
            return Err(Error::new(ErrorKind::TruncatedAttribute));
        }
        if datagram.len() - off < 4 {
            return Err(Error::new(ErrorKind::TrailingOctets));
        }
        let code = u16::from_be_bytes([datagram[off], datagram[off + 1]]);
        let value_len = usize::from(u16::from_be_bytes([datagram[off + 2], datagram[off + 3]]));
        let stride = 4 + value_len + (4 - value_len % 4) % 4;
        let end = off
            .checked_add(stride)
            .ok_or_else(|| Error::new(ErrorKind::LengthTooLarge))?;
        if end > datagram.len() {
            return Err(Error::new(ErrorKind::TruncatedAttribute));
        }
        let kind = AttrCode::attr_from_wire(code);
        // The MESSAGE-INTEGRITY-SHA256 length rule is structural, not a value
        // check: it must fail before the value is decoded, so a 3-octet tag is
        // reported as `MessageIntegritySha256Length`, not as a malformed value.
        if code == MESSAGE_INTEGRITY_SHA256_CODE
            && !((MESSAGE_INTEGRITY_SHA256_MIN_LEN
                    ..=crate::integrity::MESSAGE_INTEGRITY_SHA256_LEN)
                .contains(&value_len)
                && value_len.is_multiple_of(4))
        {
                return Err(Error::attr(
                    ErrorKind::MessageIntegritySha256Length,
                    MESSAGE_INTEGRITY_SHA256_CODE,
                ));
            }
        let value = &datagram[off + 4..off + 4 + value_len];
        let attr = parse_attribute_value(kind, value, &txid_bytes)?;
        match kind {
            AttributeKind::Unknown(c) => {
                if !is_comprehension_optional(kind) {
                    return Err(Error::attr(ErrorKind::UnknownRequired, c));
                }
                unknown.push(UnknownAttribute {
                    code: c,
                    kind,
                    value: Bytes::copy_from_slice(value),
                });
            }
            AttributeKind::Known(c) if is_trailer_only(kind) => match c {
                AttrCode::Fingerprint => {
                    if fingerprint_offset.is_some() {
                        return Err(Error::attr(ErrorKind::FingerprintNotLast, FINGERPRINT_CODE));
                    }
                    fingerprint_offset = Some(off);
                }
                AttrCode::MessageIntegritySha256 => {
                    if !((MESSAGE_INTEGRITY_SHA256_MIN_LEN
                            ..=crate::integrity::MESSAGE_INTEGRITY_SHA256_LEN)
                        .contains(&value_len)
                        && value_len.is_multiple_of(4))
                    {
                        return Err(Error::attr(
                            ErrorKind::MessageIntegritySha256Length,
                            MESSAGE_INTEGRITY_SHA256_CODE,
                        ));
                    }
                    if integrity_location.is_some() {
                        return Err(Error::attr(
                            ErrorKind::DuplicateAttribute,
                            MESSAGE_INTEGRITY_SHA256_CODE,
                        ));
                    }
                    integrity_location =
                        Some(AttributeLocation { off, code, value_len });
                }
                AttrCode::MessageIntegrity => {
                    if integrity_location.is_some() {
                        return Err(Error::attr(
                            ErrorKind::DuplicateAttribute,
                            MESSAGE_INTEGRITY_CODE,
                        ));
                    }
                    integrity_location =
                        Some(AttributeLocation { off, code, value_len });
                }
                _ => unreachable!("is_trailer_only covers only the three trailers"),
            },
            _ => {}
        }
        attributes.push(attr);
        count += 1;
        off = end;
    }
    if let Some(fp) = fingerprint_offset {
        if fp + 8 != datagram.len() {
            return Err(Error::attr(ErrorKind::FingerprintNotLast, FINGERPRINT_CODE));
        }
    }
    Ok(Message {
        header,
        txid,
        datagram_bytes: Bytes::copy_from_slice(datagram),
        attributes,
        unknown,
        integrity_location,
        fingerprint_offset,
    })
}

/// Validate and parse a datagram owned as a `Vec<u8>`.
#[inline]
pub fn parse_vec(datagram: Vec<u8>) -> Result<Message, Error> {
    parse(&datagram)
}

/// Validate and parse a datagram owned as a `bytes::Bytes`.
#[inline]
pub fn parse_bytes(datagram: Bytes) -> Result<Message, Error> {
    parse(&datagram)
}

/// Write the `message-length` field for a buffer of this size: the length
/// field excludes the 20-octet header (RFC 8489 §5.1). Fails when the body
/// would not fit in 16 bits.
fn set_length(out: &mut [u8]) -> Result<(), Error> {
    if out.len() < HEADER_LEN || out.len() - HEADER_LEN > u16::MAX as usize {
        return Err(Error::new(ErrorKind::LengthTooLarge));
    }
    let length = u16::try_from(out.len() - HEADER_LEN).expect("checked above");
    out[LENGTH_OFFSET..4].copy_from_slice(&length.to_be_bytes());
    Ok(())
}

/// Assemble a response datagram: the 20-octet header, one attribute per entry,
/// and a back-filled `message-length`.
///
/// `msg_type` is the full message-type field (class and method bits), `attrs`
/// are the body attributes to append after the header, and `integrity_key` /
/// `fingerprint` select the trailers, which are always the last attributes
/// (RFC 8489 §11.1). The trailers are optional: the caller supplies them as
/// plain attributes when they must be part of the attribute list, and passes
/// `None` to build an unauthenticated message.
///
/// Order matters and is fixed here so every caller gets the same result:
/// attributes, then `MESSAGE-INTEGRITY` (with the length field patched to the
/// end of that attribute while the HMAC is computed and restored afterwards),
/// then `FINGERPRINT` (whose CRC-32 covers the correct length field including
/// the `FINGERPRINT` attribute itself).
pub fn build_response(
    msg_type: u16,
    txid: &TransactionId,
    attrs: &[Attribute],
    integrity_key: Option<(&[u8], IntegrityAlgorithm)>,
    fingerprint: bool,
) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::with_capacity(HEADER_LEN + 256);
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // message-length, back-filled
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(txid.as_bytes());
    for a in attrs {
        // Emit the unpadded value length so the wire length field matches the
        // real value, then pad to the 4-octet boundary as RFC 8489 §3.1
        // requires: the length field records the real value length, not the
        // padded one.
        emit_attribute(&mut out, attribute_kind(a), a.to_value(txid.as_bytes())?.as_slice())?;
    }
    set_length(&mut out)?;
    if let Some((key, algorithm)) = integrity_key {
        // The length field must already describe the whole message,
        // `MESSAGE-INTEGRITY` included, before the HMAC is computed.
        let at = out.len();
        out.extend_from_slice(&algorithm.attribute_code().to_be_bytes());
        out.extend_from_slice(&(algorithm.mac_len() as u16).to_be_bytes());
        out.extend_from_slice(&vec![0u8; algorithm.mac_len()]);
        set_length(&mut out)?;
        compute_integrity(&mut out, at, algorithm, key)?;
    }
    if fingerprint {
        // Same for the CRC-32: the length field must include the
        // `FINGERPRINT` attribute itself (RFC 8489 §14.7).
        let at = out.len();
        out.extend_from_slice(&FINGERPRINT_CODE.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        set_length(&mut out)?;
        crate::fingerprint::compute(&mut out, at)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::MappedAddress;
    use crate::attribute::{emit_attribute, emit_attribute_value, is_registered, pad_len, ErrorCode};
    use crate::fingerprint::{attribute_offset as fingerprint_off, verify as verify_fp};
    use crate::integrity::{
        attribute_offset as integrity_off, compute as compute_integrity,
        integrity_pad_value_len, mac_input, verify as verify_integrity, IntegrityAlgorithm,
        MESSAGE_INTEGRITY_SHA256_LEN,
    };
    use crate::message_type::{Class, Method};

    const SECRET: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";
    const TXID_5769: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];
    const USERNAME_UTF8: [u8; 18] = [
        0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88, 0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82,
        0xaf, 0xe3, 0x82, 0xb9,
    ];

    // RFC 5769 Section 2.1, 108 octets: Binding request with SOFTWARE,
    // ICE-PRIORITY, ICE-CONTROLLED, USERNAME, MESSAGE-INTEGRITY, FINGERPRINT.
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

    // RFC 5769 Section 2.2, 80 octets: Binding success with SOFTWARE,
    // XOR-MAPPED-ADDRESS (IPv4), MESSAGE-INTEGRITY, FINGERPRINT.
    const RFC5769_2_2: [u8; 80] = [
        0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01,
        0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b,
        0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
        0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
        0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
        0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7,
        0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96
    ];

    // RFC 5769 Section 2.3, 92 octets: Binding success with XOR-MAPPED-ADDRESS
    // (IPv6), MESSAGE-INTEGRITY, FINGERPRINT.
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

    // RFC 5769 Section 2.4, 116 octets: long-term credential request with
    // USERNAME, NONCE, REALM, MESSAGE-INTEGRITY and no FINGERPRINT.
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

    fn cookie_at(buf: &[u8]) -> u32 {
        u32::from_be_bytes([
            buf[MAGIC_COOKIE_OFFSET],
            buf[MAGIC_COOKIE_OFFSET + 1],
            buf[MAGIC_COOKIE_OFFSET + 2],
            buf[MAGIC_COOKIE_OFFSET + 3],
        ])
    }

    /// Assemble a datagram: the 20-octet header, `body`, then a
    /// `MESSAGE-INTEGRITY` and, when asked, a `FINGERPRINT` trailer in the
    /// RFC 8489 Section 11.1 order, with the length field patched for each
    /// trailer.
    fn build_datagram(
        msg_type: u16,
        txid: &[u8; 12],
        body: &[u8],
        integrity_key: Option<&[u8]>,
        fingerprint: bool,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + body.len() + 8 + 32);
        out.extend_from_slice(&msg_type.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(txid);
        out.extend_from_slice(body);
        patch_length(&mut out);
        if let Some(key) = integrity_key {
            let at = out.len();
            out.extend_from_slice(&MESSAGE_INTEGRITY_CODE.to_be_bytes());
            out.extend_from_slice(&20u16.to_be_bytes());
            out.extend_from_slice(&[0u8; 20]);
            patch_length(&mut out);
            compute_integrity(&mut out, at, IntegrityAlgorithm::Sha1, key).unwrap();
        }
        if fingerprint {
            let at = out.len();
            out.extend_from_slice(&FINGERPRINT_CODE.to_be_bytes());
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&[0u8; 4]);
            patch_length(&mut out);
            crate::fingerprint::compute(&mut out, at).unwrap();
        }
        out
    }

    fn patch_length(out: &mut [u8]) {
        let total_len = out.len();
        let length = u16::try_from(total_len - HEADER_LEN).unwrap();
        out[LENGTH_OFFSET..4].copy_from_slice(&length.to_be_bytes());
    }

    fn body(attr: &Attribute, txid: &[u8; 12]) -> Vec<u8> {
        let mut out = Vec::new();
        emit_attribute_value(&mut out, attr, txid).unwrap();
        out
    }

    #[test]
    fn rfc5769_2_1_parses_byte_exact() {
        let msg = parse(&RFC5769_2_1).expect("2.1 must parse");
        assert_eq!(msg.datagram_bytes(), &RFC5769_2_1[..]);
        assert_eq!(msg.datagram_len(), 108);
        assert_eq!(msg.header().msg_type.bits(), 0x0001);
        assert_eq!(msg.header().message_length, 0x58);
        assert_eq!(msg.header().total_len(), 108);
        assert_eq!(msg.msg_type().class(), Class::Request);
        // 0x0001 is a Binding request: method 0x001 with the class bits zero.
        assert_eq!(msg.msg_type().method(), Method::Binding);
        assert_eq!(&msg.transaction_id().as_bytes()[..], &TXID_5769[..]);
        assert_eq!(msg.transaction_id().to_string(), "b7e7a701bc34d686fa87dfae");
        assert_eq!(msg.len(), 6);
        assert!(!msg.is_empty());
        assert_eq!(msg.get(0), Some(&Attribute::Software("STUN test client".to_string())));
        assert_eq!(msg.get(1), Some(&Attribute::IcePriority(0x6e00_01ff)));
        assert_eq!(
            msg.get(2),
            Some(&Attribute::IceControlled([
                0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36
            ]))
        );
        assert_eq!(msg.get(3), Some(&Attribute::Username("evtj:h6vY".to_string())));
        assert_eq!(
            msg.get(4),
            Some(&Attribute::MessageIntegrity([
                0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2,
                0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2
            ]))
        );
        assert_eq!(msg.get(5), Some(&Attribute::Fingerprint(0xe57a_3bcf)));
        assert!(msg.get(6).is_none());
        assert_eq!(msg.username(), Some("evtj:h6vY"));
        assert_eq!(msg.software(), Some("STUN test client"));
        assert_eq!(msg.ice_priority(), Some(0x6e00_01ff));
        assert_eq!(msg.fingerprint(), Some(0xe57a_3bcf));
        assert_eq!(msg.fingerprint_offset(), Some(100));
        assert!(msg.has(0x0006));
        assert!(msg.has(0x8029));
        assert!(msg.has(FINGERPRINT_CODE));
        assert!(msg.has(0x0008));
        assert!(!msg.has(0x0021));
        assert!(msg.integrity().is_some());
        assert!(msg.has_integrity());
        assert!(msg.has_message_integrity());
        assert!(msg.has_fingerprint());
        assert!(msg.unknown_optional().is_empty());
        assert!(msg.find(0x0006).is_some());
        assert!(msg.find(0x8022).is_some());
        // RFC 5769 Section 2.1 carries no XOR-encoded address attribute, so no
        // attribute here needs the transaction identifier.
        assert!(!msg.attributes().iter().any(|a| a.needs_txid()));
        assert!(msg.attributes().iter().all(|a| !a.needs_txid()));
        assert!(msg.error().is_none());
        assert!(msg.xor_relayed_address().is_none());
        assert!(msg.lifetime_secs().is_none());
        assert!(msg.data_bytes().is_none());
        assert!(msg.channel_number().is_none());
        assert!(msg.realm().is_none());
        assert!(msg.nonce().is_none());
        let _ = msg.clone();
    }

    #[test]
    fn rfc5769_2_1_is_reproduced_by_the_encoders() {
        let mut buf = RFC5769_2_1;
        let at = integrity_off(&buf).unwrap();
        assert_eq!(at.off, 76);
        assert_eq!(at.code, 0x0008);
        assert_eq!(at.value_len, 20);
        assert_eq!(at.algorithm(), Some(IntegrityAlgorithm::Sha1));
        assert!(!at.is_last(&buf));
        assert_eq!(fingerprint_off(&buf), Some(100));
        let input = mac_input(&buf, at.off, 20).unwrap();
        assert_eq!(input.len(), 76);
        assert_eq!(&input[LENGTH_OFFSET..4], &[0x00, 0x50]);
        // Recompute over a copy with a dummy tag and check the stored octets
        // come back byte for byte.
        buf[80..100].fill(0xff);
        let tag = compute_integrity(&mut buf, at.off, IntegrityAlgorithm::Sha1, SECRET).unwrap();
        assert_eq!(&buf[80..100], &tag[..20]);
        assert_eq!(&buf[80..100], &RFC5769_2_1[80..100]);
        assert_eq!(
            crate::fingerprint::compute(&mut buf, 100).unwrap().bits(),
            0xe57a_3bcf
        );
        assert_eq!(&buf[..], &RFC5769_2_1[..]);
        assert!(verify_integrity(&buf, at.off, IntegrityAlgorithm::Sha1, SECRET).is_ok());
        assert!(verify_fp(&buf, 100).is_ok());
        assert_eq!(
            crate::integrity::short_term_key(SECRET),
            SECRET
        );
        assert_eq!(integrity_pad_value_len(4), 0);
        assert_eq!(integrity_pad_value_len(0), 0);
        assert_eq!(integrity_pad_value_len(6), 2);
        assert_eq!(integrity_pad_value_len(16), 0);
    }

    #[test]
    fn rfc5769_2_2_parses_byte_exact() {
        let msg = parse(&RFC5769_2_2).expect("2.2 must parse");
        assert_eq!(msg.datagram_len(), 80);
        assert_eq!(msg.datagram_bytes(), &RFC5769_2_2[..]);
        assert_eq!(msg.header().message_length, 0x3c);
        assert_eq!(msg.header().total_len(), 80);
        assert_eq!(msg.msg_type().bits(), 0x0101);
        assert_eq!(msg.msg_type().class(), Class::SuccessResponse);
        assert!(msg.msg_type().is_response());
        assert!(!msg.msg_type().is_request());
        assert!(!msg.msg_type().class().is_indication());
        assert!(msg.msg_type().error_response_type().is_none());
        assert!(msg.msg_type().success_response_type().is_none());
        assert!(!msg.msg_type().can_reply_420());
        assert!(msg.msg_type().unknown_attribute_reply_type().is_none());
        assert_eq!(&msg.transaction_id().as_bytes()[..], &TXID_5769[..]);
        assert!(msg.transaction_id().as_bytes() == msg.transaction_id().as_ref());
        assert!(msg.transaction_id().as_ref().len() == 12);
        assert_eq!(msg.len(), 4);
        assert!(!msg.is_empty());
        assert_eq!(msg.get(0), Some(&Attribute::Software("test vector".to_string())));
        assert_eq!(msg.get(1), Some(&Attribute::XorMappedAddress(MappedAddress::from_ipv4(192, 0, 2, 1, 32853))));
        assert_eq!(
            msg.xor_mapped_address().unwrap().to_string(),
            "192.0.2.1:32853"
        );
        assert_eq!(
            msg.get(2),
            Some(&Attribute::MessageIntegrity([
                0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a,
                0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7
            ]))
        );
        assert_eq!(msg.get(3), Some(&Attribute::Fingerprint(0xc07d_4c96)));
        assert!(msg.get(4).is_none());
        assert!(msg.get(1).unwrap().needs_txid());
        assert!(!msg.get(0).unwrap().needs_txid());
        assert!(!msg.get(2).unwrap().needs_txid());
        assert!(!msg.get(3).unwrap().needs_txid());
        assert_eq!(msg.software(), Some("test vector"));
        assert_eq!(msg.fingerprint(), Some(0xc07d_4c96));
        assert_eq!(msg.fingerprint_offset(), Some(72));
        assert!(msg.has_message_integrity());
        assert!(msg.has_integrity());
        assert!(msg.has_fingerprint());
        assert!(msg.integrity().is_some());
        assert!(msg.unknown_optional().is_empty());
        assert!(msg.username().is_none());
        assert!(msg.realm().is_none());
        let _ = msg.clone();
    }

    #[test]
    fn rfc5769_2_2_verifies_with_a_short_term_key() {
        let mut buf = RFC5769_2_2;
        let loc = integrity_off(&buf).unwrap();
        assert_eq!(loc.off, 48);
        assert_eq!(loc.code, 0x0008);
        assert_eq!(loc.value_len, 20);
        let input = mac_input(&buf, loc.off, 20).unwrap();
        assert_eq!(input.len(), 48);
        assert_eq!(&input[LENGTH_OFFSET..4], &[0x00, 0x34]);
        let computed = compute_integrity(&mut buf, loc.off, IntegrityAlgorithm::Sha1, SECRET)
            .unwrap();
        assert_eq!(&computed[..20], &RFC5769_2_2[loc.off + 4..loc.off + 24]);
        assert_eq!(buf, RFC5769_2_2);
        assert!(verify_integrity(&buf, loc.off, IntegrityAlgorithm::Sha1, SECRET).is_ok());
        assert!(verify_integrity(&buf, loc.off, IntegrityAlgorithm::Sha1, b"wrong").is_err());
        assert!(verify_fp(&buf, 72).is_ok());
        assert!(fingerprint_off(&buf).is_some());
        assert!(AttributeLocation { off: loc.off, code: loc.code, value_len: loc.value_len }
            == loc);
        assert!(format!("{loc:?}").contains("48"));
        let fp_msg = parse(&buf).unwrap();
        assert!(fp_msg.has_message_integrity());
        assert!(fp_msg.integrity().is_some());
        assert_eq!(fp_msg.integrity().unwrap().off, 48);
    }

    #[test]
    fn rfc5769_2_3_parses_byte_exact() {
        let msg = parse(&RFC5769_2_3).expect("2.3 must parse");
        assert_eq!(msg.datagram_len(), 92);
        assert_eq!(msg.datagram_bytes(), &RFC5769_2_3[..]);
        assert_eq!(msg.header().message_length, 0x48);
        assert_eq!(msg.header().total_len(), 92);
        assert_eq!(msg.msg_type().bits(), 0x0101);
        assert!(msg.msg_type().is_response());
        assert_eq!(&msg.transaction_id().as_bytes()[..], &TXID_5769[..]);
        assert_eq!(msg.len(), 4);
        assert!(!msg.is_empty());
        assert_eq!(msg.get(0), Some(&Attribute::Software("test vector".to_string())));
        assert_eq!(msg.software(), Some("test vector"));
        assert_eq!(msg.get(1), Some(&Attribute::XorMappedAddress(MappedAddress::from_ipv6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22, 0x33, 0x44,
                0x55, 0x66, 0x77
            ],
            32853
        ))));
        assert_eq!(msg.xor_mapped_address().unwrap().port, 32853);
        assert_eq!(
            msg.xor_mapped_address().unwrap().ipv6(),
            Some([
                0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22, 0x33, 0x44,
                0x55, 0x66, 0x77
            ])
        );
        assert!(msg.xor_mapped_address().unwrap().ipv4().is_none());
        assert!(msg.xor_relayed_address().is_none());
        assert_eq!(
            msg.get(2),
            Some(&Attribute::MessageIntegrity([
                0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c, 0x82,
                0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41
            ]))
        );
        assert_eq!(msg.get(3), Some(&Attribute::Fingerprint(0xc8fb_0b4c)));
        assert!(msg.get(4).is_none());
        assert!(!msg.get(0).unwrap().needs_txid());
        assert!(msg.get(1).unwrap().needs_txid());
        assert!(msg.has_fingerprint());
        assert!(msg.has_integrity());
        assert!(msg.integrity().is_some());
        assert_eq!(msg.fingerprint(), Some(0xc8fb_0b4c));
        assert_eq!(msg.fingerprint_offset(), Some(84));
        assert!(msg.username().is_none());
        let _ = msg.clone();
    }

    #[test]
    fn rfc5769_2_3_verifies_with_a_short_term_key() {
        let buf = RFC5769_2_3;
        let loc = integrity_off(&buf).unwrap();
        assert_eq!(loc.off, 60);
        assert_eq!(loc.value_len, 20);
        assert!(loc.algorithm().is_some());
        assert!(!loc.is_last(&buf));
        assert!(verify_integrity(&buf, loc.off, IntegrityAlgorithm::Sha1, SECRET).is_ok());
        assert!(verify_fp(&buf, 84).is_ok());
        let input = mac_input(&buf, loc.off, 20).unwrap();
        assert_eq!(input.len(), 60);
        assert_eq!(&input[LENGTH_OFFSET..4], &[0x00, 0x40]);
        assert!(fingerprint_off(&buf) == Some(84));
        assert!(AttributeLocation { off: loc.off, code: loc.code, value_len: loc.value_len }
            == loc);
        let _fp = AttributeKind::Known(AttrCode::Fingerprint);
    }

    #[test]
    fn rfc5769_2_4_parses_byte_exact() {
        let msg = parse(&RFC5769_2_4).expect("2.4 must parse");
        assert_eq!(msg.datagram_len(), 116);
        assert_eq!(msg.datagram_bytes(), &RFC5769_2_4[..]);
        assert_eq!(msg.header().message_length, 0x60);
        assert_eq!(msg.header().total_len(), 116);
        assert_eq!(msg.msg_type().bits(), 0x0001);
        assert_eq!(msg.msg_type().class(), Class::Request);
        assert!(msg.msg_type().is_request());
        assert!(msg.msg_type().success_response_type().is_some());
        assert!(msg.msg_type().error_response_type().is_some());
        assert!(msg.msg_type().can_reply_420());
        assert!(msg.msg_type().unknown_attribute_reply_type().is_some());
        assert_eq!(
            msg.transaction_id().as_bytes(),
            &[
                0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e
            ]
        );
        assert_eq!(msg.transaction_id().to_string(), "78ad3433c6ad72c029da412e");
        assert_eq!(msg.len(), 4);
        assert!(!msg.is_empty());
        assert_eq!(msg.username(), Some("マトリックス"));
        assert_eq!(msg.realm(), Some("example.org"));
        assert_eq!(msg.nonce(), Some("f//499k954d6OL34oL9FSTvy64sA"));
        assert!(msg.has_message_integrity());
        assert!(msg.has_integrity());
        assert!(msg.integrity().is_some());
        assert!(!msg.has_fingerprint());
        assert!(msg.fingerprint().is_none());
        assert!(msg.fingerprint_offset().is_none());
        assert!(msg.xor_mapped_address().is_none());
        assert!(msg.xor_relayed_address().is_none());
        assert!(msg.error().is_none());
        assert!(msg.unknown_optional().is_empty());
        let _ = msg.clone();
    }

    #[test]
    fn rfc5769_2_4_verifies_with_a_long_term_key() {
        let buf = RFC5769_2_4;
        let loc = integrity_off(&buf).unwrap();
        assert_eq!(loc.off, 92);
        assert_eq!(loc.code, 0x0008);
        assert_eq!(loc.value_len, 20);
        assert!(loc.algorithm().is_some());
        assert!(loc.is_last(&buf));
        let key = crate::integrity::long_term_key(&USERNAME_UTF8, b"example.org", b"TheMatrIX");
        // RFC 5769 Section 2.4: MD5("マトリックス:example.org:TheMatrIX").
        assert_eq!(
            key,
            [
                0xe8, 0xca, 0x7a, 0xd5, 0x9d, 0x5e, 0xb0, 0x51, 0x8e, 0x31, 0x29, 0x11, 0xd2,
                0xda, 0xb2, 0xa9
            ]
        );
        assert!(verify_integrity(&buf, loc.off, IntegrityAlgorithm::Sha1, &key).is_ok());
        assert!(verify_integrity(&buf, loc.off, IntegrityAlgorithm::Sha1, SECRET).is_err());
        assert!(verify_integrity(&buf, loc.off, IntegrityAlgorithm::Sha1, b"").is_err());
        let input = mac_input(&buf, loc.off, 20).unwrap();
        assert_eq!(input.len(), 92);
        assert_eq!(&input[LENGTH_OFFSET..4], &[0x00, 0x60]);
        assert!(fingerprint_off(&buf).is_none());
        let mut tampered = buf;
        tampered[24] ^= 0x01;
        assert!(verify_integrity(&tampered, loc.off, IntegrityAlgorithm::Sha1, &key).is_err());
        let msg = parse(&buf).unwrap();
        assert!(msg.integrity().is_some());
        assert_eq!(msg.integrity().unwrap().code, 0x0008);
        assert_eq!(msg.integrity().unwrap().value_len, 20);
        assert!(msg.has_integrity());
        assert_eq!(
            msg.get(3),
            Some(&Attribute::MessageIntegrity([
                0xf6, 0x70, 0x24, 0x65, 0x6d, 0xd6, 0x4a, 0x3e, 0x02, 0xb8, 0xe0, 0x71, 0x2e,
                0x85, 0xc9, 0xa2, 0x8c, 0xa8, 0x96, 0x66
            ]))
        );
        let _ = msg.clone();
    }

    #[test]
    fn header_parse_reads_every_field() {
        let h = Header::parse(&RFC5769_2_2).unwrap();
        assert_eq!(h.message_length, 0x3c);
        assert_eq!(h.total_len(), 80);
        assert_eq!(h.msg_type.bits(), 0x0101);
        assert_eq!(h.msg_type(), h.msg_type);
        assert_eq!(h.message_length(), h.message_length);
        assert_eq!(h.transaction_id(), h.txid);
        assert_eq!(&h.transaction_id().as_bytes()[..], &TXID_5769[..]);
        assert!(h.msg_type().is_response());
        assert_eq!(h.msg_type().class(), Class::SuccessResponse);
        assert!(format!("{h:?}").contains("60"), "message_length is 0x3c = 60");
        let h2 = Header::parse(&RFC5769_2_4).unwrap();
        assert_eq!(h2.message_length(), 0x60);
        assert_eq!(h2.total_len(), 116);
        assert!(h2.msg_type().is_request());
        assert!(h2.msg_type().class().is_request());
        assert_eq!(h2.transaction_id().as_bytes(), &[
            0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e
        ]);
        let h3 = Header::parse(&RFC5769_2_1).unwrap();
        assert!(h3.msg_type().is_request());
        assert!(h3.msg_type().can_reply_420());
        assert!(h3.msg_type().unknown_attribute_reply_type().is_some());
        let h4 = Header::parse(&RFC5769_2_3).unwrap();
        assert_eq!(h4.msg_type().bits(), 0x0101);
        assert!(h4.msg_type().is_response());
        assert!(h4.msg_type().class().is_response());
        assert!(!h4.msg_type().is_request());
        let txid = h.transaction_id();
        assert!(txid == h.transaction_id());
        assert!(!txid.eq(&TransactionId::default()));
        assert!(format!("{txid:?}").contains("b7e7a701bc34d686fa87dfae"));
        assert_eq!(txid.to_string(), "b7e7a701bc34d686fa87dfae");
        assert_eq!(txid.as_ref(), &txid.as_bytes()[..]);
        assert_eq!(txid.as_ref().len(), 12);
        assert!(*txid.as_bytes() == TXID_5769);
        assert!(txid == TransactionId::from_bytes(TXID_5769));
        let _ = txid;
    }

    #[test]
    fn header_parse_rejects_a_bad_magic_cookie() {
        let mut buf = RFC5769_2_2;
        for at in 0..4 {
            let i = MAGIC_COOKIE_OFFSET + at;
            buf[i] ^= 0x01;
            let err = Header::parse(&buf).unwrap_err();
            assert_eq!(err.kind, ErrorKind::MagicCookie);
            assert!(err.attribute.is_none());
            let _ = parse(&buf).unwrap_err();
            buf[i] ^= 0x01;
        }
        assert!(cookie_at(&RFC5769_2_2) == MAGIC_COOKIE);
        for at in 0..4 {
            let i = MAGIC_COOKIE_OFFSET + at;
            buf[i] ^= 0xff;
            assert_eq!(Header::parse(&buf).unwrap_err().kind, ErrorKind::MagicCookie);
            buf[i] ^= 0xff;
        }
    }

    #[test]
    fn header_parse_rejects_reserved_message_types() {
        // The method field is 12 bits wide and `C1C0` occupy two more, so only
        // field bits 14 and 15 are significant-free: they sit in the top two
        // bits of the first octet and MUST be zero (RFC 8489 Section 5). The
        // second octet holds bits 0..=7, all of them in use.
        for octet0_hi in [0x40u8, 0x80, 0xC0] {
            let mut buf = RFC5769_2_2;
            buf[0] |= octet0_hi;
            let err = Header::parse(&buf).unwrap_err();
            assert_eq!(err.kind, ErrorKind::MalformedAttribute, "{octet0_hi:#04x}");
            assert!(err.attribute.is_none(), "{octet0_hi:#04x}");
            let _ = parse(&buf).unwrap_err();
        }
        // Every bit of the second octet is significant, so setting them is
        // legal: they renumber the method rather than violating the field.
        let mut buf = RFC5769_2_2;
        buf[1] |= 0x80;
        assert!(Header::parse(&buf).is_ok());
        // A reserved *method number* is still a legal message type: 0x0000
        // uses method number zero, which the registry marks reserved.
        let mut zero = RFC5769_2_2;
        zero[0] = 0x00;
        zero[1] = 0x00;
        assert_eq!(Header::parse(&zero).unwrap().msg_type(), MessageType::from_bits(0x0000).unwrap());
        // The RFC 5769 vectors are legal under the RFC 8489 numbering.
        assert!(Header::parse(&RFC5769_2_1).is_ok());
        assert!(Header::parse(&RFC5769_2_3).is_ok());
    }

    #[test]
    fn header_parse_rejects_short_datagrams() {
        for n in 0..HEADER_LEN {
            let buf = vec![0u8; n];
            assert_eq!(Header::parse(&buf).unwrap_err().kind, ErrorKind::TooShort);
            assert_eq!(parse(&buf).unwrap_err().kind, ErrorKind::TooShort);
        }
    }

    #[test]
    fn parse_rejects_a_message_length_mismatch() {
        let mut buf = RFC5769_2_2;
        buf[3] -= 1;
        assert_eq!(parse(&buf).unwrap_err().kind, ErrorKind::LengthMismatch);
        buf[3] += 2;
        assert_eq!(parse(&buf).unwrap_err().kind, ErrorKind::LengthMismatch);
        let mut buf2 = RFC5769_2_2.to_vec();
        buf2.push(0x00);
        assert_eq!(parse(&buf2).unwrap_err().kind, ErrorKind::LengthMismatch);
        let mut buf3 = [0u8; 24];
        buf3[MAGIC_COOKIE_OFFSET..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf3[LENGTH_OFFSET..4].copy_from_slice(&0xffff_u16.to_be_bytes());
        assert_eq!(parse(&buf3).unwrap_err().kind, ErrorKind::LengthMismatch);
        let mut buf4 = [0u8; HEADER_LEN + 8];
        buf4[MAGIC_COOKIE_OFFSET..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf4[LENGTH_OFFSET..4].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(parse(&buf4).unwrap_err().kind, ErrorKind::LengthMismatch);
        let mut buf5 = [0u8; 40];
        buf5[MAGIC_COOKIE_OFFSET..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf5[LENGTH_OFFSET..4].copy_from_slice(&65535_u16.to_be_bytes());
        assert_eq!(parse(&buf5).unwrap_err().kind, ErrorKind::LengthMismatch);
        let _ = MAX_MESSAGE_LENGTH;
        let _ = MAX_DATAGRAM;
    }

    #[test]
    fn parse_rejects_trailing_octets() {
        let txid = TransactionId::default();
        let t = txid.as_bytes();
        // One attribute (4 header + 3 value + 1 pad) followed by a 3-octet
        // tail: shorter than an attribute header, so the walk must fail on it
        // rather than reading a partial attribute (RFC 8489 Section 3.1).
        let mut body_bytes = Vec::new();
        body_bytes.extend_from_slice(&0x8021_u16.to_be_bytes());
        body_bytes.extend_from_slice(&3u16.to_be_bytes());
        body_bytes.extend_from_slice(&[1u8, 2, 3]);
        body_bytes.extend_from_slice(&[0u8; 1]);
        body_bytes.extend_from_slice(&[0u8; 3]);
        let datagram = build_datagram(0x0000, t, &body_bytes, None, false);
        assert_eq!(datagram.len(), 31);
        assert_eq!(parse(&datagram).unwrap_err().kind, ErrorKind::TrailingOctets);
        // A message length that over-declares the buffer fails earlier, at the
        // header, as a length mismatch.
        let mut datagram2 = datagram.clone();
        let declared = u16::from_be_bytes([datagram2[LENGTH_OFFSET], datagram2[LENGTH_OFFSET + 1]]) + 20;
        datagram2[LENGTH_OFFSET..4].copy_from_slice(&declared.to_be_bytes());
        assert_eq!(parse(&datagram2).unwrap_err().kind, ErrorKind::LengthMismatch);
        // ...and an under-declared length does the same.
        let mut datagram3 = datagram.clone();
        let declared3 = u16::from_be_bytes([datagram3[LENGTH_OFFSET], datagram3[LENGTH_OFFSET + 1]]) - 1;
        datagram3[LENGTH_OFFSET..4].copy_from_slice(&declared3.to_be_bytes());
        assert_eq!(parse(&datagram3).unwrap_err().kind, ErrorKind::LengthMismatch);
    }

    #[test]
    fn parse_rejects_truncated_attributes() {
        let txid = TransactionId::default();
        let t = txid.as_bytes();
        let body = body(&Attribute::Username("evtj:h6vY".to_string()), t);
        let datagram = build_datagram(0x0000, t, &body, None, false);
        // Inflate the USERNAME value length to 0x1008 while leaving the message
        // length field alone: the attribute now reaches past the end of the
        // declared payload (RFC 8489 Section 3.1).
        let mut bad = datagram.clone();
        bad[22] = 0x10;
        bad[23] = 0x08;
        assert_eq!(parse(&bad).unwrap_err().kind, ErrorKind::TruncatedAttribute);
        // ...and the same attribute with an under-declared message length is a
        // buffer/length disagreement instead.
        let mut short = bad.clone();
        short.truncate(short.len() - 1);
        assert_eq!(parse(&short).unwrap_err().kind, ErrorKind::LengthMismatch);
    }

    #[test]
    fn parse_rejects_an_unknown_comprehension_required_attribute() {
        let txid = TransactionId::default();
        let t = txid.as_bytes();
        let body = body(&Attribute::Username("evtj:h6vY".to_string()), t);
        let mut unknown = Vec::new();
        unknown.extend_from_slice(&0x000b_u16.to_be_bytes());
        unknown.extend_from_slice(&2u16.to_be_bytes());
        unknown.extend_from_slice(&[1u8, 2]);
        unknown.extend_from_slice(&body);
        let datagram = build_datagram(0x0000, t, &unknown, None, false);
        let err = parse(&datagram).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnknownRequired);
        assert_eq!(err.attribute, Some(0x000b));
        assert!(err.to_string().contains("0x000b"));
        assert!(format!("{err:?}").contains("UnknownRequired"));
        let io_err: std::io::Error = err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
        assert!(std::error::Error::source(&err).is_none());
        assert!(std::error::Error::source(&io_err).is_none());
        let err2 = parse(&[0u8; 10]).unwrap_err();
        assert!(err2.to_string().contains("STUN codec error"));
        assert!(!err2.to_string().contains("0x"));
        // The reply for it uses the request's method number and error code 420
        // (RFC 8489 Section 6.3.1), not the Unknown-Attributes method family.
        let reply = MessageType::BINDING_REQUEST.unknown_attribute_reply_type().unwrap();
        assert_eq!(reply.bits(), 0x0111);
        assert!(reply.class().is_response());
        assert!(reply.method() == Method::Binding);
        assert!(MessageType::BINDING_REQUEST.can_reply_420());
        assert!(!MessageType::BINDING_SUCCESS.can_reply_420());
        assert!(MessageType::BINDING_SUCCESS
            .unknown_attribute_reply_type()
            .is_none());
        assert!(crate::attribute::error_code::unknown_attribute().to_string().starts_with("420"));
        assert!(crate::attribute::error_code::stale_nonce().to_string().starts_with("438"));
    }

    #[test]
    fn unknown_comprehension_optional_attributes_are_preserved() {
        let txid = TransactionId::default();
        let t = txid.as_bytes();
        let body = body(&Attribute::Username("evtj:h6vY".to_string()), t);
        let mut unknown = Vec::new();
        unknown.extend_from_slice(&0x8005_u16.to_be_bytes());
        unknown.extend_from_slice(&4u16.to_be_bytes());
        unknown.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        unknown.extend_from_slice(&body);
        let datagram = build_datagram(0x0000, t, &unknown, None, false);
        let msg = parse(&datagram).unwrap();
        // The preserved attribute is part of the parsed list, so the message
        // carries two attributes: the unknown one first, then USERNAME.
        assert_eq!(msg.len(), 2);
        assert!(!msg.is_empty());
        assert_eq!(
            msg.get(0),
            Some(&Attribute::Unknown {
                kind: 0x8005,
                value: vec![0xde, 0xad, 0xbe, 0xef]
            })
        );
        assert_eq!(msg.get(1), Some(&Attribute::Username("evtj:h6vY".to_string())));
        assert!(msg.get(2).is_none());
        assert!(msg.has(0x8005));
        assert!(msg.has(0x0006));
        assert!(!msg.has(0x0005));
        assert_eq!(msg.unknown_optional().len(), 1);
        assert_eq!(msg.unknown_optional()[0].code, 0x8005);
        assert_eq!(msg.unknown_optional()[0].kind, AttributeKind::Unknown(0x8005));
        assert_eq!(
            msg.unknown_optional()[0].value,
            Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef][..])
        );
        assert!(msg.unknown_optional_codes().eq([0x8005u16].iter().copied()));
        assert!(msg.integrity().is_none());
        assert!(msg.fingerprint().is_none());
        let other = msg.unknown_optional()[0].clone();
        assert_eq!(other, msg.unknown_optional()[0]);
        let _ = msg.clone();
    }

    #[test]
    fn integrity_and_fingerprint_tampering_is_detected() {
        let mut buf = RFC5769_2_2;
        buf[30] ^= 0x01;
        assert!(parse(&buf).is_ok());
        assert!(verify_integrity(&buf, 48, IntegrityAlgorithm::Sha1, SECRET).is_err());
        assert!(verify_fp(&buf, 72).is_err());
        let err = verify_fp(&buf, 72).unwrap_err();
        assert_eq!(err.kind, ErrorKind::FingerprintMismatch);
        assert!(err.to_string().contains("FINGERPRINT"));
        assert!(format!("{err:?}").contains("FingerprintMismatch"));
        let mut buf2 = RFC5769_2_2;
        buf2[52] ^= 0x01;
        assert!(parse(&buf2).is_ok());
        let err2 = verify_integrity(&buf2, 48, IntegrityAlgorithm::Sha1, SECRET).unwrap_err();
        assert_eq!(err2.kind, ErrorKind::MessageIntegrityMismatch);
        assert!(err2.to_string().contains("MESSAGE-INTEGRITY"));
        assert!(format!("{err2:?}").contains("MessageIntegrityMismatch"));
        let err3 = verify_integrity(&buf2, 48, IntegrityAlgorithm::Sha1, SECRET).unwrap_err();
        assert_eq!(err3, err2);
        let _ = err3;
    }

    #[test]
    fn fingerprint_must_be_the_final_attribute() {
        let txid = TransactionId::default();
        let t = txid.as_bytes();
        let mut body_bytes = Vec::new();
        body_bytes.extend_from_slice(&FINGERPRINT_CODE.to_be_bytes());
        body_bytes.extend_from_slice(&4u16.to_be_bytes());
        body_bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        body_bytes.extend_from_slice(&body(&Attribute::Software("s".to_string()), t));
        let datagram = build_datagram(0x0000, t, &body_bytes, None, false);
        // The FINGERPRINT is the first attribute here, so its header starts
        // right after the 20-octet STUN header. The body is the 8-octet
        // FINGERPRINT plus the 8-octet SOFTWARE attribute: 20 + 16 = 36.
        assert_eq!(datagram.len(), 36);
        assert_eq!(fingerprint_off(&datagram), Some(20));
        let err = parse(&datagram).unwrap_err();
        assert_eq!(err.kind, ErrorKind::FingerprintNotLast);
        assert_eq!(err.attribute, Some(FINGERPRINT_CODE));
        assert!(err.to_string().contains("0x8028"));
        assert!(format!("{err:?}").contains("FingerprintNotLast"));
    }

    #[test]
    fn build_response_reproduces_rfc5769_2_2() {
        // The reference vector must be reproducible byte for byte: SOFTWARE,
        // XOR-MAPPED-ADDRESS (IPv4), MESSAGE-INTEGRITY, FINGERPRINT.
        // The SOFTWARE value is 11 octets, padded to a 4-octet boundary by
        // `emit_attribute`; the length field records the unpadded 11.
        let txid = TransactionId::from_bytes(TXID_5769);
        let attrs = [
            Attribute::Software("test vector".to_string()),
            Attribute::XorMappedAddress(MappedAddress::from_ipv4(192, 0, 2, 1, 32853)),
        ];
        let out = build_response(
            MessageType::BINDING_SUCCESS.bits(),
            &txid,
            &attrs,
            Some((SECRET, IntegrityAlgorithm::Sha1)),
            true,
        )
        .unwrap();
        assert_eq!(out.len(), 80);
        // Every framing octet matches the reference vector except the SOFTWARE
        // pad octet at 35: RFC 8489 Section 3.1 says pad octets are ignored by
        // the receiver, so this crate writes zeros while RFC 5769 happens to
        // print 0x20 in that slot. Both trailers cover the pad octet, so they
        // follow from it.
        assert_eq!(out[..35], RFC5769_2_2[..35]);
        assert_eq!(out[36..48], RFC5769_2_2[36..48]);
        assert_eq!(out[35], 0x00, "this crate pads with zeros");
        assert_eq!(RFC5769_2_2[35], 0x20);
        // Substituting the RFC 5769 pad octet reproduces the vector byte for
        // byte, which pins both the layout and the trailer computation.
        let mut rfc = out.clone();
        rfc[35] = 0x20;
        compute_integrity(&mut rfc, 48, IntegrityAlgorithm::Sha1, SECRET).unwrap();
        crate::fingerprint::compute(&mut rfc, 72).unwrap();
        assert_eq!(rfc, RFC5769_2_2);
        // And the rebuilt datagram parses back to the same facts.
        let msg = parse(&out).unwrap();
        assert_eq!(msg.len(), 4);
        assert_eq!(msg.fingerprint(), Some(crate::fingerprint::Fingerprint::over(&out[..72]).bits()));
        assert!(verify_integrity(&out, 48, IntegrityAlgorithm::Sha1, SECRET).is_ok());
        assert!(verify_fp(&out, 72).is_ok());
    }

    #[test]
    fn build_response_without_trailers_leaves_an_unauthenticated_message() {
        let txid = TransactionId::from_bytes([7u8; 12]);
        let attrs = [Attribute::Lifetime(300), Attribute::Software("quickrelay".to_string())];
        let out = build_response(MessageType::BINDING_SUCCESS.bits(), &txid, &attrs, None, false).unwrap();
        assert_eq!(out.len(), 44);
        assert_eq!(&out[0..2], &0x0101u16.to_be_bytes());
        assert_eq!(&out[2..4], &24u16.to_be_bytes());
        assert_eq!(&out[4..8], &MAGIC_COOKIE.to_be_bytes());
        let msg = parse(&out).unwrap();
        assert_eq!(msg.len(), 2);
        assert!(!msg.has_message_integrity());
        assert!(!msg.has_fingerprint());
        assert_eq!(msg.lifetime_secs(), Some(300));
        assert_eq!(msg.software(), Some("quickrelay"));
        // The `message-length` field counts the body only, not the header.
        assert_eq!(msg.header().message_length, 24);
        assert_eq!(msg.header().total_len(), 44);
        assert_eq!(msg.datagram_len(), 44);
    }

    #[test]
    fn build_response_rejects_an_oversized_body() {
        let txid = TransactionId::from_bytes([0u8; 12]);
        let huge = Attribute::Data(vec![0u8; 65_536]);
        assert!(build_response(MessageType::BINDING_REQUEST.bits(), &txid, &[huge], None, false)
            .is_err());
    }

    #[test]
    fn a_built_message_round_trips_through_parse() {
        let txid = TransactionId::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ]);
        let t = txid.as_bytes();
        let mut err = ErrorCode::from_number(420).unwrap();
        err.reason = b"Unknown Attribute".to_vec();
        let mut body_bytes = Vec::new();
        for attr in [
            Attribute::ErrorCode(err.clone()),
            Attribute::Lifetime(120),
            Attribute::ChannelNumber(0x4002),
            Attribute::Data(b"ping".to_vec()),
            Attribute::RequestedAddressFamily(crate::address::AddressFamily::Ipv4),
            Attribute::Software("quickrelay".to_string()),
            Attribute::Username("evtj:h6vY".to_string()),
            Attribute::XorMappedAddress(MappedAddress::from_ipv4(192, 0, 2, 9, 32853)),
        ] {
            body_bytes.extend_from_slice(&body(&attr, t));
        }
        let datagram = build_datagram(0x0001, t, &body_bytes, Some(SECRET), true);
        let msg = parse(&datagram).unwrap();
        assert_eq!(msg.len(), 10);
        assert!(!msg.is_empty());
        assert_eq!(msg.get(0), Some(&Attribute::ErrorCode(err)));
        assert_eq!(msg.error().unwrap().as_u16(), 420);
        assert_eq!(msg.error().unwrap().to_string(), "420 (Unknown Attribute)");
        assert_eq!(msg.lifetime_secs(), Some(120));
        assert_eq!(msg.channel_number(), Some(0x4002));
        assert_eq!(msg.data_bytes(), Some(&b"ping"[..]));
        assert_eq!(
            msg.find(0x0017),
            Some(&Attribute::RequestedAddressFamily(
                crate::address::AddressFamily::Ipv4
            ))
        );
        assert_eq!(msg.software(), Some("quickrelay"));
        assert_eq!(msg.username(), Some("evtj:h6vY"));
        assert_eq!(
            msg.xor_mapped_address().unwrap().to_string(),
            "192.0.2.9:32853"
        );
        assert!(msg.has_message_integrity());
        assert!(msg.has_integrity());
        assert!(msg.has_fingerprint());
        assert!(msg.has(FINGERPRINT_CODE));
        assert!(msg.has(0x0008));
        assert!(msg.find(0x0009).is_some());
        // Index 7 is the XOR-MAPPED-ADDRESS body attribute; the 8th and 9th
        // slots are the MESSAGE-INTEGRITY and FINGERPRINT trailers, neither of
        // which carries an address.
        assert!(msg.get(7).unwrap().needs_txid());
        assert!(msg.find(0x0020).unwrap().needs_txid());
        assert!(!msg.get(8).unwrap().needs_txid());
        assert!(!msg.get(9).unwrap().needs_txid());
        assert!(msg.datagram_bytes() == datagram.as_slice());
        assert_eq!(msg.datagram_len(), datagram.len());
        assert_eq!(msg.header().total_len(), datagram.len());
        assert_eq!(msg.transaction_id(), txid);
        assert_eq!(msg.msg_type(), MessageType::BINDING_REQUEST);
        assert_eq!(msg.header().msg_type(), MessageType::BINDING_REQUEST);
        assert_eq!(msg.header().msg_type().bits(), 0x0001); // method 0x001 << 2 | 0b00
        assert_eq!(msg.header().transaction_id(), txid);
        assert!(msg.unknown_optional().is_empty());
        let mi_off = msg.integrity().unwrap().off;
        assert!(verify_integrity(&datagram, mi_off, IntegrityAlgorithm::Sha1, SECRET).is_ok());
        let fp_off = msg.fingerprint_offset().unwrap();
        assert!(verify_fp(&datagram, fp_off).is_ok());
        assert!(msg.fingerprint().is_some());
        let fp_value = msg.find(FINGERPRINT_CODE).unwrap().to_value(t).unwrap();
        assert!(msg.fingerprint() == Some(u32::from_be_bytes(fp_value.try_into().unwrap())));
        let _ = msg.clone();
    }

    #[test]
    fn an_unauthenticated_message_has_no_trailers() {
        let txid = TransactionId::default();
        let t = txid.as_bytes();
        let body = body(&Attribute::Software("quickrelay".to_string()), t);
        let datagram = build_datagram(0x0000, t, &body, None, false);
        let msg = parse(&datagram).unwrap();
        assert_eq!(msg.len(), 1);
        assert!(!msg.is_empty());
        assert!(msg.get(0).unwrap() == &Attribute::Software("quickrelay".to_string()));
        assert!(msg.get(1).is_none());
        assert!(!msg.has_message_integrity());
        assert!(!msg.has_integrity());
        assert!(!msg.has_fingerprint());
        assert!(msg.fingerprint().is_none());
        assert!(msg.integrity().is_none());
        assert!(msg.fingerprint_offset().is_none());
        assert!(msg.error().is_none());
        assert!(msg.xor_relayed_address().is_none());
        assert!(msg.lifetime_secs().is_none());
        assert!(msg.data_bytes().is_none());
        assert!(msg.channel_number().is_none());
        assert!(msg.ice_priority().is_none());
        assert!(msg.realm().is_none());
        assert!(msg.nonce().is_none());
        assert!(msg.unknown_optional().is_empty());
        assert!(integrity_off(&datagram).is_none());
        assert!(fingerprint_off(&datagram).is_none());
        let _ = msg.clone();
    }

    #[test]
    fn empty_messages_and_edge_inputs() {
        let mut empty = [0u8; HEADER_LEN];
        empty[MAGIC_COOKIE_OFFSET..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        let msg = parse(&empty).unwrap();
        assert!(msg.is_empty());
        assert_eq!(msg.len(), 0);
        assert!(msg.attributes().is_empty());
        assert!(msg.get(0).is_none());
        assert!(msg.unknown_optional().is_empty());
        assert!(msg.datagram_len() == 20);
        assert!(msg.datagram_bytes().len() == 20);
        assert_eq!(msg.header().message_length, 0);
        assert_eq!(msg.header().total_len(), 20);
        assert!(!msg.has_message_integrity());
        assert!(!msg.has_fingerprint());
        assert!(msg.find(0x0006).is_none());
        let _ = msg.clone();
        for n in 0..HEADER_LEN {
            let buf = vec![0u8; n];
            assert!(parse(&buf).is_err());
        }
        let mut bad_cookie = [0u8; HEADER_LEN];
        bad_cookie[MAGIC_COOKIE_OFFSET] = 0x21;
        assert!(parse(&bad_cookie).is_err());
        let txid = TransactionId::default();
        let t = txid.as_bytes();
        let datagram = build_datagram(0x0000, t, &[], None, false);
        assert!(parse(&datagram).unwrap().is_empty());
        let empty2 = Bytes::new();
        assert!(parse_bytes(empty2).is_err());
        assert!(parse_vec(Vec::new()).is_err());
        assert!(parse_vec(vec![0u8; 12]).is_err());
        let _ = TransactionId::default();
    }

    #[test]
    fn malformed_attributes_are_rejected() {
        let txid = TransactionId::default();
        let t = txid.as_bytes();
        let body = body(&Attribute::Username("evtj:h6vY".to_string()), t);
        let mut bad = build_datagram(0x0000, t, &body, None, false);
        // The USERNAME value length is declared in octets 22..24; inflating it
        // to 0x1008 pushes the attribute past the end of the datagram.
        bad[22] = 0x10;
        bad[23] = 0x08;
        assert!(matches!(
            parse(&bad).unwrap_err().kind,
            ErrorKind::MalformedAttribute
                | ErrorKind::TrailingOctets
                | ErrorKind::TruncatedAttribute
                | ErrorKind::LengthMismatch
        ));
        let kind = AttributeKind::Known(AttrCode::Fingerprint);
        assert!(is_trailer_only(kind));
        assert!(!is_trailer_only(AttributeKind::Known(AttrCode::Username)));
        assert_eq!(kind.code(), FINGERPRINT_CODE);
        assert_eq!(kind.as_u16(), FINGERPRINT_CODE);
        assert!(is_registered(kind));
        assert!(kind.is_known());
        let unknown_kind = AttributeKind::from_code(0x8005);
        assert!(!unknown_kind.is_known());
        assert!(is_comprehension_optional(unknown_kind));
        assert!(!is_registered(unknown_kind));
        assert_eq!(unknown_kind.code(), 0x8005);
        assert_eq!(unknown_kind.as_u16(), 0x8005);
        assert_eq!(u16::from(kind), 0x8028);
        assert_eq!(u16::from(AttributeKind::Unknown(0x000b)), 0x000b);
        assert!(is_trailer_only(AttributeKind::Known(AttrCode::MessageIntegritySha256)));
        assert!(is_trailer_only(AttributeKind::Known(AttrCode::MessageIntegrity)));
        assert!(is_trailer_only(AttributeKind::Known(AttrCode::MessageIntegritySha256)));
        assert!(!is_comprehension_optional(AttributeKind::Known(AttrCode::MessageIntegrity)));
        assert!(is_comprehension_optional(AttributeKind::Known(AttrCode::Software)));
        let _pad = pad_len(9);
        assert_eq!(_pad, 3);
        assert_eq!(pad_len(0), 0);
        assert_eq!(pad_len(4), 0);
        assert_eq!(pad_len(5), 3);
        assert_eq!(crate::attribute::attr_size(9), 16);
        assert!(emit_attribute(
            &mut Vec::new(),
            AttributeKind::Known(AttrCode::Software),
            &b"short"[..]
        )
        .is_ok()
        );
    }

    #[test]
    fn message_integrity_sha256_length_rules_are_enforced() {
        let txid = TransactionId::default();
        let t = txid.as_bytes();
        // A SOFTWARE attribute followed by a MESSAGE-INTEGRITY-SHA256 attribute
        // whose value is 3 octets long — below the RFC 8489 Section 14.6
        // minimum of 16 and not a multiple of 4.
        let mut body_bytes = body(&Attribute::Software("s".to_string()), t);
        let sha = body_bytes.len();
        body_bytes.extend_from_slice(&MESSAGE_INTEGRITY_SHA256_CODE.to_be_bytes());
        body_bytes.extend_from_slice(&3u16.to_be_bytes());
        body_bytes.extend_from_slice(&[0u8; 20]);
        body_bytes.extend_from_slice(&[0u8; 3]);
        let ok = build_datagram(0x0000, t, &body_bytes, None, false);
        let bad = ok.clone();
        assert_eq!(
            parse(&bad).unwrap_err().kind,
            ErrorKind::MessageIntegritySha256Length
        );
        let mut bad2 = ok.clone();
        bad2[sha + 2..sha + 4].copy_from_slice(&5u16.to_be_bytes());
        assert!(matches!(
            parse(&bad2).unwrap_err().kind,
            ErrorKind::MessageIntegritySha256Length | ErrorKind::MalformedAttribute
        ));
        // A 16-octet tag is legal: the attribute parses and locates.
        let mut body_ok = body(&Attribute::Software("s".to_string()), t);
        body_ok.extend_from_slice(&MESSAGE_INTEGRITY_SHA256_CODE.to_be_bytes());
        body_ok.extend_from_slice(&16u16.to_be_bytes());
        body_ok.extend_from_slice(&[0u8; 16]);
        let datagram_ok = build_datagram(0x0000, t, &body_ok, None, false);
        let parsed = parse(&datagram_ok).unwrap();
        assert_eq!(parsed.integrity().unwrap().value_len, 16);
        assert_eq!(
            parsed.integrity().unwrap().algorithm(),
            Some(IntegrityAlgorithm::Sha256)
        );
        assert!(matches!(
            parsed.find(MESSAGE_INTEGRITY_SHA256_CODE).unwrap(),
            Attribute::MessageIntegritySha256(_)
        ));
        assert_eq!(MESSAGE_INTEGRITY_SHA256_MIN_LEN, 16);
        assert_eq!(MESSAGE_INTEGRITY_SHA256_LEN, 32);
        assert_eq!(AttributeLocation { off: 20, code: 0x001c, value_len: 16 }.algorithm(), Some(IntegrityAlgorithm::Sha256));
        assert_eq!(AttributeLocation { off: 20, code: 0x001c, value_len: 32 }.algorithm(), Some(IntegrityAlgorithm::Sha256));
        // 20 is legal too: it is 16 <= 20 <= 32 and a multiple of 4.
        assert_eq!(AttributeLocation { off: 20, code: 0x001c, value_len: 20 }.algorithm(), Some(IntegrityAlgorithm::Sha256));
        assert!(AttributeLocation { off: 20, code: 0x001c, value_len: 14 }.algorithm().is_none());
        assert!(AttributeLocation { off: 20, code: 0x001c, value_len: 18 }.algorithm().is_none());
        assert!(AttributeLocation { off: 20, code: 0x001c, value_len: 0 }.algorithm().is_none());
        assert!(AttributeLocation { off: 20, code: 0x001c, value_len: 36 }.algorithm().is_none());
        assert!(AttributeLocation { off: 20, code: 0x0008, value_len: 20 }.algorithm().is_some());
        assert!(AttributeLocation { off: 20, code: 0x0008, value_len: 19 }.algorithm().is_none());
        assert!(AttributeLocation { off: 20, code: 0x8028, value_len: 4 }.algorithm().is_none());
    }

    #[test]
    fn parse_vec_and_parse_bytes_share_one_validation() {
        assert!(parse_vec(RFC5769_2_1.to_vec()).is_ok());
        assert!(parse_bytes(Bytes::from_static(&RFC5769_2_2[..])).is_ok());
        assert!(parse_bytes(Bytes::copy_from_slice(&RFC5769_2_3[..])).is_ok());
        assert!(parse_bytes(Bytes::from_static(&RFC5769_2_4[..])).is_ok());
        assert!(parse_bytes(Bytes::copy_from_slice(&RFC5769_2_2[..])).is_ok());
        assert!(parse_vec(vec![]).is_err());
        assert!(parse_vec(vec![0u8; 19]).is_err());
        assert!(parse_bytes(Bytes::new()).is_err());
        assert!(parse_bytes(Bytes::from_static(b"")).is_err());
        let mut vec = RFC5769_2_4.to_vec();
        assert!(parse_vec(vec.clone()).is_ok());
        vec[4] ^= 0x01;
        assert!(parse_vec(vec).is_err());
        let static_bytes = Bytes::from_static(&RFC5769_2_1[..]);
        assert!(static_bytes[..4] == RFC5769_2_1[..4]);
        assert!(static_bytes[..20] == RFC5769_2_1[..20]);
        assert!(static_bytes[..108] == RFC5769_2_1[..108]);
        assert!(static_bytes[..].starts_with(&RFC5769_2_1[..20]));
        assert_eq!(static_bytes[..].len(), 108);
        assert!(parse_bytes(static_bytes.clone()).is_ok());
        let msg = parse_bytes(Bytes::copy_from_slice(&RFC5769_2_1[..])).unwrap();
        assert_eq!(msg.datagram_bytes(), &RFC5769_2_1[..]);
        let _ = msg.clone();
    }

    #[test]
    fn constants_match_rfc8489() {
        assert_eq!(MAGIC_COOKIE, 0x21_12_a4_42);
        assert_eq!(HEADER_LEN, 20);
        assert_eq!(TRANSACTION_ID_LEN, 12);
        assert_eq!(MAX_MESSAGE_LENGTH, 65_535);
        assert_eq!(MAX_DATAGRAM, 65_555);
        assert_eq!(LENGTH_OFFSET, 2);
        assert_eq!(MAGIC_COOKIE_OFFSET, 4);
        assert_eq!(TRANSACTION_ID_OFFSET, 8);
        assert_eq!(FINGERPRINT_CODE, 0x8028);
        assert_eq!(MESSAGE_INTEGRITY_CODE, 0x0008);
        assert_eq!(MESSAGE_INTEGRITY_SHA256_CODE, 0x001c);
        assert_eq!(UNKNOWN_ATTRIBUTES_CODE, 0x000a);
        assert_eq!(unknown_attribute_code(), 0x000a);
        assert_eq!(crate::attribute::AttrCode::UnknownAttributes.as_u16(), UNKNOWN_ATTRIBUTES_CODE);
        assert_eq!(RFC5769_2_1.len(), 108);
        assert_eq!(RFC5769_2_2.len(), 80);
        assert_eq!(RFC5769_2_3.len(), 92);
        assert_eq!(RFC5769_2_4.len(), 116);
        assert_eq!(RFC5769_2_1[LENGTH_OFFSET..4], [0x00, 0x58]);
        assert_eq!(
            RFC5769_2_1[MAGIC_COOKIE_OFFSET..8],
            [0x21, 0x12, 0xa4, 0x42]
        );
        assert_eq!(RFC5769_2_1[TRANSACTION_ID_OFFSET..20], TXID_5769);
        assert_eq!(RFC5769_2_2[LENGTH_OFFSET..4], [0x00, 0x3c]);
        assert_eq!(RFC5769_2_3[LENGTH_OFFSET..4], [0x00, 0x48]);
        assert_eq!(RFC5769_2_4[LENGTH_OFFSET..4], [0x00, 0x60]);
        assert_eq!(integrity_off(&RFC5769_2_1).unwrap().off, 76);
        assert_eq!(integrity_off(&RFC5769_2_2).unwrap().off, 48);
        assert_eq!(integrity_off(&RFC5769_2_3).unwrap().off, 60);
        assert_eq!(integrity_off(&RFC5769_2_4).unwrap().off, 92);
        assert_eq!(fingerprint_off(&RFC5769_2_1), Some(100));
        assert_eq!(fingerprint_off(&RFC5769_2_2), Some(72));
        assert_eq!(fingerprint_off(&RFC5769_2_3), Some(84));
        assert!(fingerprint_off(&RFC5769_2_4).is_none());
        let _ = MAX_ATTRIBUTE_COUNT;
    }

    fn unknown_attribute_code() -> u16 {
        0x000a
    }
}
