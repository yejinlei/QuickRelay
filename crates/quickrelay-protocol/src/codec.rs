//
//  STUN message codec: parse a datagram, and build Binding responses.
//
//  YEJ-141 ships its own codec because the codec issue (YEJ-140) is still
//  open; the shapes here are deliberately small so they can be replaced
//  later without touching the transport crate.
//
//  Every number is driven by the RFCs, not by coturn's source:
//
//  * Header, magic cookie, transaction id -- RFC 8489 section 6.
//  * Attribute padding -- RFC 8489 sections 5.2 and 15.
//  * XOR-MAPPED-ADDRESS / MAPPED-ADDRESS -- sections 14.2 and 14.1.
//  * ERROR-CODE (class in bits 8-10, number in bits 0-7) -- section 14.8.
//  * UNKNOWN-ATTRIBUTES -- section 14.13.
//  * MESSAGE-INTEGRITY -- section 14.5: the HMAC runs over the header and
//    the attributes *preceding* the attribute, with the Length field
//    rewritten to the end of the attribute.  The attribute itself is not
//    hashed.
//  * FINGERPRINT -- section 14.7: CRC-32 over everything up to (excluding)
//    the attribute, XOR 0x5354554E.  Its own header is not CRC'd, but the
//    Length field must already count it.
//
//  The two rules are easy to get wrong in the same way, so both are
//  cross-checked against the RFC 5769 test vectors rather than against the
//  prose alone: `rfc5769_vectors_reproduce` reproduces the published
//  MESSAGE-INTEGRITY and FINGERPRINT of sections 2.1, 2.2 and 2.3 byte for
//  byte, so a CRC or HMAC regression shows up as a test failure instead of
//  a silent interoperability break.

use std::net::{IpAddr, SocketAddr};

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::attr::{
    Attribute, ADDRESS_ATTR_LEN_V4, ADDRESS_ATTR_LEN_V6, ERROR_CODE_LEN, FINGERPRINT_LEN,
    MESSAGE_INTEGRITY_LEN,
};
use crate::err::ProtocolError;
use crate::method::{decode_msg_type, encode_msg_type, Class, ErrorCode, Method};
use crate::order::{self, TrailerOrder};
use crate::{FINGERPRINT_XOR, HEADER_LEN, MAGIC_COOKIE, TRANSACTION_ID_LEN};

/// HMAC-SHA1 MAC type used for MESSAGE-INTEGRITY.
type HmacSha1 = Hmac<Sha1>;

/// Largest attribute payload accepted from the network.
///
/// RFC 8489 section 10 sets no per-attribute limit, only a 65535-byte
/// message limit; this cap exists so one hostile attribute can never make
/// the transport layer allocate a megabyte for a single datagram.
const MAX_ATTRIBUTE_LEN: usize = 64 * 1024;

/// 96-bit transaction identifier, copied verbatim from the header.
///
/// RFC 8489 section 6 requires the response to carry the request's id
/// unchanged and says nothing about its byte pattern, so no field is decoded
/// from it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TransactionId([u8; TRANSACTION_ID_LEN]);

impl TransactionId {
    /// Build an id from its 12 raw bytes.
    pub const fn from_bytes(bytes: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes, as they appear in the header and are written back out.
    pub const fn bytes(&self) -> &[u8; TRANSACTION_ID_LEN] {
        &self.0
    }
}

/// Header of a parsed STUN message (RFC 8489, section 6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    /// The scrambled (method, class) message-type field, as transmitted.
    pub msg_type: u16,
    /// Declared length of the attribute section, in bytes.
    pub length: usize,
    /// The transaction identifier.
    pub transaction_id: TransactionId,
}

/// An attribute decoded from the wire.
#[derive(Clone, Debug)]
pub struct AttributeItem {
    /// Registry entry, when the code is known.  Unknown comprehension-optional
    /// codes parse fine and come out `None`: they are ignored, not rejected.
    pub attr: Option<Attribute>,
    /// The raw type code, which the trailer-order check and the
    /// UNKNOWN-ATTRIBUTES builder must read even for unknown codes.
    pub code: u16,
    /// The value, including the pad bytes (4-byte aligned).
    pub value: Vec<u8>,
    /// Length of the value part, pad excluded.
    pub length: usize,
}

impl AttributeItem {
    /// The value with its pad bytes stripped off.
    pub fn data(&self) -> &[u8] {
        &self.value[..self.length]
    }
}

/// A decoded STUN message.
#[derive(Clone, Debug)]
pub struct Message {
    /// The fixed 20-byte header.
    pub header: MessageHeader,
    /// Attributes in wire order; trailers are ordinary items so the caller
    /// can verify them.
    pub attributes: Vec<AttributeItem>,
    /// Wire length, i.e. `20 + header.length`.
    pub wire_len: usize,
    /// Codes seen that are not in the registry but are comprehension-optional.
    unknown_optional: Vec<u16>,
}

/// Verdict of the parser: only `Valid` earns a response, every other outcome is
/// dropped silently (see [`ProtocolError::is_silent`]).
pub enum ParseOutcome {
    /// The datagram is a well-formed STUN message.
    Valid(Message),
    /// Not STUN, or malformed in a way RFC 8489 says must be ignored.
    Invalid(ProtocolError),
}

/// Parse a received datagram.
///
/// The whole message must be present: UDP datagrams arrive whole, and a TCP
/// half-message must not be fed in (the framing layer handles that).
pub fn parse(bytes: &[u8]) -> ParseOutcome {
    match parse_inner(bytes) {
        Ok(msg) => ParseOutcome::Valid(msg),
        Err(e) => ParseOutcome::Invalid(e),
    }
}

fn parse_inner(bytes: &[u8]) -> Result<Message, ProtocolError> {
    if bytes.len() < HEADER_LEN {
        return Err(ProtocolError::TooShort { len: bytes.len() });
    }

    let msg_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    let declared = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));

    // Declared length must be a multiple of 4 and bounded.
    if declared % 4 != 0 {
        return Err(ProtocolError::BadLengthAlignment(declared as u16));
    }
    if declared > MAX_ATTRIBUTE_LEN {
        return Err(ProtocolError::Oversized(declared as u16));
    }
    // The datagram must be exactly header + declared attributes.
    if bytes.len() != HEADER_LEN + declared {
        return Err(ProtocolError::Truncated {
            have: bytes.len(),
            want: HEADER_LEN + declared,
        });
    }

    // Reserved bits 14-15 of the message-type field are zero.
    decode_msg_type(msg_type)?;

    // A bad magic cookie means this is not STUN at all.
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(ProtocolError::BadMagicCookie(cookie));
    }

    let tid = TransactionId::from_bytes(bytes[8..HEADER_LEN].try_into().unwrap());

    let body = &bytes[HEADER_LEN..];
    let mut attributes = Vec::new();
    let mut unknown_optional = Vec::new();
    let mut codes = Vec::new();

    let mut pos = 0usize;
    while pos < body.len() {
        if body.len() - pos < 4 {
            return Err(ProtocolError::AttributeOverrun { code: 0, length: 0 });
        }
        let code = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let raw_len = usize::from(u16::from_be_bytes([body[pos + 2], body[pos + 3]]));
        if raw_len % 4 != 0 {
            return Err(ProtocolError::BadAttributeAlignment {
                code,
                length: raw_len as u16,
            });
        }
        let total = 4 + raw_len;
        if total > body.len() - pos {
            return Err(ProtocolError::AttributeOverrun { code, length: raw_len });
        }

        codes.push(code);
        if !Attribute::known(code).is_some() && code & 0x8000 != 0 {
            // Unregistered but comprehension-optional: ignore, per RFC 8489
            // section 5.1.
            unknown_optional.push(code);
        }

        attributes.push(AttributeItem {
            attr: Attribute::known(code),
            code,
            value: body[pos + 4..pos + total].to_vec(),
            length: raw_len,
        });
        pos += total;
    }

    // An unknown *comprehension-required* attribute is a hard error: the
    // server answers with 420 + UNKNOWN-ATTRIBUTES (RFC 8489 section 6.3.1),
    // which the transport layer builds from the error.
    for a in &attributes {
        if a.attr.is_none() && a.code & 0x8000 == 0 {
            return Err(ProtocolError::UnknownAttribute(a.code));
        }
    }

    order::validate(&codes).map_err(|_| ProtocolError::BadTrailerOrder)?;

    Ok(Message {
        header: MessageHeader { msg_type, length: declared, transaction_id: tid },
        attributes,
        wire_len: bytes.len(),
        unknown_optional,
    })
}

impl Message {
    /// The message class.
    pub fn class(&self) -> Class {
        crate::method::class_of(self.header.msg_type)
    }

    /// The decoded method, `None` when the type field did not decode.
    pub fn method(&self) -> Option<Method> {
        decode_msg_type(self.header.msg_type).ok().map(|(_, m)| m)
    }

    /// Every attribute of a type, in wire order.
    pub fn of(&self, attr: Attribute) -> impl Iterator<Item = &AttributeItem> {
        self.attributes.iter().filter(move |a| a.attr == Some(attr))
    }

    /// The first attribute of a type.
    pub fn first(&self, attr: Attribute) -> Option<&AttributeItem> {
        self.attributes.iter().find(|a| a.attr == Some(attr))
    }

    /// Unregistered attributes that were safely ignored.
    ///
    /// RFC 8489 section 5.1: an attribute whose comprehension bit is set may
    /// be ignored, so the codec keeps going.  They are listed here so a
    /// logging path can report them; they never produce a response on their
    /// own.
    pub fn unknown_optional(&self) -> &[u16] {
        &self.unknown_optional
    }

    /// Unregistered comprehension-*required* attributes, in wire order.
    ///
    /// RFC 8489 section 6.3.1: the server replies 420 and *must* list these
    /// in an UNKNOWN-ATTRIBUTES attribute.  The parser itself rejects the
    /// message with [`ProtocolError::UnknownAttribute`] carrying only the
    /// first offending code, so this accessor exists for callers that build
    /// the 420 response after the fact (and so tests can assert the whole
    /// list, not just the head of it).
    pub fn unknown_required(&self) -> Vec<u16> {
        self.attributes
            .iter()
            .filter(|a| a.attr.is_none() && a.code & 0x8000 == 0)
            .map(|a| a.code)
            .collect()
    }

    /// The trailer layout of this message.
    pub fn trailer_order(&self) -> Result<TrailerOrder, ProtocolError> {
        let codes: Vec<u16> = self.attributes.iter().map(|a| a.code).collect();
        order::validate(&codes)
    }

    /// Build an empty message for a class and method.
    pub fn new(class: Class, method: Method, tid: TransactionId) -> Self {
        Message {
            header: MessageHeader {
                msg_type: encode_msg_type(class, method),
                length: 0,
                transaction_id: tid,
            },
            attributes: Vec::new(),
            wire_len: HEADER_LEN,
            unknown_optional: Vec::new(),
        }
    }

    /// Append an attribute, padding the value to a 4-byte boundary.
    pub fn push(&mut self, attr: Attribute, mut value: Vec<u8>) {
        let raw = value.len();
        if raw % 4 != 0 {
            value.resize(raw + (4 - raw % 4), 0);
        }
        let delta = 4 + value.len();
        self.header.length += delta;
        self.wire_len += delta;
        self.attributes.push(AttributeItem {
            attr: Some(attr),
            code: attr.bits(),
            value,
            length: raw,
        });
    }

    /// Absolute offset, including the header, of attribute `pos`'s type code.
    fn attr_offset(&self, pos: usize) -> usize {
        HEADER_LEN + self.attributes[..pos].iter().map(|a| 4 + a.value.len()).sum::<usize>()
    }

    /// The header plus the first `pos` attributes.
    ///
    /// `length_field` is written verbatim into the Length field, so a caller can
    /// describe a message that is longer than the bytes returned: the RFC 8489
    /// section 14.5 rule rewrites the field to the end of the MESSAGE-INTEGRITY
    /// attribute while hashing only the bytes in front of it, and the section
    /// 14.7 rule keeps the message's own declared value while CRC'ing only the
    /// bytes in front of FINGERPRINT.  Neither attribute's own header is
    /// included here -- that is the half of each rule that is easiest to get
    /// wrong.
    fn prefix_bytes(&self, pos: usize, length_field: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 4 * pos);
        out.extend_from_slice(&header_bytes(
            self.header.msg_type,
            HEADER_LEN + length_field as usize,
        ));
        for a in self.attributes.iter().take(pos) {
            out.extend_from_slice(&attr_header(a.code, a.length));
            out.extend_from_slice(&a.value);
        }
        out
    }
}

fn header_bytes(msg_type: u16, total_len: usize) -> [u8; HEADER_LEN - TRANSACTION_ID_LEN] {
    let body = (total_len - HEADER_LEN) as u16;
    [
        (msg_type >> 8) as u8,
        (msg_type & 0xFF) as u8,
        ((body >> 8) as u16 & 0xFF) as u8,
        (body & 0xFF) as u8,
        (MAGIC_COOKIE >> 24) as u8,
        (MAGIC_COOKIE >> 16) as u8,
        (MAGIC_COOKIE >> 8) as u8,
        MAGIC_COOKIE as u8,
    ]
}

fn attr_header(code: u16, len: usize) -> [u8; 4] {
    [
        (code >> 8) as u8,
        (code & 0xFF) as u8,
        ((len >> 8) as u16 & 0xFF) as u8,
        (len & 0xFF) as u8,
    ]
}

/// Computed MESSAGE-INTEGRITY / FINGERPRINT values, ready to serialise.
#[derive(Clone, Debug)]
pub struct Trailers {
    /// The 20-byte HMAC-SHA1, or `None` for an unauthenticated message.
    pub integrity: Option<[u8; MESSAGE_INTEGRITY_LEN]>,
    /// The FINGERPRINT value.
    pub fingerprint: Option<u32>,
}

/// Compute MESSAGE-INTEGRITY (when `key` is given) and FINGERPRINT.
///
/// Both hashes run over the bytes in front of the attribute being filled, and
/// the Length field must be rewritten for each one (RFC 8489):
///
/// * section 14.5 -- MESSAGE-INTEGRITY: rewrite the Length field to the end of
///   the attribute, then HMAC the header and the *preceding* attributes.  The
///   attribute's own header and value are not hashed, so the HMAC input stops
///   where the current output stops.
/// * section 14.7 -- FINGERPRINT: rewrite the Length field so it counts the
///   FINGERPRINT attribute, then CRC everything up to (excluding) it.  The
///   CRC input includes the completed MESSAGE-INTEGRITY value.
///
/// `rfc5769_vectors_reproduce` pins both rules against the published test
/// vectors, because they are easy to get wrong the same way.
pub fn compute_trailers(msg: &Message, key: Option<&[u8]>) -> Trailers {
    let mut out = Trailers { integrity: None, fingerprint: None };

    // Everything sent so far, trailers excluded.
    let mut prefix = serialize_no_trailers(msg);

    if let Some(k) = key {
        let int_attr_end = prefix.len() + 4 + MESSAGE_INTEGRITY_LEN;
        set_length(&mut prefix, int_attr_end);

        let mut mac = HmacSha1::new_from_slice(k).expect("HMAC-SHA1 accepts any key length");
        mac.update(&prefix);
        let h = mac.finalize().into_bytes();
        out.integrity = Some(h);

        // The HMAC is done; the attribute itself now enters the FINGERPRINT.
        prefix.resize(int_attr_end, 0);
        prefix.extend_from_slice(&attr_header(
            Attribute::MessageIntegrity.bits(),
            MESSAGE_INTEGRITY_LEN,
        ));
        prefix.extend_from_slice(h);
    }

    set_length(&mut prefix, prefix.len() + 4 + FINGERPRINT_LEN);
    out.fingerprint = Some(crc32fast::hash(&prefix) ^ FINGERPRINT_XOR);
    out
}

/// Serialise `msg` followed by its trailers; returns the byte count.
pub fn serialize(msg: &Message, trailers: &Trailers, out: &mut Vec<u8>) -> usize {
    let mut body = serialize_no_trailers(msg);
    let extra = trailers
        .integrity
        .map_or(0, |_| 4 + MESSAGE_INTEGRITY_LEN)
        + if trailers.fingerprint.is_some() { 4 + FINGERPRINT_LEN } else { 0 };
    set_length(&mut body, HEADER_LEN + msg.header.length + extra);
    out.clear();
    out.extend_from_slice(&body);
    if let Some(h) = trailers.integrity {
        out.extend_from_slice(&attr_header(Attribute::MessageIntegrity.bits(), MESSAGE_INTEGRITY_LEN));
        out.extend_from_slice(h);
    }
    if let Some(fp) = trailers.fingerprint {
        out.extend_from_slice(&attr_header(Attribute::Fingerprint.bits(), FINGERPRINT_LEN));
        out.extend_from_slice(&fp.to_be_bytes());
    }
    out.len()
}

/// Serialise a message without its trailers.
fn serialize_no_trailers(msg: &Message) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.wire_len);
    out.extend_from_slice(&header_bytes(msg.header.msg_type, msg.wire_len));
    out.extend_from_slice(msg.header.transaction_id.bytes());
    for a in &msg.attributes {
        if a.attr.map_or(false, |x| x.is_terminal()) {
            continue;
        }
        out.extend_from_slice(&attr_header(a.code, a.length));
        out.extend_from_slice(&a.value);
    }
    out
}

fn set_length(buf: &mut Vec<u8>, total: usize) {
    let body = (total - HEADER_LEN) as u16;
    buf[2] = ((body >> 8) as u16 & 0xFF) as u8;
    buf[3] = (body & 0xFF) as u8;
}

/// Verify MESSAGE-INTEGRITY against a shared-secret key.
///
/// The Length field is rewritten to the end of the integrity attribute, then
/// the HMAC runs over the header and the attributes *preceding* the
/// attribute (RFC 8489 section 14.5).  The attribute's own header and value
/// are outside the hash.
pub fn verify_integrity(msg: &Message, key: &[u8]) -> Result<(), ProtocolError> {
    let pos = msg
        .attributes
        .iter()
        .position(|a| a.attr == Some(Attribute::MessageIntegrity))
        .ok_or(ProtocolError::MissingAttribute(Attribute::MessageIntegrity.bits()))?;

    let end = msg.attr_offset(pos) + 4 + msg.attributes[pos].value.len();
    let buf = msg.prefix_bytes(pos, (end - HEADER_LEN) as u16);

    let mut mac = HmacSha1::new_from_slice(key).map_err(|_| ProtocolError::IntegrityMismatch)?;
    mac.update(&buf);
    let expected = mac.finalize().into_bytes();
    let actual = msg.attributes[pos].data();
    if expected.as_slice() != actual[..MESSAGE_INTEGRITY_LEN] {
        return Err(ProtocolError::IntegrityMismatch);
    }
    Ok(())
}

/// Verify FINGERPRINT: CRC-32 over everything up to (excluding) the
/// FINGERPRINT attribute, XOR `0x5354554E` (RFC 8489 section 14.7).
///
/// The Length field keeps the message's own declared value -- it already
/// counts the FINGERPRINT attribute -- and the attribute's own header is not
/// CRC'd.
pub fn verify_fingerprint(msg: &Message) -> Result<(), ProtocolError> {
    let pos = msg
        .attributes
        .iter()
        .position(|a| a.attr == Some(Attribute::Fingerprint))
        .ok_or(ProtocolError::MissingAttribute(Attribute::Fingerprint.bits()))?;

    let buf = msg.prefix_bytes(pos, msg.header.length as u16);
    let crc = crc32fast::hash(&buf);
    let expected = crc ^ FINGERPRINT_XOR;
    let actual = u32::from_be_bytes(msg.attributes[pos].data()[..4].try_into().unwrap());
    if expected != actual {
        return Err(ProtocolError::FingerprintMismatch { expected, actual });
    }
    Ok(())
}

/// XOR-MAPPED-ADDRESS value for an IPv4 address (RFC 8489, section 14.2).
///
/// `src_addr` is the address the server observed the request from.  Empty when
/// the address is IPv6 (handled by [`xor_mapped_address_v6`]).
pub fn xor_mapped_address_v4(src_addr: SocketAddr) -> Vec<u8> {
    let Some(ip) = src_addr.ip().as_ipv4() else { return Vec::new() };
    let mut out = Vec::with_capacity(ADDRESS_ATTR_LEN_V4);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&((src_addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes()));
    out.extend_from_slice(&((ip.to_u32() ^ MAGIC_COOKIE).to_be_bytes()));
    out
}

/// MAPPED-ADDRESS value for an IPv4 address (RFC 8489, section 14.1).
pub fn mapped_address_v4(src_addr: SocketAddr) -> Vec<u8> {
    let Some(ip) = src_addr.ip().as_ipv4() else { return Vec::new() };
    let mut out = Vec::with_capacity(ADDRESS_ATTR_LEN_V4);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&src_addr.port().to_be_bytes());
    out.extend_from_slice(&ip.to_u32().to_be_bytes());
    out
}

/// XOR-MAPPED-ADDRESS value for an IPv6 address, XOR'd with the magic cookie
/// concatenated with the transaction id (RFC 8489, section 14.2).
pub fn xor_mapped_address_v6(src_addr: SocketAddr, tid: TransactionId) -> Vec<u8> {
    let Some(ip) = src_addr.ip().as_ipv6() else { return Vec::new() };
    let mut out = Vec::with_capacity(ADDRESS_ATTR_LEN_V6);
    out.extend_from_slice(&[0x00, 0x02]);
    out.extend_from_slice(&((src_addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes()));
    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
    let mut xaddr = [0u8; 16];
    for (i, b) in ip.octets().iter().enumerate() {
        xaddr[i] = if i < 4 {
            b ^ cookie_bytes[i]
        } else {
            b ^ tid.bytes()[i - 4]
        };
    }
    out.extend_from_slice(&xaddr);
    out
}

/// MAPPED-ADDRESS value for an IPv6 address.
pub fn address_attr_v6(src_addr: SocketAddr) -> Vec<u8> {
    let Some(ip) = src_addr.ip().as_ipv6() else { return Vec::new() };
    let mut out = Vec::with_capacity(ADDRESS_ATTR_LEN_V6);
    out.extend_from_slice(&[0x00, 0x02]);
    out.extend_from_slice(&src_addr.port().to_be_bytes());
    out.extend_from_slice(&ip.octets());
    out
}

/// The value of an ERROR-CODE attribute: 4 bytes plus an optional reason
/// phrase.
///
/// The first two bytes are RFC 8489 section 14.8's `[Reserved:5][Class:3]`
/// form followed by the two-digit number: `0x0456` is 486, `0x0414` is 420.
pub fn error_code_value(code: ErrorCode, reason: Option<&str>) -> Vec<u8> {
    let mut v = Vec::with_capacity(ERROR_CODE_LEN + reason.map_or(0, |r| r.len()));
    v.extend_from_slice(&code.bits().to_be_bytes());
    if let Some(r) = reason {
        v.extend_from_slice(r.as_bytes());
    }
    v
}

/// Build a Binding Success response.
///
/// `src_addr` is the observed request source.  XOR-MAPPED-ADDRESS is always
/// emitted; `send_mapped_address` additionally emits the legacy MAPPED-ADDRESS
/// for clients that only know RFC 3489.  RFC 8489 section 7.3.1 says a server
/// that supports it *SHOULD NOT* send MAPPED-ADDRESS, so callers leave the flag
/// false unless an old client demands it.
pub fn binding_success(
    tid: TransactionId,
    src_addr: SocketAddr,
    send_mapped_address: bool,
) -> Message {
    let mut msg = Message::new(Class::Success, Method::Binding, tid);
    let xmap = match src_addr.ip() {
        IpAddr::V4(_) => xor_mapped_address_v4(src_addr),
        IpAddr::V6(_) => xor_mapped_address_v6(src_addr, tid),
    };
    if !xmap.is_empty() {
        msg.push(Attribute::XorMappedAddress, xmap);
    }
    if send_mapped_address {
        let map = match src_addr.ip() {
            IpAddr::V4(_) => mapped_address_v4(src_addr),
            IpAddr::V6(_) => address_attr_v6(src_addr),
        };
        if !map.is_empty() {
            msg.push(Attribute::MappedAddress, map);
        }
    }
    msg
}

/// Build a Binding Error response, optionally listing unknown attributes.
pub fn binding_error(
    tid: TransactionId,
    code: ErrorCode,
    reason: Option<&str>,
    unknown_attrs: Option<&[u16]>,
) -> Message {
    let mut msg = Message::new(Class::Error, Method::Binding, tid);
    msg.push(Attribute::ErrorCode, error_code_value(code, reason));
    if let Some(attrs) = unknown_attrs.filter(|a| !a.is_empty()) {
        let mut v = Vec::with_capacity(attrs.len() * 2);
        for a in attrs {
            v.extend_from_slice(&a.to_be_bytes());
        }
        msg.push(Attribute::UnknownAttributes, v);
    }
    msg
}

/// 486 Method Not Implemented for a method QuickRelay does not answer.
pub fn method_not_implemented(tid: TransactionId) -> Message {
    binding_error(
        tid,
        ErrorCode::MethodNotImplemented,
        Some(ErrorCode::MethodNotImplemented.reason_phrase()),
        None,
    )
}
