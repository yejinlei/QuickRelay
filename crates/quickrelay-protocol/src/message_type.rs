//! STUN / TURN message types: the 16-bit `STUN Message Type` field (RFC 8489
//! Section 5).
//!
//! # Bit layout
//!
//! Field bit numbers, `0` being the least significant octet-wise bit:
//!
//! ```text
//! bit:  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
//!       --- reserved ---  M11  M10  M9   M8  M7   -  C1  M6  M5  M4  C0  M3  M2  M1  M0
//! ```
//!
//! `M11..M0` is the 12-bit method number; the two high bits are reserved and
//! MUST be zero. The class bits are `C1` at bit 8 and `C0` at bit 4, which
//! splits the method number into three groups: `A = M3..M0`, `B = M6..M4`,
//! `D = M11..M7`. `C0` sits at bit 4 (an Indication is `0x0010`) and `C1` at
//! bit 8 (a SuccessResponse is `0x0100`), so a method number `M` encodes as
//!
//! ```text
//!  (M & 0x000F)                 -> field bits   0.. 3
//! ((M >> 4) & 0x07) << 5        -> field bits   5.. 7
//! ((M >> 7) & 0x1F) << 9        -> field bits   9..13
//! ```
//!
//! with the class OR'd on top, and decodes as
//!
//! ```text
//!  (T & 0x000F) | ((T >> 1) & 0x0070) | ((T >> 2) & 0x0F80)
//! ```
//!
//! The decode masks are those of the method-number groups, not of the field
//! positions: `0x0F80` keeps the method to 12 bits, so a stray reserved bit
//! cannot leak into the method number. A Binding request (`method = 0x001`,
//! class `0b00`) therefore encodes as `0x0001` and a Binding success response
//! as `0x0101` (RFC 8489 Section 5).
//!
//! # Method numbering
//!
//! The STUN Methods registry (RFC 8489 Section 18.2) numbers Binding as
//! `0x001`, which is why a Binding request appears as `0x0001` on the wire.
//! RFC 8656 Section 17 adds Allocate `0x003`, Refresh `0x004`, Send `0x006`,
//! Data `0x007`, CreatePermission `0x008` and ChannelBind `0x009`, and
//! RFC 6062 Section 6.1 adds Connect `0x00A`, ConnectionBind `0x00B` and
//! ConnectionAttempt `0x00C`. `0x000` and `0x002` are reserved.
//!
//! Note that ChannelData is not a STUN method at all: RFC 8656 Section 12.4
//! gives the ChannelData message its own 4-octet `channel number` + `length`
//! header that carries no STUN method field, so it is deliberately absent from
//! [`Method`].
//!

use core::fmt;

/// The `C1C0` pair of a STUN message type (RFC 8489 Section 5).
///
/// [`Class::bits`] returns the two class bits as they sit in the message type
/// field (`C1` at bit 8, `C0` at bit 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Class {
    /// `C1C0 = 0b00` — a request.
    Request = 0x0000,
    /// `C1C0 = 0b01` — an indication; no response is sent (RFC 8489 Section 5).
    Indication = 0x0010,
    /// `C1C0 = 0b10` — a success response.
    SuccessResponse = 0x0100,
    /// `C1C0 = 0b11` — an error response.
    ErrorResponse = 0x0110,
}

/// The 16-bit mask covering `C1` and `C0`.
pub const CLASS_MASK: u16 = 0x0110;
/// The 16-bit mask covering the 12-bit method field.
pub const METHOD_MASK: u16 = 0xFFE0;
/// The two high bits that are not significant and MUST be zero.
pub const RESERVE_BITS: u16 = 0xC000;
/// Mask of the method's four lowest bits `M3..M0` (method-space). These
/// occupy field bits 0..=3 unchanged.
pub const METHOD_ABITS: u16 = 0x000F;
/// Mask of method bits `M6..M4` (method-space). They land at field bits
/// 5..=7 after a left shift of one, leaving room for `C0` at bit 4.
pub const METHOD_BBITS: u16 = 0x0070;
/// Mask of method bits `M11..M7` (method-space). They land at field bits
/// 9..=13 after a left shift of two, leaving room for `C1` at bit 8.
///
/// Five bits, not six: `0x1F00` would accept `M12`, which does not exist, and
/// on the decode side it would let a reserved field bit leak into the method
/// number and break the round trip.
pub const METHOD_DBITS: u16 = 0x0F80;

impl Class {
    /// Decode the class from a message type field.
    pub const fn from_bits(bits: u16) -> Option<Self> {
        match bits & CLASS_MASK {
            0x0000 => Some(Class::Request),
            0x0010 => Some(Class::Indication),
            0x0100 => Some(Class::SuccessResponse),
            0x0110 => Some(Class::ErrorResponse),
            _ => None,
        }
    }

    /// The class bits as they appear in the message type field.
    pub const fn bits(self) -> u16 {
        self as u16
    }

    /// The two class bits, packed into the low two bits (`0`, `1`, `2`, `3`).
    pub const fn code(self) -> u8 {
        ((self as u16 & 0x0100) >> 7 | (self as u16 & 0x0010) >> 4) as u8
    }

    /// Whether this is a request.
    pub const fn is_request(self) -> bool {
        self as u16 == Class::Request as u16
    }

    /// Whether this is an indication, which receives no response.
    pub const fn is_indication(self) -> bool {
        self as u16 == Class::Indication as u16
    }

    /// Whether this is a success or error response.
    pub const fn is_response(self) -> bool {
        matches!(self, Class::SuccessResponse | Class::ErrorResponse)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Class::Request => "Request",
            Class::Indication => "Indication",
            Class::SuccessResponse => "Success",
            Class::ErrorResponse => "Error",
        };
        f.write_str(s)
    }
}

/// A STUN / TURN method number, per the STUN Methods registry
/// (RFC 8489 Section 18.2), RFC 8656 Section 17 and RFC 6062 Section 6.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// `0x001` Binding (RFC 8489 Section 18.2).
    Binding,
    /// `0x003` Allocate (RFC 8656 Section 17).
    Allocate,
    /// `0x004` Refresh (RFC 8656 Section 17).
    Refresh,
    /// `0x006` Send (RFC 8656 Section 17).
    Send,
    /// `0x007` Data (RFC 8656 Section 17).
    Data,
    /// `0x008` Create Permission (RFC 8656 Section 17).
    CreatePermission,
    /// `0x009` ChannelBind (RFC 8656 Section 17).
    ChannelBind,
    /// `0x00A` Connect (RFC 6062 Section 6.1).
    Connect,
    /// `0x00B` ConnectionBind (RFC 6062 Section 6.1).
    ConnectionBind,
    /// `0x00C` ConnectionAttempt (RFC 6062 Section 6.1).
    ConnectionAttempt,
    /// A method number not present in the registries.
    Unknown(u16),
}

impl Method {
    /// The method number as it appears in the method field.
    pub const fn bits(self) -> u16 {
        match self {
            Method::Binding => 0x001,
            Method::Allocate => 0x003,
            Method::Refresh => 0x004,
            Method::Send => 0x006,
            Method::Data => 0x007,
            Method::CreatePermission => 0x008,
            Method::ChannelBind => 0x009,
            Method::Connect => 0x00A,
            Method::ConnectionBind => 0x00B,
            Method::ConnectionAttempt => 0x00C,
            Method::Unknown(n) => n,
        }
    }

    /// Decode a method number, preserving unregistered values as
    /// [`Method::Unknown`].
    pub const fn from_bits(bits: u16) -> Self {
        match bits {
            0x001 => Method::Binding,
            0x003 => Method::Allocate,
            0x004 => Method::Refresh,
            0x006 => Method::Send,
            0x007 => Method::Data,
            0x008 => Method::CreatePermission,
            0x009 => Method::ChannelBind,
            0x00A => Method::Connect,
            0x00B => Method::ConnectionBind,
            0x00C => Method::ConnectionAttempt,
            n => Method::Unknown(n),
        }
    }

    /// Whether this method is registered in the STUN / TURN registries.
    pub const fn is_registered(self) -> bool {
        !matches!(self, Method::Unknown(_))
    }

    /// Whether this method is not present in the registries.
    pub const fn is_unknown(self) -> bool {
        matches!(self, Method::Unknown(_))
    }

    /// Whether this method uses one of the reserved method numbers
    /// (`0x000` and `0x002`).
    pub const fn is_reserved(self) -> bool {
        matches!(self, Method::Unknown(n) if n == 0x000 || n == 0x002)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Method::Binding => "Binding",
            Method::Allocate => "Allocate",
            Method::Refresh => "Refresh",
            Method::Send => "Send",
            Method::Data => "Data",
            Method::CreatePermission => "CreatePermission",
            Method::ChannelBind => "ChannelBind",
            Method::Connect => "Connect",
            Method::ConnectionBind => "ConnectionBind",
            Method::ConnectionAttempt => "ConnectionAttempt",
            Method::Unknown(n) => return write!(f, "Unknown-Method({n:#x})"),
        };
        f.write_str(s)
    }
}

/// A STUN / TURN message type: a method number plus a class (RFC 8489
/// Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageType {
    method: Method,
    class: Class,
}

impl MessageType {
    /// Binding request: `0x0001`.
    pub const BINDING_REQUEST: Self = Self::new(Method::Binding, Class::Request);
    /// Binding success: `0x0101`.
    pub const BINDING_SUCCESS: Self = Self::new(Method::Binding, Class::SuccessResponse);
    /// Binding error: `0x0111`.
    pub const BINDING_ERROR: Self = Self::new(Method::Binding, Class::ErrorResponse);
    /// Allocate request: `0x0003`.
    pub const ALLOCATE_REQUEST: Self = Self::new(Method::Allocate, Class::Request);
    /// Allocate success: `0x0103`.
    pub const ALLOCATE_SUCCESS: Self = Self::new(Method::Allocate, Class::SuccessResponse);
    /// Allocate error: `0x0113`.
    pub const ALLOCATE_ERROR: Self = Self::new(Method::Allocate, Class::ErrorResponse);
    /// Refresh request: `0x0004`.
    pub const REFRESH_REQUEST: Self = Self::new(Method::Refresh, Class::Request);
    /// Refresh success: `0x0104`.
    pub const REFRESH_SUCCESS: Self = Self::new(Method::Refresh, Class::SuccessResponse);
    /// Send request: `0x0006`.
    pub const SEND_REQUEST: Self = Self::new(Method::Send, Class::Request);
    /// Data indication: `0x0017`.
    pub const DATA_INDICATION: Self = Self::new(Method::Data, Class::Indication);
    /// Create Permission request: `0x0008`.
    pub const CREATE_PERMISSION_REQUEST: Self =
        Self::new(Method::CreatePermission, Class::Request);
    /// ChannelBind request: `0x0009`.
    pub const CHANNEL_BIND_REQUEST: Self = Self::new(Method::ChannelBind, Class::Request);
    /// ChannelBind success: `0x0109`.
    pub const CHANNEL_BIND_SUCCESS: Self = Self::new(Method::ChannelBind, Class::SuccessResponse);
    /// ChannelBind error: `0x0119`.
    pub const CHANNEL_BIND_ERROR: Self = Self::new(Method::ChannelBind, Class::ErrorResponse);
    /// Connect request: `0x000A`.
    pub const CONNECT_REQUEST: Self = Self::new(Method::Connect, Class::Request);
    /// Connect success: `0x010A`.
    pub const CONNECT_SUCCESS: Self = Self::new(Method::Connect, Class::SuccessResponse);
    /// ConnectionBind request: `0x000B`.
    pub const CONNECTION_BIND_REQUEST: Self = Self::new(Method::ConnectionBind, Class::Request);
    /// ConnectionBind success: `0x010B`.
    pub const CONNECTION_BIND_SUCCESS: Self =
        Self::new(Method::ConnectionBind, Class::SuccessResponse);
    /// ConnectionAttempt indication: `0x001C`.
    pub const CONNECTION_ATTEMPT_INDICATION: Self =
        Self::new(Method::ConnectionAttempt, Class::Indication);
    /// A registered method whose only permitted class is the indication.
    pub const SEND_INDICATION: Self = Self::new(Method::Send, Class::Indication);

    /// Build a message type from a method and a class.
    pub const fn new(method: Method, class: Class) -> Self {
        MessageType { method, class }
    }

    /// The method.
    pub const fn method(self) -> Method {
        self.method
    }

    /// The class.
    pub const fn class(self) -> Class {
        self.class
    }

    /// The raw 16-bit wire encoding (RFC 8489 Section 5).
    ///
    /// The method bits are interleaved with the class bits, so each method bit
    /// group is shifted by the number of class bits below it. A single shift
    /// of the whole method cannot be used: `M & 0xF800` is a shift by three,
    /// which leaves the two top method bits in the reserved positions.
    pub const fn bits(self) -> u16 {
        let m = self.method.bits();
        (m & METHOD_ABITS)
            | (((m >> 4) & 0x07) << 5)
            | (((m >> 7) & 0x1F) << 9)
            | self.class.bits()
    }

    /// Parse a raw 16-bit message type. Returns `None` when the two most
    /// significant bits are not zero (RFC 8489 Section 5: the method is 12 bits
    /// wide, so bits 14 and 15 must be zero).
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & RESERVE_BITS != 0 {
            return None;
        }
        let Some(class) = Class::from_bits(bits) else {
            return None;
        };
        // Reverse of [`MessageType::bits`]: pull each method group out of its
        // field position back into the method number.
        let method_bits = (bits & METHOD_ABITS) | ((bits >> 1) & METHOD_BBITS) | ((bits >> 2) & METHOD_DBITS);
        Some(MessageType { method: Method::from_bits(method_bits), class })
    }

    /// Build a message type from its raw method number and class, for callers
    /// that only know the method number.
    pub const fn from_method_and_class(method_bits: u16, class: Class) -> Self {
        Self::new(Method::from_bits(method_bits), class)
    }

    /// Whether this is a request (RFC 8489 Section 3.1).
    pub const fn is_request(self) -> bool {
        self.class.is_request()
    }

    /// Whether this is a response — success or error.
    pub const fn is_response(self) -> bool {
        self.class.is_response()
    }

    /// Whether this is an indication, which receives no reply.
    pub const fn is_indication(self) -> bool {
        self.class.is_indication()
    }

    /// The success response type for a request, or `None` when this type
    /// already is a response or an indication (which receives none).
    pub const fn success_response_type(self) -> Option<Self> {
        if self.class.is_response() || self.class.is_indication() {
            return None;
        }
        Some(Self::new(self.method, Class::SuccessResponse))
    }

    /// The error response type for a request, or `None` when none can be sent.
    pub const fn error_response_type(self) -> Option<Self> {
        if self.class.is_response() || self.class.is_indication() {
            return None;
        }
        Some(Self::new(self.method, Class::ErrorResponse))
    }

    /// Whether a `420 Unknown Attribute` reply can be sent for a message of
    /// this type, per RFC 8489 Section 6.3.1; RFC 5389 Section 7.3.1 says the
    /// same for requests, which it answers with the code its Section 15.6
    /// table assigns to it, 420.
    pub const fn can_reply_420(self) -> bool {
        !self.class.is_response() && !self.class.is_indication()
    }

    /// The response type a `420 Unknown Attribute` reply uses, or `None` when
    /// no reply is possible.
    ///
    /// The reply carries an UNKNOWN-ATTRIBUTES *attribute* (code `0x000A`)
    /// listing the offending codes; it is not itself a separate method. Both
    /// RFC 8489 Section 6.3.1 and RFC 5389 Section 7.3.1 specify the error
    /// class with the method number of the request that carried the unknown
    /// attribute, so a reply to a Binding request is a Binding error.
    pub const fn unknown_attribute_reply_type(self) -> Option<Self> {
        if self.class.is_response() || self.class.is_indication() {
            return None;
        }
        Some(Self::new(self.method, Class::ErrorResponse))
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.method, self.class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_bits_match_the_rfc8489_field_layout() {
        assert_eq!(Class::Request.bits(), 0x0000);
        assert_eq!(Class::Indication.bits(), 0x0010);
        assert_eq!(Class::SuccessResponse.bits(), 0x0100);
        assert_eq!(Class::ErrorResponse.bits(), 0x0110);
        assert_eq!(Class::from_bits(0x0000), Some(Class::Request));
        assert_eq!(Class::from_bits(0x0010), Some(Class::Indication));
        assert_eq!(Class::from_bits(0x0100), Some(Class::SuccessResponse));
        assert_eq!(Class::from_bits(0x0110), Some(Class::ErrorResponse));
        assert!(Class::Request.is_request());
        assert!(Class::Indication.is_indication());
        assert!(Class::SuccessResponse.is_response());
        assert!(Class::ErrorResponse.is_response());
        assert!(!Class::Request.is_response());
        assert!(!Class::Indication.is_response());
        assert!(!Class::Request.is_indication());
        assert_eq!(Class::Request.code(), 0);
        assert_eq!(Class::Indication.code(), 1);
        assert_eq!(Class::SuccessResponse.code(), 2);
        assert_eq!(Class::ErrorResponse.code(), 3);
        assert_eq!(CLASS_MASK, 0x0110);
        assert_eq!(METHOD_MASK, 0xFFE0);
        assert_eq!(RESERVE_BITS, 0xC000);
    }

    #[test]
    fn rfc8489_section_5_examples_encode_as_0x0001_and_0x0101() {
        // RFC 8489 Section 5: "a Binding request has class=0b00 and
        // method=0b000000000001 (Binding) and is encoded into the first 16 bits
        // as 0x0001. A Binding response has class=0b10 and method=0b000000000001
        // and is encoded ... as 0x0101." These are also the RFC 5769 Section 2.1
        // and 2.2 message type octets.
        assert_eq!(MessageType::BINDING_REQUEST.bits(), 0x0001);
        assert_eq!(MessageType::BINDING_SUCCESS.bits(), 0x0101);
        assert_eq!(MessageType::BINDING_ERROR.bits(), 0x0111);
        assert_eq!(MessageType::from_bits(0x0001), Some(MessageType::BINDING_REQUEST));
        assert_eq!(MessageType::from_bits(0x0101), Some(MessageType::BINDING_SUCCESS));
        assert_eq!(MessageType::from_bits(0x0111), Some(MessageType::BINDING_ERROR));
    }

    #[test]
    fn the_registry_constants_are_arithmetic_correct() {
        assert_eq!(MessageType::ALLOCATE_REQUEST.bits(), 0x0003);
        assert_eq!(MessageType::ALLOCATE_SUCCESS.bits(), 0x0103);
        assert_eq!(MessageType::ALLOCATE_ERROR.bits(), 0x0113);
        assert_eq!(MessageType::REFRESH_REQUEST.bits(), 0x0004);
        assert_eq!(MessageType::REFRESH_SUCCESS.bits(), 0x0104);
        assert_eq!(MessageType::SEND_REQUEST.bits(), 0x0006);
        assert_eq!(MessageType::SEND_INDICATION.bits(), 0x0016);
        assert_eq!(MessageType::DATA_INDICATION.bits(), 0x0017);
        assert_eq!(MessageType::CREATE_PERMISSION_REQUEST.bits(), 0x0008);
        assert_eq!(MessageType::CHANNEL_BIND_REQUEST.bits(), 0x0009);
        assert_eq!(MessageType::CHANNEL_BIND_SUCCESS.bits(), 0x0109);
        assert_eq!(MessageType::CHANNEL_BIND_ERROR.bits(), 0x0119);
        assert_eq!(MessageType::CONNECT_REQUEST.bits(), 0x000A);
        assert_eq!(MessageType::CONNECT_SUCCESS.bits(), 0x010A);
        assert_eq!(MessageType::CONNECTION_BIND_REQUEST.bits(), 0x000B);
        assert_eq!(MessageType::CONNECTION_BIND_SUCCESS.bits(), 0x010B);
        assert_eq!(MessageType::CONNECTION_ATTEMPT_INDICATION.bits(), 0x001C);
    }

    #[test]
    fn method_numbers_match_the_registry() {
        assert_eq!(Method::Binding.bits(), 0x001);
        assert_eq!(Method::Allocate.bits(), 0x003);
        assert_eq!(Method::Refresh.bits(), 0x004);
        assert_eq!(Method::Send.bits(), 0x006);
        assert_eq!(Method::Data.bits(), 0x007);
        assert_eq!(Method::CreatePermission.bits(), 0x008);
        assert_eq!(Method::ChannelBind.bits(), 0x009);
        assert_eq!(Method::Connect.bits(), 0x00A);
        assert_eq!(Method::ConnectionBind.bits(), 0x00B);
        assert_eq!(Method::ConnectionAttempt.bits(), 0x00C);
        assert!(Method::Unknown(0x005).is_unknown());
        assert!(Method::from_bits(0x000).is_reserved());
        assert!(Method::from_bits(0x002).is_reserved());
        assert!(!Method::from_bits(0x005).is_reserved());
    }

    #[test]
    fn reserved_bits_are_rejected() {
        // The method field is 12 bits wide, so bits 14/15 cannot carry method
        // bits and MUST be zero.
        for bits in [0xC000u16, 0xC001, 0xD000, 0xF110, 0xFFFF, 0xC010] {
            assert!(MessageType::from_bits(bits).is_none(), "{bits:#06x}");
        }
        assert!(MessageType::from_bits(0x0001).is_some());
        assert!(MessageType::from_bits(0x0101).is_some());
        assert!(MessageType::from_bits(0x0111).is_some());
    }

    #[test]
    fn every_12_bit_method_number_roundtrips_in_every_class() {
        for method in 0x0000u16..0x1000 {
            for class in [
                Class::Request,
                Class::Indication,
                Class::SuccessResponse,
                Class::ErrorResponse,
            ] {
                let t = MessageType::new(Method::Unknown(method), class);
                let bits = t.bits();
                assert_eq!(bits & RESERVE_BITS, 0, "{method:#06x} {class:?}");
                assert_eq!(
                    MessageType::from_bits(bits).map(|r| (r.method().bits(), r.class())),
                    Some((method, class)),
                    "{bits:#06x} from {method:#06x} {class:?}"
                );
            }
        }
    }

    #[test]
    fn roundtrip_every_registered_method_and_class() {
        let methods = [
            Method::Binding,
            Method::Allocate,
            Method::Refresh,
            Method::Send,
            Method::Data,
            Method::CreatePermission,
            Method::ChannelBind,
            Method::Connect,
            Method::ConnectionBind,
            Method::ConnectionAttempt,
        ];
        let classes = [
            Class::Request,
            Class::Indication,
            Class::SuccessResponse,
            Class::ErrorResponse,
        ];
        for method in methods {
            for class in classes {
                let t = MessageType::new(method, class);
                let bits = t.bits();
                assert_eq!(bits & RESERVE_BITS, 0, "{method:?} {class:?}");
                assert_eq!(MessageType::from_bits(bits), Some(t), "{bits:#06x}");
                assert_eq!(t.method(), method);
                assert_eq!(t.class(), class);
                assert!(t.method().is_registered());
            }
        }
    }

    #[test]
    fn unknown_methods_are_preserved_not_dropped() {
        // 0x005 is unassigned, 0x00E is the first unassigned number above the
        // RFC 6062 range, 0x07F the top of the IETF-review range, and 0x0FF
        // the largest 12-bit value. Note 0x013 is Allocate's number, so it must
        // decode to the named variant rather than being preserved as Unknown.
        for method in [0x005u16, 0x00E, 0x00F, 0x014, 0x07F, 0x0FF] {
            let t = MessageType::from_method_and_class(method, Class::Request);
            assert_eq!(t.method(), Method::Unknown(method));
            assert_eq!(
                MessageType::from_bits(t.bits()).unwrap().method(),
                Method::Unknown(method)
            );
            assert!(t.method().is_unknown());
            assert!(!t.method().is_registered());
            assert!(!t.to_string().is_empty());
        }
        assert!(Method::from_bits(0x001).is_registered());
        assert!(Method::from_bits(0x005).is_unknown());
        assert!(!Method::from_bits(0x005).is_registered());
    }

    #[test]
    fn the_bit_groups_are_twelve_bits_wide() {
        // A = 4 bits, B = 3 bits, D = 5 bits: 4 + 3 + 5 = 12, the width of the
        // method field. Anything wider lets bits outside the method leak in.
        assert_eq!(METHOD_ABITS, 0x000F);
        assert_eq!(METHOD_BBITS, 0x0070);
        assert_eq!(METHOD_DBITS, 0x0F80);
        assert_eq!(
            METHOD_ABITS.count_ones() + METHOD_BBITS.count_ones() + METHOD_DBITS.count_ones(),
            12
        );
        assert_eq!(METHOD_DBITS >> METHOD_DBITS.trailing_zeros(), 0x1F);
        // No two groups share a bit position, so the assembly is an OR.
        assert_eq!(METHOD_ABITS & METHOD_BBITS, 0);
        assert_eq!(METHOD_ABITS & METHOD_DBITS, 0);
        assert_eq!(METHOD_BBITS & METHOD_DBITS, 0);
        // Class bits occupy bit 4 and bit 8; neither group reaches them.
        assert_eq!(Class::Indication.bits(), 0x0010);
        assert_eq!(Class::SuccessResponse.bits(), 0x0100);
    }

    #[test]
    fn encode_and_decode_are_inverse_for_every_method_number() {
        // The 0x0F80 width guard earns its keep here: the same expression
        // round-trips every 12-bit method number in every class. Registered
        // numbers come back as their named variant, so the comparison is on
        // the method number, not on the `Unknown` wrapper.
        for m in 0x0000u16..0x1000 {
            for bits_class in [0x0000u16, 0x0010, 0x0100, 0x0110] {
                let t = MessageType::new(Method::Unknown(m), Class::from_bits(bits_class).unwrap());
                let wire = t.bits();
                assert_eq!(wire & RESERVE_BITS, 0, "{m:#06x} class {bits_class:#06x}");
                let back = MessageType::from_bits(wire).unwrap_or_else(|| panic!("{m:#06x}"));
                assert_eq!(back.method().bits(), m, "{m:#06x} class {bits_class:#06x}");
                assert_eq!(back.class(), t.class());
            }
        }
    }

    #[test]
    fn response_type_logic() {
        assert_eq!(
            MessageType::BINDING_REQUEST.success_response_type(),
            Some(MessageType::BINDING_SUCCESS)
        );
        assert_eq!(
            MessageType::BINDING_REQUEST.error_response_type(),
            Some(MessageType::BINDING_ERROR)
        );
        assert_eq!(MessageType::BINDING_SUCCESS.success_response_type(), None);
        assert_eq!(MessageType::BINDING_SUCCESS.error_response_type(), None);
        assert_eq!(MessageType::BINDING_ERROR.success_response_type(), None);
        assert_eq!(MessageType::BINDING_ERROR.error_response_type(), None);
        assert_eq!(MessageType::SEND_INDICATION.success_response_type(), None);
        assert_eq!(MessageType::SEND_INDICATION.error_response_type(), None);
        assert_eq!(
            MessageType::ALLOCATE_REQUEST.error_response_type(),
            Some(MessageType::ALLOCATE_ERROR)
        );
        let unknown = MessageType::from_method_and_class(0x005, Class::Request);
        assert_eq!(
            unknown.error_response_type(),
            Some(MessageType::new(Method::Unknown(0x005), Class::ErrorResponse))
        );
        assert!(unknown.success_response_type().is_some());
    }

    #[test]
    fn unknown_attribute_reply_type_carries_the_request_method() {
        // RFC 8489 Section 6.3.1: the 420 reply carries the method number of
        // the request that held the unknown attribute.
        assert_eq!(
            MessageType::BINDING_REQUEST.unknown_attribute_reply_type(),
            Some(MessageType::BINDING_ERROR)
        );
        assert_eq!(
            MessageType::ALLOCATE_REQUEST.unknown_attribute_reply_type(),
            Some(MessageType::ALLOCATE_ERROR)
        );
        assert_eq!(MessageType::BINDING_ERROR.unknown_attribute_reply_type(), None);
        assert_eq!(MessageType::SEND_INDICATION.unknown_attribute_reply_type(), None);
        assert!(MessageType::BINDING_REQUEST.can_reply_420());
        assert!(MessageType::ALLOCATE_REQUEST.can_reply_420());
        assert!(!MessageType::BINDING_ERROR.can_reply_420());
        assert!(!MessageType::SEND_INDICATION.can_reply_420());
    }

    #[test]
    fn display_and_hash() {
        assert_eq!(MessageType::BINDING_REQUEST.to_string(), "Binding Request");
        assert_eq!(MessageType::BINDING_SUCCESS.to_string(), "Binding Success");
        assert_eq!(
            MessageType::SEND_INDICATION.to_string(),
            "Send Indication"
        );
        assert_eq!(Method::Data.to_string(), "Data");
        assert_eq!(Method::Connect.to_string(), "Connect");
        assert_eq!(Method::ConnectionAttempt.to_string(), "ConnectionAttempt");
        assert_eq!(Class::Request.to_string(), "Request");
        assert_eq!(Class::ErrorResponse.to_string(), "Error");
        assert!(Method::Unknown(0x005).to_string().contains("0x5"));
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(MessageType::BINDING_REQUEST));
        assert!(!seen.insert(MessageType::new(Method::Binding, Class::Request)));
        assert!(seen.insert(MessageType::BINDING_SUCCESS));
    }

    #[test]
    fn method_bits_roundtrip() {
        for m in [
            Method::Binding,
            Method::Allocate,
            Method::Refresh,
            Method::Send,
            Method::Data,
            Method::CreatePermission,
            Method::ChannelBind,
            Method::Connect,
            Method::ConnectionBind,
            Method::ConnectionAttempt,
            Method::Unknown(0x005),
            Method::Unknown(0x0FF),
        ] {
            assert_eq!(Method::from_bits(m.bits()), m, "{m:?}");
            assert!(!m.to_string().is_empty());
        }
    }
}
