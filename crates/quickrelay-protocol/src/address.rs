use crate::error::{Error, ErrorKind};

/// IP address family in the mapped-address address-family field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddressFamily {
    /// IPv4, address-family value 0x01 (RFC 5389 Section 15.1).
    Ipv4 = 0x01,
    /// IPv6, address-family value 0x02.
    Ipv6 = 0x02,
}

impl AddressFamily {
    /// Decode the address-family octet.
    pub const fn from_octet(octet: u8) -> Option<Self> {
        match octet {
            0x01 => Some(AddressFamily::Ipv4),
            0x02 => Some(AddressFamily::Ipv6),
            _ => None,
        }
    }

    /// The on-wire address-family value.
    pub const fn to_octet(self) -> u8 {
        self as u8
    }

    /// Octets the address occupies in a mapped-address value.
    pub const fn address_octets(self) -> usize {
        match self {
            AddressFamily::Ipv4 => 4,
            AddressFamily::Ipv6 => 16,
        }
    }

    /// Total value length for a mapped address of this family.
    pub const fn value_len(self) -> usize {
        4 + self.address_octets()
    }
}

/// A MAPPED-ADDRESS / XOR-MAPPED-ADDRESS value: family, address and port.
///
/// The address is stored as up to 16 network-order octets so an IPv4 value can
/// be carried uniformly; use [`MappedAddress::ipv4`] / [`MappedAddress::ipv6`]
/// for typed access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MappedAddress {
    pub family: AddressFamily,
    pub ip: [u8; 16],
    pub port: u16,
}

/// Mapped-address length for IPv4: 4 octets of header + 4 octets of address.
pub const MAPPED_ADDRESS_IPV4_LEN: usize = 8;
/// Mapped-address length for IPv6: 4 octets of header + 16 octets of address.
pub const MAPPED_ADDRESS_IPV6_LEN: usize = 20;

impl MappedAddress {
    /// Build from an IPv4 address and port.
    pub const fn from_ipv4(a: u8, b: u8, c: u8, d: u8, port: u16) -> Self {
        MappedAddress {
            family: AddressFamily::Ipv4,
            ip: [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            port,
        }
    }

    /// Build from an IPv6 address and port.
    pub const fn from_ipv6(ip: [u8; 16], port: u16) -> Self {
        MappedAddress {
            family: AddressFamily::Ipv6,
            ip,
            port,
        }
    }

    /// The IPv4 octets, when the family is IPv4.
    pub fn ipv4(&self) -> Option<(u8, u8, u8, u8)> {
        (self.family == AddressFamily::Ipv4).then(|| (self.ip[0], self.ip[1], self.ip[2], self.ip[3]))
    }

    /// The IPv6 address octets, when the family is IPv6.
    pub fn ipv6(&self) -> Option<[u8; 16]> {
        (self.family == AddressFamily::Ipv6).then(|| self.ip)
    }

    /// Encode into a mapped-address value buffer. `out` must be long enough
    /// (see [`MAPPED_ADDRESS_IPV4_LEN`], [`MAPPED_ADDRESS_IPV6_LEN`]). Returns
    /// the number of octets written.
    pub fn write_value(&self, out: &mut [u8]) -> Result<usize, Error> {
        let need = self.family.value_len();
        if out.len() < need {
            return Err(Error::new(ErrorKind::ValueTooLong));
        }
        out[0] = 0x00;
        out[1] = self.family.to_octet();
        out[2..4].copy_from_slice(&self.port.to_be_bytes());
        let n = self.family.address_octets();
        out[4..4 + n].copy_from_slice(&self.ip[..n]);
        Ok(need)
    }

    /// Decode a mapped-address value.
    ///
    /// The leading two octets must be zero (the reserved field). Non-zero
    /// padding octets are tolerated, because RFC 5389 Section 6 permits any
    /// value in padding.
    pub fn read_value(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 4 {
            return Err(Error::new(ErrorKind::MalformedAddress));
        }
        if buf[0] != 0 {
            return Err(Error::new(ErrorKind::MalformedAddress));
        }
        let Some(family) = AddressFamily::from_octet(buf[1]) else {
            return Err(Error::new(ErrorKind::UnsupportedAddressFamily));
        };
        if buf.len() < family.value_len() {
            return Err(Error::new(ErrorKind::MalformedAddress));
        }
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let mut ip = [0u8; 16];
        let n = family.address_octets();
        ip[..n].copy_from_slice(&buf[4..4 + n]);
        Ok(MappedAddress { family, ip, port })
    }
}

/// Decode an address carried with family and port in separate fields, as used
/// by RELAYED-ADDRESS (RFC 6061 Section 3.5).
pub fn read_relayed_address(buf: &[u8]) -> Result<MappedAddress, Error> {
    if buf.len() < 8 {
        return Err(Error::new(ErrorKind::MalformedRelayedAddress));
    }
    let Some(family) = AddressFamily::from_octet(buf[0]) else {
        return Err(Error::new(ErrorKind::UnsupportedAddressFamily));
    };
    let n = family.address_octets();
    if buf.len() < 4 + n {
        return Err(Error::new(ErrorKind::MalformedRelayedAddress));
    }
    let mut ip = [0u8; 16];
    ip[..n].copy_from_slice(&buf[4..4 + n]);
    Ok(MappedAddress {
        family,
        ip,
        port: u16::from_be_bytes([buf[2], buf[3]]),
    })
}

/// Write RELAYED-ADDRESS: family, port, then the address.
pub fn write_relayed_address(addr: &MappedAddress, out: &mut [u8]) -> Result<usize, Error> {
    let need = 4 + addr.family.address_octets();
    if out.len() < need {
        return Err(Error::new(ErrorKind::ValueTooLong));
    }
    out[0] = addr.family.to_octet();
    out[2..4].copy_from_slice(&addr.port.to_be_bytes());
    let n = addr.family.address_octets();
    out[4..4 + n].copy_from_slice(&addr.ip[..n]);
    Ok(need)
}

/// Decode an ALTERNATE-SERVER / CHANGE-IP value: address family, reserved, port,
/// then the address. The value is 8 octets for IPv4 and 20 for IPv6.
pub fn read_alternate_server(buf: &[u8]) -> Result<MappedAddress, Error> {
    let Some(family) = AddressFamily::from_octet(buf[0]) else {
        return Err(Error::new(ErrorKind::UnsupportedAddressFamily));
    };
    let n = family.address_octets();
    if buf.len() < 4 + n {
        return Err(Error::new(ErrorKind::MalformedAlternateServer));
    }
    let mut ip = [0u8; 16];
    ip[..n].copy_from_slice(&buf[4..4 + n]);
    Ok(MappedAddress {
        family,
        ip,
        port: u16::from_be_bytes([buf[2], buf[3]]),
    })
}

/// Write an ALTERNATE-SERVER / CHANGE-IP value: address family, port, address.
pub fn write_alternate_server(addr: &MappedAddress, out: &mut [u8]) -> Result<usize, Error> {
    let need = 4 + addr.family.address_octets();
    if out.len() < need {
        return Err(Error::new(ErrorKind::ValueTooLong));
    }
    out[0] = addr.family.to_octet();
    out[2..4].copy_from_slice(&addr.port.to_be_bytes());
    let n = addr.family.address_octets();
    out[4..4 + n].copy_from_slice(&addr.ip[..n]);
    Ok(need)
}

/// The XOR-MAPPED-ADDRESS port key: the magic cookie shifted right by 16.
///
/// `0x2112A442 >> 16 == 0x2112` (RFC 5389 Section 15.2).
pub const XOR_PORT_KEY: u16 = 0x2112;

/// The 4-octet XOR key for an IPv4 address: the magic cookie itself.
pub const MAGIC_COOKIE_OCTETS: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// The 4-octet XOR key for an IPv4 address.
pub fn xor_key_v4() -> [u8; 4] {
    MAGIC_COOKIE_OCTETS
}

/// The 16-octet XOR key for an IPv6 address: the 4-octet magic cookie followed
/// by the 12-octet transaction identifier, used directly (RFC 5389 Section
/// 15.2). This is NOT the peer address, and it is NOT cycled.
pub fn xor_key_v6(txid: &[u8; 12]) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&MAGIC_COOKIE_OCTETS);
    key[4..].copy_from_slice(txid);
    key
}

/// Decode an XOR-MAPPED-ADDRESS value using a transaction identifier.
///
/// X-Port  = Port XOR 0x2112
/// X-IPv4  = Address XOR 0x2112A442
/// X-IPv6  = Address XOR (0x2112A442 || Transaction-ID)
pub fn read_xor_address(buf: &[u8], txid: &[u8; 12]) -> Result<MappedAddress, Error> {
    if buf.len() < 4 {
        return Err(Error::new(ErrorKind::MalformedAddress));
    }
    if buf[0] != 0 {
        return Err(Error::new(ErrorKind::MalformedAddress));
    }
    let Some(family) = AddressFamily::from_octet(buf[1]) else {
        return Err(Error::new(ErrorKind::UnsupportedAddressFamily));
    };
    if buf.len() < family.value_len() {
        return Err(Error::new(ErrorKind::MalformedAddress));
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]) ^ XOR_PORT_KEY;
    let n = family.address_octets();
    let mut ip = [0u8; 16];
    if family == AddressFamily::Ipv4 {
        let key = xor_key_v4();
        for (i, b) in buf[4..4 + n].iter().enumerate() {
            ip[i] = b ^ key[i];
        }
    } else {
        let key = xor_key_v6(txid);
        for (i, b) in buf[4..4 + n].iter().enumerate() {
            ip[i] = b ^ key[i];
        }
    }
    Ok(MappedAddress { family, ip, port })
}

/// Encode a MAPPED-ADDRESS into an XOR-MAPPED-ADDRESS value.
pub fn write_xor_address(addr: &MappedAddress, txid: &[u8; 12], out: &mut [u8]) -> Result<usize, Error> {
    let need = addr.family.value_len();
    if out.len() < need {
        return Err(Error::new(ErrorKind::ValueTooLong));
    }
    out[0] = 0x00;
    out[1] = addr.family.to_octet();
    out[2..4].copy_from_slice(&(addr.port ^ XOR_PORT_KEY).to_be_bytes());
    let n = addr.family.address_octets();
    if addr.family == AddressFamily::Ipv4 {
        let key = xor_key_v4();
        for i in 0..n {
            out[4 + i] = addr.ip[i] ^ key[i];
        }
    } else {
        let key = xor_key_v6(txid);
        for i in 0..n {
            out[4 + i] = addr.ip[i] ^ key[i];
        }
    }
    Ok(need)
}

impl core::fmt::Display for MappedAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.family {
            AddressFamily::Ipv4 => write!(
                f,
                "{}.{}.{}.{}:{port}",
                self.ip[0], self.ip[1], self.ip[2], self.ip[3],
                port = self.port
            ),
            AddressFamily::Ipv6 => write!(
                f,
                "[{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}]:{port}",
                self.ip[0], self.ip[1], self.ip[2], self.ip[3],
                self.ip[4], self.ip[5], self.ip[6], self.ip[7],
                self.ip[8], self.ip[9], self.ip[10], self.ip[11],
                self.ip[12], self.ip[13], self.ip[14], self.ip[15],
                port = self.port
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5769 Section 2.2 transaction identifier.
    const TXID_V4: [u8; 12] = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    #[test]
    fn rfc5769_2_2_xor_mapped_address_ipv4() {
        // XOR-MAPPED-ADDRESS 00 20 00 08 | 00 01 a1 47 e1 12 a6 43
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let addr = read_xor_address(&value, &TXID_V4).expect("parse");
        assert_eq!(addr.family, AddressFamily::Ipv4);
        assert_eq!(addr.port, 32853);
        assert_eq!(addr.ipv4(), Some((192, 0, 2, 1)));
        assert_eq!(addr.to_string(), "192.0.2.1:32853");
    }

    #[test]
    fn rfc5769_2_3_xor_mapped_address_ipv6() {
        // XOR-MAPPED-ADDRESS 00 20 00 14 | 00 02 a1 47 01 13 a9 fa a5 d3 f1 79
        //                                     bc 25 f4 b5 be d2 b9 d9
        let value = [
            0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25,
            0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
        ];
        let addr = read_xor_address(&value, &TXID_V4).expect("parse");
        assert_eq!(addr.family, AddressFamily::Ipv6);
        assert_eq!(addr.port, 32853);
        // 2001:db8:1234:5678:11:2233:4455:6677
        assert_eq!(addr.ipv6(), Some([
            0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77
        ]));
    }

    #[test]
    fn xor_roundtrip_ipv4() {
        let addr = MappedAddress::from_ipv4(192, 0, 2, 1, 32853);
        let mut value = [0u8; MAPPED_ADDRESS_IPV4_LEN];
        assert_eq!(write_xor_address(&addr, &TXID_V4, &mut value).unwrap(), 8);
        assert_eq!(value, [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);
        assert_eq!(read_xor_address(&value, &TXID_V4).unwrap(), addr);
    }

    #[test]
    fn xor_roundtrip_ipv6() {
        let addr = MappedAddress::from_ipv6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77,
            ],
            32853,
        );
        let mut value = [0u8; MAPPED_ADDRESS_IPV6_LEN];
        assert_eq!(write_xor_address(&addr, &TXID_V4, &mut value).unwrap(), 20);
        assert_eq!(
            value,
            [
                0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc,
                0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9
            ]
        );
        assert_eq!(read_xor_address(&value, &TXID_V4).unwrap(), addr);
    }

    #[test]
    fn mapped_address_roundtrip() {
        for addr in [
            MappedAddress::from_ipv4(127, 0, 0, 1, 3478),
            MappedAddress::from_ipv6(
                [
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                32853,
            ),
        ] {
            let mut buf = [0u8; MAPPED_ADDRESS_IPV6_LEN];
            let n = addr.write_value(&mut buf).unwrap();
            let back = MappedAddress::read_value(&buf[..n]).unwrap();
            assert_eq!(back, addr, "round-trip of {addr}");
        }
    }

    #[test]
    fn port_key_is_magic_cookie_shifted_right_16() {
        assert_eq!(u32::from_be_bytes([0x21, 0x12, 0xa4, 0x42]) >> 16, u32::from(XOR_PORT_KEY));
        assert_eq!(XOR_PORT_KEY, 0x2112);
        assert_eq!(xor_key_v4(), [0x21, 0x12, 0xa4, 0x42]);
    }

    #[test]
    fn ipv6_xor_key_is_magic_cookie_then_full_txid() {
        let key = xor_key_v6(&TXID_V4);
        assert_eq!(
            key,
            [
                0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa,
                0x87, 0xdf, 0xae
            ]
        );
    }

    #[test]
    fn malformed_address_family_is_rejected() {
        // family 0x03 is neither 0x01 nor 0x02
        assert_eq!(
            MappedAddress::read_value(&[0x00, 0x03, 0x00, 0x00, 0, 0, 0, 0]).unwrap_err().kind,
            ErrorKind::UnsupportedAddressFamily
        );
        assert_eq!(
            read_xor_address(&[0x00, 0x03, 0x00, 0x00, 0, 0, 0, 0], &TXID_V4)
                .unwrap_err()
                .kind,
            ErrorKind::UnsupportedAddressFamily
        );
    }

    #[test]
    fn malformed_nonzero_reserved_field_is_rejected() {
        assert_eq!(
            MappedAddress::read_value(&[0x01, 0x01, 0x00, 0x00, 0, 0, 0, 0]).unwrap_err().kind,
            ErrorKind::MalformedAddress
        );
    }

    #[test]
    fn malformed_short_value_is_rejected() {
        assert_eq!(MappedAddress::read_value(&[0x00, 0x01, 0x00, 0x00]).unwrap_err().kind, ErrorKind::MalformedAddress);
        assert_eq!(
            MappedAddress::read_value(&[0x00, 0x01, 0x00, 0x00, 1, 2, 3]).unwrap_err().kind,
            ErrorKind::MalformedAddress
        );
        assert_eq!(MappedAddress::read_value(&[]).unwrap_err().kind, ErrorKind::MalformedAddress);
        assert_eq!(
            read_xor_address(&[0x00, 0x01], &TXID_V4).unwrap_err().kind,
            ErrorKind::MalformedAddress
        );
    }

    #[test]
    fn address_family_value_lengths() {
        assert_eq!(AddressFamily::Ipv4.value_len(), 8);
        assert_eq!(AddressFamily::Ipv6.value_len(), 20);
        assert_eq!(AddressFamily::Ipv4.address_octets(), 4);
        assert_eq!(AddressFamily::Ipv6.address_octets(), 16);
        assert_eq!(AddressFamily::from_octet(0x01), Some(AddressFamily::Ipv4));
        assert_eq!(AddressFamily::from_octet(0x02), Some(AddressFamily::Ipv6));
        assert_eq!(AddressFamily::from_octet(0x00), None);
        assert_eq!(AddressFamily::from_octet(0x03), None);
        assert_eq!(AddressFamily::from_octet(0xff), None);
    }

    #[test]
    fn write_value_into_short_buffer_errors() {
        let addr = MappedAddress::from_ipv4(1, 2, 3, 4, 5);
        let mut short = [0u8; 4];
        assert_eq!(
            addr.write_value(&mut short).unwrap_err().kind,
            ErrorKind::ValueTooLong
        );
    }
}
