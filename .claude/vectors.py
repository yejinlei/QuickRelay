import hmac, hashlib, zlib, struct

KEY = bytes([0x56, 0x4f, 0x6b, 0x4a, 0x78, 0x62, 0x52, 0x6c, 0x31, 0x52,
             0x6d, 0x54, 0x78, 0x55, 0x6b, 0x2f, 0x57, 0x76, 0x4a, 0x78,
             0x42, 0x74])
COOKIE = bytes([0x21, 0x12, 0xa4, 0x42])
TXID = bytes([0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
              0xfa, 0x87, 0xdf, 0xae])


def concat(*parts):
    return b"".join(parts)


def hdr(code, length):
    return struct.pack(">HH", code, length)


REQ = concat(bytes([0x00, 0x01, 0x00, 0x58]), COOKIE, TXID,
             hdr(0x8022, 0x10) + b"STUN test client",
             hdr(0x0024, 0x04) + bytes([0x6e, 0x00, 0x01, 0xff]),
             hdr(0x8029, 0x08) + bytes([0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36]),
             hdr(0x0006, 0x09) + b"evtj:h6vY" + b"\x20" * 3,
             hdr(0x0008, 0x14) + bytes([0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56,
                                        0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49,
                                        0xc1, 0xb5, 0x71, 0xa2]),
             hdr(0x8028, 0x04) + bytes([0xe5, 0x7a, 0x3b, 0xcf]))

SW = hdr(0x8022, 0x0b) + b"test vector"

RESP_V4 = concat(bytes([0x01, 0x01, 0x00, 0x3c]), COOKIE, TXID, SW,
                 hdr(0x0020, 0x08) + bytes([0x00, 0x01, 0xa1, 0x47,
                                             0xe1, 0x12, 0xa6, 0x43]),
                 hdr(0x0008, 0x14) + bytes([0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
                                            0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53,
                                            0xf0, 0x6b, 0xe7, 0xd7]),
                 hdr(0x8028, 0x04) + bytes([0xc0, 0x7d, 0x4c, 0x96]))

RESP_V6 = concat(bytes([0x01, 0x01, 0x00, 0x48]), COOKIE, TXID, SW,
                 hdr(0x0020, 0x14) + bytes([0x00, 0x02, 0xa1, 0x47,
                                             0x01, 0x13, 0xa9, 0xfa,
                                             0xa5, 0xd3, 0xf1, 0x79,
                                             0xbc, 0x25, 0xf4, 0xb5,
                                             0xbe, 0xd2, 0xb9, 0xd9]),
                 hdr(0x0008, 0x14) + bytes([0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1,
                                            0x17, 0x84, 0x79, 0x7c, 0x82, 0x92, 0xc2, 0x75,
                                            0xbf, 0xe3, 0xed, 0x41]),
                 hdr(0x8028, 0x04) + bytes([0xc8, 0xfb, 0x0b, 0x4c]))


def check(name, msg):
    dec = 20 + struct.unpack(">H", msg[2:4])[0]
    print("===", name, "bytes:", len(msg), "declared:", dec, "ok:", len(msg) == dec)
    mi = msg.index(hdr(0x0008, 0x14))
    base = msg[:mi + 4] + b"\x00" * 20
    print("   length field used:", base[2:4].hex(), "(", struct.unpack(">H", base[2:4])[0], ")")
    got = hmac.new(KEY, base, hashlib.sha1).digest()
    exp = msg[mi + 8:mi + 28]
    print("   MESSAGE-INTEGRITY ok:", got == exp)
    print("     computed:", got.hex(), "expected:", exp.hex())
    fp = msg.index(hdr(0x8028, 0x04))
    crc = zlib.crc32(msg[:fp]) ^ 0x5354554E
    ok = struct.pack(">I", crc) == msg[fp + 4:fp + 8]
    print("   FINGERPRINT ok:", ok, "| computed %08x expected %s" % (crc, msg[fp + 4:fp + 8].hex()))


def xor_address(msg, off):
    txid = msg[8:20]
    family = msg[off]
    port = struct.unpack(">H", msg[off + 2:off + 4])[0] ^ struct.unpack(">H", txid[0:2])[0]
    raw = msg[off + 4:off + 20]
    mask = COOKIE + txid
    a = bytes([raw[i] ^ mask[i] for i in range(4, 16)])
    if family == 1:
        return ".".join(str(x) for x in a[12:16]), port
    return ":".join("%x" % struct.unpack(">H", a[i:i + 2])[0] for i in range(0, 16, 2)), port


check("REQ (RFC 5769 2.1)", REQ)
check("RESP_V4 (2.2)", RESP_V4)
check("RESP_V6 (2.3)", RESP_V6)
print("v4 unmapped:", xor_address(RESP_V4, 44))
print("v6 unmapped:", xor_address(RESP_V6, 44))
print("REQ hex len:", len(REQ) * 2)
