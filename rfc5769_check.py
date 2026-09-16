"""Verify the codec's trailer algorithm against RFC 5769 sections 2.1, 2.2, 2.3.

Findings pinned numerically by exhaustive search (see sweep.py / sweep3.py):

  MESSAGE-INTEGRITY input  = header (Length rewritten) + attributes *preceding*
                             the MESSAGE-INTEGRITY attribute.
                             The MI attribute header and value are NOT hashed.
                             Length field = offset of end of MI attribute
                             expressed as bytes-after-the-20-byte-header.
  FINGERPRINT input        = header (Length unchanged, i.e. the full message)
                             + all attributes except FINGERPRINT itself.

  section 2.1: Length field for the HMAC is 80 (0x50): 20 + 56 attributes
               + 4 (MI header) + 20 (MI value) = 100 absolute, 100 - 20 = 80.
               HMAC input is 76 bytes. FINGERPRINT input is 100 bytes with
               the length field at 0x58.
"""
import hmac, hashlib, zlib

KEY = b'VOkJxbRl1RmTxUk/WvJxBt'
TID = bytes.fromhex('b7e7a701bc34d686fa87dfae')
COOKIE = bytes.fromhex('2112a442')
MI_HDR = bytes.fromhex('00080014')
FP_HDR = bytes.fromhex('80280004')

def hdr(msg_type, length_field):
    return (msg_type).to_bytes(2, 'big') + (length_field).to_bytes(2, 'big') + COOKIE + TID

def check(tag, got, exp):
    ok = got == exp
    print(f'{"PASS" if ok else "FAIL"}  {tag}')
    if not ok:
        print(f'        got {got}')
        print(f'        exp {exp}')
    return ok

results = []

# ---------------- section 2.1: Binding request ----------------
SW  = bytes.fromhex('80220010') + bytes.fromhex('5354554e207465737420636c69656e74')  # 20
PRI = bytes.fromhex('00240004') + bytes.fromhex('6e0001ff')                            # 8
ICE = bytes.fromhex('80290008') + bytes.fromhex('932ff9b151263b36')                    # 12
US  = bytes.fromhex('00060009') + bytes.fromhex('6576746a3a68367659202020')            # 16
assert len(SW) + len(PRI) + len(ICE) + len(US) == 56

pre1 = SW + PRI + ICE + US
declared1 = 0x58                                   # 88 bytes of attributes
assert len(pre1) + len(MI_HDR) + 20 + len(FP_HDR) + 4 == declared1

results.append(check(
    '2.1 MESSAGE-INTEGRITY',
    hmac.new(KEY, hdr(0x0001, len(pre1) + 24) + pre1, hashlib.sha1).hexdigest(),
    '9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2'))

results.append(check(
    '2.1 FINGERPRINT',
    '0x%08x' % ((zlib.crc32(
        hdr(0x0001, declared1) + pre1 + MI_HDR + bytes.fromhex(
            '9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2')) ^ 0x5354554E) & 0xffffffff),
    '0xe57a3bcf'))

# ---------------- section 2.2: IPv4 Binding success ----------------
SOFT2 = bytes.fromhex('8022000b') + bytes.fromhex('7465737420766563746f7220')          # 16
XMAP4 = bytes.fromhex('00200008') + bytes.fromhex('0001a147e112a643')                  # 12
MI2 = bytes.fromhex('2b91f599fd9e90c38c7489f92af9ba53f06be7d7')
assert len(SOFT2) + len(XMAP4) + 24 + 8 == 0x3c

pre2 = SOFT2 + XMAP4
results.append(check(
    '2.2 MESSAGE-INTEGRITY',
    hmac.new(KEY, hdr(0x0101, len(pre2) + 24) + pre2, hashlib.sha1).hexdigest(),
    '2b91f599fd9e90c38c7489f92af9ba53f06be7d7'))

results.append(check(
    '2.2 FINGERPRINT',
    '0x%08x' % ((zlib.crc32(hdr(0x0101, 0x3c) + pre2 + MI_HDR + MI2) ^ 0x5354554E) & 0xffffffff),
    '0xc07d4c96'))

# ---------------- section 2.3: IPv6 Binding success ----------------
XMAP6 = bytes.fromhex('00200014') + bytes.fromhex('0002a1470113a9faa5d3f179bc25f4b5bed2b9d9')  # 24
MI3 = bytes.fromhex('a382954e4be67bf11784c97c8292c275bfe3ed41')
assert len(SOFT2) + len(XMAP6) + 24 + 8 == 0x48

pre3 = SOFT2 + XMAP6
results.append(check(
    '2.3 MESSAGE-INTEGRITY',
    hmac.new(KEY, hdr(0x0101, len(pre3) + 24) + pre3, hashlib.sha1).hexdigest(),
    'a382954e4be67bf11784c97c8292c275bfe3ed41'))

results.append(check(
    '2.3 FINGERPRINT',
    '0x%08x' % ((zlib.crc32(hdr(0x0101, 0x48) + pre3 + MI_HDR + MI3) ^ 0x5354554E) & 0xffffffff),
    '0xc8fb0b4c'))

print()
print('%d/%d vectors reproduced' % (sum(results), len(results)))
