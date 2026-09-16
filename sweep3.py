import hmac, hashlib, zlib

tid = bytes.fromhex('b7e7a701bc34d686fa87dfae')
cookie = bytes.fromhex('2112a442')
key = b'VOkJxbRl1RmTxUk/WvJxBt'
exp_mi = bytes.fromhex('9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2')
mi_hdr = bytes.fromhex('00080014')
fp_hdr = bytes.fromhex('80280004')

# SOFTWARE value is 16 bytes: "STUN test client" padded to the 0x10 declared.
pre = (
    bytes.fromhex('80220010') + bytes.fromhex('5354554e207465737420636c69656e74')
    + bytes.fromhex('00240004') + bytes.fromhex('6e0001ff')
    + bytes.fromhex('80290008') + bytes.fromhex('932ff9b151263b36')
    + bytes.fromhex('00060009') + bytes.fromhex('6576746a3a68367659202020')
)
assert len(pre) == 56, len(pre)

def hdr(ml):
    return (0x0001).to_bytes(2, 'big') + ml.to_bytes(2, 'big') + cookie + tid

def test(tag, buf):
    h = hmac.new(key, buf, hashlib.sha1).digest()
    if h == exp_mi:
        print('MATCH  ', tag, 'len', len(buf))
        return True
    return False

variants = []
# V1: with MI header, 20 zero bytes, length field = end of MI (absolute)
for ml in (80, 100, 88, 84, 76):
    variants.append((f'V1 ml={ml} (hdr+MI hdr+20 zero)', hdr(ml) + pre + mi_hdr + b'\x00' * 20))
# V2: without MI header at all
for ml in (80, 100, 88, 84, 76, 56):
    variants.append((f'V2 ml={ml} (no MI hdr)', hdr(ml) + pre))
# V3: with MI header, no zero value
for ml in (80, 100, 88, 84):
    variants.append((f'V3 ml={ml} (MI hdr only)', hdr(ml) + pre + mi_hdr))
# V4: FP attribute present before MI header? (no)
# V5: include the FINGERPRINT attribute too
for ml in (80, 88, 104, 108):
    variants.append((f'V5 ml={ml} (hdr+MI+FP hdr+zero)', hdr(ml) + pre + mi_hdr + b'\x00' * 20 + fp_hdr + b'\x00' * 4))
# V6: length field little-endian in the hash input
for ml in (80, 100):
    b = bytearray(hdr(ml) + pre + mi_hdr + b'\x00' * 20)
    b[2], b[3] = b[3], b[2]
    variants.append((f'V6 ml={ml} le', bytes(b)))
# V7: RFC 3489 legacy (no cookie scrambling) -- length field = 0x58 kept as-is
variants.append(('V7 ml=0x58 as transmitted', hdr(0x58) + pre + mi_hdr + b'\x00' * 20))

for tag, buf in variants:
    test(tag, buf)

print('--- done; total variants', len(variants))
print()
print('--- response vectors (which we already know validate) for sanity ---')
soft2 = bytes.fromhex('8022000b') + bytes.fromhex('7465737420766563746f7220')
print('soft2 len', len(soft2), soft2.hex())
pre2 = soft2 + bytes.fromhex('00200008') + bytes.fromhex('0001a147e112a643')
print('pre2 len', len(pre2))
b2 = (0x0101).to_bytes(2, 'big') + (20 + len(pre2) + 4 + 20).to_bytes(2, 'big') + cookie + tid + pre2 + mi_hdr + b'\x00' * 20
h2 = hmac.new(key, b2, hashlib.sha1).digest()
print('MI2 with ABS length:', h2.hex(), 'match', h2 == bytes.fromhex('2b91f599fd9e90c38c7489f92af9ba53f06be7d7'))
b2b = (0x0101).to_bytes(2, 'big') + (len(pre2) + 4 + 20).to_bytes(2, 'big') + cookie + tid + pre2 + mi_hdr + b'\x00' * 20
h2b = hmac.new(key, b2b, hashlib.sha1).digest()
print('MI2 with FIELD length:', h2b.hex(), 'match', h2b == bytes.fromhex('2b91f599fd9e90c38c7489f92af9ba53f06be7d7'))
