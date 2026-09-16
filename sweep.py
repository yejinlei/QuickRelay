import hmac, hashlib, zlib

tid = bytes.fromhex('b7e7a701bc34d686fa87dfae')
cookie = bytes.fromhex('2112a442')
key = b'VOkJxbRl1RmTxUk/WvJxBt'
exp_mi = bytes.fromhex('9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2')
exp_fp = 0xe57a3bcf
mi_hdr = bytes.fromhex('00080014')
fp_hdr = bytes.fromhex('80280004')

pre = (
    bytes.fromhex('80220010') + bytes.fromhex('5354554e207465737420636c69656e74')
    + bytes.fromhex('00240004') + bytes.fromhex('6e0001ff')
    + bytes.fromhex('80290008') + bytes.fromhex('932ff9b151263b36')
    + bytes.fromhex('00060009') + bytes.fromhex('6576746a3a68367659202020')
)
assert len(pre) == 56, len(pre)
assert len(exp_mi) == 20
assert len(mi_hdr) == 4
assert len(fp_hdr) == 4

# --- MESSAGE-INTEGRITY: find the length field that reproduces the HMAC ---
hits = []
for ml in range(20, 65536, 4):
    buf = (0x0001).to_bytes(2, 'big') + ml.to_bytes(2, 'big') + cookie + tid + pre + mi_hdr + b'\x00' * 20
    if hmac.new(key, buf, hashlib.sha1).digest() == exp_mi:
        hits.append(ml)
print('HMAC length-field hits:', [(h, hex(h)) for h in hits])

# --- FINGERPRINT: find the length field that reproduces the CRC ---
fp_tail = pre + mi_hdr + exp_mi + fp_hdr
hits2 = []
for fl in range(20, 65536, 4):
    buf = (0x0001).to_bytes(2, 'big') + fl.to_bytes(2, 'big') + cookie + tid + fp_tail
    if (zlib.crc32(buf) ^ 0x5354554E) & 0xffffffff == exp_fp:
        hits2.append(fl)
print('CRC  length-field hits:', [(h, hex(h)) for h in hits2])

# Same sweep but without the FINGERPRINT header in the CRC input
hits3 = []
for fl in range(20, 65536, 4):
    buf = (0x0001).to_bytes(2, 'big') + fl.to_bytes(2, 'big') + cookie + tid + pre + mi_hdr + exp_mi
    if (zlib.crc32(buf) ^ 0x5354554E) & 0xffffffff == exp_fp:
        hits3.append(fl)
print('CRC (no FP hdr) hits:', [(h, hex(h)) for h in hits3])

print('sanity: end of MI attr =', 20 + len(pre) + 4 + 20, hex(20 + len(pre) + 4 + 20))
print('sanity: length field for full msg =', len(pre) + 4 + 20 + 8)
print('sanity: wire length =', 20 + len(pre) + 24 + 8)
