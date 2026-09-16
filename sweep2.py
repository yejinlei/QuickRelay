import hmac, hashlib, zlib, itertools

tid = bytes.fromhex('b7e7a701bc34d686fa87dfae')
cookie = bytes.fromhex('2112a442')
key = b'VOkJxbRl1RmTxUk/WvJxBt'
exp_mi = bytes.fromhex('9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2')
exp_fp = 0xe57a3bcf
mi_hdr = bytes.fromhex('00080014')
fp_hdr = bytes.fromhex('80280004')

SW = bytes.fromhex('80220010') + bytes.fromhex('5354554e207465737420636c69656e74')
PRI = bytes.fromhex('00240004') + bytes.fromhex('6e0001ff')
ICE = bytes.fromhex('80290008') + bytes.fromhex('932ff9b151263b36')
US_nopad = bytes.fromhex('00060009') + bytes.fromhex('6576746a3a68367659')

base = SW + PRI + ICE + US_nopad
assert len(base) == 44, len(base)

print('--- sweep over USERNAME padding and length field ---')
found = []
for pad in (b'\x20' * 3, b'\x00' * 3):
    pre = base + pad
    for ml in range(0, 65536):
        if ml % 4:
            continue
        buf = (0x0001).to_bytes(2, 'big') + ml.to_bytes(2, 'big') + cookie + tid + pre + mi_hdr + b'\x00' * 20
        if hmac.new(key, buf, hashlib.sha1).digest() == exp_mi:
            found.append(('pad=' + pad.hex(), ml, hex(ml)))
print('hits:', found)

print('--- sweep with SOFTWARE padding variants too ---')
found2 = []
for sw_pad in (b'', b'\x20', b'\x00'):
    sw = bytes.fromhex('80220010') + bytes.fromhex('5354554e207465737420636c69656e74') + sw_pad
    if sw_pad:
        continue  # declared len 0x10 forbids it; keep as sanity note
    for pad in (b'\x20' * 3, b'\x00' * 3):
        pre = sw + PRI + ICE + US_nopad + pad
        for ml in range(0, 400, 4):
            buf = (0x0001).to_bytes(2, 'big') + ml.to_bytes(2, 'big') + cookie + tid + pre + mi_hdr + b'\x00' * 20
            if hmac.new(key, buf, hashlib.sha1).digest() == exp_mi:
                found2.append((pad.hex(), ml))
print('hits2:', found2)

print('--- per-byte diff search: which single byte, if changed, fixes the HMAC? ---')
pre = base + b'\x20' * 3
best = []
for pos in range(len(pre)):
    for v in range(256):
        if v == pre[pos]:
            continue
        cand = pre[:pos] + bytes([v]) + pre[pos + 1:]
        for ml in (80, 84, 100, 104):
            buf = (0x0001).to_bytes(2, 'big') + ml.to_bytes(2, 'big') + cookie + tid + cand + mi_hdr + b'\x00' * 20
            if hmac.new(key, buf, hashlib.sha1).digest() == exp_mi:
                best.append((pos, v, ml))
print('single-byte fixes:', best)
