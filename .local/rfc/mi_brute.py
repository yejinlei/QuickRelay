import re
import hashlib
import hmac
import sys

d = open('rfc5769.txt', encoding='utf-8', errors='replace').read()
body = d[d.find('All included vectors are represented'):]
i = body.find('2.4.  Sample Request with Long-Term')
j = body.find('3.  Security Considerations', i)
hr = re.compile(r'((?:[0-9A-Fa-f]{2}\s+){3}[0-9A-Fa-f]{2})')
raw = bytearray()
for ln in body[i:j].splitlines():
    m = hr.search(ln)
    if m:
        raw.extend(int(x, 16) for x in m.group(1).split())
b = bytes(raw)
tot = 20 + int.from_bytes(b[2:4], 'big')

off = 20
mi_off = None
while off + 4 <= tot:
    a = int.from_bytes(b[off:off + 2], 'big')
    l = int.from_bytes(b[off + 2:off + 4], 'big')
    if a == 0x0008:
        mi_off = off
        break
    off += 4 + ((l + 3) // 4 * 4)

vec = bytes.fromhex('f67024656dd64a3e02b8e0712e85c9a28ca89666')
user = bytes.fromhex('e3839ee38388e383aae38383e382afe382b9')
realm = b'example.org'

pws = [
    ('SASLprep', b'the\xadmatrix'),
    ('NFKC-only', b'The\xadMatrIX'),
    ('literal', b'TheMatrIX'),
]

out = ['mi_off=%d' % mi_off]
for pname, pw in pws:
    key = hashlib.md5(user + b':' + realm + b':' + pw).digest()
    for name, cover in [('before-MI-hdr', b[:mi_off]), ('incl-MI-hdr', b[:mi_off + 4])]:
        mi = hmac.new(key, cover, hashlib.sha1).digest()
        tag = '<<< MATCH' if mi == vec else ''
        out.append('%-14s %-15s cover=%d mac=%s %s' % (pname, name, len(cover), mi.hex(), tag))
sys.stdout.buffer.write(('\n'.join(out) + '\n').encode('utf-8'))
