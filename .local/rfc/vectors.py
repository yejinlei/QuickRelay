import re, struct, zlib

d = open('rfc5769.txt', encoding='utf-8', errors='replace').read()
BODY = d


def section(name_start, name_end=None):
    # skip the table of contents: locate the body section, not the ToC entry
    k = BODY.find('All included vectors are represented')
    body = BODY[k:]
    i = body.find(name_start)
    j = body.find(name_end, i) if name_end else len(body)
    return body[i:j]


def parse_vec(text):
    """Pull bytes from 'xx yy zz' hex rows, ignoring prose/labels."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        # strip trailing label after the hex run
        m = re.match(r'^((?:[0-9A-Fa-f]{2}\s*)+)(.*)$', s)
        if m and len(m.group(1)) >= 4:
            out.extend(int(x, 16) for x in m.group(1).split())
            continue
        if re.fullmatch(r'[0-9A-Fa-f]{2,}', s):
            s2 = s if len(s) % 2 == 0 else s[:-1]
            out.extend(int(s2[i:i + 2], 16) for i in range(0, len(s2), 2))
    return bytes(out)


def check(name, b):
    assert len(b) >= 20, (name, len(b))
    msgtype, length = struct.unpack('>HH', b[0:4])
    cookie, txn = b[4:8], b[8:20]
    assert b[0] == 0x00, name
    assert cookie == bytes.fromhex('2112a442'), (name, cookie.hex())
    assert length % 4 == 0, (name, length)
    assert 20 + length == len(b), (name, len(b), length)
    print('%-22s len=%-4d msgtype=0x%04X nattr=%d' % (name, length, msgtype, 0))
    off = 20
    attrs = []
    while off < 20 + length:
        at, al = struct.unpack('>HH', b[off:off + 4])
        attrs.append((at, al, b[off + 4:off + 4 + al]))
        off += 4 + al
    # fingerprint check
    for i, (at, al, val) in enumerate(attrs):
        if at == 0x8028 and al == 4:
            head = b[:off - 8]
            fp = (zlib.crc32(head) ^ 0x5354554E) & 0xFFFFFFFF
            got = struct.unpack('>I', val)[0]
            print('   FINGERPRINT msg=0x%08X computed=0x%08X -> %s' %
                  (got, fp, 'OK' if got == fp else 'MISMATCH'))
    print('   attrs: ' + ', '.join('0x%04X(%d)%s' % (at, al, '/' + val.decode('latin-1')
                                                     if al <= 20 and al > 0 else '')
                                    for at, al, val in attrs))
    return b


v1 = parse_vec(section('2.1.  Sample Request', '2.2.  Sample IPv4 Response'))
v2 = parse_vec(section('2.2.  Sample IPv4 Response', '2.3.  Sample IPv6 Response'))
v3 = parse_vec(section('2.3.  Sample IPv6 Response', '2.4.  Sample Request with Long-Term'))
v4 = parse_vec(section('2.4.  Sample Request with Long-Term', '3.  Security Considerations'))

for nm, v in [('sample-request', v1), ('sample-response-v4', v2),
              ('sample-response-v6', v3), ('sample-request-longterm', v4)]:
    check(nm, v)
    print('   HEX(' + str(len(v)) + '): ' + v.hex(' '))
    print()
