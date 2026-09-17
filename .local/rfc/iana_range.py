import re, sys

d = open('iana.xml', encoding='utf-8', errors='replace').read()

# Split into registry blocks so we only read the STUN Attributes registry.
blocks = re.split(r'<registry\b', d)
target = None
for b in blocks[1:]:
    head = b[:400]
    if 'STUN Attributes' in b[:2000] and 'stun-attributes' in head:
        target = b
        break
if target is None:
    for b in blocks[1:]:
        if '0x8022' in b:
            target = b
            break

rows = []
for m in re.finditer(r'<record[^>]*>(.*?)</record>', target, re.S):
    r = m.group(1)
    v = re.sub(r'\s+', ' ', re.search(r'<value>(.*?)</value>', r, re.S).group(1)).strip()
    desc = re.sub(r'\s+', ' ', re.search(r'<description>(.*?)</description>', r, re.S).group(1)).strip()
    xref = ' '.join(re.findall(r'<xref[^>]*data="(rfc[^"]+)"', r))
    rows.append((v, desc, xref))

lo = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0
hi = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0xFFFF
for v, desc, x in rows:
    a = int(v.split('-')[0], 16)
    if lo <= a <= hi:
        print(v, desc[:44].ljust(46), x)
