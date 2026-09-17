import re
d = open('iana.xml', encoding='utf-8', errors='replace').read()
recs = []
for m in re.finditer(r'<record>(.*?)</record>', d, re.S):
    vals = [re.sub(r'\s+', ' ', x).strip() for x in re.findall(r'<value>(.*?)</value>', m.group(1), re.S)]
    if vals and re.match(r'^0x[0-9A-Fa-f]{4}(\s*-\s*0x[0-9A-Fa-f]{4})?$', vals[0]):
        recs.append(vals)
lo, hi = 0x8020, 0x8040
for v in recs:
    a = int(v[0].split('-')[0], 16)
    if lo <= a <= hi:
        print(v[0], '|', v[1] if len(v) > 1 else '', '|', ' | '.join(v[2:]))
print('=== also 0x8040-0x8048 ===')
for v in recs:
    a = int(v[0].split('-')[0], 16)
    if 0x8040 <= a <= 0x8048:
        print(v[0], '|', v[1] if len(v) > 1 else '')
