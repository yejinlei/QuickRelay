import re
d = open('iana.xml', encoding='utf-8', errors='replace').read()
for m in re.finditer(r'<registry\b[^>]*>(.*?)(?=<registry\b|</registry-assignments>)', d, re.S):
    head = m.group(0)[:200]
    rid = re.search(r'id="([^"]+)"', head)
    rdesc = re.search(r'<registry[^>]*>\s*<name>([^<]+)</name>', head, re.S)
    rows = re.findall(r'<record[^>]*>.*?</record>', m.group(1), re.S)
    print('=== %s  (%s) rows=%d' % (rid.group(1) if rid else '?', rdesc.group(1) if rdesc else '?', len(rows)))
    if rid and rid.group(1) == 'stun-parameters-4':
        for r in rows:
            v = re.sub(r'\s+', ' ', re.search(r'<value>(.*?)</value>', r, re.S).group(1)).strip()
            desc = re.sub(r'\s+', ' ', re.search(r'<description>(.*?)</description>', r, re.S).group(1)).strip()
            x = ' '.join(re.findall(r'<xref[^>]*data="(rfc[^"]+)"', r))
            print('   ', v.ljust(16), desc[:46].ljust(48), x)
