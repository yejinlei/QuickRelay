import re, struct, sys
d=open('rfc5769.txt',encoding='utf-8',errors='replace').read()
body=d[d.find('All included vectors are represented'):]
i=body.find('2.4.  Sample Request with Long-Term'); j=body.find('3.  Security Considerations',i)
hr=re.compile(r'((?:[0-9A-Fa-f]{2}\s+){3}[0-9A-Fa-f]{2})')
raw=bytearray()
for ln in body[i:j].splitlines():
    m=hr.search(ln)
    if m: raw.extend(int(x,16) for x in m.group(1).split())
b=bytes(raw)
tot=20+struct.unpack('>H',b[2:4])[0]
out=['len raw=%d total=%d'%(len(b),tot)]
o=20
while o+4<=tot:
    at,al=struct.unpack('>HH',b[o:o+4])
    out.append('off=%d type=0x%04X len=%d val=%s'%(o,at,al,b[o+4:o+4+al].hex()))
    o+=4+((al+3)//4*4)
out.append('walk end=%d'%o)
sys.stdout.buffer.write(('\n'.join(out)+'\n').encode())
