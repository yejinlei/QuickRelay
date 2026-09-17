import re, struct, hashlib, hmac, sys
d=open('rfc5769.txt',encoding='utf-8',errors='replace').read()
body=d[d.find('All included vectors are represented'):]
i=body.find('2.4.  Sample Request with Long-Term'); j=body.find('3.  Security Considerations',i)
hr=re.compile(r'((?:[0-9A-Fa-f]{2}\s+){3}[0-9A-Fa-f]{2})')
raw=bytearray()
for ln in body[i:j].splitlines():
    m=hr.search(ln)
    if m: raw.extend(int(x,16) for x in m.group(1).split())
b=bytes(raw[:20+struct.unpack('>H',raw[2:4])[0]])
attrs={}; off=20; mi_end=None
while off<len(b):
    at,al=struct.unpack('>HH',b[off:off+4]); attrs[at]=b[off+4:off+4+al]
    end=off+4+((al+3)//4*4); off=end
    if at==0x0008 and mi_end is None: mi_end=end-4-al
user=b'30de30c830ea30c330af30b9'.decode('utf-8')
realm=attrs[0x0014].rstrip(b'\x00')
covered=b[:mi_end]; want=b[-20:]
for pw,tag in [(u'TheMatrIX','SASLprep'), (u'The­MªtrⅨ','raw')]:
    key=hashlib.md5(user.encode()+b':'+realm+b':'+pw.encode()).digest()
    mac=hmac.new(key,covered,hashlib.sha1).digest()
    sys.stdout.buffer.write(('%-10s key=%s mac=%s vec=%s %s\n'%(tag,key.hex(),mac.hex(),want.hex(),'MATCH' if mac==want else 'MISMATCH')).encode())
