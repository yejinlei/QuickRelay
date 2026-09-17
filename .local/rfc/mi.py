import hashlib, hmac, sys
u='30de30c830ea30c330af30b9'.encode().decode('utf-8')
pw='TheMatrIX'
realm='example.org'
head=bytes.fromhex('000100602112a44278ad3433c6ad72c029da412e')
out=[]
for covdesc, cov in [
    ('header+20+4+20+4+24+4', head+bytes.fromhex('00060012')[:20]+b''),
]:
    pass
# covered = head + USERNAME(hdr 00060012 + 18 val) + NONCE(hdr 0015001c + 28 val) + REALM(hdr 0014000b + 11 val) + INTEGRITY hdr
cov = head
cov += bytes.fromhex('00060012') + bytes.fromhex('e3839ee38388e383aae38383e382afe382b9')
cov += bytes.fromhex('0015001c') + bytes.fromhex('662f2f3439396b39353464364f4c33346f4c39465354767936347341')
cov += bytes.fromhex('0014000b') + b'example.org'
cov += bytes.fromhex('00080014')
out.append('covered len=%d hex=%s'%(len(cov), cov.hex()))
key=hashlib.md5((u+':'+realm+':'+pw).encode()).digest()
out.append('key=%s'%key.hex())
mi=hmac.new(key,cov,hashlib.sha1).digest()
out.append('computed=%s'%mi.hex())
out.append('vector  =f67024656dd64a3e02b8e0712e85c9a28ca89666')
out.append('RESULT  = %s'%('MATCH' if mi.hex()=='f67024656dd64a3e02b8e0712e85c9a28ca89666' else 'MISMATCH'))
out.append('covered ends with INTEGRITY header: %s'%cov[-4:].hex())
sys.stdout.buffer.write(('\n'.join(out)+'\n').encode())
