import struct, hashlib, hmac, sys
b=bytes.fromhex('000100602112a44278ad3433c6ad72c029da412e')
assert len(b)==14
user=b'\xe3\x83\x9e\xe3\x83\x88\xe3\x83\xaa\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9'
realm=b'example.org'
for pw in ['TheMatrIX','TheMatrIX']:
    pb=pw.encode()
    sys.stdout.buffer.write('pw=%s  codepoints=%s\n'%(pb, str([hex(ord(c)) for c in pw])).encode())
    concat=user+b':'+realm+b':'+pb
    sys.stdout.buffer.write('concat=%s\n'%concat.hex().encode())
    key=hashlib.md5(concat).digest()
    sys.stdout.buffer.write('key=%s\n'%key.hex().encode())
    sys.stdout.buffer.write('covered=%s\n'%b.hex().encode())
    sys.stdout.buffer.write('mac=%s\n'%hmac.new(key,b,hashlib.sha1).digest().hex().encode())
    sys.stdout.buffer.write('vec=%s\n'%b'f67024656dd64a3e02b8e0712e85c9a28ca89666'.hex().encode())
