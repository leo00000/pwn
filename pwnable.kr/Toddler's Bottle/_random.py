from pwn import *


con = ssh("random", "pwnable.kr", 2222, "guest")
sh = con.process("./random")
sh.sendline("3039230856")
print(sh.recvlines(2)[1])

# Mommy, I thought libc random is unpredictable...
