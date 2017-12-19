from pwn import *

con = ssh("leg", "pwnable.kr", 2222, "guest")
sh = con.run(" ")
key1 = 0x00008cdc + 8
key2 = 0x00008d04 + 4 + 4
key3 = 0x00008d80
sh.recvuntil("input/input1")
sh.sendline("/leg")
sh.recvline()
sh.sendline(str(key1 + key2 + key3))
print(sh.recvlines(4)[3])

# My daddy has a lot of ARMv5te muscle!
