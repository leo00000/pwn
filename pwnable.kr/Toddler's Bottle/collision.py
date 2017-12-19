from pwn import *

con = ssh("col", "pwnable.kr", 2222, "guest")
argv = ["/home/col/col", "\x01\x01\x01\x01" * 4 + p32(0x21dd09ec - 0x1010101 * 4)]
sh = con.process(argv, executable=argv[0])
print(sh.recvall())

# daddy! I just managed to create a hash collision :)
