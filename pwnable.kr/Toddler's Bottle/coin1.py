from pwn import *

pwnfile = r"""
from pwn import *


def guess(count):
    n, c = map(int, re.findall("\d+", sh.recvline_regex("^N=(\d+) C=(\d+)")))    
    index = 0
    while True:
        if n == 0:
            sh.sendline(str(index))
        else:
            sh.sendline(" ".join(map(str, range(index, index + n/2 + n%2))))        
        r = sh.recvline().strip()
        if r.startswith("Wrong") or r.startswith("format"):
            print n, index, soldier
        if r.startswith("Correct!"):
            print("Got {0} coins!".format(count + 1))
            return
        elif not (int(r) % 2):
            index = index + n/2 + n%2
        n /= 2
        

sh = process(["/bin/nc", "0", "9007"], executable="/bin/nc")
[guess(x) for x in range(0, 100)]
print(sh.recv())

"""

con = ssh("input2", "pwnable.kr", 2222, "guest")
con.shell("mkdir /tmp/leo/")
con.upload_data(pwnfile, "/tmp/leo/pwnfile2.py")
sh = con.run("python -i /tmp/leo/pwnfile2.py")
for x in range(0, 104):
    print(sh.recvline().strip())

# b1NaRy_S34rch1nG_1s_3asy_p3asy
