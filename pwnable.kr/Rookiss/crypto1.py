from pwn import *

charset = string.digits + string.ascii_lowercase + "_-"
cookie = ""  # you_will_never_guess_this_sugar_honey_salt_cookie


def recv_cipher(plain):
    sh = remote("pwnable.kr", 9006)
    sh.recvuntil("ID")
    sh.sendline(plain)
    sh.recvuntil("PW")
    sh.sendline("")
    recv_data = sh.recvuntil(")")
    sh.close()
    return recv_data[recv_data.find("(") + 1: recv_data.find(")")]


def pwn_flag():
    pw = hashlib.sha256("admin" + cookie).hexdigest()

    sh = remote("pwnable.kr", 9006)
    sh.recvuntil("ID")
    sh.sendline("admin")
    sh.recvuntil("PW")
    sh.sendline(pw)
    print sh.recvall()


# cookie's lenth is between 48 and 64
for n in range(0, 64):
    rounds = (n + 2) / 16 + 1
    cookie_prefix = "-" * (16 * (rounds - 1) + 13 - n)
    brute_prefix = "-" * (16 * (rounds - 1) + 15 - n) + cookie
    cookie_cipher = recv_cipher(cookie_prefix)[:rounds * 32]
    for c in charset:
        if recv_cipher(brute_prefix + c)[: rounds * 32] == cookie_cipher:
            cookie += c
            print(cookie)
            break
        if c == "-":
            pwn_flag()
            exit()

# byte to byte leaking against block cipher plaintext is fun!!
