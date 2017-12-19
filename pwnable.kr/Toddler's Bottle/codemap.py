from pwn import *

ida_script = r"""
from idaapi import *

chunks = {}

class DbgHook(DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        global chunks
        chunks[GetRegValue("eax")] = dbg_read_memory(GetRegValue("ebx"), 20)
        continue_process()
        return 0

try:
    if debugger:
        debugger.unhook()
except Exception as e:
    pass


AddBpt(0x403E65)
debugger = DBG_Hooks()
debugger.hook()
request_start_process("C:\\Users\\win7\\Desktop\\codemap.exe", "", "")
run_requests()


#chunk_3rd = chunks[sorted(chunks.key())[-3]]
#chunk_2nd = chunks[sorted(chunks.key())[-2]]
"""

chunk_2nd = "roKBkoIZGMUKrMb"
chunk_3rd = "2ckbnDUabcsMA2s"

con = ssh("codemap", "pwnable.kr", 2222, "guest")
sh = con.process(["/bin/nc", "0", "9021"])
sh.recvuntil("What is the string inside 2nd biggest chunk? :")
sh.sendline(chunk_2nd)
sh.recvuntil("What is the string inside 3rd biggest chunk? :")
sh.sendline(chunk_3rd)
print(sh.recvlines(3)[2])

# Congratz! flag : select_eax_from_trace_order_by_eax_desc_limit_20
