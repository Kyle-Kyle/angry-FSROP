from pwn import *
context.arch = 'amd64'

######## CONFIGURATION ##########
TIMEOUT = 60
MAX_STEP = 100
_IO_vtable_check = 0x89f70
libc_path = "./bins/libc.so.6"
libc_symbol_path = "./bins/389d485a9793dbe873f0ea2c93e02efaa9aa3d.debug"
output_dir = "outputs"
#################################

e = ELF(libc_path)
raw_bytes = e.section('__libc_IO_vtables')
os.makedirs(output_dir, exist_ok=True)

def get_symbols():
    symbols = [(x, y, e.functions[x].size) for x, y in e.symbols.items() if x in e.functions]

    output = subprocess.getoutput(f"readelf -W -s {libc_symbol_path}")
    for line in output.splitlines():
        elems = line.split()
        if len(elems) != 8:
            continue
        _, addr_str, size_str, _, _, _, _, sym_name = elems
        try:
            addr = int(addr_str, 16)
        except Exception:
            continue
        size = int(size_str)
        if addr == 0:
            continue
        if '@' in sym_name:
            sym_name = sym_name.split('@')[0]
        # print(sym_name, hex(addr))
        symbols.append((sym_name, addr, size))
    return symbols

symbols = get_symbols()

# get all the pointers in the vtable section
ptrs = []
for i in range(0, len(raw_bytes), 8):
    ptr = u64(raw_bytes[i:i+8])
    if ptr == 0:
        continue
    ptrs.append(ptr)

# get names of all the functions that need to be examined
func_names = []
for ptr in ptrs:
    for name, addr, _ in symbols:
        if addr == ptr:
            func_names.append(name)
            break
    else:
        print(ptr)
        print(func_names)
        raise
func_names = set(func_names)


#for func_name in func_names:
#    for name, addr, size in symbols:
#        if func_name != name:
#            continue
#        disassembly = e.disasm(addr, size)
#        print(name, hex(addr))
#        print(disassembly)
#        print("="*0x10)

import sys
import angr
import claripy
import logging
from angr.concretization_strategies import SimConcretizationStrategy

#sys.setrecursionlimit(0x100000)

logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel("ERROR")
logging.getLogger("angr.engines.successors").setLevel("ERROR")

target_symbols = {(x, y, z) for x, y, z in symbols if x in func_names}

class FSOPSimConcretizationStrategy(SimConcretizationStrategy):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._cnt = 0

    def _concretize(self, memory, addr, **kwargs):
        addrs = memory.state.solver.eval_upto(addr, 3)
        #import IPython; IPython.embed()
        #prin(addr, addrs)
        if len(addrs) == 3:
            self._cnt += 1
            return [0, 0x1000000000000 * self._cnt]
        else:
            return addrs
        #print(addr, kwargs)
        #print([0, 0x1000000000000 * self._cnt])
        #print(memory, addr)
        #import IPython; IPython.embed()

proj = angr.Project(libc_path, main_opts={"base_addr": 0})
file_struct = claripy.Concat(*[claripy.BVS("content_%#x" % x, 8*8, explicit_name=True)  for x in range(0, 0x200, 8)])
wide_data = claripy.BVS("wide_data", 8*8, explicit_name=True)
for name, addr, size in target_symbols:
    if name != "_IO_wfile_overflow":
        continue

    print(name)
    state = proj.factory.blank_state(addr=addr)
    reg_list = [x for x in state.arch.default_symbolic_registers if x not in ['rip', 'rsp']]
    for reg in reg_list:
        setattr(state.regs, reg, claripy.BVS(f"orig_{reg}", 8*8, explicit_name=True))
    state.stack_push(0x41414141)
    state.regs.rdi = 0x5000000
    state.memory.store(state.regs.rdi, file_struct)
    state.memory.store(state.regs.rdi+0xa0, wide_data)
    #state.memory.read_strategies = [FSOPSimConcretizationStrategy()]
    #state.memory.write_strategies = [FSOPSimConcretizationStrategy()]
    #import IPython; IPython.embed()

    # state.options.add(angr.sim_options.SYMBOLIC_WRITE_ADDRESSES)
    simgr = proj.factory.simgr(state, save_unconstrained=True)
    #veri = angr.exploration_techniques.Veritesting()
    #simgr.use_technique(veri)

    # do exploration
    simgr.stashes['avoided'] = []
    simgr.stashes['bad'] = []
    simgr.stashes['unconstrained'] = []
    step = 0
    try:
        while simgr.active:
            start = time.time()
            simgr.step()
            elapsed_time = time.time() - start
            simgr.move("active", "deadended", filter_func=lambda s: s.addr == 0x41414141)
            simgr.move("active", "avoided", filter_func=lambda s: s.addr == _IO_vtable_check)
            simgr.move("unconstrained", "bad", filter_func=lambda s: s.regs.pc.depth > 1)
            simgr.move("active", "errored", filter_func=lambda s: proj.loader.find_segment_containing(s.addr) is None)
            print(f"\ntime: {elapsed_time}")
            print(simgr)
            step += 1
            if elapsed_time > TIMEOUT:
                break
            if step > MAX_STEP:
                break
            #if simgr.unconstrained:
            #    print("FOUND!!!!!!!!!!!!!!!" + "\n!!!!!!!!!!!!!!!"*3)
            #    import IPython; IPython.embed()
    except Exception:
        pass

    # save results if there are any
    if simgr.unconstrained:
        with open(f"{output_dir}/{name}.pickle", 'wb') as f:
            pickle.dump(simgr.unconstrained, f)
