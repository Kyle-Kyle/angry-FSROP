import sys
import angr
import claripy
import archinfo
import logging
from angr.concretization_strategies import SimConcretizationStrategy
from pwn import *
context.arch = 'amd64'

logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel("ERROR")
logging.getLogger("angr.engines.successors").setLevel("ERROR")

######## CONFIGURATION ##########
TIMEOUT = 20
MAX_STEP = 10
_IO_vtable_check = 0x89f70
libc_path = "./bins/libc.so.6"
libc_symbol_path = "./bins/389d485a9793dbe873f0ea2c93e02efaa9aa3d.debug"
output_dir = "hacklu_outputs"
control_size = 0x100
FAKE_RET_ADDR = 0x41414141
FS_ADDR = 0x5000000
#################################

class FSROP:
    def __init__(self, libc_path, symbol_path):

        # for static analysis
        self.elf = ELF(libc_path)
        self.all_funcs = []
        self.target_funcs = []
        self.vtable_ptrs = []

        # for symbolic analysis
        self.project = angr.Project(libc_path, main_opts={"base_addr": 0})
        self.sim_file = self.init_sim_file(self.project)

    def init_sim_file(self, project):
        """
        create a symbolic file structure, store the pointers in the correct endianness for interpretability
        """
        bits = project.arch.bits
        bytes = project.arch.bytes
        if project.arch.memory_endness == "Iend_LE":
            return claripy.Concat(*[claripy.BVS("file_%#x" % x, bits, explicit_name=True).reversed  for x in range(0, control_size, bytes)])
        return claripy.Concat(*[claripy.BVS("file_%#x" % x, bits, explicit_name=True) for x in range(0, control_size, bytes)])

    def create_sim_states(self, addr, invoke_offset):
        """
        find all vtables that can lead to setting PC to <addr>.
        For each such case, create a symbolic state
        TODO: make this function not x64-specific
        """
        bits = self.project.arch.bits
        bytes = self.project.arch.bytes

        # bootstrap an empty symbolic state first by symbolize all the registers
        state = self.project.factory.blank_state(addr=addr)
        state.options.add(angr.sim_options.SYMBOLIC_WRITE_ADDRESSES)
        reg_list = [x for x in state.arch.default_symbolic_registers if x not in ['rip', 'rsp']]
        for reg in reg_list:
            setattr(state.regs, reg, claripy.BVS(f"reg_{reg}", bits, explicit_name=True))

        # push a fake return address so we will know when the target function finishes execution
        state.stack_push(FAKE_RET_ADDR)

        # store the symbolic file structure
        state.regs.rdi = FS_ADDR
        state.memory.store(FS_ADDR, self.sim_file)
        #state.memory.store(FS_ADDR+0x80, claripy.BVV(0, 0x40*8))

        # now, concretize the vtable itself to avoid angr exploiting it by setting the vtable and invoking another handler
        # this is invoking function-specific
        vtable_sec_base = self.elf.get_section_by_name('__libc_IO_vtables').header['sh_addr']
        vtable_candidates = [vtable_sec_base+bytes*i-invoke_offset for i in range(len(self.vtable_ptrs)) if self.vtable_ptrs[i] == addr]
        states = []
        for vtable in vtable_candidates:
            # concretize the vtable field for each state
            s = state.copy()
            s.memory.store(FS_ADDR+27*bytes, claripy.BVV(vtable, bits), endness=self.project.arch.memory_endness)
            states.append(s)
        return states

    def get_vtable_ptrs(self):
        """
        extract unique raw pointers from the vtable region
        """
        raw_bytes = self.elf.section('__libc_IO_vtables')
        self.vtable_ptrs = [u64(raw_bytes[i:i+8]) for i in range(0, len(raw_bytes), 8)]

    def get_all_funcs(self):
        """
        extract all function information from the libc itself and its symbol file
        each entry is a tuple of (function_name, address, function_size)
        """
        e = self.elf
        info = [(x, y, e.functions[x].size) for x, y in e.symbols.items() if x in e.functions]

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
            info.append((sym_name, addr, size))
        self.all_funcs = info

    def get_target_funcs(self):
        """
        extract raw function pointers in the vtable region and return the information
        of each vtable function pointer
        each entry is a tuple of (function_name, address, function_size)
        """
        target_funcs = set()
        for ptr in self.vtable_ptrs:
            if ptr == 0:
                continue
            for name, addr, size in self.all_funcs:
                if addr == ptr:
                    target_funcs.add((name, addr, size))
                    break
            else:
                log.warning("No symbol for pointer: %#x", ptr)

        self.target_funcs = list(target_funcs)

    def sim_explore(self, simgr):
        """
        use angr to explore the states
        """
        simgr.stashes['avoided'] = []
        simgr.stashes['bad'] = []
        simgr.stashes['unconstrained'] = []
        simgr.stashes['bad_addr'] = []
        step = 0
        try:
            while simgr.active:
                start = time.time()
                simgr.step()
                elapsed_time = time.time() - start
                simgr.move("active", "deadended", filter_func=lambda s: s.addr == FAKE_RET_ADDR)
                simgr.move("active", "avoided", filter_func=lambda s: s.addr == _IO_vtable_check)
                simgr.move("unconstrained", "bad", filter_func=lambda s: s.regs.pc.depth > 1)
                simgr.move("active", "bad_addr", filter_func=lambda s: self.project.loader.find_segment_containing(s.addr) is None or s.addr < 0x1000)
                print(f"\ntime: {elapsed_time}")
                print(simgr)
                step += 1
                if elapsed_time > TIMEOUT:
                    break
                if step > MAX_STEP:
                    break
        except Exception:
            pass
        return simgr

    def analyze(self):
        self.get_vtable_ptrs()
        self.get_all_funcs()
        self.get_target_funcs()

        for name, addr, size in self.target_funcs:
            print(name, hex(addr), hex(size))
            states = self.create_sim_states(addr, 0x60)
            simgr = self.project.factory.simgr(states, save_unconstrained=True)
            self.sim_explore(simgr)

            # save results if there are any
            if simgr.unconstrained:
                with open(f"{output_dir}/{name}.pickle", 'wb') as f:
                    pickle.dump(simgr.unconstrained, f)

if __name__ == '__main__':
    fsrop = FSROP(libc_path, libc_symbol_path)
    fsrop.analyze()
