import os
import sys
import time
import struct
import pickle
import logging
import subprocess

import angr
import claripy

from pwnlib.elf import ELF
from pwnlib.log import getLogger, console
from angr.concretization_strategies import SimConcretizationStrategy

angr.loggers.disable_root_logger() # disable angr's intrusive logging behavior
log = getLogger("FSROP")
log.addHandler(console)
log.setLevel("DEBUG")

######## CONFIGURATION ##########
DEFAULT_OUTPUT_FOLDER = "./outputs"
DEFAULT_TIMEOUT = 20
DEFAULT_MAX_STEP = 10
DEFAULT_CONTROL_SIZE = 0x100
FAKE_RET_ADDR = 0x41414141
FS_ADDR = 0x5000000
IO_JUMP_ATTR = ["dummy", "dummy2", "finish", "overflow", "underflow", "uflow",
          "pbackfail", "xsputn", "xsgetn", "seekoff", "seekpos", "setbuf",
          "sync", "doallocate", "read", "write", "seek", "close", "stat",
          "showmanyc", "imbue"]
#################################

class FSROPSimConcretizationStrategy(SimConcretizationStrategy):
    def __init__(self, project, **kwargs):
        super().__init__(**kwargs)
        self._cnt = 0
        self.project = project
        self.max_addr = (1 << self.project.arch.bits) - 0x1000

    def _sim_data(self, addr):
        bits = self.project.arch.bits
        bytes = self.project.arch.bytes

        bvs = [claripy.BVS("data_%#x" % (addr+x), bits, explicit_name=True) for x in range(0, 0x200, bytes)]
        if self.project.arch.memory_endness == "Iend_LE":
            bvs = [x.reversed for x in bvs]
        return claripy.Concat(*bvs)

    def _concretize(self, memory, addr, **kwargs):
        # print("concretizing", memory, addr)
        # the addresses have to be smaller than the max, or it will wrap around in some cases,
        # which is bad
        addrs = memory.state.solver.eval_upto(addr, 3, extra_constraints=[addr<self.max_addr])

        # in case the memory is heavily constrained, just return all the possible choices
        if len(addrs) < 3:
            return addrs

        # it is unconstrained, then we just return our own fake pointer
        if len(addrs) == 3:
            self._cnt += 1
            addr = 0x10000000 * self._cnt
            memory.state.memory.store(addr, self._sim_data(addr))
            return [addr]

class FSROP:
    def __init__(self, libc_path, trigger_func, symbol_path, timeout=DEFAULT_TIMEOUT,
                 max_step=DEFAULT_MAX_STEP, output_dir=DEFAULT_OUTPUT_FOLDER, control_size=DEFAULT_CONTROL_SIZE):
        self.output_dir = output_dir

        # for static analysis
        self.elf = ELF(libc_path)
        self.libc_symbol_path = symbol_path
        self.all_funcs = []
        self.target_funcs = []
        self.vtable_ptrs = []
        self._IO_vtable_check = None

        # for symbolic analysis
        self.control_size = control_size
        self.timeout = timeout
        self.max_step = max_step
        self.project = angr.Project(libc_path, main_opts={"base_addr": 0})
        self.sim_file = self.init_sim_file(self.project)

        # determine the function offset in the vtable
        self.offset_map = {attr:idx*self.project.arch.bytes for idx, attr in enumerate(IO_JUMP_ATTR)}
        self.offset = self.offset_map[trigger_func]

    def init_sim_file(self, project):
        """
        create a symbolic file structure, store the pointers in the correct endianness for interpretability
        """
        bits = project.arch.bits
        bytes = project.arch.bytes
        bvs = [claripy.BVS("file_%#x" % x, bits, explicit_name=True) for x in range(0, self.control_size, bytes)]
        if project.arch.memory_endness == "Iend_LE":
            bvs = [x.reversed for x in bvs]
        return claripy.Concat(*bvs)

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
        state.memory.read_strategies = [FSROPSimConcretizationStrategy(self.project)]
        state.memory.write_strategies = [FSROPSimConcretizationStrategy(self.project)]
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
        bytes = self.project.arch.bytes
        raw_bytes = self.elf.section('__libc_IO_vtables')
        def unpack(s):
            return struct.unpack(self.project.arch.struct_fmt(), s)[0]
        self.vtable_ptrs = [unpack(raw_bytes[i:i+bytes]) for i in range(0, len(raw_bytes), bytes)]

    def get_all_funcs(self):
        """
        extract all function information from the libc itself and its symbol file
        each entry is a tuple of (function_name, address, function_size)
        """
        e = self.elf
        info = [(x, y, e.functions[x].size) for x, y in e.symbols.items() if x in e.functions]

        output = subprocess.getoutput(f"readelf -W -s {self.libc_symbol_path}")
        for line in output.splitlines():
            elems = line.split()
            if len(elems) != 8:
                continue
            _, addr_str, size_str, _, _, _, _, sym_name = elems
            try:
                addr = int(addr_str, 16)
            except Exception as e:
                continue
            size = int(size_str)
            if addr == 0:
                continue
            if '@' in sym_name:
                sym_name = sym_name.split('@')[0]
            # print(sym_name, hex(addr))
            info.append((sym_name, addr, size))
        self.all_funcs = info

        # resolve the address of _IO_vtable_check
        for x in self.all_funcs:
            if x[0] == '_IO_vtable_check':
                self._IO_vtable_check = x[1]
                break
        else:
            raise RuntimeError("Failed to find the address of _IO_vtable_check!!!")

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
                simgr.move("active", "avoided", filter_func=lambda s: s.addr == self._IO_vtable_check)
                simgr.move("unconstrained", "bad", filter_func=lambda s: s.regs.pc.depth > 1)
                simgr.move("active", "bad_addr", filter_func=lambda s: self.project.loader.find_segment_containing(s.addr) is None or s.addr < 0x1000)
                log.debug(f"time: {elapsed_time}")
                log.debug(str(simgr))
                #log.debug(str(simgr.active))
                step += 1
                if elapsed_time > self.timeout:
                    break
                if step > self.max_step:
                    break
        except Exception as e:
            log.exception(e)
        return simgr

    def analyze(self):
        self.get_vtable_ptrs()
        self.get_all_funcs()
        self.get_target_funcs()

        os.makedirs(self.output_dir, exist_ok=True)

        for name, addr, size in self.target_funcs:
            log.info("trying to find a chain starting from %s...", name)
            #if name != '_IO_file_finish':
            #    continue
            states = self.create_sim_states(addr, self.offset)
            simgr = self.project.factory.simgr(states, save_unconstrained=True)
            self.sim_explore(simgr)

            # save results if there are any
            if simgr.unconstrained:
                with open(f"{self.output_dir}/{name}.pickle", 'wb') as f:
                    pickle.dump(simgr.unconstrained, f)
            #import IPython; IPython.embed()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Find a path to get PC-control when controlling a file structure',
                                     usage="%(prog)s [options] <libc_path> <trigger>")
    parser.add_argument('libc_path',
                        help="the path to the target libc binary")
    parser.add_argument('-f', '--function', type=str, choices=IO_JUMP_ATTR,
                        help="specify the triggering function", required=True)
    parser.add_argument('-o', '--output', type=str,
                        help="path of the result folder", default=DEFAULT_OUTPUT_FOLDER)
    parser.add_argument('-s', '--symbol-path', type=str,
                        help="path to the libc symbol file (to assist the analysis)", required=True)
    parser.add_argument('-t', '--timeout', type=int,
                        help="stop symbolic exploration for a path after <timeout> seconds", default=DEFAULT_TIMEOUT)
    parser.add_argument('-m', '--max-step', type=int,
                        help="stop symbolic exploration after <step> steps", default=DEFAULT_MAX_STEP)
    parser.add_argument('-c', '--control-size', type=int,
                        help="how many bytes are in our control", default=DEFAULT_CONTROL_SIZE)

    args = parser.parse_args()

    assert os.path.isfile(args.libc_path), f"{args.libc_path} is not a file!"
    assert os.path.isfile(args.symbol_path), f"{args.symbol_path} is not a file!"

    fsrop = FSROP(args.libc_path, args.function, args.symbol_path, timeout=args.timeout,
                  max_step=args.max_step, output_dir=args.output, control_size=args.control_size)
    fsrop.analyze()
