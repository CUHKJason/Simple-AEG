import logging
from pwn import *

l = logging.getLogger("aeg.dba")

class DBA(object):

    def __init__(self, binary):
        self.binary = binary
        self.state = None

    def _binary_info(self):
        #pwntools
        elf = ELF(self.binary)
        self.result['elf'] = {
            'RELRO': elf.relro,
            'Canary': elf.canary,
            'NX': elf.nx,
            'PIE': elf.pie
        }
    
    def _check_continuity(self, address, addresses):
        i = 0
        while True:
            if not address + i in addresses:
                return address, i
            i = i + 1

    def _find_symbolic_buffer(self):
        state = self.state

        stdin = state.posix.stdin
        #stdin_file = self.path.posix.get_file(0)
        

        sym_addrs = []
        #for var in stdin_file.variables():
        #    sym_addrs.extend(state.memory.addrs_for_name(var))
        for _, symbol in state.solver.get_variables('file', stdin.ident):
            sym_addrs.extend(state.memory.addrs_for_name(next(iter(symbol.variables))))
        
        buffer = []
        for addr in sym_addrs:
            addr, length = self._check_continuity(addr, sym_addrs)
            buffer.append({'addr': addr, 'length': length})
        return buffer


    def _analyze(self):
        state = self.state
        self._binary_info()
        self.result['arch'] = state.arch.name
        self.result['buffer'] = self._find_symbolic_buffer()


    def analyze(self, state):
        self.state = state
        self.result = {
            'arch': '',
            'buffer': [],
            'elf': {}
        }
        self._analyze()
        
        return self.result
