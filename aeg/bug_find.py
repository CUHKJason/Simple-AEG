import angr
import logging
import os


from angr import sim_options as so

l = logging.getLogger("aeg.bug_find")
l.setLevel("INFO")

class BugFind(object):
    def __init__(self, binary):
        self.binary = binary
        self.binary_name = ''
        self.simgr = self._init_simgr()

    def _init_simgr(self):
        p = angr.Project(self.binary)
        self.binary_name = os.path.basename(self.binary)
        extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY}
        state = p.factory.entry_state(add_options=extras)
        simgr = p.factory.simulation_manager(state, save_unconstrained=True)
        return simgr

    def _fully_symbolic(self, state, variable):
        for i in range(state.arch.bits):
            if not state.solver.symbolic(variable[i]):
                return False
        return True

    def find(self):
        l.info("Looking for vulnerability in '%s'", self.binary_name)
        exploitable_state = None

        while exploitable_state is None:
            self.simgr.step()
            if len(self.simgr.unconstrained) > 0:
                l.info("Found some unconstrained states, checking exploitability")
                for state in self.simgr.unconstrained:
                    if self._fully_symbolic(state, state.regs.pc):
                        exploitable_state = state
                        break
                l.info("These unconstrained states are not exploitable")
                self.simgr.drop(stash='unconstrained')

        l.info("Found a state which looks exploitable")
        assert exploitable_state.solver.symbolic(exploitable_state.regs.pc), "PC must be symblic at this point"
        return exploitable_state