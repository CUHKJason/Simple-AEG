from bug_find import BugFind
from dba import DBA
from exploit_gen import Exploit
from verify import Verify
import logging
import os

l = logging.getLogger("aeg.simple_aeg")
logging.getLogger("angr").setLevel("CRITICAL")
l.setLevel("INFO")

class SimpleAEG(object):
    def __init__(self, binary):
        self.binary = os.path.abspath(binary)

        self.bug_find = BugFind(self.binary)
        self.dba = DBA(self.binary)
        self.exploit = Exploit(self.binary)
        self.verify = Verify(self.binary)
        
    def attack(self):
        l.info("Preparation...")
        found_path = self.bug_find.find()
        if found_path is None:
            l.info("No exploitation found")
        dba_result = self.dba.analyze(found_path)
        l.info("Attempting to create exploit")
        payload = self.exploit.generate(found_path, dba_result)
        if not payload:
            l.info('Cannot generate any payload')
            return False
        if self.verify.verify(payload):
            filename = '%s-exploit' %self.binary
            with open(filename, 'w') as f:
                f.write(payload)
            l.info('Payload generated in %s' %filename)
            l.info('Exploitation completed')
            return True
        l.info('Failed, quit...')