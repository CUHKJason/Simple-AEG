import logging
from pwn import *

l = logging.getLogger("aeg.verify")
l.setLevel("INFO")
HOST = 0.0.0.0
PORT = 31337
class Verify(object):

    def __init__(self, binary):
        self.binary = binary
        self.delay = 0.5

    def verify(self, payload):
        try:
            l.info('Verifying ...')
            s = remote(HOST,PORT)
            s.sendline(payload)
            s.recvrepeat(self.delay)
            s.interactive()
            s.close()
            return True
        except Exception, e:
            l.warning('Pwnlib Error: %s %s' % (Exception, e))
        return False