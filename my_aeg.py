from aeg import SimpleAEG
import sys

if len(sys.argv) > 1:
    binary = SimpleAEG(sys.argv[1])
    binary.exploits()
else:
    print "%s: <binary>" % sys.argv[0]


