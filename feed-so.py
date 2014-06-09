#!/usr/bin/python

import os
import struct
import sys

def main():
    for so in sys.argv[1:]:
        size = os.path.getsize(so)
        sys.stdout.write(struct.pack("<L", size))
        sys.stdout.write(open(so).read())
    sys.stdout.write("\x00\x00\x00\x00")

if __name__ == "__main__":
    main()
