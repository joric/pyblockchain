#!/usr/bin/env python

# difficulty parser
# usage: difficulty.py > out

import datetime
import struct
import math

from pyblockchain import BlockParser

def bits2diff(bits):
    fast_log = math.log
    exp = math.exp
    max_body = fast_log(0x00ffff)
    scaland = fast_log(256)
    return exp(max_body - fast_log(bits & 0x00ffffff) + scaland * (0x1d - ((bits & 0xff000000) >> 24)))

class DiffParser(BlockParser):
    def __init__(self):
        BlockParser.__init__(self)
        self.startblock = 0
        self.stopblock = -1
        self.bits = -1
        self.diff = 1.0
        self.ts = 0

    def block_header(self, pos, size, header, r):
        (ver, pb, mr, ts, bits, nonce) = struct.unpack('I32s32sIII', header)
        if bits != self.bits and ts > self.ts:
            if self.bits == -1:
                self.bits = bits
            diff = bits2diff(bits)
            delta = diff / self.diff
            date = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            print self.block, date, diff, delta
            self.bits = bits
            self.diff = diff
            self.ts = ts

def main():
    p = DiffParser()
    p.scan()

if __name__ == '__main__':
    main()
