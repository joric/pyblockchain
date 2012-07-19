#!/usr/bin/env python

# difficulty parser
# usage: difficulty.py > out

import datetime
import time
import struct
import urllib
import os
import sys
import decimal, math

from pyblockchain import BlockParser

def timedelta(ts, delta):
    date = datetime.datetime.fromtimestamp(ts)
    if   delta == '+1 hour': date += datetime.timedelta(hours=1)
    elif delta == '+1 day': date += datetime.timedelta(days=1)
    elif delta == '+1 week': date += datetime.timedelta(weeks=1)
    elif delta == '+1 month':
        year, month= divmod(date.month + 1, 12)
        if month == 0: 
            month = 12
            year = year - 1
        date = datetime.datetime(date.year + year, month, 1)
    return time.mktime(date.timetuple())

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

    def block_header(self, pos, size, header, r):
        (ver, pb, mr, ts, bits, nonce) = struct.unpack('I32s32sIII', header)
        if bits != self.bits:

            if self.bits == -1:
                self.bits = bits

            diff = bits2diff(bits)

            delta = diff / self.diff

            date = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            print self.block, date, diff, delta

            self.bits = bits
            self.diff = diff

def main():
    p = DiffParser()
    p.scan()

if __name__ == '__main__':
    main()
