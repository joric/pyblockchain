#!/usr/bin/env python

# google chart parser
# example output: http://goo.gl/A53P0

import datetime
import time
import struct
from pyblockchain import BlockParser

def google_chart(stats):
    dataset = []
    labels = []
    values = []

    for k in stats:
        dataset.append('%.2f' % (k[2] / 1024.0 / 1024.0))

    step = 12
    dts = 0
    t0 = 0
    for i in range(0, len(stats), step):
        t = stats[i][0]
        d = stats[i][1]
        labels.append(str(d.year))
        values.append(str(t))
        dts = t - t0
        t0 = t

    m = len(stats) - 1

    x1 = stats[0][0]
    x2 = stats[m][0]
    y1 = float(dataset[0])
    y2 = float(dataset[m])

    xdr = '%.2f,%.2f' % (x1, x2)
    ydr = '%.2f,%.2f' % (y1, y2)

    grid = '%.2f,%.2f,1,1' % (100.0 / ((x2-x1) / float(dts) * 4.0), 100.0 / (y2 / 50.0))

    return 'http://chart.apis.google.com/chart' + \
        '?chxl=1:|'+ '|'.join(labels) + \
        '&chxp=1,' + ','.join(values) + \
        '&chxr=0,'+ ydr + '|1,' + xdr + \
        '&chxt=y,x' + \
        '&chs=512x512' + \
        '&cht=lc' + \
        '&chco=3D7930' + \
        '&chds=' + ydr + \
        '&chd=t:' + ','.join(dataset) + \
        '&chg=' + grid + \
        '&chls=2,4,0' + \
        '&chm=B,C5D4B5BB,0,0,0' + \
        '&chtt=Bitcoin+blockchain+size+to+time,+in+megabytes'

class ChartParser(BlockParser):
    def __init__(self):
        BlockParser.__init__(self)
        self.startblock = 0
        self.stopblock = -1
        self.stats = []
        self.date = self.next_date()
        self.scan()
        for k in self.stats: print '%s\t%s\t%s' % (k[0], k[1], k[2])
        print google_chart(self.stats)

    def next_date(self, date=None, ts=0, size=0):
        d = datetime.date.fromtimestamp(ts)
        if not date or date <= d:
            if not date:
                date = datetime.date(2009, 1, 1)
                dt = datetime.datetime.strptime(str(date), '%Y-%m-%d')
                ts = int(time.mktime(dt.timetuple()))
            year, month = divmod(date.month + 1, 12)
            if month == 0: 
                  month = 12
                  year = year - 1
            self.stats.append((ts, date, size))
            date = datetime.date(date.year + year, month, 1)
        return date

    def status(self, s):
        return '%s, %s' % (s, self.date)

    def block_header(self, pos, size, header, r):
        (ver, pb, mr, ts, bits, nonce) = struct.unpack('I32s32sIII', header)
        self.date = self.next_date(self.date, ts, pos + size)

def main():
    ChartParser()

if __name__ == '__main__':
    main()
