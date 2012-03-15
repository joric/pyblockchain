#!/usr/bin/env python

# google chart parser
# example output: http://goo.gl/A53P0

import datetime
import time
import struct
import urllib

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

class Chart:
    def __init__(self, title, start, delta, key, type='lc'):
        self.ts = 0
        self.title = title
        self.start = start
        self.delta = delta
        self.key = key
        self.value = 0
        self.maxvalue = 0
        self.avgvalue = 0
        self.count = 0
        self.type = type
        self.samples = 0
        self.data = []

    def dump(self):

        labels = []
        values = []

        dataset = []

        x = []
        y = []

        for r in self.data:
            ts, value = r
            x.append(ts)
            y.append(value)
            dataset.append(str(value))
            date = datetime.datetime.fromtimestamp(ts)

#            labels.append( date.strftime("%b %d") )
#            labels.append( date.strftime("%d") )
#            values.append( str(ts) )


        y1 = 0
        y2 = max(y)

        x1 = min(x)
        x2 = max(x)

        # see http://code.google.com/apis/chart/image/docs/chart_params.html

        p = {}

        p['cht'] = 'lc'
        p['chs'] = '512x512'

        p['chd'] = 't:'+','.join(dataset)

        p['chds'] = 'a'

        p['chxt'] = 'y,x,x,x'

        #chxl= <axis_index>:|<label_1>|...|<label_n>

        labels = []
        labels.append ([str(x) for x in range(len(dataset))])
        labels.append (['Jan','July','Jan','July','Jan'])
        labels.append ([str(x) for x in range(2009,2012)])

        chxl =  '|'.join('%d:|%s' % (i+1,'|'.join(labels[i])) for i in range(len(labels)))

        p['chxl'] = chxl

        p['chg'] = '-1,-1,1,1'

        print 'http://chart.apis.google.com/chart?%s' % '&'.join(k+'='+p[k] for k in p)

    def update(self, ts, r):

        if self.ts == 0:
            self.ts = time.mktime(time.strptime(self.start, '%Y-%m-%d'))

        value = int(r[self.key])

        self.value += 1
        self.count += 1

        if self.ts <= ts:

            if self.samples > 0:
                self.data.append( (self.ts, self.value) )

            self.value = 0
            self.ts = timedelta(self.ts, self.delta)

            self.samples += 1

class ChartParser(BlockParser):
    def __init__(self):
        BlockParser.__init__(self)
        self.startblock = 0
        self.stopblock = -1
        self.charts = []

    def dump(self):
        for c in self.charts: c.dump()

    def status(self, s):
        return s + ', ' + str(len(self.charts[0].data)) + ' samples'

    def update(self, time, r):
        for c in self.charts: c.update(time, r)

    def block_header(self, pos, size, header, r):
        self.update( r['time'], r )

def main():
    p = ChartParser()

#    p.charts.append( Chart('Transactions per day','2012-01-01','+1 day','n_tx') )
#    p.charts.append( Chart('Block size per month','2009-01-01','+1 month','size') )
#    p.charts.append( Chart('Average block size per month','2009-01-01','+1 month','size') )

#    p.charts.append( Chart('Number of 1-tx blocks','2012-02-01','+1 day','n_tx') )

    p.charts.append( Chart('Number of blocks a day (should be 144 - 6 blocks a hour)','2012-03-01','+1 day','n_tx') )

    p.scan()
    p.dump()


if __name__ == '__main__':
    main()
