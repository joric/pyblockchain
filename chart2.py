#!/usr/bin/env python

# google chart parser
# example output: http://goo.gl/A53P0

import datetime
import time
import struct
import urllib
import os

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

def add_elem(arr, elem):
    if not arr or arr[-1] != elem:
        arr.append(elem)

class Chart:
    def __init__(self, title, start, delta, mode='l', key=[]):
        self.ts = 0
        self.title = title
        self.start = start
        self.delta = delta
        self.key = key
        self.mode = mode
        self.count = 0
        self.samples = 0
        self.data = []
        self.filters = {}
        self.values = {}

    def update(self, ts, r):

        if self.ts == 0:
            self.ts = time.mktime(time.strptime(self.start, '%Y-%m-%d'))

        self.count += 1

        if len(self.key):
            n = int( r[self.key] )
            if 'f' in self.mode:
                if n == self.filter:
                    self.value += 1
            else:
                self.value += n
        else:
            self.value = self.count

        if self.ts <= ts:
            if self.samples > 0:

                if 'a' in self.mode:
                    self.value = self.value / self.count

                date = datetime.datetime.fromtimestamp(self.ts).strftime("%Y-%m-%d")
                r = []
                r.append('%s' % date)
                r.append('%d' % self.value)

                self.data.append(r)

            if 'c' not in self.mode:
                self.value = 0
                self.count = 0

            self.ts = timedelta(self.ts, self.delta)

            self.samples += 1

    def dump(self):
        x = []
        y = []
        for r in self.data:
            ts = time.mktime(time.strptime(r[0], '%Y-%m-%d'))
            xv = int(ts)
            yv = int(r[1]) * self.scale
            x.append(xv)
            y.append(yv)
#            date = datetime.datetime.fromtimestamp(ts)
#            labels.append( date.strftime("%b %d") )
#            labels.append( date.strftime("%d") )
#            values.append( str(ts) )

        y1 = 0
        y2 = max(y)

        x1 = min(x)
        x2 = max(x)

        # see http://code.google.com/apis/chart/image/docs/chart_params.html

        p = {}

        # chs=<width>x<height>

        p['chs'] = '512x512'

        # cht=<type>[:nda] type = (bar) bvs, bvg, bvo (line) lc, ls, lxy (pie) p, p3, pc
        # You can add :nda after the chart type in line charts to hide the default axes.

        p['cht'] = 'lc'

        # chbh Bar Width and Spacing (bar chart only) may be 'a' or 'r' (relative)
        # chbh=<bar_width_or_scale>,<space_between_bars>,<space_between_groups>

        if 'b' in self.mode:
            p['cht'] = 'bvs'
#            p['chbh'] = 'a'

#        p['chbh'] = 'r'
#        p['chbh'] = '10,0'
        # % 15.0
        #% (float(512) / len(self.data))

        # chd=t:val,val,val|val,val,val
        # chds=<series_1_min>,<series_1_max>,...,<series_n_min>,<series_n_max>

        p['chd'] = 't:'+','.join(str(i*self.scale) for i in y)

        p['chds'] = 'a'

#        p['chds'] = '%d,%d' % (y1,y2) # then you have to define chxr as well

        # chxt = <axis_1> ,..., <axis_n>

        p['chxt'] = 'y,x'

        # chxl= <axis_index>:|<label_1>|...|<label_n>


        labels = []
        values = []
        for i in range(0,len(self.data)):
            r = self.data[i]
            ts = time.mktime(time.strptime(r[0], '%Y-%m-%d'))
            value = int(r[1]) * self.scale

            d = datetime.datetime.fromtimestamp(ts)
            day = ''
            if i % 5 == 1:
                day = d.strftime("%b.%d")
            labels.append( day )
            values.append( str(ts) )

        p['chxl'] = '1:|' + '|'.join(labels)


#        p['chxp'] = '1,'  + ','.join(values)

#        if p['chds'] != 'a':
#            p['chxr'] = '0,%d,%d|1,%d,%d' % (y1,y2,x1,x2)

        """
        p['chxt'] = 'y,x,x,x'
        labels = []
        days = []
        months = []
        years = []
        for i in range(0,len(self.data),2):
            ts,value = self.data[i]
            d = datetime.datetime.fromtimestamp(ts)
            add_elem(days, d.strftime("%d"))
            add_elem(months, d.strftime("%b"))
            add_elem(years, d.strftime("%Y"))
        labels.append (days)
        labels.append (months)
        labels.append (years)
        chxl =  '|'.join('%d:|%s' % (i+1,'|'.join(labels[i])) for i in range(len(labels)))
        p['chxl'] = chxl
        """

        # chg = Grid Lines [Line, Bar, Radar, Scatter]
        # chg= <x_axis_step_size>,<y_axis_step_size>,<opt_dash_length>,
        # <opt_space_length>,<opt_x_offset>,<opt_y_offset>
        # note -1 doesn't work with 'chbh' = 'a'

        p['chg'] = '0,-1,1,1'

        p['chtt'] = urllib.quote(self.title)

        url = 'http://chart.apis.google.com/chart?' + '&'.join(k+'='+p[k] for k in p)

        print url

        if os.name == 'nt':
            os.system('start %s' % url.replace('&','^&').replace('|','^|'))

    def save(self, fname):
        open(fname,'w').write('\n'.join('\t'.join(r) for r in self.data))

    def load(self, fname):
        try:
            lines = open(fname).read().splitlines()
            for s in lines:
                self.data.append(s.split("\t"))
            return True
        except IOError:
            return False

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

    # Chart (title, start, delta, mode='l', key='{hash of keys:filters}')
    # chart modes:
    # a - average; b = bar chart; c - cumulative

#    p.charts.append( Chart('Blockchain size to time','2009-01-01','+1 month', 'c', 'size', scale=1.0/2**10))
#    p.charts.append( Chart('Transactions per day','2012-01-01','+1 day','ba','n_tx') )
#    p.charts.append( Chart('Block size per month','2009-01-01','+1 month','a', 'size') )
#    p.charts.append( Chart('Blocks per month','2009-01-01','+1 month') )
#    p.charts.append( Chart('Blocks a day','2012-02-01','+1 day') )

    series = [('n_tx'),('n_tx',1)]
    ch = Chart('1-tx blocks a day (2012)','2012-01-01','+1 day','b', series)
    p.charts.append( ch )

    chart = p.charts[0]

    fname = 'chart_%s.csv' % urllib.quote(chart.title+chart.start+chart.delta+chart.key)

    if not chart.load(fname):
       p.scan()

    chart.save(fname)

    p.dump()

if __name__ == '__main__':
    main()
