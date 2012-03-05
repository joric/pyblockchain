#!/usr/bin/env python

# pyblockchain.py 1.0
# public domain

import struct
import os
import sys
import platform
import json
import hashlib
import optparse
import time
import datetime
import math

def determine_db_dir():
    if platform.system() == 'Darwin':
        return os.path.expanduser('~/Library/Application Support/Bitcoin/')
    elif platform.system() == 'Windows':
        return os.path.join(os.environ['APPDATA'], 'Bitcoin')
    return os.path.expanduser('~/.bitcoin')

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(s).digest())
    return h.digest()

class ProgressBar:
    def __init__(self, total=0):
        self.count = 0
        self.total = total
        self.ts_start = time.time()
        self.ts_last = self.ts_start

    def __str__(self):
        elapsed = self.ts_current - self.ts_start
        left = elapsed * self.total / self.count - elapsed
        p = (self.count * 100.0 / self.total)
        return '%.2f%%' % (p)

    def update(self, count):
        self.count = count
        self.ts_current = time.time()
        done = self.count == self.total
        last = self.ts_last
        self.ts_last = self.ts_current
        return done or int(self.ts_current) > int(last)

hash160 = None
param = None
date = None
stats = []
received = {}
volume = 0

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0, (b58_digits[r]))
    return ''.join(l)

def base58_decode(s):
    n = 0
    for ch in s:
        n *= 58
        digit = b58_digits.index(ch)
        n += digit
    return n

def base58_encode_padded(s):
    res = base58_encode(int ('0x' + s.encode ('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0): pad += 1
        else: break
    return b58_digits[0] * pad + res

def base58_decode_padded(s):
    pad = 0
    for c in s:
        if c == b58_digits[0]: pad += 1
        else: break
    h = '%x' % base58_decode(s)
    if len(h) % 2:
        h = '0' + h
    res = h.decode ('hex')
    return chr(0) * pad + res

class BadAddress(Exception):
    pass

def hash_to_address(s, addrtype=0):
    vs = chr(addrtype) + s
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)

def address_to_hash(s, addrtype=0):
    k = base58_decode_padded(s)
    hash160, check0 = k[1:-4], k[-4:]
    check1 = dhash(chr (addrtype) + hash160)[:4]
    if check0 != check1:
        raise BadAddress(s)
    return hash160  

def  u8(f): return struct.unpack('B', f.read(1))[0]
def u16(f): return struct.unpack('H', f.read(2))[0]
def u32(f): return struct.unpack('I', f.read(4))[0]
def u64(f): return struct.unpack('Q', f.read(8))[0]
    
def var_int(f):
    t = u8(f)
    if   t == 0xfd: return u16(f)
    elif t == 0xfe: return u32(f)
    elif t == 0xff: return u64(f)
    else: return t

def opcode(t):
    if   t == 0xac: return 'OP_CHECKSIG'
    elif t == 0x76: return 'OP_DUP'
    elif t == 0xa9: return 'OP_HASH160'
    elif t == 0x88: return 'OP_EQUALVERIFY'
    else: return 'OP_UNSUPPORTED:%02X' % t

def parse_script(s):
    global param
    r = []
    i = 0
    param = None
    while i < len(s):
        c = ord(s[i])
        if c > 0 and c < 0x4b:
            i += 1
            param = s[i:i+c]
            r.append(param.encode('hex'))
            i += c
        else:
            r.append(opcode(c))
            i += 1

    if len(r) == 2 and r[1] == 'OP_CHECKSIG':
        param = rhash(param)

    return ' '.join(r)

def read_string(f):
    len = var_int(f)
    return f.read(len)

def read_tx(f):
    tx_in = []
    tx_out = []
    startpos = f.tell()
    tx_ver = u32(f)

    vin_sz = var_int(f)

    for i in xrange(vin_sz):
        outpoint = f.read(32)
        n = u32(f)
        sig = read_string(f)
        seq = u32(f)

        type = int(n != 4294967295)
        name = ['coinbase','scriptSig'][type]
        prev_out = {'hash':outpoint.encode('hex'), 'n':n}
        tx_in.append({name:sig[type:].encode('hex'), "prev_out":prev_out})

    vout_sz = var_int(f)

    for i in xrange(vout_sz):
        value = u64(f)
        script = read_string(f)
        spk = parse_script(script)

        global hash160, param, received, volume
        if param and hash160 == param:
            volume += value
            key = param
            if key not in received:
                received[key] = 0
            received[key] += value

        tx_out.append({'value':'%.8f' % (value * 1e-8), 'scriptPubKey':spk})

    lock_time = u32(f)

    size = f.tell() - startpos
    f.seek(startpos)
    hash = dhash(f.read(size))

    r = {}
    r['hash'] = hash[::-1].encode('hex')
    r['ver'] = tx_ver
    r['vin_sz'] = vin_sz
    r['vout_sz'] = vout_sz
    r['lock_time'] = lock_time
    r['size'] = size
    r['in'] = tx_in
    r['out'] = tx_out

    return r

def next_date(date=None, ts=0, size=0):
    global stats

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

        stats.append((ts, date, size))

        date = datetime.date(date.year + year, month, 1)
    return date

def read_block(f, skip=False):
    global date

    magic = u32(f)
    size = u32(f)
    endpos = f.tell() + size

    header = f.read(80)
    (ver, pb, mr, ts, bits, nonce) = struct.unpack('I32s32sIII', header)

    date = next_date(date, ts, endpos)

    if skip:
        f.seek(endpos)
        return False

    hash = dhash(header)

    n_tx = var_int(f)

    r = {}
    r['hash'] = hash[::-1].encode('hex')
    r['ver'] = ver
    r['prev_block'] = pb.encode('hex')
    r['mrkl_root'] = mr.encode('hex')
    r['time'] = ts
    r['bits'] = bits
    r['nonce'] = nonce
    r['n_tx'] = n_tx
    r['size'] = size
    r['tx'] = []

    for i in xrange(n_tx):
        r['tx'].append(read_tx(f))

    return r

def read_blockchain(f, fsize, block):
    global hash160, received, volume, date

    stopblock = -1

    p = ProgressBar(fsize)
    r = []
    fpos = 0
    blocks = 0
    while fpos < fsize and blocks != stopblock:

        if hash160:
            skip = False
        else:
            skip = (blocks != block)

        r = read_block(f, skip)
        fpos = f.tell()
        blocks += 1

        if p.update(fpos):
            sys.stderr.write('\r%s, %d blocks, %f BTC, %s' % (date, blocks, volume*1e-8, p))

        if not skip and not hash160:
            break

    if hash160:
        keys = received.keys()
        keys.sort(key=lambda s:-received[s])
        for k in keys:
            key = hash_to_address(k)
            print '%s\t%f' % (key, received[k] * 1e-8)
        return False

    if date:
        print google_chart(stats)
        for k in stats: print k[0], k[1], k[2]

    return r

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

    grid = '%.2f,%.2f,1,1' % (100.0 / ((x2-x1) / float(dts) * 4.0 ), 100.0 / (y2 / 50.0))

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
        '&chtt=Bitcoin+blockchain+size+to+time, in megabytes'

def scan(block=None, address=None, chart=None):
    global hash160, date, stats

    fname = os.path.join(determine_db_dir(), 'blk0001.dat')
    f = open(fname, 'rb')
    f.seek(0, os.SEEK_END)
    fsize = f.tell()
    f.seek(0)

    if address:
        hash160 = address_to_hash(address)

    if chart:
        date = next_date()

    r = read_blockchain(f, fsize, block)
    if r:
        print json.dumps(r, indent=True)

    f.close()

def main():
    parser = optparse.OptionParser(usage='%prog [options]',
        version='%prog 1.0')

    parser.add_option('--dumpblock', dest='block',
        help='dump block by index in json format')

    parser.add_option('--address', dest='address',
        help='get amount received by address')

    parser.add_option('--chart', action='store_true',
        help='get blockchain statistics (size to time)')

    (options, args) = parser.parse_args()

    if not options.block and not options.address and not options.chart:
        print 'A mandatory option is missing\n'
        parser.print_help()
        sys.exit(1)

    if options.block:
        scan(block=int(options.block))
    elif options.address:
        scan(address=options.address)
    elif options.chart:
        scan(chart=options.chart)

if __name__ == '__main__':
    main()

