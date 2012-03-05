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
import datetime
import time

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
        return '%.2f%% %s' % (p, self.ftime(left))

    def ftime(self, seconds):
        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)
        d, h = divmod(h, 24)
        y, d = divmod(d, 365)
        if y > 1: return "%d years" % y
        elif d > 1: return "%d days" % d
        else: return "%02d:%02d:%02d" % (h, m, s)

    def update(self, count):
        self.count = count
        self.ts_current = time.time()
        done = self.count == self.total
        last = self.ts_last
        self.ts_last = self.ts_current
        return done or int(self.ts_current) > int(last)

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

def read_string(f):
    len = var_int(f)
    return f.read(len)

class BCParser(object):
    def __init__(self):
        self.fullscan = False

    def scan(self):
        fname = os.path.join(determine_db_dir(), 'blk0001.dat')
        f = open(fname, 'rb')
        self.read_blockchain(f)
        f.close()

    def parse_script(self, s, value):
        r = []
        i = 0
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

            if len(r) == 5 and r[1] == 'OP_HASH160':
                self.address({'hash':param, 'value':value})

            elif len(r) == 2 and r[1] == 'OP_CHECKSIG':
                self.address({'hash':rhash(param), 'value':value})

        return ' '.join(r)

    def read_tx(self, f):
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
            spk = self.parse_script(script, value)
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

    def read_block(self, f, skip=False):

        magic = u32(f)
        size = u32(f)
        pos = f.tell()

        header = f.read(80)

        self.block_header(pos, size, header)

        if skip:
            f.seek(pos + size)
            return False

        (ver, pb, mr, ts, bits, nonce) = struct.unpack('I32s32sIII', header)

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
            r['tx'].append(self.read_tx(f))

        self.block(r)

        return r

    def read_blockchain(self, f):
        f.seek(0, os.SEEK_END)
        fsize = f.tell()
        f.seek(0)

        p = ProgressBar(fsize)
        r = []
        fpos = 0
        blocks = 0

        while fpos < fsize:
            skip = (blocks != self.stopblock) and not self.fullscan
            r = self.read_block(f, skip)
            fpos = f.tell()
            if blocks == self.stopblock:
                break
            blocks += 1
            if p.update(fpos) or blocks == self.stopblock:
                s = '%s, %d blocks' % (p, blocks)
                sys.stderr.write('\r%s' % self.status(s))
        return r

    def status(self, s):
        return s

    def block_header(self, pos, size, header):
        pass

    def address(self, r):
        pass

    def tx(self, r):
        pass

    def block(self, r):
        pass

class BlockParser(BCParser):
    def __init__(self, stopblock):
        self.stopblock = int(stopblock)
        self.fullscan = False
        self.r = None
        self.scan()
        if self.r:
            print json.dumps(self.r, indent=True)
    def block(self, r):
        self.r = r

class AddressParser(BCParser):
    def __init__(self, address=None):
        self.key = None
        self.count = 0
        self.total = 0
        if address:
            self.key = address_to_hash(address)
        self.addr = {}
        self.stopblock = -1
        self.fullscan = True
        self.scan()
        keys = self.addr.keys()
        keys.sort(key=lambda x:-self.addr[x][0])
        for key in keys:
            recv, sent, count = self.addr[key]
            print "%s\t%.8f\t%.8f\t%d" % (hash_to_address(key), recv*1e-8, sent*1e-8, count)

    def status(self, s):
        return '%s, %d addresses, %.2f BTC' % (s, self.count, self.total*1e-8)

    def address(self, r):
        if self.key and r['hash'] != self.key:
            return
        key = r['hash']
        value = r['value']
        if key not in self.addr:
            self.addr[key] = (0, 0, 0)
            self.count += 1
        recv,sent,count = self.addr[key]
        recv += value
        count += 1
        self.count += 1
        self.total += value
        self.addr[key] = (recv, sent, count)

def main():
    parser = optparse.OptionParser(usage='%prog [options]',
        version='%prog 1.0')

    parser.add_option('--block', dest='block',
        help='dump block by index in json format')

    parser.add_option('--address', dest='address',
        help='get amount received by address')

    parser.add_option('--index', action='store_true',
        help='re-index blockchain')

    (opt, args) = parser.parse_args()

    if not opt.block and not opt.address and not opt.index:
        print 'A mandatory option is missing\n'
        parser.print_help()
        sys.exit(1)

    if opt.block: BlockParser(opt.block)
    elif opt.address: AddressParser(opt.address)
    elif opt.index: AddressParser(None)

if __name__ == '__main__':
    main()
