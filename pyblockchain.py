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
    if   t == 0xAC: return 'OP_CHECKSIG'
    elif t == 0x76: return 'OP_DUP'
    elif t == 0xA9: return 'OP_HASH160'
    elif t == 0x88: return 'OP_EQUALVERIFY'
    else: return 'OP_UNSUPPORTED:%02X' % t

def read_string(f):
    len = var_int(f)
    return f.read(len)

class BlockParser:
    def __init__(self):
        self.fullscan = False
        self.startblock = 0
        self.stopblock = -1

    def scan(self):
        fname = os.path.join(determine_db_dir(), 'blk0001.dat')
        f = open(fname, 'rb')
        self.read_blockchain(f)
        f.close()

    def parse_script(self, script, value=0):
        r = []
        i = 0
        while i < len(script):
            b = ord(script[i])
            if b < 0x4b:
                i += 1
                param = script[i:i+b]
                r.append(param.encode('hex'))
                i += b
            else:
                r.append(opcode(b))
                i += 1
        return ' '.join(r)

    def read_tx(self, f):
        tx_in = []
        tx_out = []
        inputs = []
        outputs = []
        startpos = f.tell()
        tx_ver = u32(f)

        vin_sz = var_int(f)

        for i in xrange(vin_sz):
            op = f.read(32)
            n = u32(f)
            script = read_string(f)
            seq = u32(f)

            prev_out = {'hash':op.encode('hex'), 'n':n}

            if n == 4294967295:
                cb = script.encode('hex')
                tx_in.append({'coinbase': cb, "prev_out": prev_out})
            else:
                ss = self.parse_script(script)
                tx_in.append({'scriptSig': ss, "prev_out": prev_out})
                inputs.append( (op, n) )

        vout_sz = var_int(f)

        for i in xrange(vout_sz):
            value = u64(f)
            script = read_string(f)

            spk = self.parse_script(script, value)
            tx_out.append({'value':'%.8f'%(value*1e-8), 'scriptPubKey': spk})

            h160 = None

            if len(script) == 25:# and ord(script[1]) == 0x76:
                h160 = script[3:-2]

            if len(script) == 67:# and ord(script[66]) == 0xAC:
                pubkey = script[1:-1]
                h160 = rhash(pubkey)

            if h160:
                outputs.append((h160,value,i))

        lock_time = u32(f)

        size = f.tell() - startpos
        f.seek(startpos)
        hash = dhash(f.read(size))

        self.tx_hash(hash)

        for op, n in inputs:
            self.tx_input(hash, op, n)

        for h160, value, n in outputs:
            self.tx_output(hash, h160, value, n)

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
            return f.seek(pos + size)

        (ver, pb, mr, ts, bits, nonce) = struct.unpack('I32s32sIII', header)

        hash = dhash(header)

        self.block_hash(hash)

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

        return r

    def read_blockchain(self, f):
        f.seek(0, os.SEEK_END)
        fsize = f.tell()
        f.seek(0)

        p = ProgressBar(fsize)
        r = []
        fpos = 0
        block = 0

        while fpos < fsize:

            skip = (block != self.stopblock) and not self.fullscan

            if block < self.startblock:
                skip = True

            r = self.read_block(f, skip)
            fpos = f.tell()

            if block == self.stopblock:
                break

            block += 1
            if p.update(fpos) or block == self.stopblock:
                s = '%s, %d blocks' % (p, block)
                sys.stderr.write('\r%s' % self.status(s))

        sys.stderr.write('\n')

        return r

    def status(self, s):
        return s

    def block_header(self, pos, size, header):
        pass
    def block_hash(self, hash):
        pass
    def tx_hash(self, hash):
        pass
    def tx_input(self, tx, op, n):
        pass
    def tx_output(self, tx, h160, value, n):
        pass

class BalanceParser(BlockParser):
    def __init__(self):
        BlockParser.__init__(self)

        self.fullscan = True

        self.stopblock = -1

        self.addr = {}
        self.outp = {}

    def status(self, s):
        return s + ', %d addresses, %d outpoints' % (len(self.addr), len(self.outp))

    def add_hash(self, d, hash, f=None):
        uid = len(d) + 1
        if hash not in d:
            d[hash] = uid, f
        return d[hash]

    def tx_input(self, tx, op, n):
        key = op + str(n)
        if key in self.outp:
            h160, value = self.outp[key]
            i, (recv, sent) = self.addr[h160]
            self.addr[h160] = i, (recv, sent+value)
            self.outp.pop(key)

    def tx_output(self, tx, h160, value, n):
        self.add_hash(self.addr, h160, (0,0))
        i, (recv, sent) = self.addr[h160]
        self.addr[h160] = i, (recv + value, sent)
        self.outp[tx + str(n)] = h160, value

    def dump(self):
        keys = self.addr.keys()
        keys.sort(key=lambda x:-self.addr[x][1][0])
        for x in keys:
            i,(recv,sent) = self.addr[x]
            balance = recv - sent
            print "%s\t%d\t%d\t%d\t%d" % (hash_to_address(x), i, recv, sent, balance)

def main():
    p = BalanceParser()
    p.scan()
    p.dump()

if __name__ == '__main__':
    main()
