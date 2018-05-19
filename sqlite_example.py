from pyblockchain import *

import sqlite3 as sqlite

class SQLiteIndexer(BlockParser):
    def __init__(self):
        BlockParser.__init__(self)

        self.fullscan = True
        self.stopblock = -1

        self.cx = sqlite.connect('blockchain.db')
        self.cu = self.cx.cursor()

        self.count = 0

        self.tid = None
        self.aid = None

        s = """
            CREATE TABLE blks (uid INTEGER PRIMARY KEY, hash TEXT);
            CREATE UNIQUE INDEX blks_idx ON blks(hash ASC);

            CREATE TABLE addr (uid INTEGER PRIMARY KEY, addr TEXT);
            CREATE UNIQUE INDEX addr_idx ON addr(addr ASC);

            CREATE TABLE txns (uid INTEGER PRIMARY KEY, bid INTEGER, hash TEXT);
            CREATE UNIQUE INDEX txns_idx ON txns(hash ASC);

            CREATE TABLE txin (tid INTEGER, n INTEGER, PRIMARY KEY(tid, n));
            CREATE TABLE txout (tid INTEGER, aid INTEGER, n INTEGER, value INTEGER, PRIMARY KEY(tid, n));
            """

        for sql in s.split('\n'):
            try:
                self.cu.execute(sql)
            except sqlite.Error, e:
                print "Warning:", e.args[0]

    def block_content(self, r):

        # blockexplorer json to sqlite

        cur = self.cu
        bid = self.block + 1

        try: 
            cur.execute('insert into blks (uid,hash) values (%d,"%s")' % (bid, r['hash']))
        except: 
            pass

        for tx in r['tx']:

            try: 
                cur.execute('insert into txns (bid, hash) values (%d,"%s")' % (bid, tx['hash']) )
                tid = cur.lastrowid
            except:
                cur.execute("select uid from txns where hash='%s'" % tx['hash'] )
                tid = cur.fetchall()[0][0]

            n = 0
            for to in tx['out']:
                addr = None
                script = to['scriptPubKey'].split(' ')

                if len(script) == 5 and len(script[2]) == 20*2:
                    addr = hash_to_address(script[2].decode('hex'))

                if len(script) == 2 and len(script[0]) == 65*2:
                    addr = hash_to_address(rhash(script[0].decode('hex')))

                if addr:
                    try: 
                        cur.execute('insert into addr (addr) values ("%s")' % addr)
                        aid = cur.lastrowid
                    except:
                        cur.execute("select uid from addr where addr='%s'" % addr)
                        aid = cur.fetchall()[0][0]

                    value = int(float(to['value']) * 1e8)

                    try:
                        cur.execute('insert into txout(tid,aid,n,value) values (%d,%d,%d,%d)' % (tid, aid, n, value))
                    except:
                        # not unique ?
                        pass

                n += 1

            for ti in tx['in']:
                if ti.has_key('scriptSig'):
                    op = ti['prev_out']
                    try:
                        n = int(op['n'])
                        cur.execute('select uid from txns where hash="%s"' % op['hash'])
                        tid = cur.fetchall()[0][0]
                        cur.execute('insert into txin(tid, n) values (%d,%d)' % (tid, n))
                    except:
                        pass

    def status(self, s):
        self.count += 1
        if self.count % 60 == 0: # commit every 60 seconds
           self.cx.commit()
        return '<SQLite> ' + s


def index():
    p = SQLiteIndexer()
    p.scan()
    p.cx.commit()

def browse():

    print "Browsing..."

    con = sqlite.connect('blockchain.db')
    cur = con.cursor()

    addr = '12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S'

    print "Received"

    cur.execute('select * from txout, addr where aid=addr.uid and addr="%s"' % addr)

    for r in cur.fetchall():
        print r

    print "Sent"

    cur.execute('select * from txin, txout, addr where txout.aid=addr.uid and txin.tid=txout.tid and addr="%s"' % addr)

    for r in cur.fetchall():
        print r

def main():
    index()
    browse()

if __name__ == '__main__':
    main()
