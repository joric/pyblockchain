from pyblockchain import *

import sqlite3 as sqlite

class SQLiteIndexer(BlockParser):
    def __init__(self):
        BlockParser.__init__(self)

        self.fullscan = True
        self.stopblock = -1

        self.txns = {}
        self.addr = {}
        self.blks = {}

        self.cx = sqlite.connect('blockchain.db')
        self.cu = self.cx.cursor()

        self.count = 0

        s = """
            CREATE TABLE blks (uid INTEGER PRIMARY KEY, hash TEXT);
            CREATE UNIQUE INDEX blks_idx ON blks(hash ASC);

            CREATE TABLE addr (uid INTEGER PRIMARY KEY, addr TEXT);
            CREATE UNIQUE INDEX addr_idx ON addr(addr ASC);

            CREATE TABLE txns (uid INTEGER PRIMARY KEY, hash TEXT);
            CREATE UNIQUE INDEX txns_idx ON txns(hash ASC);
            """

        for sql in s.split('\n'):
            try:
                self.cu.execute(sql)
            except sqlite.Error, e:
                pass #print "Warning:", e.args[0]

    def ins(self, table, field, value):
        sql = 'insert into %s(%s) values ("%s")' % (table, field, value)
        try:
            self.cu.execute(sql)
        except sqlite.Error, e:
            pass

    def status(self, s):

        self.count += 1
        if self.count % 10 == 0:
            self.cx.commit()

        return '<SQLite> ' + s

    def block_hash(self, hash):
        self.ins('blks','hash',hash[::-1].encode('hex'))

    def tx_hash(self, hash):
        self.ins('txns','hash',hash[::-1].encode('hex'))

    def tx_input(self, tx, op, n):
        pass

    def tx_output(self, tx, h160, value, n):
        self.ins('addr','addr',hash_to_address(h160))

def index():
    p = SQLiteIndexer()
    p.scan()
    p.cx.commit()

def browse():
    cx = sqlite.connect('blockchain.db')
    cu = cx.cursor()
    cu.execute('select * from addr where addr like "1AB%"')
    for r in cu.fetchall():
        print r

def main():
    index()
#    browse()

if __name__ == '__main__':
    main()
