/*
    cpp blockchain parser, public domain
    see http://github.com/joric/pyblockchain
*/

#include <iostream>
#include <fstream>
#include <time.h>
#include <string>
#include <map>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

using namespace std;

#ifdef WIN32 
#include <shlwapi.h>
#endif

//#include "base58.h"

char *htoa(char *src, uint32_t len, bool reversed=false)
{
    static char dest[256];
    len = len > 255 ? 255 : len;
    char *d = dest;
    while (len--)
    {
        if (reversed)
            sprintf(d, "%02x", (unsigned char)*(src + len)), d += 2;
        else
            sprintf(d, "%02x", (unsigned char)*src++), d += 2;
    }
    return dest;
}

char *dhash(char *src, int len)
{
    static unsigned char res[32];
    unsigned char buf[32];
    SHA256((unsigned char *)src, len, buf);
    SHA256(buf, 32, res);
    return (char *)res;
}

char *rhash(char *src, int len)
{
    static unsigned char res[20];
    unsigned char buf[32];
    SHA256((unsigned char *)src, len, buf);
    RIPEMD160(buf, 32, res);
    return (char *)res;
}

#ifndef __BASE58__
char *address_to_hash(char *md) { static char r[32] = {0}; return r; }
char *hash_to_address(char *md) { return htoa(md,20); }
#else
char *address_to_hash(char *address)
{
    static char result[32];
    b58_decode_check(address, result, 32);
    return result + 1;
}

char *hash_to_address(char *h160)
{
    static char result[32];
    unsigned char binres[21] = { 0, };
    memcpy(binres + 1, h160, 20);
    b58_encode_check(binres, sizeof(binres), result);
    return result;
}
#endif

struct ProgressBar
{
    uint64_t total, count;
    time_t ts_start, ts_last, ts_current;

    ProgressBar(int size) 
    {
        total = size;
        count = 0;
        ts_start = time(0);
        ts_last = ts_start;
    }

    char* c_str()
    {
        static char buf[256];
        time_t elapsed = ts_current - ts_start;
        time_t left = elapsed * total / count - elapsed;
        left = left > 0 ? left : 0;
        float p = count * 100.0 / total;
        sprintf(buf, "%.2f%% est. %d seconds", p, left);
        return buf;
    }

    bool update(int pos)
    {
        count = pos;
        ts_current = time(0);
        bool done = count == total;
        int last = ts_last;
        ts_last = ts_current;
        return done || ts_current > last;
    }
};

string determine_db_dir()
{
#ifndef WIN32
    char* home = getenv("HOME");
    if (!home) return "";
#ifdef MAC_OSX
    return string(home) + "/Library/Application Support/Bitcoin/";
#else
    return string(home) + "/.bitcoin/";
#endif
#else
    char buf[MAX_PATH];
    return SUCCEEDED(::SHGetFolderPath( NULL, CSIDL_APPDATA, NULL, 0, buf)) ?
        string(buf) + "\\Bitcoin\\" : "";
#endif
}

const int MB = 1024 * 1024;

class bfile: public ifstream 
{
    char* memblock;
    uint64_t boffset;
    uint64_t bsize;

public:

    bfile(const char *fname, openmode mode):ifstream(fname, mode) 
    {
        bsize = 1 * MB;
        boffset = 0;
        memblock = new char[bsize];
    }

    ~bfile()
    {
        delete[] memblock;
    }

    void cache(uint64_t pos, uint64_t count)
    {
        if (boffset > 0)
            return;

        boffset = bsize;

        uint64_t loaded = 0;
        uint64_t rsize = 16 * MB;

        cerr << "Loading file into memory." << endl;

        while (loaded < bsize)
        {
            uint64_t left = bsize - loaded;
            uint64_t portion = left >= rsize ? rsize : left;
            ifstream::read(memblock + loaded, portion);
            loaded += portion;
            cerr << "\rLoaded " << loaded / MB << " of " << bsize / MB << " MB";
        }
        cerr << endl;
    }

    void* read(char* dest, int count)
    {
//        cache(tellg(), count);
        return ifstream::read(dest, count);
    }

    void* seekg(uint64_t pos, seekdir dir=ios::beg) 
    { 
        return ifstream::seekg(pos, dir);
    }

    uint64_t tellg() 
    { 
        return ifstream::tellg();
    }
};

template <int N> struct ckey
{
    char val[N];

    ckey(char* s)
    {  
        memcpy(val, s, N);
    }

    bool operator < (const ckey& oth) const 
    { 
        return memcmp(val, oth.val, N) < 0;
    }
};

class BlockReader
{
    typedef map<ckey<20>, uint64_t> addr_map;
    typedef map<ckey<32>, uint64_t> tx_map;

    tx_map blks;
    tx_map txns;
    addr_map addr;

    int startblock;
    int stopblock;

    uint8_t   u8(bfile& f) { uint8_t  n; f.read((char*)&n, 1); return n; }
    uint16_t u16(bfile& f) { uint16_t n; f.read((char*)&n, 2); return n; }
    uint32_t u32(bfile& f) { uint32_t n; f.read((char*)&n, 4); return n; }
    uint64_t u64(bfile& f) { uint64_t n; f.read((char*)&n, 8); return n; }

    uint64_t var_int(bfile& f)
    {
        uint8_t t = u8(f);
        if (t == 0xfd) return u16(f); else
        if (t == 0xfe) return u32(f); else 
        if (t == 0xff) return u64(f); else 
        return t;
    }

public:
    bool scan()
    {
        string fname = determine_db_dir() + "blk0001.dat";

        bfile f(fname.c_str(), ios::in | ios::binary);

        if (!f.is_open())
            return false;

        f.seekg(0, ios::end);
        uint64_t fsize = f.tellg();
        f.seekg(0, ios::beg);

        cout << "name: " << fname << endl;
        cout << "size: " << fsize / MB << " MB" << endl;

        ProgressBar p(fsize);

        startblock = 0;
        stopblock = 1000;

        for (int block = 0; read_block(f, startblock >= block) > 0; block++)
        {
            if (p.update(f.tellg()) || block == stopblock)
                cerr << "\r" << p.c_str()
                    << ", " << block << " blks"
                    << ", " << addr.size() << " addr"
                    << ", " << txns.size() << " txns";

            if (block == stopblock)
                break;
        }

        cout << endl << "Done." << endl;

#if 1
        for (addr_map::iterator it=addr.begin(); it!=addr.end(); ++it) 
            cout << hash_to_address((char*)it->first.val) << " " << it->second << endl;
#endif

#if 0
        for (map<ckey<32>, int>::iterator it=blks.begin(); it!=blks.end(); ++it) 
            cout << htoa((char*)it->first.val, 32, true) << endl;
#endif

        return true;
    }

    int read_script(bfile& f, int64_t value)
    {
        uint64_t size = var_int(f);
        char* script = new char[size];

        f.read(script, size);

        if (size == 25 && script[0] == (char)0x76) 
            hash160(script+3, value);

        if (size == 67 && script[66] == (char)0xAC)
            hash160(rhash(script+1,65), value);

        delete[] script;

        return size;
    }

    int read_tx(bfile& f)
    {
        uint64_t pos = f.tellg();
        uint32_t tx_ver = u32(f);

        uint64_t vin_sz = var_int(f);

        for (int i = 0; i < vin_sz; i++)
        {
            char op[32]; f.read(op, 32);
            uint32_t n = u32(f);
            read_script(f, 0);
            uint32_t seq = u32(f);
        }

        uint64_t vout_sz = var_int(f);

        for (int i = 0; i < vout_sz; i++)
        {
            uint64_t value = u64(f);
            read_script(f, value);
        }

        uint32_t lock_time = u32(f);

        uint64_t size = (uint64_t)f.tellg() - pos;

        f.seekg(pos);
        char* buf = new char[size];
        f.read(buf, size);
        char* hash = dhash(buf, size);
        tx_hash(hash);
        delete[] buf;

        return size;
    }

    int read_block(bfile& f, bool skip = false) 
    {
        uint32_t magic = u32(f);
        uint32_t size = u32(f);
        uint64_t pos = f.tellg();

        if (skip)
        {
            f.seekg(size + pos);
            return f.eof() ? -1 : size;
        }

        char header[80];

        f.read(header, 80);
        block_header(header);
        uint64_t n_tx = var_int(f);

        for (int i = 0; i < n_tx; i++)
            read_tx(f);

        return f.eof() ? -1 : size;
    }

    void hash160(char* hash, int64_t value)
    {
        addr[ckey<20>(hash)] += value;
    }

    void tx_hash(char* hash)
    {
        txns[ckey<32>(hash)] = txns.size();
//        cout << htoa(hash, 32, 1) << " " << txns.size() << endl;
    }

    void block_header(char* header)
    {
        char* hash = dhash(header, 80);
        blks[ckey<32>(hash)] = blks.size();
//        cout << htoa(hash, 32, 1) << " " << blks.size() << endl;
    }

};

int main()
{
    BlockReader b;
    b.scan();
}

