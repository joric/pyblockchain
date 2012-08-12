/*
    cpp blockchain parser, public domain
    see http://github.com/joric/pyblockchain
    compile using g++ -std=gnu++0x -lssl cppblockchain.cpp
*/

#include <iostream>
#include <fstream>
#include <time.h>
#include <string>
#include <vector>
#include <map>
#include <memory.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

using namespace std;

#ifdef WIN32 
#include <shlwapi.h>
#endif

#include "base58.h"

//char m_addr[] = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; //first address ever
char m_addr[] = "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S"; //blocks 0-100
char m_hash[20] = {0};

template <int N> struct ckey
{
    char val[N];

    ckey(char* s)
    {
        memcpy(val, s, N);
    }

    bool operator < (const ckey& oth) const
    {
        return memcmp(val,oth.val,N)<0;
    }
};

typedef ckey<20> hash160;
typedef ckey<32> hash256;

struct addr_info_t {
    uint64_t received;
    uint64_t sent;
};

typedef map<hash160, addr_info_t> rhash_map;

typedef rhash_map::iterator rhash_it;

struct tx_point_t {
    rhash_it address;
    uint64_t value;
};

typedef vector<tx_point_t> output_vector_t;
typedef map<hash256, output_vector_t*> dhash_map;
typedef dhash_map::iterator dhash_it;

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

char* atoh(char *dest, char *src, int len)
{
    int v = 0;
    while (sscanf(src, "%02x", &v) > 0)
        *dest++ = v, src += 2;
    return dest;
}

char *dhash(char* dest, char *src, int len)
{
    unsigned char buf[32];
    SHA256((unsigned char *)src, len, buf);
    SHA256(buf, 32, (unsigned char*)dest);
    return dest;
}

char *rhash(char *dest, char *src, int len)
{
    unsigned char buf[32];
    SHA256((unsigned char *)src, len, buf);
    RIPEMD160(buf, 32, (unsigned char*)dest);
    return dest;
}

#ifndef __BASE58__
char *address_to_hash(const char *md) { static char r[32] = {0}; return r; }
char *hash_to_address(char *md) { return htoa(md,20); }
#else
char *address_to_hash(const char *address)
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
    uint64_t total;
    uint64_t count;
    time_t ts_start;
    time_t ts_last;
    time_t ts_current;
    char buf[256];

    ProgressBar(int size)
    {
        total = size;
        count = 0;
        ts_start = time(0);
        ts_last = ts_start;
    }

    char* c_str()
    {
        time_t elapsed = ts_current - ts_start;
        time_t left = elapsed * total / count - elapsed;
        left = left > 0 ? left : 0;
        int h = left / 60 / 60;
        int m = left / 60 - h*60;
        int s = left % 60;
        sprintf(buf, "%.2f%%, est. %02d:%02d:%02d", 
            count * 100.0 / total, h, m, s);
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

class BlockReader
{
    uint8_t   u8(ifstream& f) { uint8_t  n; f.read((char*)&n, 1); return n; }
    uint16_t u16(ifstream& f) { uint16_t n; f.read((char*)&n, 2); return n; }
    uint32_t u32(ifstream& f) { uint32_t n; f.read((char*)&n, 4); return n; }
    uint64_t u64(ifstream& f) { uint64_t n; f.read((char*)&n, 8); return n; }

    uint64_t var_int(ifstream& f)
    {
        uint8_t t = u8(f);
        if (t == 0xfd) return u16(f); else
        if (t == 0xfe) return u32(f); else 
        if (t == 0xff) return u64(f); else 
        return t;
    }

public:
    int startblock;
    int stopblock;
    dhash_map txns;
    rhash_map addr;

    BlockReader() {
        startblock = 0;
        stopblock = -1;
    }

    bool scan()
    {
        char* h = address_to_hash((char*)m_addr);
        memcpy(m_hash, h, 20);

        string fname = determine_db_dir() + "blk0001.dat";

        ifstream f(fname.c_str(), ios::in | ios::binary);

        if (!f.is_open())
            return false;

        f.seekg(0, ios::end);
        uint64_t fsize = f.tellg();
        f.seekg(0, ios::beg);

        cerr << fname << ", "<< fsize/1024/1024 << " MB" << endl;

        ProgressBar p(fsize);

        for (int block = 0; read_block(f) > 0; block++)
        {
            if (p.update(f.tellg()) || block == stopblock)
            {
                cerr << "\r" << p.c_str()
                    << ", " << block << " blks"
                    << ", " << addr.size() << " addr"
                    << ", " << txns.size() << " txns";
            }

            if (block == stopblock)
                break;
        }
#if 0
        for (rhash_map::iterator it=addr.begin(); it!=addr.end(); ++it) 
            cout << hash_to_address((char*)it->first.val) 
                << " " << it->second.received 
                << " " << it->second.sent 
                << " " << get_balance(hash160((char*)it->first.val))
                << endl;
#endif

#if 0
        for (dhash_map::iterator it=blks.begin(); it!=blks.end(); ++it) 
            cout << htoa((char*)it->first.val, 32, true) << endl;
#endif

        return true;
    }

    void dump_address(rhash_it address, uint64_t value, int direction)
    {
        char* hash = (char*)address->first.val;

        uint64_t received = address->second.received;
        uint64_t sent = address->second.sent;

        uint64_t balance = received - sent;

        if (memcmp(hash, m_hash, 20) == 0)  {

            cout.setf(ios::fixed);
            cout.precision(8);

            cout << "\n" 
                << (direction > 0 ? "->" : "<-")
                << " " << value * 1e-8
                << " " << hash_to_address(hash) 
                << " balance: " << balance * 1e-8 << endl;
        }
    }

    rhash_it read_script(ifstream& f, int64_t value)
    {
        //no reallocations
        static const int max_size = 16384;
        char script[max_size];

        uint64_t size = var_int(f);

        if (size > max_size) {
            f.seekg(size, ios::cur);
            return addr.end();
        }

        f.read(script, size);

        if (size == 25 && script[0] == (char)0x76) 
            return address_callback(script+3);

        char hash[20];
        if (size == 67 && script[66] == (char)0xAC)
            return address_callback( rhash(hash, script+1, 65) );

        return addr.end();
    }

    int read_tx(ifstream& f)
    {
        uint64_t pos = f.tellg();
        uint32_t tx_ver = u32(f);
        uint64_t vin_sz = var_int(f);

        for (int i = 0; i < vin_sz; i++)
        {
            char outpoint[32];
            f.read(outpoint, 32);
            uint32_t n = u32(f);
            read_script(f, 0);
            uint32_t seq = u32(f);

            dhash_it trans = txns.find(hash256(outpoint));

            if (trans != txns.end()) 
            {
                output_vector_t* v = trans->second;

                if (v && v->size() > n) 
                {
                    tx_point_t outp = v->at(n);

                    outp.address->second.sent += outp.value;

                    //dump_address(outp.address, outp.value, -1);
                }
            }
        }

        uint64_t vout_sz = var_int(f);

        output_vector_t* v = new output_vector_t;

        for (int i = 0; i < vout_sz; i++)
        {
            uint64_t value = u64(f);

            rhash_it address = read_script(f, value);

            if (address != addr.end()) {

                tx_point_t outp;

                outp.address = address;
                outp.value = value;
                v->push_back(outp);

                outp.address->second.received += value;

                //dump_address(outp.address, value, +1);
            }
        }

        uint32_t lock_time = u32(f);

        uint64_t size = (uint64_t)f.tellg() - pos;

        //no reallocations
        const int max_size = 16384;
        char buf[max_size];

        if (size > max_size) {
            return size;
        } else {
            char hash[32];
            f.seekg(pos);
            f.read(buf, size);
            dhash(hash, buf, size);

            hash256 key = hash256(hash);
            txns[key] = v;
        }

        return size;
    }

    int read_block(ifstream& f, bool skip = false) 
    {
        uint32_t magic = u32(f);
        uint32_t size = u32(f);
        uint64_t pos = f.tellg();

        if (!skip)
        {
            char header[80];

            f.read(header, 80);

            uint64_t n_tx = var_int(f);

            for (int i = 0; i < n_tx; i++)
                read_tx(f);
        }

        f.seekg(size + pos);
        return f.eof() ? -1 : size;
    }

    rhash_it address_callback(char* hash)
    {
        static addr_info_t v; //static modifier used for zeroing
        return addr.insert(rhash_map::value_type(hash160(hash),v)).first;
    }
};

EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
BN_CTX* ctx = BN_CTX_new();
const EC_GROUP *group = EC_KEY_get0_group(pkey);
EC_POINT* pub_key = EC_POINT_new(group);

char* pass_to_h160(const char* src, char* dest) {

    unsigned char secret[32];
    SHA256((unsigned char *)src, strlen(src), secret);

    BIGNUM *priv_key = BN_bin2bn(secret, 32, BN_new());

    EC_POINT_mul(group, pub_key, priv_key, 0, 0, ctx);

    EC_KEY_set_private_key(pkey, priv_key);
    EC_KEY_set_public_key(pkey, pub_key);

    unsigned char buf[128], *p;
    p = buf;
    int len = 65;//i2o_ECPublicKey(pkey, 0);
    i2o_ECPublicKey(pkey, &p);
    rhash(dest, (char*)buf, len);

    //EC_POINT_free(pub_key);
    //BN_CTX_free(ctx);

    //cout << htoa(dest, 20) << endl;

    return dest;
}

int check_addresses(string fname, char* opt) 
{

    BlockReader b;

    ProgressBar p(14000000);

    bool bake = opt && strcmp("-b", opt) == 0;

    if (bake) 
        b.stopblock = 1;

    if (!b.scan()) {
        cerr << "blockchain not found" << endl;
        return false;
    }

    ifstream f(fname.c_str(), ios::in | ios::binary);

    if (!f.is_open()) {
        cerr << "file not found" << endl;
        return false;
    }

    char hash[20];
    string line;
    unsigned long i = 0;
    unsigned long sec = 0;
    int found = 0;

    while (getline(f, line)) 
    {
        if (line[line.size() - 1] == '\r')
            line.resize(line.size() - 1);

        size_t pos = line.find('\t');
        if (pos != string::npos && pos == 40) { //baked
            string l = line.substr(0, pos);
            string r = line.substr(pos + 1);
            atoh(hash, (char*)l.c_str(), 20);
            line = r;
        } else {
            pass_to_h160(line.c_str(), hash);
        }

        rhash_it address = b.addr.find(hash160(hash));

        if (address != b.addr.end()) 
        {
            uint64_t balance = address->second.received - address->second.sent;
            cout << htoa(hash, 20) << "\t" << balance * 1e-8 << " " << line << endl;
            found++;
        }

        if (bake) 
        {
            cout << htoa(hash, 20) << "\t" << line << endl;
        }

        if (p.update(++i))
        {
            sec++;
            cerr << "\r" << p.c_str() << ", " << i << " keys, " 
                << found << " found, " << i/sec << " k/s." ;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    cerr << "Compiled with openssl " << OPENSSL_VERSION_TEXT << endl;

    if (argc < 2) 
    {
        cerr << "Usage: cppblockchain [dict file] <options>\nOptions: -b: bake dict" << endl;
    }
    else
    {
        check_addresses(argv[1], argv[2]);
    }
}

