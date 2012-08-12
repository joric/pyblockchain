#ifndef __BASE58__
#define __BASE58__

/*
    This version taken from http://github.com/samr7/vanitygen
    The code is still under GPL, avoid at all costs. I'll rewrite it later.
*/

#include <openssl/bn.h>
#include <openssl/sha.h>

const char *b58_alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const signed char b58_reverse_map[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1,
    -1, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

void b58_encode_check(void *buf, size_t len, char *result)
{
    unsigned char hash1[32];
    unsigned char hash2[32];

    int d, p;

    BN_CTX *bnctx;
    BIGNUM *bn, *bndiv, *bntmp;
    BIGNUM bna, bnb, bnbase, bnrem;
    unsigned char *binres;
    int brlen, zpfx;

    bnctx = BN_CTX_new();
    BN_init(&bna);
    BN_init(&bnb);
    BN_init(&bnbase);
    BN_init(&bnrem);
    BN_set_word(&bnbase, 58);

    bn = &bna;
    bndiv = &bnb;

    brlen = (2 * len) + 4;
    binres = (unsigned char *)malloc(brlen);
    memcpy(binres, buf, len);

    SHA256(binres, len, hash1);
    SHA256(hash1, sizeof(hash1), hash2);
    memcpy(&binres[len], hash2, 4);

    BN_bin2bn(binres, len + 4, bn);

    for (zpfx = 0; zpfx < (len + 4) && binres[zpfx] == 0; zpfx++);

    p = brlen;
    while (!BN_is_zero(bn))
    {
        BN_div(bndiv, &bnrem, bn, &bnbase, bnctx);
        bntmp = bn;
        bn = bndiv;
        bndiv = bntmp;
        d = BN_get_word(&bnrem);
        binres[--p] = b58_alphabet[d];
    }

    while (zpfx--)
    {
        binres[--p] = b58_alphabet[0];
    }

    memcpy(result, &binres[p], brlen - p);
    result[brlen - p] = '\0';

    free(binres);
    BN_clear_free(&bna);
    BN_clear_free(&bnb);
    BN_clear_free(&bnbase);
    BN_clear_free(&bnrem);
    BN_CTX_free(bnctx);
}

#define skip_char(c) \
    (((c) == '\r') || ((c) == '\n') || ((c) == ' ') || ((c) == '\t'))

int b58_decode_check(const char *input, void *buf, size_t len)
{
    int i, l, c;
    unsigned char *xbuf = NULL;
    BIGNUM bn, bnw, bnbase;
    BN_CTX *bnctx;
    unsigned char hash1[32], hash2[32];
    int zpfx;
    int res = 0;

    BN_init(&bn);
    BN_init(&bnw);
    BN_init(&bnbase);
    BN_set_word(&bnbase, 58);
    bnctx = BN_CTX_new();

    /* Build a bignum from the encoded value */
    l = strlen(input);
    for (i = 0; i < l; i++)
    {
        if (skip_char(input[i]))
            continue;
        c = b58_reverse_map[(int)input[i]];
        if (c < 0)
            goto out;
        BN_clear(&bnw);
        BN_set_word(&bnw, c);
        BN_mul(&bn, &bn, &bnbase, bnctx);
        BN_add(&bn, &bn, &bnw);
    }

    /* Copy the bignum to a byte buffer */
    for (i = 0, zpfx = 0; input[i]; i++)
    {
        if (skip_char(input[i]))
            continue;
        if (input[i] != b58_alphabet[0])
            break;
        zpfx++;
    }
    c = BN_num_bytes(&bn);
    l = zpfx + c;
    if (l < 5)
        goto out;
    xbuf = (unsigned char *)malloc(l);
    if (!xbuf)
        goto out;
    if (zpfx)
        memset(xbuf, 0, zpfx);
    if (c)
        BN_bn2bin(&bn, xbuf + zpfx);

    /* Check the hash code */
    l -= 4;
    SHA256(xbuf, l, hash1);
    SHA256(hash1, sizeof(hash1), hash2);
    if (memcmp(hash2, xbuf + l, 4))
        goto out;

    /* Buffer verified */
    if (len)
    {
        if (len > l)
            len = l;
        memcpy(buf, xbuf, len);
    }
    res = l;

out:
    if (xbuf)
        free(xbuf);
    BN_clear_free(&bn);
    BN_clear_free(&bnw);
    BN_clear_free(&bnbase);
    BN_CTX_free(bnctx);
    return res;
}

#endif
