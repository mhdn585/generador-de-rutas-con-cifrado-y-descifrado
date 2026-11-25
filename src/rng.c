/*
 * rng.c — Aleatoriedad sembrada con getentropy(2).
 */
#include "rng.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <sys/types.h>
#include <unistd.h>

int rng_iniciar(void)
{
    unsigned char semilla[8];
    if (getentropy(semilla, sizeof semilla) != 0)
        return -1;

    unsigned long long v;
    memcpy(&v, semilla, sizeof v);
    srandom((unsigned) (v ^ (v >> 32) ^ (unsigned long long) getpid() ^
                        (unsigned long long) time(NULL)));
    return 0;
}

long rng_entre(long lo, long hi)
{
    if (lo >= hi)
        return lo;
    unsigned long rango = (unsigned long) (hi - lo + 1);
    return lo + (long) (random() % (long) rango);
}

size_t rng_palabra(char *out, size_t outsz, size_t minlen, size_t maxlen)
{
    if (minlen < 1)
        minlen = 1;
    if (maxlen < minlen)
        maxlen = minlen;
    size_t n = (size_t) rng_entre((long) minlen, (long) maxlen);
    if (n + 1 > outsz)
        n = outsz - 1;
    for (size_t i = 0; i < n; i++)
        out[i] = (char) ('a' + random() % 26);
    out[n] = '\0';
    return n;
}

void rng_texto(char *out, size_t n)
{
    static const char pool[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
    const size_t pool_len = sizeof pool - 1; /* 63: deja 1 de 64 para salto de línea */
    for (size_t i = 0; i < n; i++) {
        long r = random() % 64;
        out[i] = (r == 63) ? '\n' : pool[r % (long) pool_len];
    }
}

const char *rng_extension(void)
{
    static const char *exts[] = {
        "txt", "dat", "log", "cfg", "csv", "md", "json", "ini", "tmp", "bak"
    };
    return exts[(size_t) random() % (sizeof exts / sizeof *exts)];
}
