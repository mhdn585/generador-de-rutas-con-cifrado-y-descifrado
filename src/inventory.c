/*
 * inventory.c — Inventario en RAM y su serialización para el manifest.
 */
#include "inventory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INV_MAGIC "INV1"
#define INV_MAX_NODOS 100000u

void inv_inicializar(inventory *inv)
{
    inv->it = NULL;
    inv->n = inv->cap = 0;
}

void inv_liberar(inventory *inv)
{
    for (size_t i = 0; i < inv->n; i++) {
        free(inv->it[i].rel);
        free(inv->it[i].enc_base);
    }
    free(inv->it);
    inv->it = NULL;
    inv->n = inv->cap = 0;
}

static int nivel_de(const char *rel)
{
    int nivel = 1;
    for (const char *p = rel; *p; p++)
        if (*p == '/')
            nivel++;
    return nivel;
}

inv_node *inv_buscar(inventory *inv, const char *rel)
{
    for (size_t i = 0; i < inv->n; i++)
        if (strcmp(inv->it[i].rel, rel) == 0)
            return &inv->it[i];
    return NULL;
}

inv_node *inv_agregar(inventory *inv, const char *rel, inv_tipo tipo)
{
    inv_node *existe = inv_buscar(inv, rel);
    if (existe)
        return existe;

    if (inv->n == inv->cap) {
        size_t nuevo = inv->cap ? inv->cap * 2 : 64;
        inv_node *it = realloc(inv->it, nuevo * sizeof *it);
        if (!it)
            return NULL;
        inv->it = it;
        inv->cap = nuevo;
    }

    inv_node *nd = &inv->it[inv->n++];
    nd->rel = strdup(rel);
    nd->enc_base = NULL;
    nd->tipo = tipo;
    nd->size = 0;
    nd->nivel = nivel_de(rel);
    memset(nd->sha, 0, sizeof nd->sha);
    if (!nd->rel) {
        inv->n--;
        return NULL;
    }
    return nd;
}

int inv_contar(const inventory *inv, inv_tipo tipo)
{
    int c = 0;
    for (size_t i = 0; i < inv->n; i++)
        if (inv->it[i].tipo == tipo)
            c++;
    return c;
}

static int cmp_nivel_asc(const void *a, const void *b)
{
    const inv_node *x = a, *y = b;
    if (x->nivel != y->nivel)
        return x->nivel - y->nivel;
    return strcmp(x->rel, y->rel);
}

static int cmp_nivel_desc(const void *a, const void *b)
{
    return -cmp_nivel_asc(a, b);
}

void inv_ordenar_por_nivel(inventory *inv, bool descendente)
{
    qsort(inv->it, inv->n, sizeof *inv->it,
          descendente ? cmp_nivel_desc : cmp_nivel_asc);
}

int inv_componer_nombres_cifrados(inventory *inv)
{
    for (size_t i = 0; i < inv->n; i++) {
        inv_node *nd = &inv->it[i];
        if (nd->enc_base)
            continue;
        const char *base = strrchr(nd->rel, '/');
        base = base ? base + 1 : nd->rel;
        char enc[512];
        if (crypto_nombre_cifrar(base, enc, sizeof enc) != 0)
            return -1;
        nd->enc_base = strdup(enc);
        if (!nd->enc_base)
            return -1;
    }
    return 0;
}

/* Encadena enc_base de cada componente buscando los nodos directorio. */
int inv_ruta_enc_rel(const inventory *inv, const inv_node *nd, char *out, size_t outsz)
{
    out[0] = '\0';
    size_t usado = 0;
    const char *p = nd->rel;
    inventory *mutable_inv = (inventory *) inv; /* inv_buscar no modifica */

    while (*p) {
        const char *s = p;
        while (*p && *p != '/')
            p++;
        size_t clen = (size_t) (p - s);

        /* rel del prefijo hasta este componente */
        char pref[4096];
        size_t prel = (size_t) (s - nd->rel) + clen;
        if (prel >= sizeof pref)
            return -1;
        memcpy(pref, nd->rel, prel);
        pref[prel] = '\0';

        const inv_node *comp = inv_buscar(mutable_inv, pref);
        if (!comp || !comp->enc_base)
            return -1;

        size_t elen = strlen(comp->enc_base);
        if (usado + elen + 2 > outsz)
            return -1;
        if (usado)
            out[usado++] = '/';
        memcpy(out + usado, comp->enc_base, elen);
        usado += elen;

        if (*p == '/')
            p++;
    }
    out[usado] = '\0';
    return 0;
}

/* ------------------------------------------------------ serialización */

static void put_u16(unsigned char **p, unsigned v)
{
    (*p)[0] = (unsigned char) v;
    (*p)[1] = (unsigned char) (v >> 8);
    *p += 2;
}

static void put_u32(unsigned char **p, unsigned v)
{
    for (int i = 0; i < 4; i++)
        (*p)[i] = (unsigned char) (v >> (8 * i));
    *p += 4;
}

static void put_u64(unsigned char **p, unsigned long long v)
{
    for (int i = 0; i < 8; i++)
        (*p)[i] = (unsigned char) (v >> (8 * i));
    *p += 8;
}

static int get_u16(const unsigned char **p, const unsigned char *fin, unsigned *v)
{
    if (*p + 2 > fin)
        return -1;
    *v = (unsigned) (*p)[0] | ((unsigned) (*p)[1] << 8);
    *p += 2;
    return 0;
}

static int get_u32(const unsigned char **p, const unsigned char *fin, unsigned *v)
{
    if (*p + 4 > fin)
        return -1;
    *v = 0;
    for (int i = 0; i < 4; i++)
        *v |= (unsigned) (*p)[i] << (8 * i);
    *p += 4;
    return 0;
}

static int get_u64(const unsigned char **p, const unsigned char *fin, unsigned long long *v)
{
    if (*p + 8 > fin)
        return -1;
    *v = 0;
    for (int i = 0; i < 8; i++)
        *v |= (unsigned long long) (*p)[i] << (8 * i);
    *p += 8;
    return 0;
}

int inv_serializar(const inventory *inv, unsigned char **buf, size_t *n)
{
    size_t cap = strlen(INV_MAGIC) + 4;
    for (size_t i = 0; i < inv->n; i++) {
        cap += 1 + 2 + strlen(inv->it[i].rel) + 1;
        cap += 2 + (inv->it[i].enc_base ? strlen(inv->it[i].enc_base) : 0);
        cap += 8 + CIFR_SHA_LEN;
    }
    unsigned char *b = malloc(cap);
    if (!b)
        return -1;
    unsigned char *p = b;

    static const char mg[] = INV_MAGIC;
    memcpy(p, mg, sizeof mg - 1);
    p += sizeof mg - 1;

    put_u32(&p, (unsigned) inv->n);
    for (size_t i = 0; i < inv->n; i++) {
        const inv_node *nd = &inv->it[i];
        *p++ = (unsigned char) nd->tipo;
        put_u16(&p, (unsigned) strlen(nd->rel));
        memcpy(p, nd->rel, strlen(nd->rel));
        p += strlen(nd->rel);
        size_t elen = nd->enc_base ? strlen(nd->enc_base) : 0;
        put_u16(&p, (unsigned) elen);
        if (elen) {
            memcpy(p, nd->enc_base, elen);
            p += elen;
        }
        put_u64(&p, (unsigned long long) (nd->size < 0 ? 0 : nd->size));
        memcpy(p, nd->sha, CIFR_SHA_LEN);
        p += CIFR_SHA_LEN;
    }
    *buf = b;
    *n = (size_t) (p - b);
    return 0;
}

int inv_deserializar(inventory *inv, const unsigned char *buf, size_t n)
{
    static const char mg[] = INV_MAGIC;
    const size_t mgl = sizeof mg - 1;
    if (n < mgl + 4 || memcmp(buf, mg, mgl) != 0)
        return -1;

    const unsigned char *p = buf + mgl;
    const unsigned char *fin = buf + n;
    unsigned cnt;
    if (get_u32(&p, fin, &cnt) != 0 || cnt > INV_MAX_NODOS)
        return -1;

    for (unsigned i = 0; i < cnt; i++) {
        if (p >= fin)
            return -1;
        unsigned char tipo = *p++;
        if (tipo != INV_DIR && tipo != INV_FILE)
            return -1;

        unsigned rlen;
        if (get_u16(&p, fin, &rlen) != 0 || rlen == 0 || p + rlen > fin)
            return -1;
        char *rel = malloc(rlen + 1);
        if (!rel)
            return -1;
        memcpy(rel, p, rlen);
        rel[rlen] = '\0';
        p += rlen;

        unsigned elen;
        if (get_u16(&p, fin, &elen) != 0 || p + elen > fin) {
            free(rel);
            return -1;
        }
        char *enc = NULL;
        if (elen) {
            enc = malloc(elen + 1);
            if (!enc) {
                free(rel);
                return -1;
            }
            memcpy(enc, p, elen);
            enc[elen] = '\0';
        }
        p += elen;

        unsigned long long size;
        if (get_u64(&p, fin, &size) != 0) {
            free(rel);
            free(enc);
            return -1;
        }
        if (p + CIFR_SHA_LEN > fin) {
            free(rel);
            free(enc);
            return -1;
        }

        /* inv_agregar puede reallocar el array; nd queda válido tras la llamada */
        inv_node *nd = inv_agregar(inv, rel, (inv_tipo) tipo);
        free(rel);
        if (!nd) {
            free(enc);
            return -1;
        }
        if (enc)
            nd->enc_base = enc; /* transferimos la propiedad del puntero */
        else
            free(enc);
        nd->size = (long long) size;
        memcpy(nd->sha, p, CIFR_SHA_LEN);
        p += CIFR_SHA_LEN;
    }
    return 0;
}
