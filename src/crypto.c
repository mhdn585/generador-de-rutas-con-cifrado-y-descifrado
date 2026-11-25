/*
 * crypto.c — AES-256-GCM con la EVP API de OpenSSL.
 */
#include "crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

_Static_assert(sizeof(CLAVE_AES) - 1 == 32, "la clave embebida debe tener 32 bytes exactos");

static const unsigned char *const CLAVE = (const unsigned char *)CLAVE_AES;
static const unsigned char MAGIC[CIFR_MAGIC_LEN] = { 'C', 'I', 'F', 'R', '1' };

int crypto_iniciar(void)
{
    /* OpenSSL 3.x no requiere inicialización global explícita. */
    return 0;
}

void crypto_terminar(void)
{
}

/* ------------------------------------------------------------------ SHA-256 */

int crypto_sha256(const unsigned char *datos, size_t n, unsigned char out[CIFR_SHA_LEN])
{
    if (EVP_Digest(datos, n, out, NULL, EVP_sha256(), NULL) != 1)
        return -1;
    return 0;
}

/* ------------------------------------------------------------- GCM interno */

/* Cifra pt -> ct (misma longitud) + tag. Devuelve ctlen o -1. */
static int gcm_cifrar(const unsigned char iv[CIFR_IV_LEN], const unsigned char *pt, size_t n,
                      unsigned char *ct, unsigned char tag[CIFR_TAG_LEN])
{
    int resultado = -1, tmp = 0, total = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CIFR_IV_LEN, NULL) != 1)
            break;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, CLAVE, iv) != 1)
            break;
        if (n > 0 && EVP_EncryptUpdate(ctx, ct, &tmp, pt, (int)n) != 1)
            break;
        total = tmp;
        if (EVP_EncryptFinal_ex(ctx, ct + total, &tmp) != 1)
            break;
        total += tmp;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CIFR_TAG_LEN, tag) != 1)
            break;
        resultado = total;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return resultado;
}

/* Descifra ct -> pt validando el tag. Devuelve ptlen o -1 (tamper/clave). */
static int gcm_descifrar(const unsigned char iv[CIFR_IV_LEN], const unsigned char *ct, size_t n,
                         const unsigned char tag[CIFR_TAG_LEN], unsigned char *pt)
{
    int resultado = -1, tmp = 0, total = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, CIFR_IV_LEN, NULL) != 1)
            break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, CLAVE, iv) != 1)
            break;
        if (n > 0 && EVP_DecryptUpdate(ctx, pt, &tmp, ct, (int)n) != 1)
            break;
        total = tmp;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CIFR_TAG_LEN,
                                (void *)(uintptr_t)tag) != 1)
            break;
        if (EVP_DecryptFinal_ex(ctx, pt + total, &tmp) != 1)
            break; /* tag inválido: datos dañados o clave incorrecta */
        total += tmp;
        resultado = total;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return resultado;
}

/* ------------------------------------------------------------ Buffer blob */

int crypto_cifrar_buf(const unsigned char *pt, size_t n, unsigned char flags,
                      unsigned char **blob, size_t *blob_n)
{
    *blob = NULL;
    *blob_n = 0;

    unsigned char *out = malloc(CIFR_HDR_LEN + n);
    if (!out)
        return -1;

    unsigned char *iv = out + CIFR_MAGIC_LEN + 1;
    unsigned char *tag = out + CIFR_MAGIC_LEN + 1 + CIFR_IV_LEN;
    unsigned char *ct = out + CIFR_HDR_LEN;

    if (RAND_bytes(iv, CIFR_IV_LEN) != 1) {
        free(out);
        return -1;
    }
    memcpy(out, MAGIC, CIFR_MAGIC_LEN);
    out[CIFR_MAGIC_LEN] = flags;

    if (gcm_cifrar(iv, pt, n, ct, tag) < 0) {
        free(out);
        return -1;
    }

    *blob = out;
    *blob_n = CIFR_HDR_LEN + n;
    return 0;
}

int crypto_descifrar_buf(const unsigned char *blob, size_t n, unsigned char esperado_flags,
                         unsigned char **pt, size_t *pt_n)
{
    *pt = NULL;
    *pt_n = 0;

    if (n < CIFR_HDR_LEN || memcmp(blob, MAGIC, CIFR_MAGIC_LEN) != 0 ||
        blob[CIFR_MAGIC_LEN] != esperado_flags)
        return -1;

    const unsigned char *iv = blob + CIFR_MAGIC_LEN + 1;
    const unsigned char *tag = blob + CIFR_MAGIC_LEN + 1 + CIFR_IV_LEN;
    const unsigned char *ct = blob + CIFR_HDR_LEN;
    size_t ctn = n - CIFR_HDR_LEN;

    unsigned char *out = malloc(ctn + 1);
    if (!out)
        return -1;

    if (gcm_descifrar(iv, ct, ctn, tag, out) < 0) {
        free(out);
        return -1;
    }
    out[ctn] = '\0';
    *pt = out;
    *pt_n = ctn;
    return 0;
}

int crypto_blob_valido(const unsigned char *blob, size_t n, unsigned char esperado_flags)
{
    unsigned char *pt = NULL;
    size_t ptn = 0;
    int r = crypto_descifrar_buf(blob, n, esperado_flags, &pt, &ptn);
    free(pt);
    return r;
}

/* ----------------------------------------------------------------- base64url */

static const char B64U[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t b64url_encriptar(const unsigned char *in, size_t n, char *out)
{
    size_t o = 0, i = 0;
    while (i + 3 <= n) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];
        out[o++] = B64U[(v >> 18) & 63];
        out[o++] = B64U[(v >> 12) & 63];
        out[o++] = B64U[(v >> 6) & 63];
        out[o++] = B64U[v & 63];
        i += 3;
    }
    size_t r = n - i;
    if (r == 1) {
        unsigned v = (unsigned)in[i] << 16;
        out[o++] = B64U[(v >> 18) & 63];
        out[o++] = B64U[(v >> 12) & 63];
    } else if (r == 2) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8);
        out[o++] = B64U[(v >> 18) & 63];
        out[o++] = B64U[(v >> 12) & 63];
        out[o++] = B64U[(v >> 6) & 63];
    }
    out[o] = '\0';
    return o;
}

static int b64_valor(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static int b64url_desencriptar(const char *in, size_t n, unsigned char *out, size_t outmax)
{
    size_t o = 0;
    int quad = 0;
    unsigned int acc = 0;
    for (size_t i = 0; i < n; i++) {
        if (in[i] == '=')
            continue;
        int v = b64_valor(in[i]);
        if (v < 0)
            return -1;
        acc = (acc << 6) | (unsigned)v;
        if (++quad == 4) {
            if (o + 3 > outmax)
                return -1;
            out[o++] = (unsigned char)((acc >> 16) & 0xff);
            out[o++] = (unsigned char)((acc >> 8) & 0xff);
            out[o++] = (unsigned char)(acc & 0xff);
            quad = 0;
            acc = 0;
        }
    }
    if (quad == 1)
        return -1;
    if (quad == 2) {
        if (o + 1 > outmax)
            return -1;
        out[o++] = (unsigned char)((acc >> 4) & 0xff);
    } else if (quad == 3) {
        if (o + 2 > outmax)
            return -1;
        out[o++] = (unsigned char)((acc >> 10) & 0xff);
        out[o++] = (unsigned char)((acc >> 2) & 0xff);
    }
    return (int)o;
}

/* -------------------------------------------------------------- Nombres */

/* Longitud máxima esperada de un nombre cifrado (para buffers). */
#define NOMBRE_MAX 255
#define BLOB_NOMBRE_MAX (CIFR_IV_LEN + CIFR_TAG_LEN + NOMBRE_MAX + 8)

int crypto_nombre_cifrar(const char *nombre, char *out, size_t outsz)
{
    size_t nl = strlen(nombre);
    if (nl == 0 || nl > NOMBRE_MAX)
        return -1;

    unsigned char blob[BLOB_NOMBRE_MAX];
    unsigned char iv[CIFR_IV_LEN];
    if (RAND_bytes(iv, CIFR_IV_LEN) != 1)
        return -1;
    memcpy(blob, iv, CIFR_IV_LEN);
    if (gcm_cifrar(iv, (const unsigned char *)nombre, nl, blob + CIFR_IV_LEN + CIFR_TAG_LEN,
                   blob + CIFR_IV_LEN) < 0)
        return -1;
    size_t bloblen = CIFR_IV_LEN + CIFR_TAG_LEN + nl;

    char b64[BLOB_NOMBRE_MAX * 2];
    b64url_encriptar(blob, bloblen, b64);

    if (snprintf(out, outsz, "%s%s", b64, CIFR_SUFJO) >= (int)outsz)
        return -1;
    return 0;
}

int crypto_nombre_descifrar(const char *enc, char *out, size_t outsz)
{
    size_t el = strlen(enc);
    size_t sl = strlen(CIFR_SUFJO);
    if (el <= sl || strcmp(enc + el - sl, CIFR_SUFJO) != 0)
        return -1;

    unsigned char blob[BLOB_NOMBRE_MAX];
    int blen = b64url_desencriptar(enc, el - sl, blob, sizeof blob);
    if (blen < CIFR_IV_LEN + CIFR_TAG_LEN + 1)
        return -1;

    int n = blen - CIFR_IV_LEN - CIFR_TAG_LEN;
    if ((size_t)n + 1 > outsz)
        return -1;

    if (gcm_descifrar(blob, blob + CIFR_IV_LEN + CIFR_TAG_LEN, (size_t)n,
                      blob + CIFR_IV_LEN, (unsigned char *)out) < 0)
        return -1;
    out[n] = '\0';
    return 0;
}

/* --------------------------------------------------------------- Archivos */

static int leer_archivo(const char *abs, unsigned char **buf, size_t *n)
{
    *buf = NULL;
    *n = 0;
    FILE *f = fopen(abs, "rb");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return -1;
    }
    rewind(f);
    unsigned char *b = malloc((size_t)sz + 1);
    if (!b) {
        fclose(f);
        return -1;
    }
    size_t leido = fread(b, 1, (size_t)sz, f);
    fclose(f);
    if (leido != (size_t)sz) {
        free(b);
        return -1;
    }
    b[sz] = '\0';
    *buf = b;
    *n = (size_t)sz;
    return 0;
}

/* Escribe tmp junto a abs y lo renombra (atómico a nivel de visibilidad). */
#define RUTA_LOCAL_MAX 4096
static int escribir_atomico(const char *abs, const unsigned char *buf, size_t n)
{
    char tmp[RUTA_LOCAL_MAX];
    if (snprintf(tmp, sizeof tmp, "%s.cifrar.tmp", abs) >= (int)sizeof tmp)
        return -1;
    FILE *f = fopen(tmp, "wb");
    if (!f)
        return -1;
    int ok = (fwrite(buf, 1, n, f) == n) && (fclose(f) == 0);
    if (!ok) {
        fclose(f);
        remove(tmp);
        return -1;
    }
    if (rename(tmp, abs) != 0) {
        remove(tmp);
        return -1;
    }
    return 0;
}

int crypto_cifrar_archivo(const char *abs)
{
    unsigned char *pt = NULL;
    size_t n = 0;
    if (leer_archivo(abs, &pt, &n) != 0)
        return -1;

    if (n >= CIFR_MAGIC_LEN && memcmp(pt, MAGIC, CIFR_MAGIC_LEN) == 0) {
        free(pt);
        return 1; /* ya estaba cifrado */
    }

    unsigned char *blob = NULL;
    size_t blobn = 0;
    int r = crypto_cifrar_buf(pt, n, CIFR_FLAG_ARCHIVO, &blob, &blobn);
    free(pt);
    if (r != 0)
        return -1;
    r = escribir_atomico(abs, blob, blobn);
    free(blob);
    return r == 0 ? 0 : -1;
}

int crypto_descifrar_archivo(const char *abs)
{
    unsigned char *blob = NULL;
    size_t blobn = 0;
    if (leer_archivo(abs, &blob, &blobn) != 0)
        return -1;
    unsigned char *pt = NULL;
    size_t ptn = 0;
    int r = crypto_descifrar_buf(blob, blobn, CIFR_FLAG_ARCHIVO, &pt, &ptn);
    free(blob);
    if (r != 0)
        return -1;
    r = escribir_atomico(abs, pt, ptn);
    free(pt);
    return r == 0 ? 0 : -1;
}

int crypto_archivo_es_cifrado(const char *abs)
{
    FILE *f = fopen(abs, "rb");
    if (!f)
        return -1;
    unsigned char head[CIFR_MAGIC_LEN];
    size_t n = fread(head, 1, sizeof head, f);
    fclose(f);
    if (n != sizeof head)
        return 0;
    return memcmp(head, MAGIC, CIFR_MAGIC_LEN) == 0 ? 1 : 0;
}

/* ------------------------------------------------------------- Selftest */

static int st_roundtrip_buf(void)
{
    unsigned char pt[2048];
    for (size_t i = 0; i < sizeof pt; i++)
        pt[i] = (unsigned char)(i * 7 + 3);

    unsigned char *blob = NULL, *out = NULL;
    size_t blobn = 0, outn = 0;
    if (crypto_cifrar_buf(pt, sizeof pt, CIFR_FLAG_ARCHIVO, &blob, &blobn) != 0)
        return -1;
    if (blobn != CIFR_HDR_LEN + sizeof pt || memcmp(blob, MAGIC, CIFR_MAGIC_LEN) != 0) {
        free(blob);
        return -1;
    }
    if (crypto_descifrar_buf(blob, blobn, CIFR_FLAG_ARCHIVO, &out, &outn) != 0) {
        free(blob);
        return -1;
    }
    int ok = (outn == sizeof pt && memcmp(out, pt, outn) == 0);

    /* Tamper: corromper un byte del ciphertext debe invalidar el tag. */
    if (ok) {
        blob[CIFR_HDR_LEN + 10] ^= 0x40;
        unsigned char *x = NULL;
        size_t xn = 0;
        if (crypto_descifrar_buf(blob, blobn, CIFR_FLAG_ARCHIVO, &x, &xn) == 0)
            ok = 0;
        free(x);
        blob[CIFR_HDR_LEN + 10] ^= 0x40;
    }
    /* Flags equivocados deben rechazar el blob. */
    if (ok) {
        unsigned char *x = NULL;
        size_t xn = 0;
        if (crypto_descifrar_buf(blob, blobn, CIFR_FLAG_MANIFEST, &x, &xn) == 0)
            ok = 0;
        free(x);
    }

    free(blob);
    free(out);
    return ok ? 0 : -1;
}

static int st_roundtrip_vacio(void)
{
    unsigned char *blob = NULL, *out = NULL;
    size_t blobn = 0, outn = 0;
    if (crypto_cifrar_buf((const unsigned char *)"", 0, CIFR_FLAG_ARCHIVO, &blob, &blobn) != 0)
        return -1;
    int r = crypto_descifrar_buf(blob, blobn, CIFR_FLAG_ARCHIVO, &out, &outn);
    int ok = (r == 0 && outn == 0);
    free(blob);
    free(out);
    return ok ? 0 : -1;
}

static int st_nombres(void)
{
    const char *casos[] = { "archivo.txt", "m", "abcdefgh1234", "db.json" };
    for (size_t i = 0; i < sizeof casos / sizeof *casos; i++) {
        char enc[512], claro[512];
        if (crypto_nombre_cifrar(casos[i], enc, sizeof enc) != 0)
            return -1;
        if (strlen(enc) > NOMBRE_MAX)
            return -1;
        if (crypto_nombre_descifrar(enc, claro, sizeof claro) != 0)
            return -1;
        if (strcmp(claro, casos[i]) != 0)
            return -1;
    }
    return 0;
}

static int st_sha(void)
{
    /* vector conocido: sha256("abc") */
    unsigned char h[CIFR_SHA_LEN];
    if (crypto_sha256((const unsigned char *)"abc", 3, h) != 0)
        return -1;
    static const unsigned char esperado[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    return memcmp(h, esperado, sizeof h) == 0 ? 0 : -1;
}

int crypto_selftest(void)
{
    struct { const char *nom; int (*fn)(void); } pruebas[] = {
        { "AES-256-GCM round-trip + tamper", st_roundtrip_buf },
        { "AES-256-GCM buffer vacío",        st_roundtrip_vacio },
        { "Nombres cifrados (base64url)",    st_nombres },
        { "SHA-256 vector conocido",          st_sha },
    };
    int fallos = 0;
    for (size_t i = 0; i < sizeof pruebas / sizeof *pruebas; i++) {
        int r = pruebas[i].fn();
        printf("  [%s] %s\n", r == 0 ? "OK  " : "FALLO", pruebas[i].nom);
        if (r != 0)
            fallos++;
    }
    return fallos == 0 ? 0 : 1;
}
