/*
 * crypto.h — Cifrado AES-256-GCM con OpenSSL (EVP API).
 *
 * Formato de blob cifrado (archivos y manifest):
 *   MAGIC "CIFR1" (5B) | flags (1B) | IV (12B) | tag GCM (16B) | ciphertext (nB)
 *
 * Nombres cifrados: base64url( IV | tag | ciphertext(nombre) ) + ".enc"
 */
#ifndef CIFRAR_CRYPTO_H
#define CIFRAR_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>

/* Clave fija embebida: 32 caracteres ASCII = 32 bytes (AES-256). */
#define CLAVE_AES "12345678901234567890123456789012"

#define CIFR_MAGIC      "CIFR1"
#define CIFR_MAGIC_LEN  5
#define CIFR_IV_LEN     12
#define CIFR_TAG_LEN    16
#define CIFR_HDR_LEN    (CIFR_MAGIC_LEN + 1 + CIFR_IV_LEN + CIFR_TAG_LEN)
#define CIFR_SHA_LEN    32
#define CIFR_SUFJO      ".enc"

#define CIFR_FLAG_ARCHIVO   1u
#define CIFR_FLAG_MANIFEST  2u

int  crypto_iniciar(void);
void crypto_terminar(void);

/* Hash SHA-256 de un buffer en memoria. */
int crypto_sha256(const unsigned char *datos, size_t n, unsigned char out[CIFR_SHA_LEN]);

/* Nivel buffer: *blob / *pt quedan asignados con malloc. 0 = ok, -1 = error. */
int crypto_cifrar_buf(const unsigned char *pt, size_t n, unsigned char flags,
                      unsigned char **blob, size_t *blob_n);
int crypto_descifrar_buf(const unsigned char *blob, size_t n, unsigned char esperado_flags,
                         unsigned char **pt, size_t *pt_n);

/* Validación sin escribir nada (dry-run): 0 = blob válido y auténtico. */
int crypto_blob_valido(const unsigned char *blob, size_t n, unsigned char esperado_flags);

/* Archivos: cifrado/descifrado en claro (escritura atómica tmp+rename). */
int crypto_cifrar_archivo(const char *abs);      /* 0 ok, 1 ya cifrado, -1 error */
int crypto_descifrar_archivo(const char *abs);   /* 0 ok, -1 error */
int crypto_archivo_es_cifrado(const char *abs);  /* 1 sí, 0 no, -1 error */

/* Nombres: devuelven 0 y dejan en out el nombre cifrado/descifrado. */
int crypto_nombre_cifrar(const char *nombre, char *out, size_t outsz);
int crypto_nombre_descifrar(const char *enc, char *out, size_t outsz);

/* Auto-pruebas (round-trip, tamper, base64url, SHA). 0 = todo OK. */
int crypto_selftest(void);

#endif /* CIFRAR_CRYPTO_H */
