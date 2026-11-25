/*
 * rng.h — Utilidades de probabilidad aleatoria para la generación.
 */
#ifndef CIFRAR_RNG_H
#define CIFRAR_RNG_H

#include <stddef.h>

int rng_iniciar(void);

/* Entero en [lo, hi] inclusivo. */
long rng_entre(long lo, long hi);

/* Palabra aleatoria de minlen..maxlen caracteres [a-z]. Devuelve la longitud. */
size_t rng_palabra(char *out, size_t outsz, size_t minlen, size_t maxlen);

/* Texto imprimible aleatorio (letras, dígitos, espacios y saltos). */
void rng_texto(char *out, size_t n);

/* Extensión aleatoria de una lista fija (sin punto). */
const char *rng_extension(void);

#endif /* CIFRAR_RNG_H */
