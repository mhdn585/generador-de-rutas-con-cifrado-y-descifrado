/*
 * inventory.h — Inventario en RAM del material generado por el programa.
 * Se serializa (y cifra) como manifest en el directorio del ejecutable.
 */
#ifndef CIFRAR_INVENTORY_H
#define CIFRAR_INVENTORY_H

#include <stdbool.h>
#include <stddef.h>

#include "crypto.h"

typedef enum { INV_DIR, INV_FILE } inv_tipo;

typedef struct {
    char *rel;       /* ruta relativa original (desde el dir del ejecutable) */
    char *enc_base;  /* componente final del nombre cifrado ("".enc") */
    inv_tipo tipo;
    long long size;              /* bytes del contenido en claro */
    unsigned char sha[CIFR_SHA_LEN]; /* SHA-256 del contenido en claro */
    int nivel;                   /* nº de componentes de la ruta */
} inv_node;

typedef struct {
    inv_node *it;
    size_t n, cap;
} inventory;

void inv_inicializar(inventory *inv);
void inv_liberar(inventory *inv);

/* Añade (o devuelve si ya existe) el nodo para rel. */
inv_node *inv_agregar(inventory *inv, const char *rel, inv_tipo tipo);
inv_node *inv_buscar(inventory *inv, const char *rel);

int inv_contar(const inventory *inv, inv_tipo tipo);

/* Ordena por nivel (descendente = hijos antes que padres). */
void inv_ordenar_por_nivel(inventory *inv, bool descendente);

/*
 * Compone el nombre cifrado (crypto_nombre_cifrar) para cada componente
 * de cada ruta. Necesario antes de escribir el manifest y renombrar.
 */
int inv_componer_nombres_cifrados(inventory *inv);

/* Ruta relativa completamente cifrada de un nodo (encadenando enc_base). */
int inv_ruta_enc_rel(const inventory *inv, const inv_node *nd, char *out, size_t outsz);

/* Serialización binaria (para manifest). malloc en *buf. */
int inv_serializar(const inventory *inv, unsigned char **buf, size_t *n);
int inv_deserializar(inventory *inv, const unsigned char *buf, size_t n);

#endif /* CIFRAR_INVENTORY_H */
