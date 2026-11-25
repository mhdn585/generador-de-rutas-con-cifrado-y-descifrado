/*
 * scanner.h — Recorrido del material generado con nftw(), leyendo cada
 * directorio con opendir()/readdir() (nombres y extensiones).
 */
#ifndef CIFRAR_SCANNER_H
#define CIFRAR_SCANNER_H

#include <stdbool.h>

#include "inventory.h"

/*
 * Recorre con nftw() los directorios raíz del inventario (en claro o
 * cifrados según el caso) y acumula en inv_desc lo encontrado, usando
 * readdir() para leer cada directorio. 0 = ok, -1 = error.
 */
int escaner_escanear(const inventory *raices, bool usar_cifradas, inventory *inv_desc);

/*
 * Contrasta inventario esperado vs. descubierto.
 *  faltantes  : nodos del esperado no hallados en disco
 *  ajenos     : hallados dentro de nuestras raíces pero no en el esperado
 * Devuelve el nº de discrepancias (0 = consistente).
 */
int escaner_contrastar(const inventory *esperado, const inventory *descubierto,
                       size_t *faltantes, size_t *ajenos);

/* Verifica que todos los archivos estén realmente cifrados (magic header).
 * *ok / *mal reciben conteos. 0 = todo cifrado. */
int escaner_verificar_cifrado(const inventory *inv, size_t *ok, size_t *mal);

/* Verifica que todo esté realmente en claro y que ningún nombre cifrado
 * subsista. *ok / *mal reciben conteos. 0 = todo en claro. */
int escaner_verificar_claro(const inventory *inv, size_t *ok, size_t *mal);

/* Symlinks u otros tipos sospechosos hallados dentro del territorio del
 * programa en el último escaneo. */
int escaner_ajenos_tipo(void);

#endif /* CIFRAR_SCANNER_H */
