/*
 * generator.h — Generación aleatoria de rutas: mkdir() para directorios,
 * fopen() para archivos. Todo queda registrado en el inventario.
 */
#ifndef CIFRAR_GENERATOR_H
#define CIFRAR_GENERATOR_H

#include "inventory.h"

/*
 * Genera el árbol aleatorio (2-4 raíces, profundidad 3-5, 2-8 archivos por
 * directorio, texto aleatorio de 1-5 KB) dentro del directorio del
 * ejecutable y lo registra en inv.
 * 0 = ok, -1 = error de E/S, -2 = RUTA INSEGURA detectada (abortar y purgar).
 */
int generador_generar(inventory *inv);

#endif /* CIFRAR_GENERATOR_H */
