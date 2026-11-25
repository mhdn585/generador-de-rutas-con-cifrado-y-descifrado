/*
 * fs_guard.h — Seguridad de rutas: toda operación queda confinada al
 * directorio del ejecutable. Incluye la purga segura del material generado.
 */
#ifndef CIFRAR_FS_GUARD_H
#define CIFRAR_FS_GUARD_H

#include <stdbool.h>
#include <stddef.h>

#include "inventory.h"

#define RUTA_MAX       4096
#define NOMBRE_MANIFEST ".cifrar.manifest"

/* Resuelve el directorio del ejecutable vía /proc/self/exe + realpath. 0 = ok. */
int fs_guard_iniciar(void);

/* Directorio absoluto del ejecutable (sin barra final). */
const char *fs_guard_dir(void);

/* Une exe_dir + rel de forma segura (rechaza absolutos, ".", ".."). 0 = ok. */
int fs_guard_ruta(const char *rel, char *out, size_t outsz);

/* 1 si abs (resuelto con realpath) está dentro de exe_dir, 0 si no, -1 error. */
int fs_guard_contiene(const char *abs);

/* mkdir + verificación de contención (realpath debe coincidir exactamente). */
int fs_guard_mkdir(const char *rel, const char *abs);

/*
 * Purga SOLO rutas registradas en el inventario (nombres en claro y cifrados),
 * de más profundas a menos. Nunca borra nada fuera de exe_dir.
 * Devuelve nº de entradas borradas o -1 si se detectó una ruta insegura.
 */
int fs_guard_purgar(const inventory *inv, bool borrar_manifest);

#endif /* CIFRAR_FS_GUARD_H */
