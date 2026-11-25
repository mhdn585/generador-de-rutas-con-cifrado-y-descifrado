/*
 * generator.c — Creación aleatoria del árbol con mkdir() y fopen().
 */
#include "generator.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fs_guard.h"
#include "rng.h"

#define MAX_NOMBRE_COMP 48 /* holgado frente al límite real de ~64 chars cifrados */

static int crear_archivo(inventory *inv, const char *dir_rel)
{
    char nombre[64];
    char base[32];
    rng_palabra(base, sizeof base, 6, 12);

    const char *ext = rng_extension();
    if (snprintf(nombre, sizeof nombre, "%s.%s", base, ext) >= (int) sizeof nombre)
        return -1;

    char rel[RUTA_MAX];
    if (snprintf(rel, sizeof rel, "%s/%s", dir_rel, nombre) >= (int) sizeof rel)
        return -1;
    if (inv_buscar(inv, rel))
        return 0; /* colisión de nombre: ya existe, se omite */

    char abs[RUTA_MAX];
    if (fs_guard_ruta(rel, abs, sizeof abs) != 0)
        return -2;

    size_t n = (size_t) rng_entre(1024, 5120); /* 1-5 KB */
    char *contenido = malloc(n + 1);
    if (!contenido)
        return -1;
    rng_texto(contenido, n);
    contenido[n] = '\0';

    FILE *f = fopen(abs, "w");
    if (!f) {
        free(contenido);
        return -1;
    }
    int ok = fwrite(contenido, 1, n, f) == n;
    if (fclose(f) != 0)
        ok = 0;
    if (!ok) {
        remove(abs);
        free(contenido);
        return -1;
    }

    inv_node *nd = inv_agregar(inv, rel, INV_FILE);
    if (!nd) {
        free(contenido);
        return -1;
    }
    nd->size = (long long) n;
    crypto_sha256((const unsigned char *) contenido, n, nd->sha);
    free(contenido);
    return 0;
}

static int crear_directorio(inventory *inv, const char *padre_rel, const char *nombre,
                            char *out_rel, size_t outsz)
{
    int r0;
    if (padre_rel && *padre_rel)
        r0 = snprintf(out_rel, outsz, "%s/%s", padre_rel, nombre);
    else
        r0 = snprintf(out_rel, outsz, "%s", nombre);
    if (r0 < 0 || r0 >= (int) outsz)
        return -1;

    char abs[RUTA_MAX];
    if (fs_guard_ruta(out_rel, abs, sizeof abs) != 0)
        return -2;

    int r = fs_guard_mkdir(out_rel, abs);
    if (r == -2) {
        fprintf(stderr, "SEGURIDAD: se detectó una ruta fuera del directorio "
                        "del programa (%s)\n", out_rel);
        return -2;
    }
    if (r != 0 && errno != EEXIST)
        return -1;

    if (!inv_agregar(inv, out_rel, INV_DIR))
        return -1;
    return 0;
}

/*
 * Crea `nivel_max` niveles anidados bajo raiz_rel: en cada directorio
 * genera 2-8 archivos y 1-2 subdirectorios; además 0-1 "sucursales hoja".
 */
static int crear_rama(inventory *inv, const char *padre_rel, int nivel, int nivel_max)
{
    int nf = (int) rng_entre(2, 8);
    for (int i = 0; i < nf; i++) {
        int r = crear_archivo(inv, padre_rel);
        if (r < 0)
            return r;
    }
    if (nivel >= nivel_max)
        return 0;

    int ns = (int) rng_entre(1, 2);
    for (int i = 0; i < ns; i++) {
        char nombre[32];
        rng_palabra(nombre, sizeof nombre, 6, 12);
        char rel[RUTA_MAX];
        int r = crear_directorio(inv, padre_rel, nombre, rel, sizeof rel);
        if (r < 0)
            return r;
        r = crear_rama(inv, rel, nivel + 1, nivel_max);
        if (r < 0)
            return r;
    }
    /* sucursal adicional superficial para dar anchura al árbol */
    if (rng_entre(0, 1) == 1) {
        char nombre[32];
        rng_palabra(nombre, sizeof nombre, 6, 12);
        char rel[RUTA_MAX];
        int r = crear_directorio(inv, padre_rel, nombre, rel, sizeof rel);
        if (r < 0)
            return r;
        int nf2 = (int) rng_entre(1, 4);
        for (int i = 0; i < nf2; i++) {
            r = crear_archivo(inv, rel);
            if (r < 0)
                return r;
        }
    }
    return 0;
}

int generador_generar(inventory *inv)
{
    int raices = (int) rng_entre(2, 4);

    for (int i = 0; i < raices; i++) {
        char nombre[24];
        rng_palabra(nombre, sizeof nombre, 6, 12);
        /* prefijo breve para distinguir raíces del programa (se cifrará igual) */
        char con_prefijo[32];
        snprintf(con_prefijo, sizeof con_prefijo, "r%.20s", nombre);

        if (crear_directorio(inv, "", con_prefijo, nombre, sizeof nombre) == -2)
            return -2;

        int profundidad = (int) rng_entre(3, 5);
        int r = crear_rama(inv, nombre, 1, profundidad);
        if (r < 0)
            return r;
    }
    return 0;
}
