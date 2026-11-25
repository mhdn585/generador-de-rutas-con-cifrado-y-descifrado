/*
 * fs_guard.c — Resolución del directorio del ejecutable, validación de
 * contención de rutas y purga segura del material generado.
 */
#include "fs_guard.h"

#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char g_dir[RUTA_MAX];

int fs_guard_iniciar(void)
{
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    char *d = dirname(buf);
    if (!d || !realpath(d, g_dir))
        return -1;

    /* Por seguridad el programa se niega a operar directamente en la raíz. */
    if (strcmp(g_dir, "/") == 0)
        return -2;
    return 0;
}

const char *fs_guard_dir(void)
{
    return g_dir;
}

/* Une exe_dir + rel normalizando componentes. Rechaza absolutos, ".." y vacíos. */
int fs_guard_ruta(const char *rel, char *out, size_t outsz)
{
    if (!rel || !*rel || rel[0] == '/')
        return -1;

    char norm[RUTA_MAX];
    size_t oi = 0;
    const char *p = rel;

    while (*p) {
        const char *s = p;
        while (*p && *p != '/')
            p++;
        size_t len = (size_t) (p - s);

        if (len == 0 || (len == 1 && s[0] == '.')) {
            /* componente redundante: se omite */
        } else if (len == 2 && s[0] == '.' && s[1] == '.') {
            return -1; /* trayecto fuera del directorio raíz */
        } else {
            if (oi + len + 2 >= sizeof norm)
                return -1;
            norm[oi++] = '/';
            memcpy(norm + oi, s, len);
            oi += len;
        }
        if (*p == '/')
            p++;
    }
    if (oi == 0)
        return -1;
    norm[oi] = '\0';

    int r = snprintf(out, outsz, "%s%s", g_dir, norm);
    if (r < 0 || (size_t) r >= outsz)
        return -1;
    return 0;
}

int fs_guard_contiene(const char *abs)
{
    char rp[PATH_MAX];
    if (!realpath(abs, rp))
        return errno == ENOENT ? 0 : -1;
    size_t dl = strlen(g_dir);
    return (strncmp(rp, g_dir, dl) == 0 && rp[dl] == '/') ? 1 : 0;
}

int fs_guard_mkdir(const char *rel, const char *abs)
{
    if (mkdir(abs, 0755) != 0)
        return -1;

    /* Verificación de seguridad: la ruta creada debe resolverse DENTRO de
     * exe_dir y coincidir exactamente (ni symlinks ni salidas laterales). */
    char rp[PATH_MAX];
    if (!realpath(abs, rp)) {
        (void) rel;
        rmdir(abs);
        return -2;
    }
    if (strcmp(rp, abs) != 0 || fs_guard_contiene(rp) != 1) {
        rmdir(abs);
        return -2; /* ruta por debajo/fuera del directorio raíz */
    }
    return 0;
}

/* Candidatos de borrado: ruta en claro y ruta cifrada de cada nodo. */
typedef struct {
    char abs[RUTA_MAX];
    int nivel;
    inv_tipo tipo;
} candidato_t;

static int cmp_cand_desc(const void *a, const void *b)
{
    const candidato_t *x = a, *y = b;
    if (x->nivel != y->nivel)
        return y->nivel - x->nivel; /* profundo primero */
    return strcmp(y->abs, x->abs);
}

int fs_guard_purgar(const inventory *inv, bool borrar_manifest)
{
    inventory copia;
    inv_inicializar(&copia);
    for (size_t i = 0; i < inv->n; i++) {
        inv_node *nd = inv_agregar(&copia, inv->it[i].rel, inv->it[i].tipo);
        if (!nd) {
            inv_liberar(&copia);
            return -1;
        }
        if (inv->it[i].enc_base)
            nd->enc_base = strdup(inv->it[i].enc_base);
    }

    candidato_t *cands = calloc(copia.n * 2 + 1, sizeof *cands);
    if (!cands) {
        inv_liberar(&copia);
        return -1;
    }
    size_t nc = 0;

    for (size_t i = 0; i < copia.n; i++) {
        inv_node *nd = &copia.it[i];
        char abs[RUTA_MAX];
        /* variante en claro */
        if (fs_guard_ruta(nd->rel, abs, sizeof abs) == 0) {
            snprintf(cands[nc].abs, RUTA_MAX, "%s", abs);
            cands[nc].nivel = nd->nivel;
            cands[nc].tipo = nd->tipo;
            nc++;
        }
        /* variante cifrada (si el nodo ya tenía nombre cifrado compuesto) */
        if (nd->enc_base) {
            char encrel[RUTA_MAX];
            if (inv_ruta_enc_rel(&copia, nd, encrel, sizeof encrel) == 0 &&
                fs_guard_ruta(encrel, abs, sizeof abs) == 0) {
                snprintf(cands[nc].abs, RUTA_MAX, "%s", abs);
                cands[nc].nivel = nd->nivel;
                cands[nc].tipo = nd->tipo;
                nc++;
            }
        }
    }

    qsort(cands, nc, sizeof *cands, cmp_cand_desc);

    int borrados = 0, inseguras = 0;
    for (size_t i = 0; i < nc; i++) {
        /* Última barrera: jamás borrar fuera de exe_dir. */
        char rp[PATH_MAX];
        if (realpath(cands[i].abs, rp)) {
            if (fs_guard_contiene(rp) != 1) {
                fprintf(stderr,
                        "SEGURIDAD: ruta fuera del directorio del programa: %s\n", rp);
                inseguras++;
                continue;
            }
        } else if (errno == ENOENT) {
            continue; /* ya no existe */
        }

        int r;
        if (cands[i].tipo == INV_FILE)
            r = unlink(cands[i].abs);
        else
            r = rmdir(cands[i].abs);
        if (r == 0)
            borrados++;
        else if (errno != ENOENT && errno != ENOTDIR && errno != EISDIR)
            fprintf(stderr, "aviso: no se pudo eliminar %s: %s\n",
                    cands[i].abs, strerror(errno));
    }

    if (borrar_manifest) {
        char man[RUTA_MAX];
        if (fs_guard_ruta(NOMBRE_MANIFEST, man, sizeof man) == 0) {
            if (unlink(man) == 0)
                borrados++;
            else if (errno != ENOENT)
                fprintf(stderr, "aviso: no se pudo eliminar el manifest\n");
        }
    }

    free(cands);
    inv_liberar(&copia);
    return inseguras ? -1 : borrados;
}
