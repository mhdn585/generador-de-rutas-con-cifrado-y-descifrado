/*
 * scanner.c — Recorrido con nftw(); lectura de cada directorio con
 * opendir()/readdir() (nombres y extensiones), llenando el inventario RAM.
 */
#include "scanner.h"

#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "fs_guard.h"

typedef struct {
    inventory *desc;         /* todo lo descubierto (rel a exe_dir) */
    const inventory *esperado;
    char base[RUTA_MAX];     /* exe_dir */
    size_t baselen;
    int err;
    int ajenos_tipos;        /* symlinks u otros tipos dentro de nuestro territorio */
} scan_ctx;

static scan_ctx g_ctx;

/* ¿Es parte de la gestoría del programa (manifest o temporales)? */
static int es_gestoria(const char *nombre)
{
    return strncmp(nombre, NOMBRE_MANIFEST, sizeof NOMBRE_MANIFEST - 1) == 0 ||
           strstr(nombre, ".cifrar.tmp") != NULL;
}

/* ¿rel es una ruta reconocida: registrada en claro o nombre cifrado que,
 * al descifrarse componente a componente (clave embebida), coincide con
 * una ruta del inventario? */
static int esperado_reconoce(const inventory *esp, const char *rel)
{
    if (inv_buscar((inventory *) esp, rel))
        return 1;

    char claro[RUTA_MAX];
    size_t o = 0;
    const char *p = rel;
    while (*p) {
        const char *s = p;
        while (*p && *p != '/')
            p++;
        size_t l = (size_t) (p - s);
        char comp[512], dec[512];
        if (l == 0 || l >= sizeof comp)
            return 0;
        memcpy(comp, s, l);
        comp[l] = '\0';
        if (crypto_nombre_descifrar(comp, dec, sizeof dec) != 0)
            return 0;
        int r = snprintf(claro + o, sizeof claro - o, o ? "/%s" : "%s", dec);
        if (r < 0 || o + (size_t) r >= sizeof claro)
            return 0;
        o += (size_t) r;
        if (*p == '/')
            p++;
    }
    claro[o] = '\0';
    return inv_buscar((inventory *) esp, claro) != NULL;
}

/* ¿rel cuelga de alguna raíz del inventario (en claro o cifrada)? */
static int bajo_raiz_propia(const inventory *esp, const char *rel)
{
    for (size_t i = 0; i < esp->n; i++) {
        const inv_node *nd = &esp->it[i];
        if (nd->nivel != 1 || nd->tipo != INV_DIR)
            continue;
        size_t l = strlen(nd->rel);
        if (strncmp(rel, nd->rel, l) == 0 && (rel[l] == '/' || rel[l] == '\0'))
            return 1;
        if (nd->enc_base) {
            size_t el = strlen(nd->enc_base);
            if (strncmp(rel, nd->enc_base, el) == 0 && rel[el] == '/')
                return 1;
        }
    }
    return 0;
}

/* Leer un directorio con readdir(): registra nombres (y por tanto extensiones). */
static void leer_con_readdir(scan_ctx *cx, const char *dir_abs, const char *dir_rel)
{
    DIR *dp = opendir(dir_abs);
    if (!dp) {
        cx->err = 1;
        return;
    }
    struct dirent *e;
    errno = 0;
    while ((e = readdir(dp)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0 ||
            es_gestoria(e->d_name))
            continue;

        char rel[RUTA_MAX];
        int r;
        if (dir_rel[0] == '\0')
            r = snprintf(rel, sizeof rel, "%s", e->d_name);
        else
            r = snprintf(rel, sizeof rel, "%s/%s", dir_rel, e->d_name);
        if (r < 0 || r >= (int) sizeof rel)
            continue;

        inv_tipo t;
        if (e->d_type == DT_DIR)
            t = INV_DIR;
        else if (e->d_type == DT_REG)
            t = INV_FILE;
        else {
            /* symlink u otros tipos: marcar como ajeno sospechoso */
            t = INV_FILE;
            char full[RUTA_MAX];
            struct stat st;
            snprintf(full, sizeof full, "%s/%s", dir_abs, e->d_name);
            if (lstat(full, &st) == 0 && !S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))
                cx->ajenos_tipos++;
        }
        if (!inv_buscar(cx->desc, rel) && !inv_agregar(cx->desc, rel, t))
            cx->err = 1;
    }
    if (errno != 0)
        cx->err = 1;
    closedir(dp);
}

static int scan_cb(const char *fpath, const struct stat *sb, int tipo, struct FTW *ftwbuf)
{
    (void) sb;
    (void) ftwbuf;

    if (tipo == FTW_NS || tipo == FTW_DNR) {
        if (tipo == FTW_DNR)
            fprintf(stderr, "error: no se puede leer el directorio %s\n", fpath);
        g_ctx.err = 1;
        return 0;
    }
    if (strlen(fpath) < g_ctx.baselen)
        return 0;
    const char *rel = fpath + g_ctx.baselen + 1;
    if (strcmp(rel, ".") == 0 || es_gestoria(rel))
        return 0;

    inv_tipo t = (tipo == FTW_D) ? INV_DIR : INV_FILE;
    if (!inv_buscar(g_ctx.desc, rel) && !inv_agregar(g_ctx.desc, rel, t))
        g_ctx.err = 1;

    if (tipo == FTW_D)
        leer_con_readdir(&g_ctx, fpath, rel);
    return 0;
}

int escaner_escanear(const inventory *raices, bool usar_cifradas, inventory *inv_desc)
{
    (void) usar_cifradas;
    memset(&g_ctx, 0, sizeof g_ctx);
    g_ctx.desc = inv_desc;
    g_ctx.esperado = raices;
    snprintf(g_ctx.base, sizeof g_ctx.base, "%s", fs_guard_dir());
    g_ctx.baselen = strlen(g_ctx.base);

    /* nftw FTW_PHYS: nunca sigue symlinks plantados. */
    if (nftw(g_ctx.base, scan_cb, 12, FTW_PHYS) != 0)
        g_ctx.err = 1;
    return g_ctx.err ? -1 : 0;
}

int escaner_ajenos_tipo(void)
{
    return g_ctx.ajenos_tipos;
}

int escaner_contrastar(const inventory *esperado, const inventory *descubierto,
                       size_t *faltantes, size_t *ajenos)
{
    size_t falt = 0, ajen = 0;

    for (size_t i = 0; i < esperado->n; i++) {
        const inv_node *nd = &esperado->it[i];
        if (inv_buscar((inventory *) descubierto, nd->rel))
            continue;
        char encrel[RUTA_MAX];
        if (nd->enc_base &&
            inv_ruta_enc_rel(esperado, nd, encrel, sizeof encrel) == 0 &&
            inv_buscar((inventory *) descubierto, encrel))
            continue;
        falt++;
    }
    for (size_t i = 0; i < descubierto->n; i++) {
        const char *rel = descubierto->it[i].rel;
        if (!esperado_reconoce(esperado, rel) && bajo_raiz_propia(esperado, rel))
            ajen++;
    }
    if (faltantes)
        *faltantes = falt;
    if (ajenos)
        *ajenos = ajen;
    return (int) (falt + ajen);
}

/* ------------------------------------------- verificación de estados */

static int ruta_existe(const char *rel)
{
    char abs[RUTA_MAX];
    if (fs_guard_ruta(rel, abs, sizeof abs) != 0)
        return 0;
    return access(abs, F_OK) == 0;
}

static int ruta_enc_existe(const inventory *inv, const inv_node *nd)
{
    char encrel[RUTA_MAX];
    if (!nd->enc_base || inv_ruta_enc_rel(inv, nd, encrel, sizeof encrel) != 0)
        return 0;
    return ruta_existe(encrel);
}

int escaner_verificar_cifrado(const inventory *inv, size_t *ok, size_t *mal)
{
    size_t n_ok = 0, n_mal = 0;

    for (size_t i = 0; i < inv->n; i++) {
        const inv_node *nd = &inv->it[i];
        char encrel[RUTA_MAX];
        if (!nd->enc_base || inv_ruta_enc_rel(inv, nd, encrel, sizeof encrel) != 0 ||
            !ruta_existe(encrel)) {
            n_mal++;
            continue;
        }
        if (nd->tipo == INV_FILE) {
            char abs[RUTA_MAX];
            if (fs_guard_ruta(encrel, abs, sizeof abs) != 0 ||
                crypto_archivo_es_cifrado(abs) != 1) {
                n_mal++;
                continue;
            }
        }
        if (ruta_existe(nd->rel)) {
            n_mal++; /* el nombre original debería haber desaparecido */
            continue;
        }
        n_ok++;
    }
    if (ok)
        *ok = n_ok;
    if (mal)
        *mal = n_mal;
    return n_mal == 0 ? 0 : -1;
}

int escaner_verificar_claro(const inventory *inv, size_t *ok, size_t *mal)
{
    size_t n_ok = 0, n_mal = 0;

    for (size_t i = 0; i < inv->n; i++) {
        const inv_node *nd = &inv->it[i];
        if (!ruta_existe(nd->rel)) {
            n_mal++;
            continue;
        }
        if (nd->tipo == INV_FILE) {
            char abs[RUTA_MAX];
            if (fs_guard_ruta(nd->rel, abs, sizeof abs) != 0 ||
                crypto_archivo_es_cifrado(abs) != 0) {
                n_mal++;
                continue;
            }
        }
        if (ruta_enc_existe(inv, nd)) {
            n_mal++; /* algún nombre cifrado subsiste */
            continue;
        }
        n_ok++;
    }
    if (ok)
        *ok = n_ok;
    if (mal)
        *mal = n_mal;
    return n_mal == 0 ? 0 : -1;
}
