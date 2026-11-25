/*
 * main.c — Máquina de estados del programa:
 *
 *   arranque: detecta si hay material (manifest) en claro, cifrado o mixto.
 *   generar -> escanear (nftw+readdir) -> confirmar -> cifrar | purgar.
 *   cifrado -> confirmar -> descifrar -> confirmar -> purgar opcional.
 *
 * Seguridad: todas las rutas se construyen desde el directorio del
 * ejecutable. Si algo se sale de él, se aborta y se purga TODO lo generado.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include "crypto.h"
#include "fs_guard.h"
#include "generator.h"
#include "inventory.h"
#include "rng.h"
#include "scanner.h"
#include "ui.h"

typedef enum { EST_NADA, EST_CLARO, EST_CIFRADO, EST_MIXTO, EST_ERROR } estado_t;

/* ------------------------------------------------------- utilidades ruta */

static int abs_de_rel(const char *rel, char *out, size_t outsz)
{
    return fs_guard_ruta(rel, out, outsz);
}

/* Ruta absoluta "padre-en-claro/enc_base": destino intermedio durante el
 * renombrado (los padres aún sin renombrar están en claro). */
static int abs_parojo(const inv_node *nd, char *out, size_t outsz)
{
    if (!nd->enc_base)
        return -1;
    char rel[RUTA_MAX];
    const char *slash = strrchr(nd->rel, '/');
    int r;
    if (slash)
        r = snprintf(rel, sizeof rel, "%.*s/%s", (int) (slash - nd->rel), nd->rel,
                     nd->enc_base);
    else
        r = snprintf(rel, sizeof rel, "%s", nd->enc_base);
    if (r < 0 || r >= (int) sizeof rel)
        return -1;
    return abs_de_rel(rel, out, outsz);
}

/* ------------------------------------------- transacciones con señales */

static void bloquear_interrupciones(sigset_t *old)
{
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGINT);
    sigaddset(&s, SIGTERM);
    sigprocmask(SIG_BLOCK, &s, old);
}

static void restaurar_interrupciones(const sigset_t *old)
{
    sigprocmask(SIG_SETMASK, old, NULL);
}

/* ------------------------------------------------------- manifest */

static int manifest_abs(char *out, size_t outsz)
{
    return abs_de_rel(NOMBRE_MANIFEST, out, outsz);
}

static int guardar_manifest(const inventory *inv)
{
    unsigned char *buf = NULL, *blob = NULL;
    size_t n = 0, blobn = 0;
    char abs[RUTA_MAX];

    if (inv_serializar(inv, &buf, &n) != 0)
        return -1;
    if (crypto_cifrar_buf(buf, n, CIFR_FLAG_MANIFEST, &blob, &blobn) != 0) {
        free(buf);
        return -1;
    }
    free(buf);

    if (manifest_abs(abs, sizeof abs) != 0) {
        free(blob);
        return -1;
    }
    char tmp[RUTA_MAX + 16];
    snprintf(tmp, sizeof tmp, "%s.cifrar.tmp", abs);
    FILE *f = fopen(tmp, "wb");
    if (!f) {
        free(blob);
        return -1;
    }
    int ok = fwrite(blob, 1, blobn, f) == blobn;
    if (fclose(f) != 0)
        ok = 0;
    free(blob);
    if (!ok || rename(tmp, abs) != 0) {
        remove(tmp);
        return -1;
    }
    return 0;
}

static int cargar_manifest(inventory *inv)
{
    char abs[RUTA_MAX];
    if (manifest_abs(abs, sizeof abs) != 0)
        return -1;
    FILE *f = fopen(abs, "rb");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -2;
    }
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 16 * 1024 * 1024) {
        fclose(f);
        return -2;
    }
    unsigned char *blob = malloc((size_t) sz);
    if (!blob) {
        fclose(f);
        return -2;
    }
    size_t leido = fread(blob, 1, (size_t) sz, f);
    fclose(f);
    if (leido != (size_t) sz) {
        free(blob);
        return -2;
    }
    unsigned char *pt = NULL;
    size_t ptn = 0;
    int r = crypto_descifrar_buf(blob, (size_t) sz, CIFR_FLAG_MANIFEST, &pt, &ptn);
    free(blob);
    if (r != 0) {
        free(pt);
        return -2; /* manifest corrupto o clave inválida */
    }
    r = inv_deserializar(inv, pt, ptn);
    free(pt);
    return r == 0 ? 0 : -2;
}

/* ------------------------------------------------ detección de estado */

static estado_t detectar_estado(inventory *inv)
{
    size_t claro = 0, enc = 0;
    for (size_t i = 0; i < inv->n; i++) {
        inv_node *nd = &inv->it[i];
        char abs[RUTA_MAX];
        if (abs_de_rel(nd->rel, abs, sizeof abs) == 0 && access(abs, F_OK) == 0)
            claro++;
        char encrel[RUTA_MAX];
        if (nd->enc_base && inv_ruta_enc_rel(inv, nd, encrel, sizeof encrel) == 0 &&
            access(encrel, F_OK) == 0)
            enc++;
    }
    if (claro == inv->n && enc == 0)
        return EST_CLARO;
    if (enc == inv->n && claro == 0)
        return EST_CIFRADO;
    if (claro == 0 && enc == 0)
        return EST_NADA; /* material externo borrado: manifest huérfano */
    return EST_MIXTO;
}

/* --------------------------------------------------------- verificación */

/* Contención: toda ruta del inventario debe resolver dentro de exe_dir. */
static int verificar_contencion(const inventory *inv)
{
    for (size_t i = 0; i < inv->n; i++) {
        char abs[RUTA_MAX];
        if (abs_de_rel(inv->it[i].rel, abs, sizeof abs) != 0) {
            fprintf(stderr, "SEGURIDAD: ruta inválida en inventario: %s\n", inv->it[i].rel);
            return -1;
        }
        char rp[RUTA_MAX];
        if (realpath(abs, rp)) {
            if (fs_guard_contiene(rp) != 1) {
                fprintf(stderr, "SEGURIDAD: la ruta escapa del directorio del "
                                "programa: %s\n", rp);
                return -1;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------ cifrado completo */

/* 0 = todo cifrado y verificado; -1 = fallo (el llamador decide purgar). */
static int cifrar_material(inventory *inv)
{
    sigset_t old;

    if (inv_componer_nombres_cifrados(inv) != 0) {
        fprintf(stderr, "error: no se pudieron componer los nombres cifrados\n");
        return -1;
    }
    /* El manifest se escribe ANTES de tocar el disco: es la fuente de
     * verdad para descifrar o completar tras una interrupción. */
    if (guardar_manifest(inv) != 0) {
        fprintf(stderr, "error: no se pudo escribir el manifest\n");
        return -1;
    }

    bloquear_interrupciones(&old);

    /* 1) contenido de los archivos (rutas en claro aún intactas) */
    for (size_t i = 0; i < inv->n; i++) {
        inv_node *nd = &inv->it[i];
        if (nd->tipo != INV_FILE)
            continue;
        char abs[RUTA_MAX];
        if (abs_de_rel(nd->rel, abs, sizeof abs) != 0) {
            restaurar_interrupciones(&old);
            return -1;
        }
        int r = crypto_cifrar_archivo(abs);
        if (r < 0) {
            fprintf(stderr, "error: fallo de E/S al cifrar %s\n", nd->rel);
            restaurar_interrupciones(&old);
            return -1;
        }
    }

    /* 2) renombrar archivos (padres aún en claro) */
    for (size_t i = 0; i < inv->n; i++) {
        inv_node *nd = &inv->it[i];
        if (nd->tipo != INV_FILE)
            continue;
        char de[RUTA_MAX], a[RUTA_MAX];
        if (abs_de_rel(nd->rel, de, sizeof de) != 0 || abs_parojo(nd, a, sizeof a) != 0) {
            restaurar_interrupciones(&old);
            return -1;
        }
        if (strcmp(de, a) == 0)
            continue;
        if (rename(de, a) != 0) {
            fprintf(stderr, "error: no se pudo renombrar %s\n", nd->rel);
            restaurar_interrupciones(&old);
            return -1;
        }
    }

    /* 3) renombrar directorios, de los más profundos a las raíces.
     * NOTA: orden comparte el array de inv (solo reordena; NO se libera). */
    inventory orden = *inv;
    inv_ordenar_por_nivel(&orden, true);
    for (size_t i = 0; i < orden.n; i++) {
        inv_node *nd = &orden.it[i];
        if (nd->tipo != INV_DIR)
            continue;
        char de[RUTA_MAX], a[RUTA_MAX];
        if (abs_de_rel(nd->rel, de, sizeof de) != 0 || abs_parojo(nd, a, sizeof a) != 0) {
            restaurar_interrupciones(&old);
            return -1;
        }
        if (strcmp(de, a) == 0)
            continue;
        if (rename(de, a) != 0) {
            fprintf(stderr, "error: no se pudo renombrar el directorio %s\n", nd->rel);
            restaurar_interrupciones(&old);
            return -1;
        }
    }

    restaurar_interrupciones(&old);

    /* 4) comprobar que TODO el material fue cifrado */
    size_t ok = 0, mal = 0;
    if (escaner_verificar_cifrado(inv, &ok, &mal) != 0) {
        fprintf(stderr, "error: verificación incompleta (%zu/%zu elementos ok)\n",
                ok, ok + mal);
        return -1;
    }
    printf("Cifrado verificado: %zu elementos (archivos con contenido cifrado,\n"
           "nombres renombrados con .enc).\n", ok);
    return 0;
}

/* ------------------------------------------------------ descifrado */

static int validar_descifrado_previo(const inventory *inv)
{
    for (size_t i = 0; i < inv->n; i++) {
        const inv_node *nd = &inv->it[i];
        if (nd->tipo != INV_FILE)
            continue;
        char encrel[RUTA_MAX];
        if (!nd->enc_base || inv_ruta_enc_rel(inv, nd, encrel, sizeof encrel) != 0)
            return -1;
        char abs[RUTA_MAX];
        if (abs_de_rel(encrel, abs, sizeof abs) != 0)
            return -1;
        /* leer + validar tag sin escribir nada */
        FILE *f = fopen(abs, "rb");
        if (!f)
            return -1;
        if (fseek(f, 0, SEEK_END) != 0) {
            fclose(f);
            return -1;
        }
        long sz = ftell(f);
        rewind(f);
        if (sz < 0) {
            fclose(f);
            return -1;
        }
        unsigned char *blob = malloc((size_t) sz);
        if (!blob) {
            fclose(f);
            return -1;
        }
        size_t leido = fread(blob, 1, (size_t) sz, f);
        fclose(f);
        int r = (leido == (size_t) sz) ?
                    crypto_blob_valido(blob, (size_t) sz, CIFR_FLAG_ARCHIVO) : -1;
        free(blob);
        if (r != 0)
            return -1;
    }
    return 0;
}

/* hash SHA-256 del contenido de un archivo en disco; 0 = ok */
static int sha_archivo(const char *abs, unsigned char out[CIFR_SHA_LEN])
{
    FILE *f = fopen(abs, "rb");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    rewind(f);
    if (sz < 0) {
        fclose(f);
        return -1;
    }
    unsigned char *b = malloc((size_t) sz);
    if (!b) {
        fclose(f);
        return -1;
    }
    size_t leido = fread(b, 1, (size_t) sz, f);
    fclose(f);
    int r = (leido == (size_t) sz) ? crypto_sha256(b, (size_t) sz, out) : -1;
    free(b);
    return r;
}

static int descifrar_material(inventory *inv)
{
    sigset_t old;

    /* Comprobación completa ANTES de tocar disco: así un fallo deja todo
     * intacto en estado cifrado. */
    if (validar_descifrado_previo(inv) != 0) {
        fprintf(stderr, "ERROR INESPERADO: el material cifrado no se puede validar\n"
                        "(dañado, incompleto o la clave no coincide). No se modificó nada.\n");
        return -1;
    }

    bloquear_interrupciones(&old);

    /* 1) renombrar directorios de menos profundo a más (padre antes que hijos).
     * NOTA: orden comparte el array de inv (solo reordena; NO se libera). */
    inventory orden = *inv;
    inv_ordenar_por_nivel(&orden, false);
    for (size_t i = 0; i < orden.n; i++) {
        inv_node *nd = &orden.it[i];
        if (nd->tipo != INV_DIR || !nd->enc_base)
            continue;
        char de[RUTA_MAX], a[RUTA_MAX];
        if (abs_parojo(nd, de, sizeof de) != 0 || abs_de_rel(nd->rel, a, sizeof a) != 0) {
            restaurar_interrupciones(&old);
            return -1;
        }
        if (strcmp(de, a) == 0)
            continue;
        if (rename(de, a) != 0) {
            fprintf(stderr, "error inesperado: no se pudo restaurar el directorio %s\n",
                    nd->rel);
            restaurar_interrupciones(&old);
            return -1;
        }
    }

    /* 2) renombrar archivos a sus nombres originales */
    for (size_t i = 0; i < orden.n; i++) {
        inv_node *nd = &orden.it[i];
        if (nd->tipo != INV_FILE || !nd->enc_base)
            continue;
        char de[RUTA_MAX], a[RUTA_MAX];
        if (abs_parojo(nd, de, sizeof de) != 0 || abs_de_rel(nd->rel, a, sizeof a) != 0) {
            restaurar_interrupciones(&old);
            return -1;
        }
        if (strcmp(de, a) == 0)
            continue;
        if (rename(de, a) != 0) {
            fprintf(stderr, "error inesperado: no se pudo restaurar el archivo %s\n", nd->rel);
            restaurar_interrupciones(&old);
            return -1;
        }
    }

    /* 3) descifrar contenidos y validar SHA-256 contra el manifest */
    for (size_t i = 0; i < inv->n; i++) {
        inv_node *nd = &inv->it[i];
        if (nd->tipo != INV_FILE)
            continue;
        char abs[RUTA_MAX];
        if (abs_de_rel(nd->rel, abs, sizeof abs) != 0 ||
            crypto_descifrar_archivo(abs) != 0) {
            fprintf(stderr, "error inesperado: no se pudo descifrar %s\n", nd->rel);
            restaurar_interrupciones(&old);
            return -1;
        }
        unsigned char sha[CIFR_SHA_LEN];
        if (nd->size == 0 || sha_archivo(abs, sha) != 0 || memcmp(sha, nd->sha, sizeof sha) != 0) {
            fprintf(stderr, "error inesperado: el contenido restaurado de %s no "
                            "coincide con el manifest (datos dañados).\n", nd->rel);
            restaurar_interrupciones(&old);
            return -1;
        }
    }

    restaurar_interrupciones(&old);

    size_t ok = 0, mal = 0;
    if (escaner_verificar_claro(inv, &ok, &mal) != 0) {
        fprintf(stderr, "ERROR INESPERADO: verificación post-descifrado incompleta.\n");
        return -1;
    }
    printf("Descifrado verificado: %zu elementos restaurados en claro.\n", ok);
    return 0;
}

/* --------------------------------------------- flujos */

/* Antes de operar con material preexistente, recorre el territorio con
 * nftw()+readdir() y rechaza entradas no registradas o tipos extraños
 * (symlinks plantados). 0 = territorio limpio, -1 = discrepancias. */
static int chequeo_territorio(const inventory *inv, bool material_cifrado)
{
    inventory desc;
    inv_inicializar(&desc);
    if (escaner_escanear(inv, material_cifrado, &desc) != 0) {
        inv_liberar(&desc);
        return -1;
    }
    size_t falt = 0, ajen = 0;
    escaner_contrastar(inv, &desc, &falt, &ajen);
    int tipos = escaner_ajenos_tipo();
    inv_liberar(&desc);
    if (falt || ajen || tipos) {
        fprintf(stderr, "ERROR INESPERADO: territorio inconsistente "
                        "(faltan %zu, no registrados %zu, tipos extraños %d).\n"
                        "No se modificará nada; revisa el directorio del programa.\n",
                falt, ajen, tipos);
        return -1;
    }
    return 0;
}

static void resumen(const inventory *inv)
{
    printf("  directorios: %d   archivos: %d\n",
           inv_contar(inv, INV_DIR), inv_contar(inv, INV_FILE));
}

/* Generar + escanear + preguntar + cifrar/purgar. Devuelve código de salida. */
static int flujo_generar(void)
{
    inventory inv;
    inv_inicializar(&inv);

    puts("Generando rutas aleatorias junto al ejecutable...");
    int r = generador_generar(&inv);
    if (r == -2) {
        fprintf(stderr, "ERROR DE SEGURIDAD: se detectó una ruta fuera del directorio\n"
                        "del programa. Eliminando todo el material generado...\n");
        fs_guard_purgar(&inv, true);
        inv_liberar(&inv);
        return 2;
    }
    if (r != 0) {
        fprintf(stderr, "error de E/S durante la generación; purgando...\n");
        fs_guard_purgar(&inv, false);
        inv_liberar(&inv);
        return 1;
    }
    printf("Generación completa. ");
    resumen(&inv);

    /* Recorrido con nftw()+readdir(): revalidar en disco contra el inventario. */
    inventory desc;
    inv_inicializar(&desc);
    if (escaner_escanear(&inv, false, &desc) != 0) {
        fprintf(stderr, "error: el recorrido nftw() falló; purgando material.\n");
        fs_guard_purgar(&inv, false);
        inv_liberar(&inv);
        inv_liberar(&desc);
        return 1;
    }
    size_t falt = 0, ajen = 0;
    escaner_contrastar(&inv, &desc, &falt, &ajen);
    if (falt || ajen || escaner_ajenos_tipo() > 0) {
        fprintf(stderr, "ERROR INESPERADO: discrepancia en el recorrido "
                        "(faltan %zu, no registrados %zu, tipos extraños %d).\n"
                        "Eliminando todo el material generado...\n",
                falt, ajen, escaner_ajenos_tipo());
        fs_guard_purgar(&inv, false);
        inv_liberar(&inv);
        inv_liberar(&desc);
        return 2;
    }
    inv_liberar(&desc);

    if (verificar_contencion(&inv) != 0) {
        fprintf(stderr, "ERROR DE SEGURIDAD: ruta fuera del directorio raíz; "
                        "purgando todo el material generado...\n");
        fs_guard_purgar(&inv, false);
        inv_liberar(&inv);
        return 2;
    }

    if (!ui_pregunta("¿Desea cifrar todo el material generado?")) {
        puts("Cifrado denegado: eliminando todas las rutas y archivos generados...");
        fs_guard_purgar(&inv, false);
        inv_liberar(&inv);
        puts("Material eliminado. El programa va a terminar.");
        return 0;
    }

    puts("Cifrando todo el material generado (contenido + nombres)...");
    if (cifrar_material(&inv) != 0) {
        fprintf(stderr, "ERROR INESPERADO durante el cifrado. "
                        "Eliminando todo el material generado...\n");
        fs_guard_purgar(&inv, true);
        inv_liberar(&inv);
        return 1;
    }
    resumen(&inv);
    puts("Todo el material ha sido cifrado. El programa va a terminar.");
    inv_liberar(&inv);
    return 0;
}

static int flujo_descifrar(inventory *inv)
{
    puts("Descifrando todo el material (nombres + contenidos)...");
    if (descifrar_material(inv) != 0) {
        puts("El material permanece CIFRADO (no se modificó nada o quedó\n"
             "verificable en una próxima ejecución).");
        return 1;
    }
    if (ui_pregunta("¿Eliminar todo el material generado ahora?")) {
        fs_guard_purgar(inv, true);
        puts("Material eliminado por completo.");
    } else {
        puts("Material conservado en claro. El manifest se mantiene para\n"
             "que el programa reconozca el material en futuras ejecuciones.");
    }
    return 0;
}

/* Material en claro preexistente: cifrar, regenerar o eliminar. */
static int flujo_existente(inventory *inv)
{
    for (;;) {
        int op = ui_menu_existente();
        if (op == 3)
            return 0;
        if (op == 4) {
            if (ui_pregunta("¿Confirmas eliminar TODO el material generado?")) {
                fs_guard_purgar(inv, true);
                puts("Material eliminado por completo.");
            }
            return 0;
        }
        if (op == 2) {
            if (!ui_pregunta("¿Eliminar el material existente antes de regenerar?"))
                continue;
            fs_guard_purgar(inv, true);
            return flujo_generar();
        }
        /* op == 1 */
        if (!ui_pregunta("¿Confirmas cifrar TODO el material existente?"))
            continue;
        if (cifrar_material(inv) != 0) {
            fprintf(stderr, "ERROR INESPERADO durante el cifrado; "
                            "eliminando el material generado...\n");
            fs_guard_purgar(inv, true);
            return 1;
        }
        resumen(inv);
        puts("Todo el material ha sido cifrado. El programa va a terminar.");
        return 0;
    }
}

/* --------------------------------------------- prueba de seguridad CLI */

/* Crea deliberadamente una ruta FUERA del directorio del programa y pide
 * al guardián que la audite: debe rechazarla y purgar lo generado. */
static int prueba_inseguro(void)
{
    char dir[RUTA_MAX];
    snprintf(dir, sizeof dir, "%s/../cifrar-test-inseguro", fs_guard_dir());
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "prueba: no se pudo crear %s\n", dir);
        return 1;
    }
    inventory inv;
    inv_inicializar(&inv);
    inv_agregar(&inv, "../cifrar-test-inseguro", INV_DIR);
    int r = verificar_contencion(&inv);
    printf("verificar_contencion(ruta externa) = %s\n", r == -1 ? "RECHAZADA (ok)" : "ACEPTADA (mal)");
    inv_liberar(&inv);
    rmdir(dir);
    return r == -1 ? 0 : 1;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc > 1 && strcmp(argv[1], "--selftest") == 0)
        return crypto_selftest();
    if (argc > 1 && strcmp(argv[1], "--prueba-inseguro") == 0) {
        if (fs_guard_iniciar() != 0)
            return 1;
        return prueba_inseguro();
    }

    ui_banner();

    if (crypto_iniciar() != 0 || rng_iniciar() != 0) {
        fprintf(stderr, "error: no se pudo inicializar el entorno aleatorio.\n");
        return 1;
    }
    int gr = fs_guard_iniciar();
    if (gr != 0) {
        fprintf(stderr, "error: no se pudo resolver el directorio del ejecutable%s\n",
                gr == -2 ? " (el programa se niega a operar en /)" : "");
        return 1;
    }
    printf("Ubicación de trabajo: %s\n", fs_guard_dir());

    inventory inv;
    inv_inicializar(&inv);
    int mr = cargar_manifest(&inv);
    estado_t est;
    if (mr == -1)
        est = EST_NADA; /* sin manifest */
    else if (mr == -2)
        est = EST_ERROR;
    else
        est = detectar_estado(&inv);

    if (est == EST_NADA && mr == 0) {
        /* manifest huérfano (material borrado manualmente): se retira */
        puts("Aviso: el manifest existía pero su material ya no está; se elimina.");
        char abs[RUTA_MAX];
        if (manifest_abs(abs, sizeof abs) == 0)
            unlink(abs);
    }

    int codigo = 0;

    if (est == EST_CIFRADO) {
        ui_separador();
        puts("Se detectó material generado y CIFRADO por este programa.");
        if (chequeo_territorio(&inv, true) != 0) {
            inv_liberar(&inv);
            crypto_terminar();
            return 1;
        }
        if (ui_pregunta("¿Desea quitar el cifrado de todo el material?")) {
            codigo = flujo_descifrar(&inv);
        } else {
            puts("Se conserva el material cifrado. Saliendo.");
        }
        inv_liberar(&inv);
        crypto_terminar();
        return codigo;
    }

    if (est == EST_MIXTO) {
        ui_separador();
        fprintf(stderr, "ERROR INESPERADO: estado mixto (material parcialmente\n"
                        "cifrado). Se recomienda eliminar todo el material generado.\n");
        if (ui_pregunta("¿Eliminar todo el material generado para sanear?")) {
            fs_guard_purgar(&inv, true);
            puts("Material saneado.");
        } else {
            puts("Se deja el material tal cual. Saliendo.");
            codigo = 1;
        }
        inv_liberar(&inv);
        crypto_terminar();
        return codigo;
    }

    if (est == EST_ERROR) {
        ui_separador();
        fprintf(stderr, "ERROR INESPERADO: existe un manifest ilegible o dañado\n"
                        "y no se puede verificar el estado del material.\n");
        if (ui_pregunta("¿Eliminar el manifest corrupto para empezar de cero?")) {
            char abs[RUTA_MAX];
            if (manifest_abs(abs, sizeof abs) == 0)
                unlink(abs);
            puts("Manifest eliminado.");
        }
        inv_liberar(&inv);
        crypto_terminar();
        return 1;
    }

    if (est == EST_CLARO) {
        ui_separador();
        puts("Existe material generado por este programa (sin cifrar):");
        resumen(&inv);
        if (chequeo_territorio(&inv, false) != 0) {
            inv_liberar(&inv);
            crypto_terminar();
            return 1;
        }
        if (!ui_pregunta("¿Desea trabajar con esa data existente?")) {
            puts("Saliendo sin tocar el material existente.");
            inv_liberar(&inv);
            crypto_terminar();
            return 0;
        }
        codigo = flujo_existente(&inv);
        inv_liberar(&inv);
        crypto_terminar();
        return codigo;
    }

    /* EST_NADA: menú principal */
    for (;;) {
        int op = ui_menu_principal();
        if (op == 2)
            break;
        codigo = flujo_generar();
        break; /* tras generar+cifrar (o purgar), el programa termina */
    }
    inv_liberar(&inv);
    crypto_terminar();
    return codigo;
}
