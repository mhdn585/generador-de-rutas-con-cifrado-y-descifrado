/*
 * ui.c — Menú y confirmaciones en español. Lectura robusta con fgets.
 */
#include "ui.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

static int leer_linea(char *buf, size_t bufsz)
{
    if (!fgets(buf, (int) bufsz, stdin))
        return 0; /* EOF: tratamos como "no" */
    /* vaciar resto de la línea si es larga */
    size_t l = strlen(buf);
    if (l > 0 && buf[l - 1] != '\n') {
        int c;
        while ((c = getchar()) != '\n' && c != EOF)
            ;
    }
    return 1;
}

static char responder(const char *pregunta)
{
    for (;;) {
        printf("%s [s/n]: ", pregunta);
        fflush(stdout);
        char buf[256];
        if (!leer_linea(buf, sizeof buf))
            return 'n';
        /* primera letra no blanca */
        for (size_t i = 0; buf[i]; i++) {
            if (!isspace((unsigned char) buf[i])) {
                char c = (char) tolower((unsigned char) buf[i]);
                if (c == 's' || c == 'y')
                    return 's';
                if (c == 'n')
                    return 'n';
                break;
            }
        }
        printf("  Responda 's' (sí) o 'n' (no).\n");
    }
}

int ui_pregunta(const char *pregunta)
{
    return responder(pregunta) == 's';
}

void ui_separador(void)
{
    puts("------------------------------------------------------------");
}

void ui_banner(void)
{
    ui_separador();
    puts("  CIFRAR — generador de rutas con cifrado AES-256-GCM");
    ui_separador();
}

int ui_menu_principal(void)
{
    for (;;) {
        puts("");
        puts("  Menú:");
        puts("    1) Generar rutas y archivos");
        puts("    2) Salir");
        printf("  Opción: ");
        fflush(stdout);
        char buf[64];
        if (!leer_linea(buf, sizeof buf))
            return 2;
        if (buf[0] == '1')
            return 1;
        if (buf[0] == '2')
            return 2;
        puts("  Opción no válida.");
    }
}

int ui_menu_existente(void)
{
    for (;;) {
        puts("");
        puts("  Menú (material existente en claro):");
        puts("    1) Cifrar todo el material");
        puts("    2) Eliminarlo y generar material nuevo");
        puts("    3) Salir sin tocar nada");
        puts("    4) Eliminar todo el material y salir");
        printf("  Opción: ");
        fflush(stdout);
        char buf[64];
        if (!leer_linea(buf, sizeof buf))
            return 3;
        if (buf[0] == '1')
            return 1;
        if (buf[0] == '2')
            return 2;
        if (buf[0] == '3')
            return 3;
        if (buf[0] == '4')
            return 4;
        puts("  Opción no válida.");
    }
}
