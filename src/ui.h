/*
 * ui.h — Interfaz de terminal en español: menú y confirmaciones.
 * Toda lectura usa fgets (robusta ante EOF).
 */
#ifndef CIFRAR_UI_H
#define CIFRAR_UI_H

void ui_banner(void);

/* Pregunta sí/no. Devuelve 1 = sí, 0 = no (EOF cuenta como no). */
int ui_pregunta(const char *pregunta);

/* Menú principal estado vacío. Devuelve opción (1 generar, 2 salir). */
int ui_menu_principal(void);

/* Menú con material en claro preexistente. 1 cifrar, 2 regenerar, 3 salir,
 * 4 eliminar todo y salir. */
int ui_menu_existente(void);

void ui_separador(void);

#endif /* CIFRAR_UI_H */
