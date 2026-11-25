# cifrar

Programa en **C23** para Linux que genera rutas aleatorias (directorios
anidados y archivos con `mkdir()`/`fopen()`) junto al ejecutable y cifra
**contenidos y nombres** con **AES-256-GCM** (OpenSSL) usando una clave
embebida de 32 bytes.

## Compilar

```sh
make        # produce ./cifrar
make test   # selftest criptográfico + prueba de seguridad + smoke e2e
make run    # ejecutar
make clean
```

## Uso

```sh
./cifrar
```

- Opción 1 del menú: genera 2-4 rutas raíz con subdirectorios y archivos
  de texto aleatorio, recorre lo generado con `nftw()` leyendo cada
  directorio con `readdir()`, guarda el inventario en RAM y pregunta si
  desea cifrar.
  - **Sí** → escribe un manifest cifrado (`.cifrar.manifest`), cifra los
    contenidos (formato `CIFR1|flags|IV|tag|ciphertext`) y renombra
    archivos y directorios a nombres cifrados en base64url con sufijo
    `.enc`.
  - **No** → elimina todo el material generado y termina.
- Al relanzarlo detecta el estado del material:
  - **cifrado** → pregunta si desea quitar el cifrado; al descifrar,
    pregunta si desea eliminar todo.
  - **en claro** → pregunta si desea trabajar con la data existente.
  - manifest corrupto o inconsistentes → **error inesperado** sin tocar
    datos recuperables.

## Seguridad de rutas

Todas las rutas se construyen desde el directorio del ejecutable
(`/proc/self/exe` + `realpath()`). Se rechazan rutas absolutas, `..` y
symlinks dentro del territorio generado. Si en cualquier momento se
detecta una ruta fuera del directorio raíz, el programa purga
únicamente el material que generó (el manifest es la única lista de lo
que le pertenece) y aborta. `nftw()` usa `FTW_PHYS` para no seguir
enlaces simbólicos.

## Pruebas extra

```sh
make sanitize          # compila cifrar-asan (ASan+UBSan)
make test              # puede repetirse con ./cifrar-asan en tests/smoke.sh
./cifrar --selftest    # round-trips AES-GCM, tamper, base64url, SHA-256
./cifrar --prueba-inseguro  # verifica que una ruta externa es rechazada
```
