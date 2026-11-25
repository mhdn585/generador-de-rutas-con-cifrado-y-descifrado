#!/usr/bin/env bash
# smoke.sh — ciclo completo: generar→cifrar→reabrir→descifrar→eliminar.
# El programa trabaja junto a su ejecutable, así que se copia a una
# Sandbox limpia y se ejercita con stdin guionado.
set -u

BIN="${1:-./cifrar}"
command -v timeout >/dev/null 2>&1 && TMO="timeout 60" || TMO=""

SBX="$(mktemp -d /tmp/cifrar-smoke.XXXXXX)"
cp "$BIN" "$SBX/cifrar"
cd "$SBX" || exit 1
MAN="$SBX/.cifrar.manifest"

falla=0
chk() { # chk "msg" cmd...
    local msg="$1"; shift
    if ! "$@"; then
        echo "FALLO: $msg"
        falla=1
    else
        echo "ok: $msg"
    fi
}

resto() { # huérfanos del programa (sin contar el binario)
    find . -mindepth 1 ! -name cifrar ! -name '.cifrar.manifest' | head -5
}

sin_enc() { # entradas cuyo nombre no termina en .enc
    find . -mindepth 1 ! -name cifrar ! -name '.cifrar.manifest' \
        -printf '%f\n' | grep -v '\.enc$' | wc -l
}

echo "== 1) generar y NEGAR cifrado → debe purgar todo =="
printf '1\nn\n' | $TMO ./cifrar >/dev/null 2>&1
chk "sin manifest tras negar cifrado" test ! -e "$MAN"
chk "sin material tras negar cifrado" test -z "$(resto)"

echo "== 2) generar y CIFRAR =="
printf '1\ns\n' | $TMO ./cifrar >/dev/null 2>&1
chk "manifest presente tras cifrar" test -e "$MAN"
chk "todos los nombres cifrados (.enc)" test "$(sin_enc)" -eq 0
chk "hay archivos .enc" test "$(find . -name '*.enc' -type f | wc -l)" -gt 5
CIFRADOS="$(find . -name '*.enc' -type f | wc -l)"

echo "== 3) reabrir: descifrar SÍ, eliminar NO =="
printf 's\nn\n' | $TMO ./cifrar >/dev/null 2>&1
chk "salida 0 tras descifrar" test $? -eq 0
chk "manifest conservado tras descifrar" test -e "$MAN"
chk "sin restos .enc tras descifrar" test -z "$(find . -name '*.enc')"
ARCHIVOS="$(find . -type f ! -name cifrar ! -name '.cifrar.manifest' | wc -l)"
DIRS="$(find . -mindepth 1 -type d | wc -l)"
chk "material restaurado (archivos > 5)" test "$ARCHIVOS" -gt 5
chk "material restaurado (directorios > 2)" test "$DIRS" -gt 2

echo "== 4) reabrir: trabajar con material existente → cifrar otra vez =="
printf 's\n1\ns\n' | $TMO ./cifrar >/dev/null 2>&1
chk "re-cifrado completo (nombres .enc)" test "$(sin_enc)" -eq 0
chk "mismo nº de archivos cifrados" test "$(find . -name '*.enc' -type f | wc -l)" -eq "$CIFRADOS"

echo "== 5) reabrir: descifrar y ELIMINAR todo =="
printf 's\ns\ns\n' | $TMO ./cifrar >/dev/null 2>&1
chk "manifest eliminado" test ! -e "$MAN"
chk "sin material tras eliminar" test -z "$(resto)"

echo "== 6) blob de manifest ilegible → ERROR INESPERADO =="
printf 'basura-no-cifrada' > "$MAN"
printf 'n\n' | $TMO ./cifrar >/dev/null 2>&1
R=$?
chk "código de error ante manifest corrupto" test "$R" -ne 0
rm -f "$MAN"

if [ "$falla" -eq 0 ]; then
    echo "SMOKE TEST: TODO OK"
    rm -rf "$SBX"
    exit 0
else
    echo "SMOKE TEST: FALLOS (sandbox conservada en $SBX)"
    exit 1
fi
