#!/usr/bin/env bash
# Кросс-валидация: crypto-gost ↔ OpenSSL 3.x (ГОСТ-провайдер)
#
# Алгоритмы:
#   - Streebog-256 (хэш, ГОСТ Р 34.11-2012)
#   - Streebog-512 (хэш, ГОСТ Р 34.11-2012)
#   - HMAC-Streebog-256 (RFC 7836)
#   - HMAC-Streebog-512 (RFC 7836)
#   - CMAC-Kuznyechik (ГОСТ Р 34.13-2015)
#
# Требования: OpenSSL 3.x с GOST-провайдером (gost-engine или встроенным)
#
# Использование: bash cross-validate-openssl.sh
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$BENCH_DIR/target/benchmarks.jar"
JAVA="${JAVA:-java}"
JAVA_OPTS="${JAVA_OPTS:---add-opens java.base/java.lang=ALL-UNNAMED}"
TOOL_CLASS="org.rssys.bench.MacTool"

SIZES=(0 1 16 255 1024)
TMP_DIR=""

# ───────────────────────────────────────────────────────────────────────────────
# Счётчики
# ───────────────────────────────────────────────────────────────────────────────
total=0
passed=0
failed=0

# ───────────────────────────────────────────────────────────────────────────────
# Вспомогательные функции
# ───────────────────────────────────────────────────────────────────────────────

check_prereqs() {
    echo "  Проверка зависимостей..."

    if ! command -v openssl &>/dev/null; then
        echo "  ОШИБКА: openssl не найден"
        exit 1
    fi

    local ver
    ver=$(openssl version)
    echo "  OpenSSL: $ver"

    # Проверяем наличие streebog256
    if ! openssl dgst -streebog256 /dev/null &>/dev/null; then
        echo "  ОШИБКА: openssl не поддерживает -streebog256. Нужен GOST-провайдер."
        exit 1
    fi
    echo "  Streebog-256: OK"

    # Проверяем HMAC-Streebog-256
    if ! echo -n "" | openssl mac -digest streebog256 -macopt "hexkey:$(python3 -c "print('00'*32)")" HMAC &>/dev/null; then
        echo "  ОШИБКА: openssl mac HMAC-streebog256 недоступен"
        exit 1
    fi
    echo "  HMAC-Streebog-256: OK"

    # Проверяем CMAC-Kuznyechik
    if ! echo -n "" | openssl mac -cipher kuznyechik-cbc -macopt "hexkey:$(python3 -c "print('00'*32)")" CMAC &>/dev/null; then
        echo "  ОШИБКА: openssl mac CMAC kuznyechik-cbc недоступен. Нужен GOST-провайдер."
        exit 1
    fi
    echo "  CMAC-Kuznyechik: OK"

    if [ ! -f "$JAR" ]; then
        echo "  ОШИБКА: JAR не найден: $JAR. Запусти 'make build' в bench/mac/"
        exit 1
    fi
    echo "  JAR: OK"
    echo
}

# Генерирует тестовые файлы в TMP_DIR
generate_data() {
    TMP_DIR=$(mktemp -d)
    for sz in "${SIZES[@]}"; do
        local f="$TMP_DIR/data-${sz}.bin"
        if [ "$sz" -eq 0 ]; then
            touch "$f"
        else
            # Последовательность байт 0x00..0xFF по кругу (как в MacCrossValidation.msg())
            python3 -c "
import sys
sz = $sz
data = bytes([i & 0xFF for i in range(sz)])
sys.stdout.buffer.write(data)
" > "$f"
        fi
    done
}

cleanup() {
    [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Вывод результата одной проверки
check() {
    local algo="$1"
    local sz="$2"
    local direction="$3"
    local gost_hex="$4"
    local ossl_hex="$5"

    total=$((total + 1))
    # нормализуем к нижнему регистру для сравнения
    local g_lo
    local o_lo
    g_lo=$(echo "$gost_hex" | tr '[:upper:]' '[:lower:]')
    o_lo=$(echo "$ossl_hex" | tr '[:upper:]' '[:lower:]')

    if [ "$g_lo" = "$o_lo" ]; then
        passed=$((passed + 1))
        printf "    %-8s %-22s размер=%-6d PASS\n" "$direction" "$algo" "$sz"
    else
        failed=$((failed + 1))
        printf "    %-8s %-22s размер=%-6d FAIL\n" "$direction" "$algo" "$sz"
        printf "      crypto-gost: %s\n" "$g_lo"
        printf "      openssl    : %s\n" "$o_lo"
    fi
}

# ───────────────────────────────────────────────────────────────────────────────
# Streebog-256
# ───────────────────────────────────────────────────────────────────────────────
validate_streebog256() {
    echo "  Алгоритм: Streebog-256 (хэш)"
    for sz in "${SIZES[@]}"; do
        local f="$TMP_DIR/data-${sz}.bin"

        local gost_hex
        gost_hex=$($JAVA $JAVA_OPTS -cp "$JAR" "$TOOL_CLASS" streebog256 "$f")

        local ossl_hex
        ossl_hex=$(openssl dgst -streebog256 -r "$f" | awk '{print $1}')

        check "Streebog-256" "$sz" "gost→ossl" "$gost_hex" "$ossl_hex"
    done
    echo
}

# ───────────────────────────────────────────────────────────────────────────────
# Streebog-512
# ───────────────────────────────────────────────────────────────────────────────
validate_streebog512() {
    echo "  Алгоритм: Streebog-512 (хэш)"
    for sz in "${SIZES[@]}"; do
        local f="$TMP_DIR/data-${sz}.bin"

        local gost_hex
        gost_hex=$($JAVA $JAVA_OPTS -cp "$JAR" "$TOOL_CLASS" streebog512 "$f")

        local ossl_hex
        ossl_hex=$(openssl dgst -streebog512 -r "$f" | awk '{print $1}')

        check "Streebog-512" "$sz" "gost→ossl" "$gost_hex" "$ossl_hex"
    done
    echo
}

# ───────────────────────────────────────────────────────────────────────────────
# HMAC-Streebog-256
# ───────────────────────────────────────────────────────────────────────────────
validate_hmac256() {
    echo "  Алгоритм: HMAC-Streebog-256"
    local key_hex
    key_hex=$(openssl rand -hex 32)

    for sz in "${SIZES[@]}"; do
        local f="$TMP_DIR/data-${sz}.bin"

        local gost_hex
        gost_hex=$($JAVA $JAVA_OPTS -cp "$JAR" "$TOOL_CLASS" hmac256 "$key_hex" "$f")

        local ossl_hex
        ossl_hex=$(openssl mac -digest streebog256 -macopt "hexkey:$key_hex" HMAC < "$f" | tr '[:upper:]' '[:lower:]')

        check "HMAC-Str-256" "$sz" "gost→ossl" "$gost_hex" "$ossl_hex"
    done
    echo
}

# ───────────────────────────────────────────────────────────────────────────────
# HMAC-Streebog-512
# ───────────────────────────────────────────────────────────────────────────────
validate_hmac512() {
    echo "  Алгоритм: HMAC-Streebog-512"
    local key_hex
    key_hex=$(openssl rand -hex 32)

    for sz in "${SIZES[@]}"; do
        local f="$TMP_DIR/data-${sz}.bin"

        local gost_hex
        gost_hex=$($JAVA $JAVA_OPTS -cp "$JAR" "$TOOL_CLASS" hmac512 "$key_hex" "$f")

        local ossl_hex
        ossl_hex=$(openssl mac -digest streebog512 -macopt "hexkey:$key_hex" HMAC < "$f" | tr '[:upper:]' '[:lower:]')

        check "HMAC-Str-512" "$sz" "gost→ossl" "$gost_hex" "$ossl_hex"
    done
    echo
}

# ───────────────────────────────────────────────────────────────────────────────
# CMAC-Kuznyechik
# ───────────────────────────────────────────────────────────────────────────────
validate_cmac() {
    echo "  Алгоритм: CMAC-Kuznyechik"
    local key_hex
    key_hex=$(openssl rand -hex 32)

    for sz in "${SIZES[@]}"; do
        local f="$TMP_DIR/data-${sz}.bin"

        local gost_hex
        gost_hex=$($JAVA $JAVA_OPTS -cp "$JAR" "$TOOL_CLASS" cmac "$key_hex" "$f")

        local ossl_hex
        ossl_hex=$(openssl mac -cipher kuznyechik-cbc -macopt "hexkey:$key_hex" CMAC < "$f" | tr '[:upper:]' '[:lower:]')

        check "CMAC-Kuz" "$sz" "gost→ossl" "$gost_hex" "$ossl_hex"
    done
    echo
}

# ───────────────────────────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────────────────────────
main() {
    echo "$(printf '=%.0s' {1..72})"
    echo "  Кросс-валидация: crypto-gost ↔ OpenSSL"
    echo "  Алгоритмы: Streebog-256/512, HMAC-256/512, CMAC-Kuznyechik"
    echo "$(printf '=%.0s' {1..72})"
    echo

    check_prereqs
    generate_data

    validate_streebog256
    validate_streebog512
    validate_hmac256
    validate_hmac512
    validate_cmac

    echo "$(printf '=%.0s' {1..72})"
    echo "  Сводка:"
    printf "    Всего проверок:  %d\n" "$total"
    printf "    Пройдено:        %d\n" "$passed"
    printf "    Ошибок:          %d\n" "$failed"
    if [ "$failed" -eq 0 ]; then
        echo "    Статус:          УСПЕХ"
    else
        echo "    Статус:          ПРОВАЛ"
    fi
    echo "$(printf '=%.0s' {1..72})"

    exit "$failed"
}

main
