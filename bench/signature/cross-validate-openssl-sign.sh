#!/bin/bash
# Кросс-валидация: crypto-gost → OpenSSL (подпись ГОСТ Р 34.10-2012)
#
# Direction: crypto-gost подписывает, OpenSSL engine gost верифицирует.
#
# Формат подписи:
#   crypto-gost : s_BE || r_BE  (s первые rolen байт, r вторые rolen байт, X.509-формат)
#   OpenSSL gost: s_BE || r_BE  (X.509-формат)
#   Конвертация не требуется — crypto-gost и OpenSSL используют единый формат.
#
# Поддерживаемые кривые (совместимость OID подтверждена):
#   CryptoPro-A  OID 1.2.643.2.2.35.1  ↔  OpenSSL engine gost paramset A
#   CryptoPro-B  OID 1.2.643.2.2.35.2  ↔  OpenSSL engine gost paramset B
#   CryptoPro-C  OID 1.2.643.2.2.35.3  ↔  OpenSSL engine gost paramset C
#
# TC26-A-256 не включена: OID 1.2.643.7.1.2.1.2.1 не поддерживается
# engine gost на данной системе.
# 512-бит кривые не поддерживаются текущим engine gost.

set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$BENCH_DIR/target/benchmarks.jar"

JAVA_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED \
           --add-opens java.base/java.util=ALL-UNNAMED \
           --add-opens java.base/java.io=ALL-UNNAMED \
           --add-opens java.base/java.text=ALL-UNNAMED \
           --add-opens java.base/jdk.internal.misc=ALL-UNNAMED"

SIG_TOOL="java $JAVA_OPTS -cp $JAR org.rssys.bench.SignatureTool"

# OpenSSL engine gost — классический GOST engine (поддерживает все CryptoPro кривые)
OSSL_ENGINE="-engine gost"
OSSL_DIGEST_256="-streebog256"

TMPDIR_LOCAL=$(mktemp -d)
trap 'rm -rf "$TMPDIR_LOCAL"' EXIT

PASS=0
FAIL=0
TOTAL=0

# Количество тестовых сообщений на кривую
NUM_MESSAGES=10
MSG_SIZE=1024

# ---------------------------------------------------------------
# Проверка зависимостей
# ---------------------------------------------------------------
check_prereqs() {
    if ! command -v openssl &>/dev/null; then
        echo "ОШИБКА: openssl не найден."
        exit 1
    fi

    # Проверяем доступность engine gost
    if ! openssl engine gost >/dev/null 2>&1; then
        echo "ОШИБКА: OpenSSL engine gost не найден."
        echo "  Установите openssl-gost-engine или аналог."
        exit 1
    fi

    # Проверяем что streebog256 доступен
    if ! printf '' | openssl dgst -streebog256 >/dev/null 2>&1; then
        echo "ОШИБКА: openssl dgst -streebog256 не поддерживается."
        exit 1
    fi

    # Проверяем генерацию ключей
    if ! openssl genpkey $OSSL_ENGINE -algorithm gost2012_256 -pkeyopt paramset:A \
            -out /dev/null 2>/dev/null; then
        echo "ОШИБКА: engine gost не поддерживает gost2012_256."
        exit 1
    fi

    if [ ! -f "$JAR" ]; then
        echo "ОШИБКА: не найден $JAR. Выполните make build."
        exit 1
    fi

    echo "OpenSSL: $(openssl version)"
    echo "JAR: $JAR"
    echo
}

# ---------------------------------------------------------------
# Один тест: одно сообщение, одна кривая
# ---------------------------------------------------------------
# Аргументы:
#   $1 — label          (CryptoPro-A)
#   $2 — curve-name     (cryptopro-A)
#   $3 — privkey-hex    (64 hex chars)
#   $4 — msg-file       (путь к файлу сообщения)
run_one() {
    local label="$1"
    local curve="$2"
    local privhex="$3"
    local msgfile="$4"

    local sigfile="$TMPDIR_LOCAL/sig.bin"
    local pubfile="$TMPDIR_LOCAL/pub.der"
    local sig_bad="$TMPDIR_LOCAL/sig_bad.bin"

    TOTAL=$((TOTAL + 1))

    # Step 1: crypto-gost генерирует публичный ключ в DER SubjectPublicKeyInfo
    if ! $SIG_TOOL pubkey "$curve" "$privhex" "$pubfile" 2>/dev/null; then
        printf "  %-14s  gost->ossl  FAIL (pubkey error)\n" "$label"
        FAIL=$((FAIL + 1))
        return
    fi

    # Step 2: crypto-gost подписывает — формат s_BE || r_BE (X.509)
    if ! $SIG_TOOL sign "$curve" "$privhex" "$msgfile" "$sigfile" 2>/dev/null; then
        printf "  %-14s  gost->ossl  FAIL (sign error)\n" "$label"
        FAIL=$((FAIL + 1))
        return
    fi

    # Step 3: OpenSSL engine gost верифицирует напрямую (единый формат s||r)
    local verify_result
    # || true: не прерываем скрипт при ошибке верификации (set -e)
    verify_result=$(openssl dgst $OSSL_DIGEST_256 $OSSL_ENGINE \
        -verify "$pubfile" \
        -signature "$sigfile" \
        "$msgfile" 2>&1) || true

    if echo "$verify_result" | grep -q "Verified OK"; then
        PASS=$((PASS + 1))
        printf "  %-14s  gost->ossl  OK\n" "$label"
    else
        FAIL=$((FAIL + 1))
        printf "  %-14s  gost->ossl  FAIL (verify: %s)\n" "$label" "$verify_result"
        return
    fi

    # Step 4: Tamper-тест — портим первый байт подписи (s-компоненты), OpenSSL должен отклонить
    TOTAL=$((TOTAL + 1))
    python3 -c "
sig = open('$sigfile','rb').read()
bad = bytearray(sig); bad[0] ^= 0x01
open('$sig_bad','wb').write(bytes(bad))
"

    local tamper_result
    # || true: openssl exit 1 при Verification Failure — не прерываем скрипт (set -e)
    tamper_result=$(openssl dgst $OSSL_DIGEST_256 $OSSL_ENGINE \
        -verify "$pubfile" \
        -signature "$sig_bad" \
        "$msgfile" 2>&1) || true

    if echo "$tamper_result" | grep -q "Verification Failure\|verification failure\|error"; then
        PASS=$((PASS + 1))
        printf "  %-14s  tamper      OK (rejected)\n" "$label"
    else
        FAIL=$((FAIL + 1))
        printf "  %-14s  tamper      FAIL (tampered sig accepted!)\n" "$label"
    fi
}

# ---------------------------------------------------------------
# Тест одной кривой: NUM_MESSAGES случайных сообщений
# ---------------------------------------------------------------
test_curve() {
    local label="$1"
    local curve="$2"

    echo "--- $label ---"

    for i in $(seq 1 $NUM_MESSAGES); do
        local privhex
        privhex=$(openssl rand -hex 32)

        local msgfile="$TMPDIR_LOCAL/msg_${i}.bin"
        dd if=/dev/urandom bs=$MSG_SIZE count=1 of="$msgfile" 2>/dev/null

        run_one "$label" "$curve" "$privhex" "$msgfile"
    done

    echo
}

# ---------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------
check_prereqs

echo "============================================================"
echo "  Кросс-валидация: crypto-gost → OpenSSL engine gost"
echo "  Подпись: ГОСТ Р 34.10-2012 (256-бит, CryptoPro кривые)"
  echo "  Направление: crypto-gost подписывает, OpenSSL верифицирует"
  echo "  Формат: crypto-gost и OpenSSL — единый X.509-формат s||r"
echo "============================================================"
echo

test_curve "CryptoPro-A" "cryptopro-A"
test_curve "CryptoPro-B" "cryptopro-B"
test_curve "CryptoPro-C" "cryptopro-C"

echo "============================================================"
echo "  Сводка:"
echo "    Всего проверок:  $TOTAL"
echo "    Пройдено:        $PASS"
echo "    Ошибок:          $FAIL"
echo "    Статус:          $([ $FAIL -eq 0 ] && echo 'УСПЕХ' || echo 'ПРОВАЛ')"
echo "============================================================"

exit $(( FAIL > 0 ? 1 : 0 ))
