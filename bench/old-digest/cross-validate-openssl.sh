#!/bin/bash
# Кросс-валидация: crypto-gost <-> OpenSSL (Streebog256, Streebog512)
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$BENCH_DIR/target/benchmarks.jar"
HASH_TOOL="java --add-opens java.base/java.lang=ALL-UNNAMED \
                --add-opens java.base/java.util=ALL-UNNAMED \
                --add-opens java.base/java.io=ALL-UNNAMED \
                --add-opens java.base/java.text=ALL-UNNAMED \
                --add-opens java.base/jdk.internal.misc=ALL-UNNAMED \
                -cp "$JAR" org.rssys.bench.HashTool"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0
TOTAL=0

# ---------------------------------------------------------------
# Проверка: openssl и поддержка Стрибога
# ---------------------------------------------------------------
check_prereqs() {
  if ! command -v openssl &>/dev/null; then
    echo "ОШИБКА: openssl не найден."
    exit 1
  fi

  OPENSSL_VER=$(openssl version | awk '{print $2}')
  echo "OpenSSL версия: $OPENSSL_VER"

  for a in streebog256 streebog512; do
    if ! openssl dgst -list 2>/dev/null | grep -q "$a"; then
      echo "ОШИБКА: алгоритм $a недоступен в openssl."
      exit 1
    fi
  done
  echo "Все алгоритмы Стрибога доступны."
  echo

  if [ ! -f "$JAR" ]; then
    echo "ОШИБКА: не найден $JAR. Сначала выполните make build."
    exit 1
  fi
}

# ---------------------------------------------------------------
# Один тест
# ---------------------------------------------------------------
run_test() {
  local algo="$1"
  local sz="$2"
  TOTAL=$((TOTAL + 1))

  local data="$TMPDIR/data.bin"
  if [ "$sz" -eq 0 ]; then
    : > "$data"
  else
    openssl rand "$sz" > "$data" 2>/dev/null
  fi

  local gost_hash
  gost_hash=$($HASH_TOOL "$algo" "$data" 2>/dev/null) || true

  local ossl_hash
  ossl_hash=$(openssl dgst "-$algo" -r "$data" 2>/dev/null | awk '{print $1}') || true

  if [ "$gost_hash" = "$ossl_hash" ]; then
    PASS=$((PASS + 1))
    printf "  %-14s size=%-8d %s  OK\n" "$algo" "$sz" "$gost_hash"
  else
    FAIL=$((FAIL + 1))
    printf "  %-14s size=%-8d FAIL\n" "$algo" "$sz"
    echo "    gost: $gost_hash"
    echo "    ossl: $ossl_hash"
  fi
}

# ---------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------
check_prereqs

echo "============================================================"
echo "  Кросс-валидация: crypto-gost <-> OpenSSL"
echo "  Хеш: Стрибог (ГОСТ Р 34.11-2012)"
echo "============================================================"
echo

for algo in streebog256 streebog512; do
  echo "--- $algo ---"
  for sz in 0 1 16 255 1024 1048576; do
    run_test "$algo" "$sz"
  done
  echo
done

# ---------------------------------------------------------------
# Сводка
# ---------------------------------------------------------------
echo "============================================================"
echo "  Сводка:"
echo "    Всего проверок:  $TOTAL"
echo "    Пройдено:        $PASS"
echo "    Ошибок:          $FAIL"
echo "    Статус:          $([ $FAIL -eq 0 ] && echo "УСПЕХ" || echo "ПРОВАЛ")"
echo "============================================================"

exit $(( FAIL > 0 ? 1 : 0 ))
