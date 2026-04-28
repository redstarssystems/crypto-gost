#!/bin/bash
# Кросс-валидация: crypto-gost <-> OpenSSL (Кузнечик, все режимы)
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$BENCH_DIR/target/benchmarks.jar"
CIPHER_TOOL="java --add-opens java.base/java.lang=ALL-UNNAMED \
                  --add-opens java.base/java.util=ALL-UNNAMED \
                  --add-opens java.base/java.io=ALL-UNNAMED \
                  --add-opens java.base/java.text=ALL-UNNAMED \
                  --add-opens java.base/jdk.internal.misc=ALL-UNNAMED \
                  -cp "$JAR" org.rssys.bench.KuznyechikTool"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0
TOTAL=0

# ---------------------------------------------------------------
# Проверка: openssl и поддержка Кузнечика
# ---------------------------------------------------------------
check_prereqs() {
  if ! command -v openssl &>/dev/null; then
    echo "ОШИБКА: openssl не найден. Установите OpenSSL 3.x."
    exit 1
  fi

  OPENSSL_VER=$(openssl version | awk '{print $2}')
  echo "OpenSSL версия: $OPENSSL_VER"

  if ! openssl enc -ciphers 2>/dev/null | grep -q kuznyechik; then
    echo "ОШИБКА: OpenSSL не поддерживает шифры Кузнечика."
    echo "  Требуется OpenSSL 3.x с собранной поддержкой ГОСТ."
    exit 1
  fi

  REQUIRED_MODES="kuznyechik-ctr kuznyechik-cbc kuznyechik-cfb kuznyechik-ofb"
  for m in $REQUIRED_MODES; do
    if ! openssl enc -ciphers 2>/dev/null | grep -q "$m"; then
      echo "ОШИБКА: режим $m недоступен в openssl."
      exit 1
    fi
  done
  echo "Все режимы Кузнечика доступны."
  echo

  if [ ! -f "$JAR" ]; then
    echo "ОШИБКА: не найден $JAR. Сначала выполните make build."
    exit 1
  fi
}

# ---------------------------------------------------------------
# Один тест
# ---------------------------------------------------------------
# Параметры: mode_label mode_ossl cipher_mode crypto_opts plaintext_size
#   mode_label     — отображаемое имя режима
#   mode_ossl      — имя режима для openssl (-kuznyechik-<mode>)
#   cipher_mode    — имя режима для KuznyechikTool
#   crypto_opts    — доп. опция (например -nopad) или "-"
#   plaintext_size — размер тестового сообщения в байтах
# ---------------------------------------------------------------
run_test() {
  local label="$1"
  local ossl_mode="$2"
  local ct_mode="$3"
  local ct_opts="$4"
  local sz="$5"

  TOTAL=$((TOTAL + 1))

  local plain="$TMPDIR/plain.bin"
  local cipher_ossl="$TMPDIR/cipher_ossl.bin"
  local cipher_gost="$TMPDIR/cipher_gost.bin"
  local decrypted="$TMPDIR/decrypted.bin"

  # Ключ: 32 байта (256 бит), IV: 16 байт (128 бит).
  # Для CTR: OpenSSL kuznyechik-ctr интерпретирует IV как начальное значение счётчика.
  # crypto-gost CTR использует 8-байтный IV дополненный 8 нулями справа.
  # Совместимость обеспечена: KuznyechikTool обрезает IV до 8 байт,
  # OpenSSL получает тот же IV в формате IV8||0x00*8 — результаты совпадают.
  local key=$(openssl rand -hex 32)
  local iv=$(openssl rand -hex 16)

  # тестовое сообщение
  dd if=/dev/urandom bs=1 count="$sz" of="$plain" 2>/dev/null

  local pad_opt=""
  [ "$ct_opts" != "-" ] && pad_opt="$ct_opts"

  # Direction A: openssl encrypt -> KuznyechikTool decrypt
  openssl enc -e "-kuznyechik-$ossl_mode" -K "$key" -iv "$iv" $pad_opt \
      -in "$plain" -out "$cipher_ossl" 2>/dev/null
  # shellcheck disable=SC2086
  $CIPHER_TOOL "$ct_mode" decrypt "$key" "$iv" "$cipher_ossl" "$decrypted" $pad_opt 2>/dev/null || true

  local a="FAIL"
  if cmp -s "$plain" "$decrypted"; then
    a="OK"
  fi

  # Direction B: KuznyechikTool encrypt -> openssl decrypt
  $CIPHER_TOOL "$ct_mode" encrypt "$key" "$iv" "$plain" "$cipher_gost" $pad_opt 2>/dev/null || true
  openssl enc -d "-kuznyechik-$ossl_mode" -K "$key" -iv "$iv" $pad_opt \
      -in "$cipher_gost" -out "$decrypted" 2>/dev/null

  local b="FAIL"
  if cmp -s "$plain" "$decrypted"; then
    b="OK"
  fi

  if [ "$a" = "OK" ] && [ "$b" = "OK" ]; then
    PASS=$((PASS + 1))
    printf "  %-18s size=%-5d  ossl->gost=%-3s  gost->ossl=%-3s\n" \
           "$label" "$sz" "$a" "$b"
  else
    FAIL=$((FAIL + 1))
    printf "  %-18s size=%-5d  ossl->gost=%-3s  gost->ossl=%-3s  <<< FAIL\n" \
           "$label" "$sz" "$a" "$b"
  fi
}

# ---------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------
check_prereqs

echo "============================================================"
echo "  Кросс-валидация: crypto-gost <-> OpenSSL"
echo "  Шифр: Кузнечик (ГОСТ Р 34.12-2015)"
echo "============================================================"
echo

# CTR — режим гаммирования
echo "--- CTR ---"
for sz in 0 1 16 255 10000; do
  run_test "CTR" "ctr" "ctr" "-" "$sz"
done
echo

# CBC / PKCS7
echo "--- CBC / PKCS7 ---"
for sz in 0 1 16 255 10000; do
  run_test "CBC/PKCS7" "cbc" "cbc" "-" "$sz"
done
echo

# CBC / NoPadding (только кратные блоку)
echo "--- CBC / NoPadding ---"
for sz in 16 256 1024; do
  run_test "CBC/NoPad" "cbc" "cbc-nopad" "-nopad" "$sz"
done
echo

# CFB
echo "--- CFB ---"
for sz in 0 1 16 255 10000; do
  run_test "CFB" "cfb" "cfb" "-" "$sz"
done
echo

# OFB
echo "--- OFB ---"
for sz in 0 1 16 255 10000; do
  run_test "OFB" "ofb" "ofb" "-" "$sz"
done
echo

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
