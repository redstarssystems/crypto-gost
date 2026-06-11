#!/usr/bin/env bash
set -euo pipefail

# Пример клиента на базе OpenSSL + GOST: отправляет файл на FileReceiveServer по TLS 1.3

OPENSSL=${OPENSSL:-/opt/openssl-3.6.0-gost/bin/openssl}
HOST=${HOST:-127.0.0.1}
PORT=${PORT:-8443}

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <file> [host] [port]" >&2
    echo "  OPENSSL=/path/to/openssl $0 <file>   # custom openssl binary" >&2
    echo "  TIMEOUT=600 $0 <file>                # явный таймаут (сек)" >&2
    exit 1
fi

FILE=$1
[[ ${2-} ]] && HOST=$2
[[ ${3-} ]] && PORT=$3

if [[ ! -f "$FILE" ]]; then
    echo "Error: file not found: $FILE" >&2
    exit 1
fi

SIZE=$(wc -c < "$FILE" | tr -d ' ')

# Динамический таймаут: 5 МБ/с консервативная оценка + 60 сек запас.
# Переопределить: TIMEOUT=600 ./send-file.sh bigfile
if [[ -z "${TIMEOUT:-}" ]]; then
    TIMEOUT=$(( SIZE / 5242880 + 60 ))
fi

echo "Sending: $FILE ($SIZE bytes) -> $HOST:$PORT (timeout: ${TIMEOUT}s)"

# timeout нужен потому что openssl s_client с -ign_eof ждёт
# закрытия соединения со стороны сервера; || true чтобы timeout (exit 124)
# не останавливал скрипт через set -e
RESPONSE=$(
    (
        printf "POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: application/octet-stream\r\nContent-Length: %s\r\nX-Filename: %s\r\nConnection: close\r\n\r\n" \
            "$HOST" "$SIZE" "$(basename "$FILE")"
        cat "$FILE"
    ) | timeout "$TIMEOUT" "$OPENSSL" s_client \
        -connect "${HOST}:${PORT}" \
        -tls1_3 \
        -ciphersuites TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L \
        -curves GC256B \
        -servername "$HOST" \
        -provider-path /opt/openssl-3.6.0-gost/lib/ossl-modules \
        -provider gostprov \
        -provider default \
        -quiet \
        -ign_eof \
        2>/dev/null
) || true

echo "Sent."

STATUS=$(printf '%s' "$RESPONSE" | head -1 | tr -d '\r\n')
BODY=$(printf '%s' "$RESPONSE" | awk 'found && /[^ \t]/{print; found=0} /^\r?$/{found=1}' | tr -d '\r')

if [[ -n "$STATUS" ]]; then
    echo "Status:   $STATUS"
fi
if [[ -n "$BODY" ]]; then
    echo "Response: $BODY"
fi