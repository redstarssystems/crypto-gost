# Echo-сервер

    # Запуск с L cipher suite, без mTLS
    java -cp crypto-gost-tls13/target/classes:crypto-gost-core/target/classes \
        org.rssys.gost.tls13.examples.TlsEchoServer \
        --port 4443 --cert /path/to/server.p12 --password changeit --cipher L

Параметры:

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 66%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Флаг</th>
<th style="text-align: left;">Описание</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><code>--port</code></p></td>
<td style="text-align: left;"><p>TCP-порт (по умолчанию 4443)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>--cert</code></p></td>
<td style="text-align: left;"><p>PKCS#12 с серверным сертификатом и
ключом</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>--password</code></p></td>
<td style="text-align: left;"><p>Пароль PKCS#12</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>--cipher</code></p></td>
<td style="text-align: left;"><p><code>L</code> (0xC103) или
<code>S</code> (0xC105)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>--mtls</code></p></td>
<td style="text-align: left;"><p>Запросить клиентский
сертификат</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>--ca</code></p></td>
<td style="text-align: left;"><p>PKCS#12 с CA + пароль (для
mTLS)</p></td>
</tr>
</tbody>
</table>

# Генерация тестовых сертификатов

    # CA
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:id-tc26-gost-3410-2012-256-paramSetA \
        -keyout ca.key -out ca.pem -days 365 -nodes -subj "/CN=Test CA"

    # Server
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:id-tc26-gost-3410-2012-256-paramSetA \
        -keyout server.key -out server.csr -nodes -subj "/CN=localhost"
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -out server.pem -days 365 -extfile <(echo "subjectAltName=DNS:localhost")
    openssl pkcs12 -export -in server.pem -inkey server.key -out server.p12 -passout pass:changeit

    # Client (для mTLS)
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:id-tc26-gost-3410-2012-256-paramSetA \
        -keyout client.key -out client.csr -nodes -subj "/CN=Test Client"
    openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -out client.pem -days 365
    openssl pkcs12 -export -in client.pem -inkey client.key -out client.p12 -passout pass:changeit

OpenSSL по умолчанию не поддерживает RFC 9367 cipher suites. Генерация
сертификатов работает (ГОСТ Р 34.10-2012 + Streebog signature), но
TLS-соединение через стандартный `openssl s_client` не установится.

# Известные ограничения

- Magma cipher suites не реализованы

- 0-RTT не поддерживается

- HelloRetryRequest не поддерживается (только GC256A в key\_share)

Для браузерного interop-тестирования есть `InteropTestServer`:

    java -cp crypto-gost-tls13/target/classes:crypto-gost-core/target/classes \
        org.rssys.gost.tls13.examples.InteropTestServer --port 8443

Откройте `https://<ip>:8443/` в браузере (самоподписанный сертификат —
примите предупреждение).
