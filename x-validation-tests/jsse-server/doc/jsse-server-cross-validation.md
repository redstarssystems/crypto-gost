# Цель

Проверить, что embedded-серверы приложений (Jetty 12, Tomcat 11,
Undertow 2), сконфигурированные с crypto-gost JSSE, корректно
взаимодействуют с OpenSSL `s_client` на уровне TLS 1.3 + ГОСТ.

В отличие от `x-validation-tests/jsse` (raw GostSSLEngine/GostSSLSocket
↔ OpenSSL), эти тесты проверяют HTTP-уровень через серверное middleware:
SNI-обработку, session ticket passthrough, mTLS с внешним сертификатом,
Tomcat SSLUtil-обёртку.

# Методология

## Серверные тесты (roundtrip)

1.  `RssysGostJsseProvider` регистрируется в `java.security.Security`

2.  Создаётся `SSLContext` с явным указанием провайдера:
    `SSLContext.getInstance("TLSv1.3", "RssysGostJsse")`

3.  SSLContext инициализируется `GostX509KeyManager` и
    `GostX509TrustManager` через `CryptoRandom.INSTANCE`

4.  Запускается embedded-сервер (Jetty/Tomcat/Undertow) на случайном
    порту

5.  `openssl s_client` подключается с
    `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L`, отправляет
    `GET / HTTP/1.0`

6.  Вывод s\_client вычитывается асинхронно (виртуальный поток) —
    pipe-буфер ОС (64KB) может переполниться

7.  Проверяется, что ответ содержит `INTEROP_OK`

## mTLS-тесты (Tomcat, Jetty)

1.  Создаётся **самоподписанный** (self-signed) клиентский сертификат
    через `TlsTestHelper.createCertWithKey()`

2.  Сервер доверяет публичному ключу клиента напрямую через
    `GostX509TrustManager(peerPub, false)` (pinning)

3.  Сервер запускается с `needClientAuth=true`

4.  `openssl s_client -cert -key -sigalgs gostr34102012_256b`
    подключается

5.  Проверяется HTTP 200 / INTEROP\_OK

Примечание: OpenSSL 3.x не принимает CA-подписанный ГОСТ-сертификат из
PEM-файла (`SSL_CTX_use_certificate:ca md too weak` — не распознаёт
схему подписи CA). Self-signed сертификат обходит это ограничение, а
pinning через `GostX509TrustManager` делает CA-цепочку ненужной.

Флаг `-sigalgs gostr34102012_256b` обязателен для mTLS: без него OpenSSL
не выбирает ГОСТ-схему подписи для CertificateVerify.

# Тестовые сценарии

<table>
<colgroup>
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Тест</p></td>
<td style="text-align: left;"><p>Сервер</p></td>
<td style="text-align: left;"><p>OpenSSL</p></td>
<td style="text-align: left;"><p>Сценарий</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>testServerRoundtrip</p></td>
<td style="text-align: left;"><p>Tomcat / Jetty / Undertow</p></td>
<td style="text-align: left;"><p>s_client GET</p></td>
<td style="text-align: left;"><p>HTTP 200 → INTEROP_OK</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>testMtls</p></td>
<td style="text-align: left;"><p>Tomcat / Jetty</p></td>
<td style="text-align: left;"><p>s_client -cert -sigalgs</p></td>
<td style="text-align: left;"><p>mTLS → INTEROP_OK</p></td>
</tr>
</tbody>
</table>

# Покрытие

- 2 тестовых класса, 5 проверок (3 roundtrip + 2 mTLS)

- 3 сервера: Tomcat 11, Jetty 12, Undertow 2.3

- 1 cipher suite: L

- 1 кривая: GC256B (CryptoPro-A)

- graceful skip при отсутствии OpenSSL с GOST TLS 1.3

# Что НЕ входит

- Netty — отдельный модуль `crypto-gost-netty` с собственными тестами

- PSK resumption через s\_client — покрыт в `x-validation-tests/jsse` и
  `examples/jsse`

- Undertow mTLS — обвязка прозрачна (`addHttpsListener(ctx)`), риск
  дефекта ≈ 0

- POST/chunked/raw — тестирование HTTP-парсера, не JSSE

# Требования к окружению

- OpenSSL 3.6+ с gostprov (патченая сборка)

- GOST TLS 1.3 cipher suite
  (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L`)

- Java 21+

- Maven 3.8+

# Известные ограничения

- CA-подписанный клиентский ГОСТ-сертификат не может быть загружен через
  `s_client -cert` (OpenSSL `ca md too weak`); используется self-signed
  с pinning

- 30-секундный таймаут `s_client` с асинхронным drain stdout через
  виртуальный поток (предотвращает deadlock при переполнении
  pipe-буфера)
