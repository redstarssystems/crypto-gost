# Цель

Проверить, что реализация JSSE ([JSSE
API](https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html))
библиотеки crypto-gost корректно взаимодействует с эталонной реализацией
OpenSSL (патченая сборка 3.6 с gostprov) на уровне:

- `GostSSLSocket` / `GostSSLServerSocket` (InputStream/OutputStream API)

- `GostSSLEngine` (wrap/unwrap ByteBuffer API)

Оба API должны быть совместимы с OpenSSL `s_client` и `s_server` для TLS
1.3 + ГОСТ.

# Методология

## Серверные тесты

crypto-gost выступает в роли сервера, OpenSSL `s_client` — в роли
клиента.

1.  crypto-gost создаёт `GostSSLEngine` (серверный режим) или
    `GostSSLServerSocket`

2.  Открывает TCP-порт, ждёт подключения

3.  `s_client` подключается, выполняет TLS 1.3 handshake

4.  `s_client` отправляет `GET / HTTP/1.0\nHost: example.com\n\n`

5.  Сервер отвечает `HTTP/1.1 200 OK\n...INTEROP_OK`

6.  Проверяется, что `s_client` получил строку `INTEROP_OK`

## Клиентские тесты

OpenSSL `s_server` — в роли сервера, crypto-gost — в роли клиента.

1.  `s_server` запускается с ГОСТ-сертификатом на случайном порту

2.  crypto-gost создаёт `GostSSLEngine` (клиентский режим) или
    `GostSSLSocket`

3.  Выполняется TLS 1.3 handshake

4.  crypto-gost отправляет `GET / HTTP/1.0\nHost: localhost\n\n`

5.  Проверяется, что ответ содержит информацию о соединении

# Тестовые сценарии

## Engine-сервер (GostSSLEngine + wrap/unwrap + TCP)

Ручной цикл wrap/unwrap через ServerSocket — эмуляция неблокирующего IO.

<table>
<colgroup>
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Тест</p></td>
<td style="text-align: left;"><p>Сценарий</p></td>
<td style="text-align: left;"><p>Кривые</p></td>
<td style="text-align: left;"><p>Suite</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>roundtrip L</p></td>
<td style="text-align: left;"><p>GET → INTEROP_OK</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>roundtrip S</p></td>
<td style="text-align: left;"><p>GET → INTEROP_OK</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>S</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>все кривые</p></td>
<td style="text-align: left;"><p>handshake</p></td>
<td style="text-align: left;"><p>GC256B, GC512A, GC512B</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS</p></td>
<td style="text-align: left;"><p>взаимная аутентификация</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>payload</p></td>
<td style="text-align: left;"><p>1, 15, 16, 1024, 12000 байт</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>group mismatch</p></td>
<td style="text-align: left;"><p>сервер GC512C, клиент GC256B</p></td>
<td style="text-align: left;"><p>fallback</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>KeyUpdate</p></td>
<td style="text-align: left;"><p>initiateKeyUpdate() после
handshake</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
</tbody>
</table>

## Engine-клиент (s\_server + GostSSLEngine)

<table>
<colgroup>
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Тест</p></td>
<td style="text-align: left;"><p>Сценарий</p></td>
<td style="text-align: left;"><p>Кривые</p></td>
<td style="text-align: left;"><p>Suite</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>roundtrip L</p></td>
<td style="text-align: left;"><p>GET → ответ</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>roundtrip S</p></td>
<td style="text-align: left;"><p>GET → ответ</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>S</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>все кривые</p></td>
<td style="text-align: left;"><p>handshake</p></td>
<td style="text-align: left;"><p>GC256B, GC512A, GC512B</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
</tbody>
</table>

## Socket-сервер (GostSSLServerSocket + s\_client)

<table>
<colgroup>
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Тест</p></td>
<td style="text-align: left;"><p>Сценарий</p></td>
<td style="text-align: left;"><p>Кривые</p></td>
<td style="text-align: left;"><p>Suite</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>roundtrip L</p></td>
<td style="text-align: left;"><p>GET → INTEROP_OK</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>roundtrip S</p></td>
<td style="text-align: left;"><p>GET → INTEROP_OK</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>S</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>mTLS</p></td>
<td style="text-align: left;"><p>взаимная аутентификация</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
</tbody>
</table>

## Socket-клиент (s\_server + GostSSLSocket)

<table>
<colgroup>
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
<col style="width: 20%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Тест</p></td>
<td style="text-align: left;"><p>Сценарий</p></td>
<td style="text-align: left;"><p>Кривые</p></td>
<td style="text-align: left;"><p>Suite</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>roundtrip L</p></td>
<td style="text-align: left;"><p>GET → ответ</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"><p>roundtrip S</p></td>
<td style="text-align: left;"><p>GET → ответ</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>S</p></td>
<td style="text-align: left;"></td>
</tr>
</tbody>
</table>

# Покрытие

- 23 тестовых сценария (22 активных + 1 @Disabled KeyUpdate)

- 3 кривые: GC256B (CryptoPro-A), GC512A (TC26-512A), GC512B (TC26-512B)

- 2 cipher suites: L и S

- 2 API: SSLEngine и SSLSocket

- 5 размеров payload

- mTLS

- Group mismatch (fallback)

- KeyUpdate (@Disabled до подтверждения OpenSSL)

# Требования к окружению

- OpenSSL 3.6+ с gostprov (патченая сборка)

- GOST TLS 1.3 cipher suites:
  `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L` (0xC103) и
  `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S` (0xC105)

- Java 21+ (virtual threads)

- Maven 3.8+
