# Цели

Юнит-тесты и KAT-векторы проверяют отдельные криптографические
примитивы, но не гарантируют протокольную совместимость. TLS 1.3 —
многоэтапный протокол: расхождение может скрываться в порядке
формирования транскрипта, выборе группы key\_share, echo-отражении
legacy\_session\_id или wire-формате сертификата.

Кросс-валидация закрывает три цели:

1.  **Протокольная совместимость** — crypto-gost успешно выполняет
    полный TLS 1.3 handshake с OpenSSL 3.6.0 (gostprov + патч TLS 1.3) и
    обменивается прикладными данными.

2.  **Корректность key schedule** — traffic keys совпадают на обеих
    сторонах; MGM-тег каждой записи верифицируется принимающей стороной.

3.  **Граничные размеры payload** — TLSTREE re-keying и MGM-AEAD
    корректны на данных от 1 до 12 000 байт, покрывая границу блока
    Кузнечика.

# Предусловия

## OpenSSL с поддержкой ГОСТ TLS 1.3

Необходимы OpenSSL 3.6.0 + gostprov, пересобранные с патчем TLS 1.3
gost-engine. [Инструкция по
сборке.](../../doc/openssl-3.6-gost-how-to.md)

Проверить готовность (провайдер подставить по конфигурации):

    openssl ciphers -s -tls1_3 \
        -ciphersuites TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L
    # Ожидаемый вывод: TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L

## Маппинг OpenSSL paramset → кривые Java

`gost2012_256 paramset:A` в OpenSSL соответствует CryptoPro-A (GC256B),
а не TC26-A-256. Для 512-бит маппинг прямой.

<table style="width:100%;">
<colgroup>
<col style="width: 28%" />
<col style="width: 28%" />
<col style="width: 14%" />
<col style="width: 28%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">OpenSSL algo + paramset</th>
<th style="text-align: left;">Java ECParameters</th>
<th style="text-align: left;">NamedGroup</th>
<th style="text-align: left;">Схема подписи</th>
</tr>
</thead>
<tbody>
<tr>
<td
style="text-align: left;"><p><code>gost2012_256 paramset:A</code></p></td>
<td
style="text-align: left;"><p><code>ECParameters.cryptoProA()</code></p></td>
<td style="text-align: left;"><p>GC256B (0x0023)</p></td>
<td style="text-align: left;"><p><code>gostr34102012_256b</code>
(0x070A)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>gost2012_512 paramset:A</code></p></td>
<td
style="text-align: left;"><p><code>ECParameters.tc26a512()</code></p></td>
<td style="text-align: left;"><p>GC512A (0x0026)</p></td>
<td style="text-align: left;"><p><code>gostr34102012_512a</code>
(0x070D)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>gost2012_512 paramset:B</code></p></td>
<td
style="text-align: left;"><p><code>ECParameters.tc26b512()</code></p></td>
<td style="text-align: left;"><p>GC512B (0x0027)</p></td>
<td style="text-align: left;"><p><code>gostr34102012_512b</code>
(0x070E)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>gost2012_256 paramset:TCA</code></p></td>
<td
style="text-align: left;"><p><code>ECParameters.tc26a256()</code></p></td>
<td style="text-align: left;"><p>GC256A (0x0022)</p></td>
<td style="text-align: left;"><p><code>gostr34102012_256a</code>
(0x0709)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>gost2012_512 paramset:C</code></p></td>
<td
style="text-align: left;"><p><code>ECParameters.tc26c512()</code></p></td>
<td style="text-align: left;"><p>GC512C (0x0028)</p></td>
<td style="text-align: left;"><p><code>gostr34102012_512c</code>
(0x070F)</p></td>
</tr>
</tbody>
</table>

GC256A и GC512C имеют кофактор 4: ECDHE на них считается как `(h·d)·Q`
(RFC 9367 §6.1.1). Кривые с кофактором 1 такую ошибку не выявляют,
поэтому эти две кривые обязательны в матрице. GC256C, GC256D: нет
подтверждённого маппинга OpenSSL paramset.

# Что и как проверяется

## Группа 1: crypto-gost-сервер ← OpenSSL-клиент (s\_client)

crypto-gost-сервер и `openssl s_client` запускаются на свободном порту;
s\_client передаются флаги `-servername example.com -ign_eof`.

Сервер обрабатывает HTTP GET или сырые байты и эхо-возвращает их.

Проверяется:

1.  crypto-gost-сервер не выбросил исключений.

2.  Ответ s\_client содержит маркер `INTEROP_OK`.

3.  Для payload-тестов дополнительно: сервер получил ровно те же байты,
    что отправлены.

## Группа 2: OpenSSL-сервер (s\_server) ← crypto-gost-клиент

`s_server` с флагом `-sigalgs` выбирает ГОСТ-схему подписи для
`CertificateVerify`. Клиент crypto-gost валидирует сертификат и схему
подписи по RFC 8446 + 9367.

# Матрица тестов

<table>
<colgroup>
<col style="width: 38%" />
<col style="width: 12%" />
<col style="width: 12%" />
<col style="width: 12%" />
<col style="width: 12%" />
<col style="width: 12%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Тест</th>
<th style="text-align: left;">Suite</th>
<th style="text-align: left;">Кривые</th>
<th style="text-align: left;">mTLS</th>
<th style="text-align: left;">Payload</th>
<th style="text-align: left;">Статус</th>
</tr>
</thead>
<tbody>
<tr>
<td
style="text-align: left;"><p><code>testServerRoundtrip</code></p></td>
<td style="text-align: left;"><p>L и S</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (2 теста)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>testServerAllCurves</code></p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"><p>GC256B, GC512A, GC512B</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (3 теста)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>testServerMtls</code></p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>✓</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>testServerPayload</code></p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>1, 15, 16, 1024, 12 000 байт</p></td>
<td style="text-align: left;"><p>✓ (5 тестов)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>testServerGroupMismatch</code></p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"><p>клиент GC256B, сервер GC512C</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>testClientRoundtrip</code></p></td>
<td style="text-align: left;"><p>L и S</p></td>
<td style="text-align: left;"><p>GC256B</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (2 теста)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>testClientAllCurves</code></p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"><p>GC256B, GC512A, GC512B</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>—</p></td>
<td style="text-align: left;"><p>✓ (3 теста)</p></td>
</tr>
</tbody>
</table>

Итого по этой матрице: **17 активных тестов**. Возобновление по PSK
описано в отдельном разделе ниже.

# Возобновление по PSK

Тесты `OpenSslTls13ResumptionCrossValidationTest` проверяют, что второе
соединение возобновляется по тикету, на обеих сторонах и с обменом
данными. Тикет выдаёт внешняя сторона, предъявляет его вторая; стенд -
OpenSSL gostprov, `s_client -sess_out/-sess_in` и `s_server`.

<table style="width:100%;">
<colgroup>
<col style="width: 42%" />
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 28%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Тест</th>
<th style="text-align: left;">Suite</th>
<th style="text-align: left;">Кривые</th>
<th style="text-align: left;">Статус</th>
</tr>
</thead>
<tbody>
<tr>
<td
style="text-align: left;"><p><code>clientResumesAgainstOpenSslServer</code>:
клиент crypto-gost, <code>s_server</code>; стартовая группа клиента
(<code>withSelectedNamedGroup</code>) совпадает с кривой сервера,
HelloRetryRequest нет</p></td>
<td style="text-align: left;"><p>L и S</p></td>
<td style="text-align: left;"><p>GC256B, GC256A</p></td>
<td style="text-align: left;"><p>✓ (4 теста)</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>serverResumesOpenSslClient</code>:
<code>s_client</code>, сервер crypto-gost</p></td>
<td style="text-align: left;"><p>L и S</p></td>
<td style="text-align: left;"><p>GC256B, GC256A</p></td>
<td style="text-align: left;"><p>✓ (4 теста)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>clientResumesThroughHrr</code>:
клиент crypto-gost со стартовой группой по умолчанию (GC256B),
<code>s_server</code></p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"><p>GC256A (HelloRetryRequest в каждом
соединении)</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>serverResumesThroughHrr</code>:
<code>s_client -curves GC256B:GC256A</code>, сервер crypto-gost</p></td>
<td style="text-align: left;"><p>L</p></td>
<td style="text-align: left;"><p>GC256A (HelloRetryRequest в каждом
соединении)</p></td>
<td style="text-align: left;"><p>✓</p></td>
</tr>
</tbody>
</table>

Клиент `TlsSession` по умолчанию начинает с группы GC256B;
`TlsClientConfig.withSelectedNamedGroup` задаёт другую. Были ли в
соединении два ClientHello (то есть HelloRetryRequest), тесты определяют
по числу открытых handshake-записей
(`HandshakeRecordCountingTransport`). Binder второго ClientHello
считается по RFC 8446 §4.2.11.2 (один хэш от `message_hash`,
HelloRetryRequest и усечённого ClientHello); OpenSSL проверяет его
независимо. Возобновление с КриптоПро описано в
`x-validation-tests/cryptopro/README.adoc`.

# Тестовые размеры payload

<table>
<colgroup>
<col style="width: 33%" />
<col style="width: 66%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Размер</th>
<th style="text-align: left;">Цель</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p>1</p></td>
<td style="text-align: left;"><p>Один байт — граничный случай MGM,
неполный блок Кузнечика.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>15</p></td>
<td style="text-align: left;"><p>Максимальный неполный блок (16 − 1
байт).</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>16</p></td>
<td style="text-align: left;"><p>Ровно один блок Кузнечика.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>1 024</p></td>
<td style="text-align: left;"><p>Реалистичный малый HTTP-ответ.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p>12 000</p></td>
<td style="text-align: left;"><p>Проверяет корректность seqNum при
фрагментации и что <code>runSClientWithData</code> не блокируется на
Linux pipe buffer (64 КБ).</p></td>
</tr>
</tbody>
</table>

Размер 64 КБ и выше не включён — `runSClientWithData` передаёт данные
через stdin process pipe. Запись блокируется если pipe buffer заполнен,
а `s_client` не читает до завершения handshake. Требуется асинхронная
запись в отдельном треде.

# Структура модуля

    x-validation-tests/tls13/
      pom.xml
      doc/tls13-cross-validation.adoc
      src/test/java/.../crossval/tls13/
        OpenSslTls13Helper.java               — управление subprocess: s_client, s_server,
                                                автодетект провайдера, генерация PKI через OpenSSL
        OpenSslTls13CrossValidationTest.java  — JUnit 5: 17 активных тестов

## Технические решения

**`Thread.sleep(200)` перед s\_client.** Компенсирует время запуска
серверного треда до `ss.accept()`. `CountDownLatch` передан в серверный
тред, но `await()` не вызывается — фактическая синхронизация остаётся на
`sleep(200)`.

**Graceful skip.** Если пропатченный OpenSSL недоступен —
`assumeGostTls13()` вызывает `Assumptions.assumeTrue(false)`, тесты
помечаются как skipped, сборка остаётся зелёной.

**PKI для mTLS.** `generateMtlsPKI` создаёт CA и серверный
ключ/сертификат через crypto-gost (`PkixCertTestHelper`), затем
упаковывает серверный сертификат в PFX через `openssl pkcs12 -export` —
это проверяет wire-совместимость формата с тем, что ожидает s\_client.
Клиентский сертификат создаётся отдельно в `runServerTest()` через
`PkixCertTestHelper.createCertWithKey()` (crypto-gost), PEM записывается
во временный файл и передаётся s\_client через `-cert` / `-key`.
`MtlsPkiResult.clientCertPem = null`.

**Сертификаты без mTLS через `PkixCertTestHelper`.**
`createCertWithKey()` генерирует самоподписанный сертификат на стороне
crypto-gost. s\_client принимает его без проверки цепочки.

**Автодетект провайдера (`resolveTls13Flags()`).** Порядок проверок:

1.  `openssl-gost.cnf` рядом с бинарником (только при абсолютном пути к
    OpenSSL) — флаги не нужны, провайдер задаётся через `OPENSSL_CONF`.

2.  `-provider gost -provider default`

3.  `-provider gostprov -provider default`

4.  `-provider-path .../ossl-modules -provider gostprov -provider default`
    (при наличии кастомного корня)

5.  Fallback: `-engine gost`

Результат кешируется в `cachedTls13Flags`.

# Запуск

    # Стандартная сборка из doc/openssl-3.6-gost-how-to.md
    mvn -Pcrossval test -pl x-validation-tests/tls13 -am \
        -Dsurefire.failIfNoSpecifiedTests=false

    # openssl в кастомном пути
    mvn -Pcrossval test -pl x-validation-tests/tls13 -am \
        -Dopenssl.binary=/opt/openssl-3.6.0-gost/bin/openssl \
        -Dsurefire.failIfNoSpecifiedTests=false

    # Только payload-тесты
    mvn -Pcrossval test -pl x-validation-tests/tls13 -am \
        -Dtest="OpenSslTls13CrossValidationTest#testServerPayload" \
        -Dsurefire.failIfNoSpecifiedTests=false

    # Только mTLS-тест
    mvn -Pcrossval test -pl x-validation-tests/tls13 -am \
        -Dtest="OpenSslTls13CrossValidationTest#testServerMtls" \
        -Dsurefire.failIfNoSpecifiedTests=false

Без пропатченного OpenSSL сборка упадёт с ошибкой — кросс-валидация
требует рабочего окружения для проверки.
