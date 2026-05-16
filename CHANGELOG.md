# \[0.3.0\] - 16-05-2026

## Общее

- Добавлен `.mvn/maven-config` для управления версией библиотеки из
  единого места.

- В корневой Makefile добавлены цели:

  - `doc` - для формирования документов md, на основе asciidoc.

  - `version` - для управления и обновления версией библиотеки

## Целевая платформа - JDK 21

Для JSSE-провайдера это означает: архитектура с самого начала должна
минимизировать зависимость от sun.security.ssl.\*. Дело в том, что API,
связанное с TLS значительно стабилизировалось только к JDK17: исправлены
десятки багов в state machine, session resumption, post-handshake auth,
0-RTT обработке.  

С JDK 17 по JDK 21 также произошли значительные улучшения и исправления
в TLS 1.3: post-handshake authentication, session ticket handling,
лучшая обработка middlebox compatibility mode, исправления в HKDF
использовании.  

Вирутальные потоки - важная вещь для производительности JSSE модуля.

JEP 452 — Key Encapsulation Mechanism API в JDK 21 заметное изменение
для криптографического стека. Появился javax.crypto.KEM —
стандартизированная абстракция для механизмов инкапсуляции ключей.

Постквантовые алгоритмы — это KEM по природе. TLS 1.3 hybrid key
exchange (RFC 9180-style) тоже мыслится в терминах KEM.

В ядре Mgm-режим, а значит TLS 1.3 может быть кратно ускорен благодаря
арифметике доступной в Java 21.

**Поэтому по совокупности факторов мной принято решение вести дальнейшую
разработу всех модулей под JDK 21.**

Старые версии (0.2.1 и ниже) для модулей `crypto-gost-core`,
`crypto-gost-tls13` остались доступны под JDK 11. Их можно скачать из
опубликованных релизов.

## Модуль crypto-gost-core.

Переход JDK 11 → JDK 21.

Было:

Кузнечик и MGM работали на байтовых массивах. Каждый 16-байтовый блок —
это byte\[16\], который создавался заново на каждой операции. Таблицы
подстановки хранились как byte\[\]\[\]\[\]. GF(2^128) умножение делалось
побитово — 128 итераций, каждая сдвигала 16 байт по одному.  
**Итог:** 4–6 МБ/с на TLS-записях.

Стало:

- Блок как два long вместо byte\[16\]. 128-битное состояние хранится как
  пара (hi, lo) — JIT держит их в регистрах, никаких аллокаций на
  горячем пути.

- Таблицы переупакованы в long\[\]\[\] с встроенной S-заменой. Вместо
  двух lookup-ов на байт (T\[i\]\[PI\[x\]\]) — один (T\_S\[i\]\[x\]).
  Вместо 256 байтовых XOR на раунд — 32 длинных.

- GF(2^128) переведён на 4-битный Horner. Вместо 128 однобитных итераций
  — 32 итерации по nibble с предвычисленной таблицей на 16 элементов.
  ~1.75× быстрее на MAC-шаге MGM.  

**Итог:** 4–6 МБ/с → 48–49 МБ/с на 16KB TLS-записях. Ускорение ~9× на
чистой Java, без нативного кода, без изменения протокола.

Остальные режимы: CBC, CFB, CTR, OFB - тоже кратно ускорены примерно в
8-9 раз, но бенчмарки проводились для проверки только для CTR, CFB.

## Модуль crypto-gost-jsse

Новый модуль `crypto-gost-jsse` — JSSE-провайдер для ГОСТ TLS 1.3. Это
прослойка между стандартным JSSE-API (`SSLContext`, `SSLEngine`,
`SSLSocket`, `KeyManagerFactory`, `TrustManagerFactory`) и ядром
протокола из `crypto-gost-tls13`. После регистрации провайдера любой
существующий Java-код, работающий со стандартным `SSLContext`, начинает
работать с ГОСТ TLS 1.3 без изменений в самом коде.

    Security.addProvider(new RssysGostJsseProvider());
    SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");

Дальше — обычный JSSE-сценарий: `ctx.init(km, tm, null)`,
`ctx.createSSLEngine(host, port)`, `wrap()`/`unwrap()`. Это даёт ГОСТ
TLS в любом Java-стеке, который умеет работать с `SSLContext`:
HTTP-клиенты, JDBC-драйверы, message brokers, embedded HTTPS-серверы,
Netty.

### Что реализовано

JSSE API

- `RssysGostJsseProvider` — регистрация провайдера через
  `Security.addProvider`. Имена сервисов — без алиасов «TLS» и «PKIX»,
  чтобы случайно не подменить стандартный SunJSSE.

- `GostSSLContextSpi` — реализация `SSLContextSpi`: создание
  `SSLEngine`, `SSLSocketFactory`, `SSLServerSocketFactory`, управление
  `SSLSessionContext`.

- `GostSSLEngine` — реализация `SSLEngine` (wrap/unwrap state machine).
  Раздельные блокировки для inbound и outbound (JSSE допускает
  параллельный вызов wrap и unwrap из разных потоков). Дорогие операции
  — валидация сертификата, OCSP-fetch — выносятся в `NEED_TASK`, чтобы
  не блокировать carrier thread виртуального потока.

- `GostSSLSession` — реализация `SSLSession`: peer-сертификаты, cipher
  suite, выбранный ALPN-протокол, время создания сессии.

- `GostSSLSessionContext` — реализация `SSLSessionContext` с
  LRU-эвикцией: настраиваемый размер кэша (`setSessionCacheSize`) и
  время жизни (`setSessionTimeout`).

SSLSocket

- `GostSSLSocket` / `GostSSLServerSocket` — реализация `SSLSocket`
  поверх обычного TCP-сокета. Поддерживает layered socket (как
  использует `HttpsURLConnection`), `HandshakeCompletedListener`,
  параллельное чтение и запись из разных потоков, `setSoTimeout`.

- `GostSSLSocketFactory` / `GostSSLServerSocketFactory` — фабрики
  сокетов, доступные через `ctx.getSocketFactory()`.

Key/Trust managers

- `GostKeyManagerFactorySpi` + `GostX509KeyManager` — управление ключами
  из стандартного `KeyStore` (PKCS12 с ГОСТ-ключами читается
  JDK-средствами через JCA-провайдер `crypto-gost-core`).

- `GostTrustManagerFactorySpi` + `GostX509TrustManager` — валидация
  цепочки сертификатов пира через `TlsCertificateValidator` из
  `crypto-gost-tls13`. Реализует `X509ExtendedTrustManager` — все шесть
  методов `checkClientTrusted`/`checkServerTrusted` (без контекста, с
  `Socket`, с `SSLEngine`).

OCSP — четыре политики

- `OcspPolicy.DISABLED` — OCSP-проверка отключена.

- `OcspPolicy.IF_PRESENT` — проверять только если OCSP-ответ
  присутствует (stapled). Если нет — fail-open.

- `OcspPolicy.STAPLING_REQUIRED` — OCSP stapling обязателен, без него
  соединение отклоняется.

- `OcspPolicy.STAPLING_OR_FETCH` — сначала пробуем stapled-ответ, при
  его отсутствии — fetch с CA через HTTP.

- `JdkHttpOcspFetcher` — реализация OCSP fetcher через стандартный
  `HttpURLConnection`. Извлекает URI ответчика из AuthorityInfoAccess
  сертификата, отправляет POST с подписанным OCSP-запросом.

- `OcspRequestBuilder` — построение OCSP-запроса с поддержкой nonce
  (RFC 8954) и опциональной подписи (RFC 6960 §3.1).

- Кеширование OCSP-ответов с настраиваемым TTL (по умолчанию час). Кэш
  разделяет ответы по `(issuerSerialHex, certSerialHex)`.

Bridge между JSSE и tls13

- `CertificateBridge` — конверсия `java.security.cert.X509Certificate`
  (JCA-тип) ↔ `TlsCertificate` (tls13-тип).

- `KeyBridge` — конверсия `java.security.PrivateKey` ↔
  `PrivateKeyParameters` (tls13-тип).

- `IanaMapper` — маппинг IANA-имён cipher suite и signature scheme
  (например, `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L`) в числовые
  коды tls13. Нужен потому, что JSSE задаёт настройки строками, а tls13
  — числами.

- `AlertMapper` — конверсия TLS-алертов в `SSLException` подклассы
  (`SSLHandshakeException`, `SSLProtocolException`).

### Поддерживаемые JSSE-features

- Server-only TLS (стандартный HTTPS).

- mTLS: `setNeedClientAuth(true)` и `setWantClientAuth(true)` —
  обязательный и опциональный клиентский сертификат.

- ALPN (RFC 7301) через `SSLParameters.setApplicationProtocols`.

- SNI (RFC 6066) через `SSLParameters.setServerNames` — на клиенте, и
  multi-tenant выбор сертификата по hostname — на сервере.

- `KeyUpdate` (RFC 8446 §4.6.3): авто-инициация при приближении к SNMAX
  cipher suite, защита от флуда (не больше 32 KeyUpdate за сессию).

- Корректное закрытие через `closeOutbound`/`closeInbound`: обмен
  `close_notify` алертами, затирание ключей.

- `HandshakeCompletedListener` для `SSLSocket`.

### Дополнительный модуль crypto-gost-netty

Модуль `crypto-gost-netty` — обёртка для интеграции с Netty. Содержит
`GostSslContextBuilder` — билдер `io.netty.handler.ssl.SslContext`
поверх `GostSSLContext`. Позволяет использовать ГОСТ TLS в любом
приложении на Netty: gRPC, Reactor Netty, Vert.x. Через эту цепочку ГОСТ
TLS доступен в Spring WebFlux, RSocket и других reactive-стеках.

### Тестирование

- 86 unit-тестов: контрактные проверки `SSLEngine` initial state,
  loopback handshake клиент-сервер через `SSLEngine`, post-handshake
  (KeyUpdate, NewSessionTicket), ALPN-селектор, eviction
  `SSLSessionContext`.

- Тесты `GostSSLSocket` через реальные TCP-сокеты (loopback): обмен
  данными, mTLS, передача 100 КБ, последовательные соединения,
  auto-handshake при первой операции записи, layered socket как у
  `HttpsURLConnection`, `HandshakeCompletedListener`, параллельное
  чтение/запись из разных потоков, PSK resumption между двумя
  TCP-соединениями, разрыв соединения узлом, `SocketTimeoutException`
  при молчащем узле.

- Тест с встроенным HTTPS-сервером на `GostSSLServerSocket` через
  `HttpsURLConnection`-запрос — проверка реального HTTP-over-TLS
  сценария.

- OCSP-тесты: построение запроса с nonce и подписью, верификация политик
  (DISABLED, IF\_PRESENT, STAPLING\_REQUIRED), HTTP-fetch.

- Тесты `GostX509KeyManager`: выбор сертификата по issuer hint
  (`chooseClientAlias` с массивом issuers от сервера).

- Бенчмарки JMH (`bench/jsse`): `JsseHandshakeBench` (полный handshake,
  mTLS), `JsseRecordBench` (wrap/unwrap на 100 B / 1 KB / 16 KB).
  Накладные расходы JSSE-обёртки на record-уровне — в пределах
  погрешности измерений.

### Целевые сценарии использования

- Embedded HTTPS-серверы (Tomcat, Jetty, Undertow) — через стандартную
  настройку `SSLContext` в `application.yml` или connector config.

- HTTP-клиенты (RestTemplate, WebClient, OkHttp, JDK HttpClient, Apache
  HttpClient) — через
  `SSLContext.getInstance("TLSv1.3", "RssysGostJsse")`.

- JDBC-драйверы (PostgreSQL, MySQL и другие) с поддержкой кастомного
  `SSLContext`.

- gRPC, Reactor Netty, Vert.x — через модуль `crypto-gost-netty`.

- Любой код, использующий стандартный JSSE-API.

### Текущие ограничения

- Не сертифицирован. Сертификации нет в планах. Библиотека
  позиционируется для коммерческого и внутреннего использования.

- TLS 1.2 + ГОСТ не поддерживается и не планируется в силу множественных
  слабостей TLS 1.2 — только TLS 1.3 (RFC 9367).

- `SSLSession` resumption через `SSLSessionContext` работает на уровне
  tls13 (PSK), но JSSE-уровневый lookup по `peerHost`/`peerPort`
  доработан не полностью.

- Не проверена кросс-совместимость с другими внешними ГОСТ TLS
  реализациями.

- HelloRetryRequest, 0-RTT, Magma-MGM cipher suites — не поддерживаются
  (наследуется от ограничений `crypto-gost-tls13`).

#### Изменено в GostSSLEngine

- `setUseClientMode(false)` больше не требует hostname для серверного
  engine. Ранее вызов `createSSLEngine()` без host (как делают
  Tomcat/Spring Boot) приводил к `IllegalArgumentException`. Теперь —
  `LOG.warning`: PSK resumption отключается, но базовый handshake
  выполняется штатно.

#### Примеры интеграции (examples/jsse)

Добавлен модуль `examples-jsse` (теперь `examples/jsse/`) — 5 примеров
интеграции с серверами приложений, проверяющих полный цикл: сертификаты
→ SSLContext → embedded server → TLS 1.3 handshake → echo-протокол.

- **Netty 4.2**: `GostSslContextBuilder.forServer(km)` +
  `ServerBootstrap` + inline Netty-клиент. CountDownLatch синхронизация.

- **Jetty 12**: `SslContextFactory.Server.setSslContext(sslContext)` +
  `Handler.Abstract` (Jetty 12 core handler API).

- **Undertow 2**:
  `Undertow.builder().addHttpsListener(port, host, sslContext)` — самый
  лаконичный вариант (3 строки конфигурации).

- **Tomcat 11 (Jakarta EE 10)**: кастомный `SSLImplementation` с
  вложенными `GostSSLImplementation`/`GostSSLUtil`. В обход
  `SSLUtilBase.getKeyManagers()` (требует keystore file). Работает через
  `connector.setProperty("sslImplementation", ...)` →
  `IntrospectionUtils` → `setSslImplementationName()`.

- **Spring Boot 3.4**: `WebServerFactoryCustomizer` +
  `SSLImplementation` (та же схема, что standalone Tomcat 11). Провайдер
  регистрируется в `static {}` — до инициализации Spring-контекста.

Makefile в `examples/jsse/`: цели `netty`, `jetty`, `undertow`,
`tomcat`, `springboot`, `all` (последовательно), `test`
(@SpringBootTest).

`@SpringBootTest` + `GostSSLSocket.startHandshake()`: подтверждает TLS
1.3 handshake с ГОСТ-наборами в embedded Tomcat.

#### Модуль crypto-gost-jsse-testkit

Вспомогательные классы для создания ГОСТ TLS-контекста в тестах и
примерах. Используется примерами `examples/jsse`, доступен для тестов
`crypto-gost-jsse`.

- `GostTestCerts.createServerCert()` — генерация CA + подписанного
  сертификата с SAN localhost. DER-кодирование вручную, без внешних
  ASN.1-зависимостей.

- `GostTestContext.buildSslContext(certs)` — регистрация провайдера
  (`Security.addProvider`) + создание `SSLContext` (`TLSv1.3`,
  `RssysGostJsse`) + инициализация key/trust managers.

- Позволяет создавать SSLContext одной строкой вместо 10 строк
  boilerplate.

- Может быть использован тестами `crypto-gost-jsse` для устранения
  дублирования `Security.addProvider` + `SSLContext.getInstance`.

Этот релиз исправляет ошибки и дает улучшения для производительности и
готовности к реализации следующего модуля JSSE.

Исправлено несколько мест, где на каждую TLS-запись создавались
временные массивы в памяти. Теперь данные передаются от сетевого буфера
до расшифровки без лишних копий. От этого GC стало меньше работы, а на
активных соединениях (сотни и тысячи записей в секунду) разница заметна.

Итог по аллокациям: отправка записи 2→1, чтение данных 4→1, чтение
handshake 3→0. Для сессии с 1000 записей/с нагрузка на GC снижена с 80
до 30 MB/s.

### Изменено

- PSK lookup на стороне сервера перенесён из TlsSession и jsse-слоя в
  `TlsHandshakeEngine.receiveClientHello()`. При получении ClientHello
  engine сам извлекает PSK identity, ищет в store
  (`setServerPskStore()`) и проверяет binder. Исключено дублирование
  парсинга ClientHello, устранён layer violation в jsse-модуле.

- TlsRecord, шифрование: tls-запись собирается прямо из входного буфера
  в выходной, минуя промежуточные копии в памяти.

- TlsRecord, расшифровка: массив под входящую tls-запись выделяется один
  раз при создании объекта и переиспользуется. Ранее каждая расшифровка
  создавала новый массив.

- Транспортный уровень: при приёме записи (Socket- и Channel-транспорты)
  все три временных массива (заголовок, тело, итоговая запись) заменены
  на один переиспользуемый буфер.

- Канальный транспорт (ChannelTlsTransport): теперь чтение через
  ByteBuffer идёт напрямую в канал, без промежуточных копий.

- Сессия: три ключевых пути — приём handshake, приём данных приложения,
  post-handshake сообщения — теперь используют цепочку ByteBuffer от
  транспорта до расшифровки, без промежуточных массивов.

### Добавлено

- Тест на регрессию шифрования: запись с известными ключами — защита от
  случайного изменения алгоритма.

- Тест на нехватку места в выходном буфере: если буфер слишком мал,
  метод сообщает об ошибке, не начиная шифрование.

- Тест на смещение указателей в ByteBuffer после шифрования.

- Тест на переиспользование буфера расшифровки: три расшифровки разного
  размера подряд через один объект — проверка, что остатки предыдущей
  записи не попадают в результат следующей.

- Тесты ByteBuffer-пути для канального транспорта: heap и direct буферы.

- Добавлены IANA-имена для cipher suite (например,
  `TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L`), именованных групп кривых
  (`GC256A`–`GC512C`) и схем подписи
  (`gostr34102012_256a`–`gostr34102012_512c`). Теперь каждую сущность
  можно найти не только по числовому коду (0xC103), но и по её
  стандартному имени из реестра — это нужно для JSSE-модуля, где
  настройки TLS задаются строками, а не числами.

- TlsMessageBuilder.buildEmptyCertificateBody() — служебный метод для
  построения пустого списка сертификатов. Нужен, когда сервер запросил
  сертификат клиента, а у клиента его нет: по RFC 8446 он обязан
  отправить пустой список, а не обрывать соединение.

- TlsRecord.isApproachingRekeyLimit() — предикат для проактивного
  KeyUpdate. Возвращает `true` при достижении 80% от SNMAX cipher suite.
  Позволяет JSSE-слою инициировать KeyUpdate до исчерпания лимита
  записей, без прерывания передачи.

- TlsCertificate.getOcspUris() / getCaIssuersUris() — разделение URI из
  AuthorityInfoAccess по типу AccessMethod (OCSP responder vs
  caIssuers). Нужен для отправки OCSP-запроса по правильному URI.

- TlsCertificate.getEncoded() — полный DER-encoded сертификат. Нужен для
  построения OCSP-запроса и других задач, где требуется исходная
  DER-кодировка.

- TlsHandshakeEngine.setAlpnSelector(Function&lt;List&lt;String&gt;,
  String&gt;) — ALPN-селектор для JSSE. Позволяет прикладному коду
  выбирать протокол динамически через callback, а не из статического
  списка. Если selector задан — engine не выбирает ALPN самостоятельно.

- TlsRecord: порог rekey теперь instance-level
  (setRekeyThreshold(long)), а не жёстко зашитый 80% от SNMAX. Нужен для
  тестирования KeyUpdate без прогона триллионов записей.

- `GostOids.java` — единый источник OID-строк для ГОСТ-криптографии:
  подписи (SIG\_WITH\_DIGEST\_256/512), кривые (CURVE\_256A–512C),
  дайджесты (DIGEST\_256/512), расширения X.509v3
  (EXT\_BC/KU/SAN/EKU/AIA), DN-атрибуты (ATTR\_CN), OCSP-идентификаторы
  (OCSP\_AD/BASIC). Заменил разрозненные OID-литералы в TlsTestHelper,
  TlsCertificateTest, OcspRequestBuilder, GostTestCerts.

- TlsOcspVerifier: добавлена проверка issuerNameHash и issuerKeyHash в
  CertID OCSP-ответа (defense-in-depth). Ранее проверялся только
  serialNumber.

- `OcspCertIdHasher` — единый источник истины для вычисления хешей
  CertID (issuerNameHash, issuerKeyHash) OCSP-ответа (RFC 6960 §4.1.1).
  Выделен из `TlsOcspVerifier` для консистентного использования в
  верификации и построении OCSP-запроса. Хеш ключа считается от BIT
  STRING value SubjectPublicKeyInfo (с байтом unused-bits, без tag и
  length BIT STRING) — строго по RFC.

- `TlsOcspVerifier.verifyNonce()` — проверка OCSP nonce (RFC 8954).
  Поддерживает strict и best-effort режимы: strict — nonce обязателен,
  best-effort — проверка только если nonce присутствует в ответе.

- `TlsCertificate.getOcspNonce()` / `setOcspNonce()` — хранение nonce,
  отправленного в OCSP-запросе, для последующей верификации.

- `TlsCertificate.verifyOcspResponse(caKey, issuer)` — перегрузка с
  явным сертификатом издателя для проверки CertID (issuerNameHash +
  issuerKeyHash).

- Best-effort OCSP для intermediate сертификатов: в
  `TlsCertificateValidator.checkServerCertificateChain()` добавлен цикл
  верификации OCSP-ответов для intermediate сертификатов в цепочке. Если
  intermediate не имеет OCSP-ответа — цепочка не бракуется (fail-open,
  следуя RFC).

- `TlsSession.wasResumed()` — проверка выполнения handshake через PSK
  resumption. Возвращает `true`, если handshake прошёл без ECDHE (после
  ввода флага `wasResumed()` в `TlsSession` и флага `isPskAccepted()` в
  `TlsHandshakeEngine`).

- `InMemoryPskStore.getForResumption()` теперь возвращает entry с
  максимальным `issueTime` (самый свежий). Ранее — первый non-expired из
  недетерминированного порядка `ConcurrentHashMap.values()`, из-за чего
  при накоплении N&gt;1 entry клиент мог отправить stale ticket →
  fallback на full handshake.

- `TlsServerConfig.withTicketsToSend(int)` — количество
  NewSessionTicket, отправляемых после handshake (≥ 1, RFC 8446 §4.6.1).
  `ticket_nonce` монотонный (big-endian counter), гарантирует
  уникальность nonce в пределах соединения.

- `TlsOcspVerifier.extractDelegatedCerts(byte[])` — извлекает
  сертификаты делегированного OCSP-responder’а из поля `certs`
  BasicOCSPResponse (RFC 6960 §2.6, case b).

- `TlsCertificateValidator.checkServerCertificateChain()`: при неудаче
  верификации OCSP-ответа ключом issuer’а автоматически пробует
  делегированные responder-сертификаты из поля `certs` OCSP-ответа.

- `TlsCertificate.isOcspSigning()` — проверка EKU id-kp-OCSPSigning
  (1.3.6.1.5.5.7.3.9). Учитывает anyExtendedKeyUsage (2.5.29.37.0) и
  отсутствие EKU (сертификат без ограничений).

- `OcspRequestBuilder.buildSigned(byte[], byte[], PrivateKeyParameters, ECParameters)`
  — опциональное подписывание OCSP-запроса подписью GOST R 34.10-2012.
  Если ключ не задан — эквивалентно `buildWithNonce()`.

- `OcspCertIdHasher.hashIssuerName(TlsCertificate)` /
  `hashIssuerPublicKey(TlsCertificate)` — перегрузки, принимающие объект
  сертификата вместо DER-массива.

### Исправлено

- mTLS: если сервер запросил сертификат, а у клиента его нет, клиент
  больше не обрывает соединение с алертом «требуется сертификат». Теперь
  он отправляет пустой список сертификатов, как велит RFC 8446 §4.4.2, и
  сервер сам решает, принять соединение без клиентского сертификата или
  отказать. Исправление нужно для поддержки wantClientAuth в JSSE-модуле
  — когда сервер хочет получить сертификат клиента, но не требует его.

- Алерт при ошибке handshake: если сбой случился в момент переключения
  ключей шифрования, алерт уходил открытым текстом, а собеседник не мог
  его расшифровать и падал с технической ошибкой. Теперь алерт шифруется
  новыми ключами, и собеседник корректно его принимает — вместо того
  чтобы спотыкаться о непонятные байты.

- Handshake: если во время рукопожатия пришёл алерт, клиент или сервер
  раньше падали с «неожиданное сообщение» (unexpected\_message, 10) — и
  причину отказа приходилось угадывать. Теперь алерт распознаётся и
  пробрасывается с его настоящим кодом — диагностика сразу показывает,
  что именно пошло не так на той стороне.

- issuerKeyHash в OCSP CertID: исправлен расчёт хеша на RFC-строгий — от
  BIT STRING value SubjectPublicKeyInfo (с байтом unused-bits, без tag и
  length BIT STRING). Ранее хеш считался от полного SPKI, что не
  соответствует RFC 6960 §4.1.1. Исправлено в `OcspCertIdHasher`,
  `TlsOcspVerifier`, `OcspRequestBuilder`,
  `TlsTestHelper.buildOcspResponse`.

- Double-readTlv в findTbsOffset: код использовал tagStart (`tlv[0]`)
  вместо valueStart для позиционирования при последовательном разборе
  TLV, что приводило к повторному чтению tag+length — пропуску
  очередного поля. `readTlv` возвращает `[valueStart, valueEnd]`, а не
  `[tagStart, valueEnd]`. Исправлено в 6 местах:
  `OcspCertIdHasher.extractSubject`,
  `OcspCertIdHasher.extractBitStringValue`, `OcspRequestBuilder`,
  тестовые хелперы.

- PSK resumption: `InMemoryPskStore.getForResumption()` возвращал
  недетерминированный entry (зависит от bucket-порядка
  `ConcurrentHashMap`). При накоплении N &gt; 1 entry клиент мог
  отправить stale ticket, который сервер уже удалил (single-use, RFC
  8446 §4.6.1) → handshake проходил полный цикл ECDHE, PSK неверно
  показывал speedup ~0 %. Фикс: выбор entry с максимальным `issueTime`
  (самый свежий NST).

- OCSP delegated responders: при верификации OCSP-ответа, если подпись
  не совпала с ключом непосредственного issuer’а, теперь автоматически
  пробуются делегированные responder-сертификаты из поля `certs`
  BasicOCSPResponse (RFC 6960 §2.6, case b) с проверкой EKU
  id-kp-OCSPSigning.

- ALPN (RFC 7301): исправлена обработка mismatch — когда клиент и сервер
  предлагают разные протоколы (например, клиент h2, сервер http/1.1).
  JDK/JdkAlpnSslEngine по договорённости возвращает пустую строку "",
  если общий протокол не найден — а не null, как можно было бы ожидать.
  Раньше движок проверял только на null, пропускал пустую строку,
  пробовал найти её в списке клиента и падал с ошибкой. Теперь пустая
  строка понимается как «протокол не согласован» — рукопожатие
  продолжается без ALPN, как и велит RFC 7301.

- TlsTestHelper, TlsCertificateTest, OcspRequestBuilder: все OID-строки
  заменены на константы GostOids.\* (SIG\_WITH\_DIGEST\_256/512,
  DIGEST\_256/512, CURVE\_256A и др.).

## Бенчмарки

- Обновлены бенчмарки в связи с новой математикой, ускорения Кузнечика.

- Обновлены pom-файлы в бенчмарках для управления версией.

# \[0.2.1\] - 09-05-2026

## Модуль crypto-gost-tls

Выпуск посвящен в основном корректировке пользовательского API: удобству
использования, устранению двусмысленности.

### Добавлено

- Извлечение данных из сертификата:

- Ссылки на OCSP-сервер и точки распространения CRL (списки отзыва).

- Идентификаторы ключей (SubjectKeyIdentifier, AuthorityKeyIdentifier).

- Политики сертификата (CertificatePolicies).

- Человеко-читаемое представление Distinguished Name (строка вида
  "CN=example.com, O=Org" + поиск по отдельным полям).

- equals/hashCode/toString для TlsCertificate.

- Выбор сертификата по имени хоста (SNI):
  TlsServerConfig.withSniSelector(). Позволяет одному серверу на одном
  порту обслуживать несколько доменов с разными сертификатами — без
  предупреждений в браузере.

- Легковесный парсер SNI: TlsMessageParser.parseClientHelloSni().

- 50+ новых тестов: парсинг SNI, выбор сертификата по SNI, экранирование
  спецсимволов в DN, ALPN через конфиг.

- PskEntry — отдельный класс для PSK-записи (раньше был вложенным в
  PskStore). Проще импортировать и использовать.

### Изменено

- TlsSession.resolveSigScheme: упрощён до прямого маппинга namedGroup →
  signatureScheme.

- TlsCertificateValidator: обе проверки OCSP-стаплинга (== null / !=
  null) заменены на симметричные hasOcspResponse() / !hasOcspResponse().

- TlsSessionTest: исправлена проверка на getKeySize().

- TlsHandshakeEngine: messageBuilder — non-final (единственное
  исключение). В receiveClientHello() добавлен блок выбора сертификата
  по SNI после PSK и до acceptableSchemes. Конструктор принимает
  SniCertificateSelector.

- getAiaUris/getCdpUris: javadoc теперь предупреждает об SSRF-рисках и
  перечисляет обязательные проверки перед использованием URI.

- Конструктор TlsCertificate: javadoc описывает контракт безопасности —
  вызов обязан обрабатывать RuntimeException как «невалидный
  сертификат».

- TlsClientConfig.withAlpnProtocols: javadoc уточнён (null → без ALPN).

- Настройки TLS (cipher suite, сертификаты, CA) и транспорт (сетевой
  канал) теперь разделены. Раньше конфиг содержал транспорт — на каждое
  новое соединение приходилось создавать новый конфиг. Теперь конфиг —
  набор настроек, его можно создать один раз и переиспользовать, а
  транспорт подставлять при создании сессии:
  `TlsSession.createServer(config, transport)`.

- TlsClientConfig и TlsServerConfig больше не хранят транспорт — только
  настройки TLS.

- TlsSession.close() больше не закрывает сетевой канал — только
  отправляет close\_notify и зачищает ключи. Транспорт нужно закрывать
  отдельно (например, try-with-resources).

- PskStore (хранилище PSK-тикетов для session resumption) теперь
  интерфейс, а не класс. Старая реализация переименована в
  InMemoryPskStore — по названию понятно, что это in-memory хранилище,
  не persistent.

- Метод `add(...)` переименован в `onTicketReceived(PskEntry)` — теперь
  ясно, что это callback: вызывается стеком при получении тикета, не
  предназначен для прямого вызова. Метод `getAnyEntry()` переименован в
  `getForResumption()` — ищет любой валидный тикет для попытки
  resumption.

- Если своя реализация PskStore бросает исключение при сохранении тикета
  (onTicketReceived) — текущее соединение не рвётся, handshake
  продолжается.

- Метод для OCSP-стаплинга на сервере переименован: `withOcspResponse` →
  `withOcspStaplingResponse`. Раньше было непонятно, зачем серверу
  «OCSP-ответ» и как это связано с клиентским `withRequireOcspStapling`.
  Теперь оба метода говорят на одном языке: клиент требует механизм
  stapling, сервер поставляет для него данные.

- Метод для дешифрования TLS-записи через ByteBuffer теперь возвращает
  результат, а не бросает исключение, если данных пока не хватает или
  выходной буфер мал. Это штатные ситуации — например, пакет ещё не
  приехал по сети или буфер оказался меньше расшифрованных данных.
  Статус ответа (OK / нужно ещё данных / увеличь буфер) позволяет
  вызывающему коду реагировать без перехвата исключений.

- Упрощён API для клиентского сертификата в mTLS: раньше было два метода
  — `withClientCertificate` (один сертификат) и
  `withClientCertificateChain` (цепочка). Они писали в разные поля, и
  геттер сам решал, что отдавать. Теперь остался один метод
  `withClientCertificateChain`, который принимает один или несколько
  сертификатов через запятую — без путаницы и без скрытой логики в
  геттере.

### Удалено

- getSafeAiaUris(String…) — фильтрация URI только по схеме не защищает
  от SSRF; ответственность за безопасный HTTP-запрос передана
  вызывающему коду.

- Устаревшие конструкторы TlsClientConfig(TlsTransport, TlsCiphersuite)
  и TlsServerConfig(TlsTransport, …) — транспорт больше не часть
  конфига.

- Устаревшие перегрузки TlsSession.createServer(TlsServerConfig) и
  createClient(TlsClientConfig) — транспорт передаётся отдельным
  аргументом.

- Старый вложенный класс PskStore.PskEntry — теперь это отдельный класс
  PskEntry.

- Старый класс PskStore (он же был и классом, и реализацией) — заменён
  на интерфейс PskStore + реализацию InMemoryPskStore.

- Убран публичный метод `getContext()`, который отдавал внутреннее
  состояние handshake (секреты, ключи, транскрипт) наружу. Любой
  пользователь библиотеки мог через него получить доступ к черновику
  handshake — хотя на практике этим никто не пользовался. Метод был
  нужен для будущего JSSE-модуля, но для него достаточно других, более
  узких методов.

### Исправлено

- ALPN (RFC 7301) через TlsClientConfig: createClient() теперь передаёт
  список протоколов из конфига в TlsSession. Ранее работало только через
  прямой вызов session.setAlpnProtocols().

- mTLS: правильные алерты при отсутствии сертификата клиента. Раньше
  сервер отвечал «ошибка декодирования» (decode\_error, 50) — непонятно,
  что сломалось. Теперь сервер отвечает «требуется сертификат»
  (certificate\_required, 116) — сразу ясно, что клиент не прислал
  сертификат и нужно проверить настройки mTLS. Исправлены три сценария:
  клиент не прислал Certificate вообще, клиент прислал пустой
  Certificate, сервер прислал пустой Certificate.

# \[0.2.0\] - 08-05-2026

## Изменено

- Рефакторинг проекта. Теперь он мультимодульный:

  - Модуль `crypto-gost` переместился в `crypto-gost-core`. Теперь это
    криптографическое ядро.

- Добавлен новый модуль `crypto-gost-tls`

- Реализован TLS 1.3 (RFC 8446 + RFC 9367): полный handshake
  клиент/сервер, защищённая передача данных, mTLS, PSK session
  resumption, TLSTREE per-record re-keying, OCSP stapling, X.509 chain
  validation. Добавлена поддержка PKCS12.

## Добавлено

### Модуль cryto-gost-core

- Новый метод в Mgm режиме `reinitICN` для реализации TLS 1.3.

- Документация для разработчика теперь crypto-gost-core/README.adoc
  (crypto-gost-core/README.md создается автоматически из asciidoc
  файла).

### Модуль crypto-gost-tls

Новый модуль `crypto-gost-tls13` реализует защищённый протокол TLS 1.3 с
ГОСТ-профилем (RFC 9367). Все криптографические операции выполняются
встроенными средствами библиотеки — без внешних зависимостей.

Поддерживаются:

- Односторонняя аутентификация сервера (основной режим).

- Взаимная аутентификация (mTLS): сервер запрашивает сертификат клиента.

- PSK session resumption (RFC 8446 §2.2): сокращённый handshake по
  сохранённому билету.

- ALPN (RFC 7301): согласование протокола прикладного уровня (HTTP/2,
  HTTP/1.1).

- SNI (RFC 6066): виртуальные хосты на одном IP.

- KeyUpdate (RFC 8446 §4.6.3): обновление ключей трафика без
  перерукопожатия.

Проверка сертификата сервера включает:

- Проверка цепочки сертификатов (BasicConstraints, KeyUsage keyCertSign,
  pathLen) по RFC 5280.

- Distinguished Name: issuer == subject предыдущего сертификата (RFC
  5280 §6.1).

- ExtendedKeyUsage: serverAuth (1.3.6.1.5.5.7.3.1) для сервера,
  clientAuth (1.3.6.1.5.5.7.3.2) для клиента.

- Проверка hostname по SubjectAltName/dNSName с wildcard и IP-адресу
  (RFC 6125).

- OCSP Stapling (RFC 6960): проверка статуса отзыва, подпись
  tbsResponseData.

- Проверка алгоритмической консистентности (RFC 5280 §4.1.1.2).

Оба cipher suite используют per-record рекейинг через TLSTREE (RFC 9367
§4.2).  

Суффикс `_L` (Light): SNMAX = 2^64 − 1 (максимальное число записей до
смены ключа).  

Суффикс `_S` (Strong): SNMAX = 2^42 − 1 (более частая смена ключа).

### Детали реализации (crypto-gost-tls 0.2.0)

#### Безопасность

- Constant-time поиск inner content type (сканирование всего padding
  безусловно) — защита от timing side-channel.

- MGM nonce: MSB первого байта очищается для ICN (RFC 9058 §3, RFC 9367
  §3.3).

- Затирание ключевого материала: destroy() на всех объектах с ключами
  (TlsKeySchedule, TlsTrafficKeys, TlsRecord, HandshakeContext).

- ECDHE-приватный ключ и транскрипт handshake уничтожаются после
  завершения handshake.

- HMAC-ключевой материал затирается после использования (HkdfStreebog,
  KdfGostR3411\_2012\_256).

- Защита от DoS/OOM: записи &gt; 16640 байт (MAX\_CIPHERTEXT\_LENGTH)
  отклоняются до аллокации.

- Защита от flood: не более 8 post-handshake сообщений за один вызов
  read() (MAX\_POST\_HANDSHAKE).

- Максимальный размер сертификата: 256 КБ (MAX\_CERT\_SIZE)

- Constant-time сравнение verify\_data и PSK binders
  (MessageDigest.isEqual).

#### Тестирование

- Known Answer Tests из RFC 9367 Appendix A.1 (L и S варианты) — полный
  key schedule, TLSTREE, AEAD, ECDHE.

- 4 интеграционных теста (self-interop) через реальные TCP-сокеты.

- Фаззинг-тесты для парсеров: TlsMessageParser (8 методов), TlsDerParser
  (3 метода), TlsOcspVerifier (1 метод).

#### Архитектурные решения

- TlsHandshakeEngine — state machine, отвязанная от I/O (для будущего
  модуля JSSE).

- ByteBuffer-перегрузки TlsRecord.protect/unprotect для NIO/JSSE.

- TLSTREE кэш (TlsTreeCache) — пересчёт только изменившихся уровней (RFC
  9367).

- InMemoryTlsTransport.Pair — двунаправленная пара для тестов и
  однопроцессного взаимодействия.

#### Текущие ограничения

- HelloRetryRequest не поддерживается

- 0-RTT, external PSK, pure PSK (без ECDHE) не поддерживаются.

- Delegated OCSP не поддерживается

- DN сравнение: byte-exact DER (не семантическое)

- CertificateRequest.certificate\_authorities не отправляется.

# \[0.1.2\] - 2026-05-01

- Исправлена ошибка в DER-кодировщике. Размер координат точки EC
  определяется модулем поля p, а не порядком группы n. Из-за этого был
  неверный вывод при кодировании. Устранена двойная OCTET STRING обёртка
  закрытого ключа.

- Обновлена версия crypto-gost в тестах и бенчмарках. Теперь выводится и
  используется актуальная.

# \[0.1.1\] - 2026-04-30

- В JCA провайдер добавлен алиас `Kuznyechik/MGM/NoPadding` для режима
  `Kuznyechik-MGM`. Это название более идиоматично для JCA. Добавлен
  соответствующий тест `Kuznyechik/MGM/NoPadding`.

- В документацию README внесены мелкие исправления и уточнения
  формулировок.

- Внесены дополнительные сведения в pom.xml о разработчике, лицензии и
  репозитории.

- Добавлено подписывание jar-файлов моим публичным ключом. В файл `KEYS`
  добавлен мой публичный ключ.

- Добавлены новые методы + тесты к ним + документация:

  - **signHash(byte\[\] hash,PrivateKeyParameters priv)** — подписывает
    готовый хэш. Внутри использует ECDSASigner.generateSignature()
    напрямую, минуя DigestSigner. RFC 6979 детерминизм сохраняется.

  - **verifyHash(byte\[\] hash, byte\[\] signature, PublicKeyParameters
    pub)** — проверяет подпись готового хэша через
    ECDSASigner.verifySignature().

- добавлено обнуление данных dBytes в ECDSASigner.

- добавлен вспомогательный класс **SignatureCodec** для вызова из разных
  мест, чтобы избежать дублирования.

- проведены тесты на кросс-валидацию повторно.

# \[0.1.0\] - 2026-04-28

Начальный выпуск.
