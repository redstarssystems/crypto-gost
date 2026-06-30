# JSSE-провайдер для криптографических алгоритмов ГОСТ — crypto-gost-jsse

Модуль `crypto-gost-jsse` реализует JSSE (Java Secure Socket Extension)
провайдера для ГОСТ-криптографии на основе модуля `crypto-gost-tls13`:

1.  **Классы JSSE:**

    - **`RssysGostJsseProvider`** — регистрация провайдера через
      `Security.addProvider()`.

    - **`GostSSLContextSpi`** — `SSLContext` для `TLSv1.3` /
      `GOST-TLSv1.3`.

    - **`GostSSLEngine`** — full `SSLEngine`: handshake, wrap/unwrap,
      ALPN (RFC 7301), SNI (RFC 6066), mTLS, OCSP stapling.

    - **`GostX509KeyManager`** — `X509ExtendedKeyManager` для
      ГОСТ-ключей; SNI-селектор.

    - **`GostX509TrustManager`** — `X509ExtendedTrustManager` для
      ГОСТ-сертификатов; валидация цепочки, OCSP (stapling + client-side
      fetch), CRL (client-side fetch), hostname verification.

    - **`GostSSLSocketFactory` / `GostSSLServerSocketFactory`** — socket
      factories.

    - **`GostSSLSocket` / `GostSSLServerSocket`** — socket-реализации.

    - **`GostSSLSession` / `GostSSLSessionContext`** — управление
      сессиями, PSK resumption.

2.  **Возможности:**

    - **Handshake**: полный (client/server), сокращённый (`PSK`),
      взаимный (`mTLS`).

    - **ALPN** — согласование протокола прикладного уровня (HTTP/2,
      HTTP/1.1).

    - **SNI** — выбор сертификата по имени сервера (multi-tenant).

    - **OCSP**: stapling (сервер прикладывает OCSP-ответ), client-side
      fetch (через `JdkHttpOcspFetcher`), кэширование.

    - **CRL**: client-side fetch (через `JdkHttpCrlFetcher`), политики
      `DISABLED` / `IF_CDP_PRESENT` / `REQUIRE`, SSRF-защита.

    - **Session resumption**: PSK через `NewSessionTicket`.

    - **Cipher suites**: `TLS_KUZNYECHIK_MGM_STREEBOG_256_L/S`.

    - **Защита записей**: `MGM-AEAD` (Kuznyechik) с nonce по RFC 8446
      §5.3, per-record TLSTREE re-keying.

3.  **Безопасность реализации:**

    - Constant-time сравнения для verify\_data и PSK binders.

    - Затирание ключевого материала при close, fatal alert, exception.

    - Защита от DoS: лимиты на размер записей, цепочку сертификатов,
      post-handshake сообщения.

    - Lock discipline: отдельные `ReentrantLock` для inbound/outbound
      (SSLEngine-контракт), отдельные блокировки для read/write на
      socket.

4.  **Ограничения:**

    - Только TLS 1.3 (TLS 1.2 и ниже не поддерживаются).

    - Только ГОСТ-наборы (non-GOST cipher suites не поддерживаются).

    - `HelloRetryRequest` (RFC 8446 §4.1.3) поддерживается — смена
      ECDHE-группы при несовпадении с сервером. Дефолтная группа GC256B,
      конфигурируется через `GostSSLEngine.setClientNamedGroup()`.

    Все криптографические операции выполняются встроенными средствами
    библиотеки — без внешних зависимостей.

## Быстрый старт — примеры для начинающих

Примеры ниже используют только публичное API модулей `crypto-gost-core`
и `crypto-gost-pkix`. Код компилируется и работает сразу после
добавления `crypto-gost-jsse` в зависимости проекта.

### Генерация тестовых сертификатов

Для примеров нужны сертификаты: CA и серверный сертификат для
`localhost`. В production сертификаты получают через УЦ и загружают как
PKCS12 (см. ниже).

    import org.rssys.gost.api.KeyGenerator;
    import org.rssys.gost.signature.ECParameters;
    import org.rssys.gost.pkix.cert.*;
    import org.rssys.gost.jca.spec.GostDerCodec;

    ECParameters params = ECParameters.tc26a256();

    // CA (самоподписанный, BasicConstraints:CA)
    var caKp = KeyGenerator.generateKeyPair(params);
    byte[] caDn = GostDnParser.encodeDn("CN=Test CA");
    GostCertificate ca = GostCertificateBuilder.create(params, caDn)
        .publicKey(caKp.getPublic())
        .notBefore("20250101120000Z").notAfter("21250101120000Z")
        .basicConstraints(true, null)   // 
        .assembleCert(caKp.getPrivate());

    // Серверный сертификат (подписан CA, SAN=localhost)
    var srvKp = KeyGenerator.generateKeyPair(params);
    byte[] srvDn = GostDnParser.encodeDn("CN=localhost");
    GostCertificate server = GostCertificateBuilder.create(params, srvDn)
        .publicKey(srvKp.getPublic())
        .issuerDn(caDn)                  // 
        .notBefore("20250101120000Z").notAfter("21250101120000Z")
        .sanDns("localhost")             // 
        .assembleCert(caKp.getPrivate());

- `isCA=true, pathLen=null` — CA без ограничения длины цепочки.

- Издатель — наш CA, а не сам субъект.

- Subject Alternative Name `dNSName=localhost` для совместимости с
  браузерами.

Экспорт в PEM-файлы для использования в `GostSsl.builder()`:

    import org.rssys.gost.pkix.cert.GostPemUtils;
    import java.nio.charset.StandardCharsets;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    Files.writeString(Paths.get("ca.pem"), ca.toPem());
    Files.writeString(Paths.get("server.pem"), server.toPem());
    byte[] keyDer = GostDerCodec.encodePrivateKey(srvKp.getPrivate());
    Files.write(Paths.get("server-key.pem"),
        GostPemUtils.toPem(keyDer, "PRIVATE KEY").getBytes(StandardCharsets.US_ASCII));

### Эхо-сервер

Сервер принимает соединение, читает строку, возвращает `ECHO: <строка>`.

    import org.rssys.gost.jsse.GostSsl;
    import javax.net.ssl.SSLContext;
    import javax.net.ssl.SSLServerSocket;
    import javax.net.ssl.SSLSocket;
    import java.nio.charset.StandardCharsets;

    SSLContext ctx = GostSsl.builder()
        .certificate(                             // 
            Files.readAllBytes(Paths.get("server.pem")),
            Files.readAllBytes(Paths.get("server-key.pem")))
        .trustCa(Files.readAllBytes(Paths.get("ca.pem"))) // 
        .buildServerContext();

    try (SSLServerSocket ss = GostSsl.serverSocket(8443, ctx)) {
        while (true) {
            try (SSLSocket s = (SSLSocket) ss.accept()) {
                s.startHandshake();               // 
                byte[] buf = new byte[1024];
                int n = s.getInputStream().read(buf);
                String msg = new String(buf, 0, n, StandardCharsets.UTF_8);
                s.getOutputStream().write(
                    ("ECHO: " + msg).getBytes(StandardCharsets.UTF_8));
            }
        }
    }

- `.certificate(byte[], byte[])` — авто-определение PEM/DER для
  сертификата и ключа.

- `.trustCa(byte[])` — авто-определение формата: одиночный PEM,
  PEM-цепочка или DER.

- Для `SSLSocket` handshake запускается автоматически при первом
  read/write. Явный `startHandshake()` — идиоматичный контроль.

### Клиент

    SSLContext ctx = GostSsl.builder()
        .trustCa(Files.readAllBytes(Paths.get("ca.pem")))
        .buildClientContext();

    SSLSocket s = GostSsl.socket("localhost", 8443, ctx); // 
    s.getOutputStream().write("PING".getBytes(StandardCharsets.UTF_8));
    byte[] buf = new byte[1024];
    int n = s.getInputStream().read(buf);
    System.out.println(new String(buf, 0, n, StandardCharsets.UTF_8)); // ECHO: PING
    s.close();

- `GostSsl.socket()` создаёт `SSLSocket` и выполняет handshake.

### Взаимная аутентификация (mTLS)

Клиент предоставляет свой сертификат — сервер проверяет его по тому же
CA. Переменные `params`, `caDn`, `serverPem`, `serverKeyPem`, `caPem` —
из раздела «Генерация тестовых сертификатов» выше.

    // Сервер: требует клиентский сертификат
    SSLContext srv = GostSsl.builder()
        .certificate(serverPem, serverKeyPem)
        .trustCa(caPem)               // CA, выпустивший клиентские сертификаты
        .buildServerContext();
    SSLServerSocket ss = GostSsl.serverSocket(8443, srv);
    ss.setNeedClientAuth(true);       // сервер требует клиентский сертификат

    // Клиент: предоставляет свой сертификат
    var clientKp = KeyGenerator.generateKeyPair(params);
    GostCertificate clientCert = GostCertificateBuilder.create(params,
            GostDnParser.encodeDn("CN=Test Client"))
        .publicKey(clientKp.getPublic())
        .issuerDn(caDn)
        .notBefore("20250101120000Z").notAfter("21250101120000Z")
        .assembleCert(caKp.getPrivate());

    SSLContext cli = GostSsl.builder()
        .certificate(clientCert.getEncoded(),       // DER-байты сертификата
            GostDerCodec.encodePrivateKey(clientKp.getPrivate()))
        .trustCa(caPem)
        .buildClientContext();
    SSLSocket s = GostSsl.socket("localhost", 8443, cli);

### PKCS12 (production)

В production сертификаты и ключи хранятся в PKCS12-контейнере.

    byte[] p12 = Files.readAllBytes(Paths.get("server.p12"));
    SSLContext ctx = GostSsl.builder()
        .certificate(p12, "password".toCharArray())
        .trustCa(p12Ca, "password".toCharArray())  // 
        .buildServerContext();

- `.trustCa(pfx, pwd)` извлекает все CA-сертификаты (isCA=true) из PFX.

### Режим разработки

Для отладки — клиент без проверки сертификата сервера. Не для
production.

    import org.rssys.gost.jsse.GostSslDev;

    SSLContext dev = GostSslDev.trustAllClientContextInsecure();

Или через builder:

    SSLContext dev = GostSsl.builder()
        .certificate(serverPem, serverKeyPem)
        .trustAll()                                 // 
        .buildServerContext();

- `trustAll()` — только для разработки и изолированных сетей.

### Loopback-проверка

Проверка работоспособности TLS без написания серверного и клиентского
кода.

    // mTLS: обе стороны с сертификатами
    GostSsl.verify(serverCertPem, serverKeyPem, clientCertPem, clientKeyPem, caPem);
    // Односторонний TLS: сервер с сертификатом, клиент только проверяет сервер
    GostSsl.verifyServer(serverCertPem, serverKeyPem, caPem);

## GostSsl — упрощённый API

Статический фасад `GostSsl` — один вызов, готовый `SSLContext`. Никаких
KeyManagerFactory, TrustManagerFactory, JKS.

### Статические методы

Все методы возвращают `SSLContext` или создают сокет. Каждый метод —
одна строка.

Серверные контексты:

    // PKCS12
    SSLContext srv = GostSsl.serverContext(p12Bytes, "password".toCharArray(), caDer);
    // PEM-строки
    SSLContext srv = GostSsl.serverContext(certPem, keyPem, caPem);
    // DER-байты
    SSLContext srv = GostSsl.serverContext(certDer, keyDer, caDer);

Клиентские контексты:

    // Без клиентского сертификата — только проверка сервера
    SSLContext cli = GostSsl.clientContext(caDer);
    // mTLS: PKCS12
    SSLContext cli = GostSsl.clientContext(p12Bytes, "password".toCharArray(), caDer);
    // mTLS: PEM-строки
    SSLContext cli = GostSsl.clientContext(certPem, keyPem, caPem);
    // mTLS: DER-байты
    SSLContext cli = GostSsl.clientContext(certDer, keyDer, caDer);

Создание сокетов:

    // Клиентский SSLSocket с автоматическим handshake
    SSLSocket s = GostSsl.socket("localhost", 8443, ctx);
    // SSLServerSocket
    SSLServerSocket ss = GostSsl.serverSocket(8443, ctx);
    // С backlog
    SSLServerSocket ss = GostSsl.serverSocket(8443, 100, ctx);
    // С backlog и адресом
    SSLServerSocket ss = GostSsl.serverSocket(8443, 100,
        InetAddress.getByName("0.0.0.0"), ctx);

### Загрузка закрытого ключа

    // Незашифрованный PEM- или DER-ключ — авто-определение формата
    PrivateKeyParameters key = GostSsl.loadPrivateKey(
        Files.readAllBytes(Paths.get("server-key.pem")));
    // Зашифрованный ключ (GOST PBES2)
    PrivateKeyParameters key = GostSsl.loadPrivateKey(
        Files.readAllBytes(Paths.get("encrypted-key.pem")),
        "password".toCharArray());

### GostSslBuilder — fluent API

Полный перечень методов строителя. Терминальные методы —
`buildServerContext()` и `buildClientContext()`.

    SSLContext ctx = GostSsl.builder()
        .certificate(certData, keyData)     // сертификат + ключ (авто PEM/DER)
        .certificate(p12Data, password)     // или из PKCS12 (только один вариант)
        .trustCa(caData)                    // CA: PEM, PEM-цепочка или DER (можно многократно)
        .trustCa(pfxData, pfxPassword)      // CA из PKCS12 (извлекает isCA=true)
        .trustCaFromPem(pemChain)           // CA из PEM-цепочки
        .ocsp(true)                         // включить OCSP-степплинг
        .sessionCacheSize(5000)             // размер кэша сессий (0=без ограничения)
        .trustAll()                         // отключить проверку (только dev)
        .buildServerContext();              // или buildClientContext()

Примеры:

    // Минимальный сервер
    SSLContext srv = GostSsl.builder()
        .certificate(serverPem, serverKeyPem)
        .trustCa(caPem)
        .buildServerContext();

    // Клиент без своего сертификата
    SSLContext cli = GostSsl.builder()
        .trustCa(caPem)
        .buildClientContext();

    // Сервер с OCSP и большим кэшем сессий
    SSLContext srv = GostSsl.builder()
        .certificate(serverP12, "pwd".toCharArray())
        .trustCa(caP12, "pwd".toCharArray())
        .ocsp(true)
        .sessionCacheSize(5000)
        .buildServerContext();

### Ограничения GostSsl

- Только один сертификат на контекст — для SNI (multi-tenant)
  используйте `GostX509KeyManager` напрямую (см. ниже).

- `GostX509TrustManager` принимает список CA-ключей
  (`List<PublicKeyParameters>`) — все переданные CA участвуют в проверке
  цепочки.

- PKCS12 с GOST PBE поддерживается нативно (PBKDF2-HMAC-Streebog +
  Кузнечик CTR-ACPKM).

## API — уровни интеграции

Модуль предоставляет три уровня:

**Socket API** — `GostSSLSocket / GostSSLServerSocket` — стандартный
Java I/O. Handshake запускается автоматически при первом read/write или
явно через `startHandshake()`.

**Engine API** — `GostSSLEngine` — низкоуровневый API для неблокирующего
I/O (NIO, Netty). Ручное управление handshake через `wrap()`/`unwrap()`.

**Context API** — `GostSSLContextSpi` — фабрика engine и сокетов, точка
входа для интеграции с серверами приложений (см. раздел «Интеграция»).

`GostSSLEngine` разрешает параллельные `wrap()` и `unwrap()` из разных
потоков. Запрещено вызывать `wrap()` из двух потоков одновременно.
`GostX509TrustManager` thread-safe.

## Конфигурация сервера — ручная настройка

Если вам нужен SNI (несколько сертификатов), тонкая настройка OCSP/CRL
или интеграция с фреймворком — используйте ручную сборку `SSLContext`.
Для большинства случаев достаточно `GostSsl.builder()` (см. выше).

### Загрузка сертификата и ключа

Три способа загрузки. Рекомендуется PKCS12 для production.

PKCS12 (ключ и цепочка в одном файле):

    import org.rssys.gost.pkix.cert.GostPkcs12Loader;
    import org.rssys.gost.pkix.cert.GostCertificate;
    import org.rssys.gost.jsse.bridge.CertificateBridge;

    GostPkcs12Loader.Result p12 = GostPkcs12Loader.load(
        Files.readAllBytes(Paths.get("server.p12")), "password".toCharArray(), true);
    PrivateKeyParameters privateKey = p12.getPrivateKey();
    X509Certificate[] chain = CertificateBridge.toJca(p12.getCertificateChain());

DER-файлы:

    import org.rssys.gost.pkix.cert.GostCertificate;
    import org.rssys.gost.jca.spec.GostDerCodec;
    import org.rssys.gost.jsse.bridge.CertificateBridge;

    byte[] certDer = Files.readAllBytes(Paths.get("server.der"));
    byte[] keyDer  = Files.readAllBytes(Paths.get("server.key"));
    PrivateKeyParameters priv = GostDerCodec.decodePrivateKey(keyDer);
    X509Certificate[] chain = {
        CertificateBridge.toJca(new GostCertificate(certDer))
    };

PEM-файлы (авто-определение формата):

    import org.rssys.gost.jsse.GostSsl;

    PrivateKeyParameters key = GostSsl.loadPrivateKey(
        Files.readAllBytes(Paths.get("server-key.pem")));
    // Зашифрованный ключ:
    PrivateKeyParameters key = GostSsl.loadPrivateKey(
        Files.readAllBytes(Paths.get("encrypted-key.pem")), "password".toCharArray());

### GostX509KeyManager

    import org.rssys.gost.jsse.manager.GostX509KeyManager;

    GostX509KeyManager km = new GostX509KeyManager();
    km.addKeyEntry("default", chain, privateKey);
    // SNI (multi-tenant): несколько записей
    km.addKeyEntry("api", apiChain, apiKey);

Сервер автоматически вызывает `asSniSelector()` — выбор сертификата по
`SubjectAltName/dNSName`.

### GostX509TrustManager

Конструкторы `GostX509TrustManager` покрывают все комбинации проверок.

Проверка цепочки + срок действия (без OCSP/CRL):

    import org.rssys.gost.jsse.manager.GostX509TrustManager;
    import org.rssys.gost.pkix.cert.GostCertificate;

    byte[] caDer = Files.readAllBytes(Paths.get("ca.der"));
    PublicKeyParameters caKey = new GostCertificate(caDer).getPublicKey();
    GostX509TrustManager tm = new GostX509TrustManager(caKey, false);

С одним CA + OCSP (stapling или client-side fetch):

    import org.rssys.gost.jsse.ocsp.OcspPolicy;
    import org.rssys.gost.jsse.ocsp.JdkHttpOcspFetcher;

    GostX509TrustManager tm = new GostX509TrustManager(
        caKey,
        OcspPolicy.STAPLING_OR_FETCH,   // 
        new JdkHttpOcspFetcher());

- Политика: `STAPLING_OR_FETCH` — если нет staple-ответа, клиент сам
  сходит на OCSP-responder. Также доступны: `DISABLED`, `IF_PRESENT`,
  `STAPLING_REQUIRED`.

С несколькими CA + OCSP:

    GostX509TrustManager tm = new GostX509TrustManager(
        List.of(caKey1, caKey2),          // 
        OcspPolicy.STAPLING_OR_FETCH,
        new JdkHttpOcspFetcher());

- Все переданные CA участвуют в проверке цепочки. Порядок не важен.

Полный конструктор: CA + OCSP + CRL:

    import org.rssys.gost.jsse.crl.CrlPolicy;
    import org.rssys.gost.jsse.crl.JdkHttpCrlFetcher;

    GostX509TrustManager tm = new GostX509TrustManager(
        List.of(caKey1, caKey2),
        OcspPolicy.STAPLING_OR_FETCH,
        new JdkHttpOcspFetcher(),
        CrlPolicy.IF_CDP_PRESENT,         // 
        new JdkHttpCrlFetcher());

- `CrlPolicy`: `DISABLED` (не проверять), `IF_CDP_PRESENT` (проверять
  если CRL DP в сертификате), `REQUIRE` (требовать CRL всегда).

Trust-all (только для разработки):

    GostX509TrustManager tm = new GostX509TrustManager(null, false);

`caKey = null` — проверка сертификата пира отключена. Только для
разработки.

### Создание SSLContext

    import org.rssys.gost.jsse.RssysGostJsseProvider;

    Security.addProvider(new RssysGostJsseProvider());          // 
    SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
    ctx.init(new KeyManager[]{km}, new TrustManager[]{tm}, null);

    // Серверный SSLEngine (для NIO)
    SSLEngine engine = ctx.createSSLEngine();
    engine.setUseClientMode(false);

    // Или socket factory
    SSLServerSocketFactory ssf = ctx.getServerSocketFactory();

- `Security.addProvider()` — один раз при старте приложения.

## Конфигурация клиента

    import org.rssys.gost.jsse.RssysGostJsseProvider;
    import org.rssys.gost.jsse.manager.GostX509TrustManager;

    Security.addProvider(new RssysGostJsseProvider());

    // TrustManager с проверкой сервера
    GostX509TrustManager tm = new GostX509TrustManager(caKey, false);
    // Пустой KeyManager — без клиентского сертификата
    GostX509KeyManager km = new GostX509KeyManager();

    SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
    ctx.init(new KeyManager[]{km}, new TrustManager[]{tm}, null);

    // Клиентский SSLEngine
    SSLEngine engine = ctx.createSSLEngine("host", 8443);
    engine.setUseClientMode(true);
    // Или socket factory
    SSLSocketFactory sf = ctx.getSocketFactory();

mTLS — клиент предоставляет свой сертификат:

    GostX509KeyManager km = new GostX509KeyManager();
    km.addKeyEntry("client", clientChain, clientPrivateKey);

    SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
    ctx.init(new KeyManager[]{km}, new TrustManager[]{tm}, null);

Для проверки hostname установите
`SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`.
`GostX509TrustManager` проверяет `dNSName`/`iPAddress` сертификата по
RFC 6125.

### Выбор клиентского сертификата по OID-фильтрам (oid\_filters)

Если сервер включил `oid_filters` (RFC 8446 §4.2.5) в
`CertificateRequest`, `GostX509KeyManager.asClientCertificateSelector()`
выбирает подходящий сертификат:

    import org.rssys.gost.jsse.manager.GostX509KeyManager;
    import org.rssys.gost.tls13.config.ClientCertificateSelector;

    GostX509KeyManager km = new GostX509KeyManager();
    km.addKeyEntry("kc1", kc1Chain, kc1Key);   // EKU: clientAuth
    km.addKeyEntry("simple", simpleChain, simpleKey);

    ClientCertificateSelector selector = km.asClientCertificateSelector();

    GostSSLEngine engine = GostSSLEngine.createForClient(km, tm, "host", 8443, sessionCtx);
    // При CertificateRequest с oid_filters selector вызывается автоматически

Записи перебираются в порядке добавления. Возвращается первая,
удовлетворяющая всем фильтрам.

## OCSP API

API для проверки статуса сертификатов через OCSP (RFC 6960).

### OcspRequestBuilder

Fluent-построитель DER-закодированного OCSP-запроса с поддержкой nonce
(RFC 8954).

    import org.rssys.gost.jsse.ocsp.OcspRequestBuilder;
    import org.rssys.gost.jsse.ocsp.OcspRequest;

    // Базовый запрос (без подписи)
    OcspRequest req = OcspRequestBuilder.create()
        .targetCert(certDer)            // проверяемый сертификат (DER) — обязателен
        .issuerCert(issuerDer)          // сертификат издателя (DER) — обязателен
        .hashLen(32)                    // 32=Streebog-256 (по умол.), 64=Streebog-512
        .build();

    byte[] ocspRequestDer = req.der();   // DER-байты OCSPRequest для отправки на респондер
    byte[] nonce = req.nonce();          // nonce для сверки с ответом

    // Запрос с подписью
    OcspRequest signedReq = OcspRequestBuilder.create()
        .targetCert(certDer)
        .issuerCert(issuerDer)
        .signKey(privateKey)            // ключ для подписи (опционально)
        .params(ECParameters.tc26a256())// параметры кривой (обязательно с signKey)
        .build();

### OcspPolicy

Перечисление политик проверки OCSP, передаётся в `GostX509TrustManager`.

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Константа</p></td>
<td style="text-align: left;"><p>Поведение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>DISABLED</code></p></td>
<td style="text-align: left;"><p>OCSP не проверяется</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>IF_PRESENT</code></p></td>
<td style="text-align: left;"><p>Проверить OCSP-ответ, если сервер его
предоставил (не фатально при отсутствии)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>STAPLING_REQUIRED</code></p></td>
<td style="text-align: left;"><p>Требовать OCSP stapling в handshake —
fail-closed при отсутствии</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>STAPLING_OR_FETCH</code></p></td>
<td style="text-align: left;"><p>Использовать stapling, если есть; иначе
клиент сам сходит на респондер</p></td>
</tr>
</tbody>
</table>

### JdkHttpOcspFetcher

Реализация `OcspFetcher` на JDK HttpClient — vthread-friendly.

    import org.rssys.gost.jsse.ocsp.JdkHttpOcspFetcher;
    import java.time.Duration;

    // С настройками по умолчанию: таймаут 5 с, лимит ответа 64 КБ
    OcspFetcher fetcher = new JdkHttpOcspFetcher();
    // Кастомные настройки
    OcspFetcher fetcher = new JdkHttpOcspFetcher(Duration.ofSeconds(10), 131072);

Использование через TrustManager:

    GostX509TrustManager tm = new GostX509TrustManager(
        caKey,
        OcspPolicy.STAPLING_OR_FETCH,
        new JdkHttpOcspFetcher());

OCSP-ответы кэшируются в `GostX509TrustManager` на 1 час (TTL
настраивается через `setOcspCacheTtlMs()`).

## CRL API

API для проверки сертификатов через CRL (Certificate Revocation List).

### CrlPolicy

Перечисление политик проверки CRL, передаётся в `GostX509TrustManager`.

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Константа</p></td>
<td style="text-align: left;"><p>Поведение</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>DISABLED</code></p></td>
<td style="text-align: left;"><p>CRL не проверяется (по
умолчанию)</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>IF_CDP_PRESENT</code></p></td>
<td style="text-align: left;"><p>Проверить CRL, если в сертификате есть
CRL Distribution Points</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>REQUIRE</code></p></td>
<td style="text-align: left;"><p>Требовать CRL всегда — fail-closed при
отсутствии CDP</p></td>
</tr>
</tbody>
</table>

### JdkHttpCrlFetcher

Реализация `CrlFetcher` на JDK HttpClient. Имеет защиту от SSRF.

    import org.rssys.gost.jsse.crl.JdkHttpCrlFetcher;
    import org.rssys.gost.jsse.crl.CrlPolicy;

    GostX509TrustManager tm = new GostX509TrustManager(
        List.of(caKey),
        OcspPolicy.IF_PRESENT,
        null,                                // без OCSP
        CrlPolicy.IF_CDP_PRESENT,
        new JdkHttpCrlFetcher());

CRL-ответы кэшируются до `nextUpdate`, с grace-периодом 1 час (перекос
часов).

## GostSSLEngine (низкоуровневый API)

`GostSSLEngine` предназначен для неблокирующих интеграций (NIO, Netty,
кастомные selector-циклы). Управление handshake — через wrap/unwrap с
`ByteBuffer`.

    import org.rssys.gost.jsse.engine.GostSSLEngine;
    import org.rssys.gost.jsse.manager.GostX509KeyManager;
    import org.rssys.gost.jsse.manager.GostX509TrustManager;
    import org.rssys.gost.tls13.TlsConstants;

    import javax.net.ssl.SSLEngineResult;
    import java.nio.ByteBuffer;

    GostSSLEngine clientEngine = GostSSLEngine.createForClient(
            km, tm, "host", 8443, null /* без PSK-контекста */);

    clientEngine.beginHandshake();
    ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
    ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

    SSLEngineResult result = clientEngine.wrap(ByteBuffer.allocate(0), netBuf);
    netBuf.flip();
    // отправить netBuf пиру
    // принять данные от пира → unwrap
    result = clientEngine.unwrap(netBuf, appBuf);

Цикл handshake — смотрите `doClientHandshake()` / `doServerHandshake()`
в `GostSSLEngineLoopbackTest.java` (исходники тестов).

## Интеграция с серверами приложений

### Общие принципы

Во всех примерах ниже используется готовый `SSLContext`, созданный по
одному из двух шаблонов:

Вариант 1 — GostX509KeyManager напрямую (DER-файлы или
GostPkcs12Loader):

    import org.rssys.gost.jsse.RssysGostJsseProvider;
    import org.rssys.gost.jsse.manager.GostX509KeyManager;
    import org.rssys.gost.jsse.manager.GostX509TrustManager;
    import org.rssys.gost.jsse.bridge.CertificateBridge;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import org.rssys.gost.signature.PublicKeyParameters;
    import org.rssys.gost.pkix.cert.GostPkcs12Loader;
    import org.rssys.gost.pkix.cert.GostCertificate;

    import javax.net.ssl.KeyManager;
    import javax.net.ssl.SSLContext;
    import javax.net.ssl.TrustManager;
    import java.nio.file.Files;
    import java.nio.file.Paths;
    import java.security.Security;
    import java.util.List;

    // Шаг 1: регистрация провайдера
    Security.addProvider(new RssysGostJsseProvider());

    // Шаг 2: загрузка сертификата и ключа через PKCS12
    GostPkcs12Loader.Result p12 = GostPkcs12Loader.load(
            Files.readAllBytes(Paths.get("server.p12")), "password".toCharArray(), true);
    PrivateKeyParameters privateKey = p12.getPrivateKey();
    List<GostCertificate> tlsChain  = p12.getCertificateChain();
    java.security.cert.X509Certificate[] jcaChain =
            CertificateBridge.toJca(tlsChain);

    // Шаг 3: KeyManager
    GostX509KeyManager km = new GostX509KeyManager();
    km.addKeyEntry("server", jcaChain, privateKey);

    // Шаг 4: TrustManager — загрузка CA
    byte[] caDer = Files.readAllBytes(Paths.get("ca.der"));
    PublicKeyParameters caKey = new GostCertificate(caDer).getPublicKey();
    GostX509TrustManager tm = new GostX509TrustManager(caKey, false);

    // Шаг 5: SSLContext
    SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
    sslContext.init(new KeyManager[]{km}, new TrustManager[]{tm}, null);

Вариант 2 — KeyManagerFactory из PKCS12 KeyStore (JCA-совместимый):

    import org.rssys.gost.jsse.RssysGostJsseProvider;
    import org.rssys.gost.jsse.manager.GostX509TrustManager;

    import javax.net.ssl.KeyManagerFactory;
    import javax.net.ssl.SSLContext;
    import javax.net.ssl.TrustManager;
    import java.security.KeyStore;
    import java.security.Security;

    Security.addProvider(new RssysGostJsseProvider());

    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(Files.newInputStream(Paths.get("server.p12")), "password".toCharArray());

    KeyManagerFactory kmf = KeyManagerFactory.getInstance("GostX509", "RssysGostJsse");
    kmf.init(ks, "password".toCharArray());

    SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
    sslContext.init(kmf.getKeyManagers(), new TrustManager[]{tm}, null);

`Security.addProvider()` достаточно вызвать один раз при старте
приложения.

Все последующие примеры ссылаются на переменную `sslContext`, полученную
одним из этих способов.

Зависимости Maven для всех примеров раздела:

    <!-- Обязательно для всех примеров -->
    <dependency>
        <groupId>org.rssys</groupId>
        <artifactId>crypto-gost-jsse</artifactId>
        <version>${project.version}</version>
    </dependency>
    <dependency>
        <groupId>org.rssys</groupId>
        <artifactId>crypto-gost-tls13</artifactId>
        <version>${project.version}</version>
    </dependency>

### Netty 4.2

Модуль `crypto-gost-netty` предоставляет `GostSslContextBuilder` —
готовый адаптер для Netty pipeline. Внутри builder сам регистрирует
`RssysGostJsseProvider` и создаёт `SSLContext` — вызывать
`Security.addProvider()` вручную не нужно.

Дополнительная зависимость:

    <dependency>
        <groupId>org.rssys</groupId>
        <artifactId>crypto-gost-netty</artifactId>
        <version>${project.version}</version>
    </dependency>
    <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-handler</artifactId>
        <version>4.2.13.Final</version>
    </dependency>

Сервер:

    import org.rssys.gost.netty.GostSslContext;
    import org.rssys.gost.netty.GostSslContextBuilder;
    import org.rssys.gost.jsse.manager.GostX509KeyManager;
    import org.rssys.gost.jsse.manager.GostX509TrustManager;
    import org.rssys.gost.jsse.bridge.CertificateBridge;

    import io.netty.bootstrap.ServerBootstrap;
    import io.netty.channel.ChannelFuture;
    import io.netty.channel.ChannelInitializer;
    import io.netty.channel.EventLoopGroup;
    import io.netty.channel.nio.NioEventLoopGroup;
    import io.netty.channel.socket.SocketChannel;
    import io.netty.channel.socket.nio.NioServerSocketChannel;

    // KeyManager (см. «Общие принципы» — загрузка сертификата)
    GostX509KeyManager km = new GostX509KeyManager();
    km.addKeyEntry("default", jcaChain, privateKey);

    // TrustManager (см. «Общие принципы»)
    GostX509TrustManager tm = new GostX509TrustManager(caKey, false);

    // GostSslContext через builder
    GostSslContext sslCtx = GostSslContextBuilder.forServer(km)
            .trustManager(tm)
            .applicationProtocols("h2", "http/1.1")    // ALPN для HTTP/2
            .build();

    // ServerBootstrap
    EventLoopGroup boss   = new NioEventLoopGroup(1);
    EventLoopGroup worker = new NioEventLoopGroup();
    try {
        ServerBootstrap b = new ServerBootstrap();
        b.group(boss, worker)
         .channel(NioServerSocketChannel.class)
         .childHandler(new ChannelInitializer<SocketChannel>() {
             @Override
             protected void initChannel(SocketChannel ch) {
                 ch.pipeline().addLast(sslCtx.newHandler(ch.alloc()));
                 ch.pipeline().addLast(new MyServerHandler());
             }
         });
        ChannelFuture f = b.bind(8443).sync();
        f.channel().closeFuture().sync();
    } finally {
        worker.shutdownGracefully();
        boss.shutdownGracefully();
    }

Клиент (mTLS):

    import org.rssys.gost.netty.GostSslContext;
    import org.rssys.gost.netty.GostSslContextBuilder;
    import org.rssys.gost.jsse.manager.GostX509KeyManager;

    import io.netty.bootstrap.Bootstrap;
    import io.netty.channel.ChannelInitializer;
    import io.netty.channel.EventLoopGroup;
    import io.netty.channel.nio.NioEventLoopGroup;
    import io.netty.channel.socket.SocketChannel;
    import io.netty.channel.socket.nio.NioSocketChannel;

    // Клиентский KeyManager для mTLS (опционально — только если нужен mTLS)
    GostX509KeyManager clientKm = new GostX509KeyManager();
    clientKm.addKeyEntry("client", clientChain, clientPrivateKey);

    GostSslContext clientCtx = GostSslContextBuilder.forClient()
            .trustManager(tm)
            .keyManager(clientKm)                          // для mTLS
            .applicationProtocols("h2", "http/1.1")
            .build();

    EventLoopGroup group = new NioEventLoopGroup();
    try {
        Bootstrap b = new Bootstrap();
        b.group(group)
         .channel(NioSocketChannel.class)
         .handler(new ChannelInitializer<SocketChannel>() {
             @Override
             protected void initChannel(SocketChannel ch) {
                 ch.pipeline().addLast(
                         clientCtx.newHandler(ch.alloc(), "host", 8443));
                 ch.pipeline().addLast(new MyClientHandler());
             }
         });
        ChannelFuture f = b.connect("host", 8443).sync();
        f.channel().closeFuture().sync();
    } finally {
        group.shutdownGracefully();
    }

mTLS: `.clientAuth(ClientAuth.REQUIRE)` — обязательный,
`.clientAuth(ClientAuth.OPTIONAL)` — опциональный.

GostSslContextBuilder.build() сам вызывает `Security.addProvider()`. Не
регистрируйте провайдер вручную при использовании Netty-модуля.

### Jetty 12

Дополнительная зависимость:

    <dependency>
        <groupId>org.eclipse.jetty</groupId>
        <artifactId>jetty-server</artifactId>
        <version>12.0.19</version>
    </dependency>

ALPN для HTTP/2 требует модуль `jetty-alpn-java-server` на classpath.
Для одного `http/1.1` зависимость не нужна — ALPN не участвует в
согласовании.

    import org.eclipse.jetty.server.HttpConfiguration;
    import org.eclipse.jetty.server.HttpConnectionFactory;
    import org.eclipse.jetty.server.Request;
    import org.eclipse.jetty.server.Response;
    import org.eclipse.jetty.server.Server;
    import org.eclipse.jetty.server.ServerConnector;
    import org.eclipse.jetty.server.SslConnectionFactory;
    import org.eclipse.jetty.server.Handler;
    import org.eclipse.jetty.util.Callback;
    import org.eclipse.jetty.util.ssl.SslContextFactory;

    import java.nio.charset.StandardCharsets;

    // SslContextFactory принимает готовый SSLContext
    SslContextFactory.Server scf = new SslContextFactory.Server();
    scf.setSslContext(sslContext);
    scf.setIncludeProtocols("TLSv1.3");

    HttpConfiguration httpsConfig = new HttpConfiguration();
    httpsConfig.addCustomizer(new SecureRequestCustomizer());

    Server server = new Server();
    ServerConnector connector = new ServerConnector(server,
            new SslConnectionFactory(scf, "http/1.1"),
            new HttpConnectionFactory(httpsConfig));
    connector.setPort(8443);
    server.addConnector(connector);

    // Handler.Abstract — Jetty 12 core handler API (блокирующий обработчик)
    server.setHandler(new Handler.Abstract() {
        @Override
        public boolean handle(Request request, Response response, Callback callback) {
            try {
                String body = org.eclipse.jetty.io.Content.Source.asString(
                        request, StandardCharsets.UTF_8).trim();
                if ("PING".equals(body)) {
                    response.setStatus(200);
                    org.eclipse.jetty.io.Content.Sink.write(
                            response, true, "PONG\n", callback);
                } else {
                    callback.succeeded();
                }
                return true;
            } catch (Exception e) {
                callback.failed(e);
                return true;
            }
        }
    });
    server.start();

mTLS: `setNeedClientAuth(true)` — обязательный,
`setWantClientAuth(true)` — опциональный.

ALPN в Jetty 12 требует модуль `jetty-alpn-java-server` на classpath.
Без него согласование HTTP/2 не будет работать.

### Undertow 2

Дополнительная зависимость:

    <dependency>
        <groupId>io.undertow</groupId>
        <artifactId>undertow-core</artifactId>
        <version>2.3.18.Final</version>
    </dependency>

    import io.undertow.Undertow;
    import io.undertow.UndertowOptions;

    Undertow server = Undertow.builder()
            .addHttpsListener(8443, "0.0.0.0", sslContext)
            .setServerOption(UndertowOptions.ENABLE_HTTP2, true)
            .setHandler(exchange -> {
                exchange.getResponseSender().send("Hello GOST TLS!");
            })
            .build();
    server.start();

Для mTLS через OptionMap:

    import org.xnio.OptionMap;
    import org.xnio.Options;
    import org.xnio.SslClientAuthMode;

    Undertow server = Undertow.builder()
            .addHttpsListener(8443, "0.0.0.0", sslContext,
                    OptionMap.create(Options.SSL_CLIENT_AUTH_MODE, SslClientAuthMode.REQUIRED))
            .setHandler(exchange -> { ... })
            .build();

mTLS: `SslClientAuthMode.REQUIRED` — обязательный,
`SslClientAuthMode.REQUESTED` — опциональный.

Undertow — самый лаконичный вариант: `SSLContext` передаётся напрямую в
`addHttpsListener`, без дополнительных фабрик и обёрток.

### Tomcat 11 (Jakarta EE 10)

Tomcat 11 не предоставляет публичного API для прямой передачи
`javax.net.ssl.SSLContext` в коннектор. Единственный поддерживаемый
способ — кастомный `SSLImplementation`.

Дополнительная зависимость:

    <dependency>
        <groupId>org.apache.tomcat.embed</groupId>
        <artifactId>tomcat-embed-core</artifactId>
        <version>11.0.7</version>
    </dependency>

    import org.rssys.gost.jsse.GostJsseConstants;
    import org.rssys.gost.jsse.examples.ExamplesCertHelper;

    import org.apache.catalina.connector.Connector;
    import org.apache.catalina.startup.Tomcat;
    import org.apache.coyote.AbstractProtocol;
    import org.apache.tomcat.util.net.SSLHostConfig;
    import org.apache.tomcat.util.net.SSLHostConfigCertificate;
    import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
    import org.apache.tomcat.util.net.SSLImplementation;
    import org.apache.tomcat.util.net.SSLSupport;
    import org.apache.tomcat.util.net.SSLUtil;

    import javax.net.ssl.KeyManager;
    import javax.net.ssl.SSLSession;
    import javax.net.ssl.SSLSessionContext;
    import javax.net.ssl.TrustManager;
    import javax.net.ssl.X509KeyManager;
    import javax.net.ssl.X509TrustManager;
    import java.util.List;
    import java.util.Map;

    ExamplesCertHelper helper = new ExamplesCertHelper();

    Connector connector = new Connector("HTTP/1.1");
    connector.setPort(8443);
    connector.setSecure(true);
    connector.setScheme("https");
    connector.setProperty("SSLEnabled", "true");
    connector.setProperty("sslImplementationName",
            GostSSLImplementation.class.getName());

    SSLHostConfig sslHostConfig = new SSLHostConfig();
    sslHostConfig.setHostName("_default_");
    sslHostConfig.setSslProtocol("TLSv1.3");

    SSLHostConfigCertificate cert = new SSLHostConfigCertificate(
            sslHostConfig, Type.UNDEFINED);
    sslHostConfig.addCertificate(cert);
    connector.addSslHostConfig(sslHostConfig);

    Tomcat tomcat = new Tomcat();
    tomcat.setPort(8080);
    tomcat.getService().addConnector(connector);
    tomcat.start();

    // ---- Вложенные классы: GostSSLImplementation и GostSSLUtil ----

    public static final class GostSSLImplementation extends SSLImplementation {
        @Override
        public SSLSupport getSSLSupport(SSLSession session,
                                        Map<String, List<String>> additional) {
            return null;
        }

        @Override
        public SSLUtil getSSLUtil(SSLHostConfigCertificate certificate) {
            return new GostSSLUtil();
        }
    }

    public static final class GostSSLUtil implements SSLUtil {
        // Единый helper — getKeyManagers() и createSSLContext() должны
        // использовать один и тот же сертификат, иначе TLS-хендшейк упадёт
        private static final ExamplesCertHelper HELPER;

        static {
            try { HELPER = new ExamplesCertHelper(); }
            catch (Exception e) { throw new RuntimeException(e); }
        }

        @Override
        public SSLContext createSSLContext(
                List<String> negotiableProtocols) throws Exception {
            X509KeyManager km = HELPER.createKeyManager();
            X509TrustManager tm = HELPER.createTrustManager();
            return SSLUtil.createSSLContext(
                    HELPER.getSslContext(), km, tm);
        }

        @Override
        public KeyManager[] getKeyManagers() throws Exception {
            return new KeyManager[]{HELPER.createKeyManager()};
        }

        @Override
        public TrustManager[] getTrustManagers() throws Exception {
            return new TrustManager[]{HELPER.createTrustManager()};
        }

        @Override
        public void configureSessionContext(
                SSLSessionContext sslSessionContext) {}

        @Override
        public String[] getEnabledProtocols() {
            return GostJsseConstants.SUPPORTED_PROTOCOLS.clone();
        }

        @Override
        public String[] getEnabledCiphers() {
            return GostJsseConstants.SUPPORTED_CIPHER_SUITES.clone();
        }
    }

mTLS: `SSLHostConfig.setCertificateVerification("required")` —
обязательный, `setCertificateVerification("optional")` — опциональный.

Tomcat 11 использует Jakarta EE 10 (`jakarta.*`). Все зависимости
проекта должны быть Jakarta-совместимыми. `javax.*` в Tomcat 11 не
работает.

`sslImplementationName` передаётся через `connector.setProperty()`.
Tomcat автоматически создаёт экземпляр `SSLImplementation` по имени
класса при старте коннектора.

### Spring Boot 3.4

Spring Boot 3.4 конфигурирует embedded Tomcat. Кастомный SSLContext
передаётся через `WebServerFactoryCustomizer` + `SSLImplementation`
(аналогично standalone Tomcat 11, но с Spring Boot управляемой
конфигурацией).

Дополнительная зависимость:

    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <version>3.4.5</version>
    </dependency>

    import org.rssys.gost.jsse.GostJsseConstants;
    import org.rssys.gost.jsse.RssysGostJsseProvider;
    import org.rssys.gost.jsse.examples.ExamplesCertHelper;

    import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
    import org.springframework.boot.web.server.WebServerFactoryCustomizer;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;

    import org.apache.catalina.connector.Connector;
    import org.apache.tomcat.util.net.SSLHostConfig;
    import org.apache.tomcat.util.net.SSLHostConfigCertificate;
    import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
    import org.apache.tomcat.util.net.SSLImplementation;
    import org.apache.tomcat.util.net.SSLSupport;
    import org.apache.tomcat.util.net.SSLUtil;

    import javax.net.ssl.*;
    import java.security.Security;
    import java.util.List;
    import java.util.Map;

    @Configuration
    public class GostSslConfig {

        static { Security.addProvider(new RssysGostJsseProvider()); }

        @Bean
        public WebServerFactoryCustomizer<TomcatServletWebServerFactory>
                gostSslCustomizer() {
            return factory -> {
                factory.addConnectorCustomizers(connector -> {
                    connector.setSecure(true);
                    connector.setScheme("https");
                    connector.setProperty("SSLEnabled", "true");
                    // Tomcat 11: sslImplementationName через setProperty
                    connector.setProperty("sslImplementationName",
                            GostSSLImplementation.class.getName());

                    SSLHostConfig hc = new SSLHostConfig();
                    hc.setHostName("_default_");
                    hc.setSslProtocol("TLSv1.3");

                    SSLHostConfigCertificate cert =
                            new SSLHostConfigCertificate(hc, Type.UNDEFINED);
                    hc.addCertificate(cert);
                    connector.addSslHostConfig(hc);
                });
                factory.setPort(8443);
            };
        }

        // ---- GostSSLImplementation и GostSSLUtil — идентичны
        //      показанным в разделе «Tomcat 11» выше ----
    }

application.properties:

    server.port=8443

Вложенные классы `GostSSLImplementation` и `GostSSLUtil` — идентичны
показанным в разделе Tomcat 11 выше. Единственное отличие:
`GostSslConfig` регистрирует провайдер в `static {}`, а не в методе,
потому что Spring Boot конфигурирует встроенный сервер до полной
инициализации контекста.

mTLS: внутри `ConnectorCustomizer` добавьте
`sslHostConfig.setCertificateVerification("required")`.

#### mTLS

Взаимная аутентификация (mTLS) включается на стороне сервера флагом
`setNeedClientAuth(true)`. TrustManager проверяет клиентский сертификат
тем же `GostX509TrustManager`, но с CA клиентских сертификатов (может
отличаться от CA серверных).

Пример для Jetty 12 (для других серверов — см. таблицу ниже):

    import org.rssys.gost.jsse.RssysGostJsseProvider;
    import org.rssys.gost.jsse.manager.GostX509TrustManager;
    import org.rssys.gost.jsse.manager.GostX509KeyManager;
    import org.rssys.gost.signature.PublicKeyParameters;
    import org.rssys.gost.pkix.cert.GostCertificate;

    import javax.net.ssl.SSLContext;
    import javax.net.ssl.KeyManager;
    import javax.net.ssl.TrustManager;
    import java.nio.file.Files;
    import java.nio.file.Paths;
    import java.security.Security;

    Security.addProvider(new RssysGostJsseProvider());

    // CA для проверки клиентских сертификатов
    byte[] clientCaDer = Files.readAllBytes(Paths.get("client-ca.der"));
    PublicKeyParameters clientCaKey = new GostCertificate(clientCaDer).getPublicKey();
    GostX509TrustManager tm = new GostX509TrustManager(clientCaKey, false);

    // Серверный KeyManager — свой сертификат
    GostX509KeyManager km = new GostX509KeyManager();
    km.addKeyEntry("default", serverChain, serverPrivateKey);

    SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
    ctx.init(new KeyManager[]{km}, new TrustManager[]{tm}, null);

    // Передать ctx в Jetty (или другой сервер) + включить needClientAuth

<table>
<caption>Способы включения mTLS для разных серверов
приложений:</caption>
<colgroup>
<col style="width: 40%" />
<col style="width: 60%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Сервер</th>
<th style="text-align: left;">Метод</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><strong>Netty</strong></p></td>
<td
style="text-align: left;"><p><code>GostSslContextBuilder.forServer(km).clientAuth(ClientAuth.REQUIRE)</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><strong>Jetty</strong></p></td>
<td
style="text-align: left;"><p><code>SslContextFactory.Server.setNeedClientAuth(true) / setWantClientAuth(true)</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><strong>Undertow</strong></p></td>
<td
style="text-align: left;"><p><code>OptionMap.create(org.xnio.Options.SSL_CLIENT_AUTH_MODE, org.xnio.SslClientAuthMode.REQUIRED)</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><strong>Tomcat</strong></p></td>
<td
style="text-align: left;"><p><code>SSLHostConfig.setCertificateVerification("required")</code></p></td>
</tr>
<tr>
<td style="text-align: left;"><p><strong>Spring Boot</strong></p></td>
<td style="text-align: left;"><p>В <code>ConnectorCustomizer</code>:
<code>sslHostConfig.setCertificateVerification("required")</code></p></td>
</tr>
</tbody>
</table>

## Потокобезопасность (Thread safety)

`GostSSLEngine` разрешает параллельные `wrap()` и `unwrap()` из разных
потоков (два `ReentrantLock` для inbound/outbound). Запрещено вызывать
`wrap()` из двух потоков одновременно.

`GostSSLSocket` — thread-safe после завершения handshake: чтение и
запись могут выполняться из разных потоков (отдельные блокировки
read/write).

`GostX509TrustManager` thread-safe — OCSP-кэш использует
`ConcurrentHashMap`.

`GostX509KeyManager` thread-safe — хранилище entry’ей использует
`CopyOnWriteArrayList` (read-heavy, lock-free reads, редкие writes).

`GostSSLSessionContext` thread-safe — PSK-хранилище использует
`InMemoryPskStore` (thread-safe), карта сессий — `synchronizedMap` с
LRU-эвiction.

## Загрузка сертификата

Для production рекомендуется PKCS12 (см. раздел «Конфигурация сервера»).

`CertificateBridge.toJca()` и `CertificateBridge.toGost()` конвертируют
между `GostCertificate` и `java.security.cert.X509Certificate`.
`toJca()` принимает `GostCertificate` / `List<GostCertificate>`,
`toGost()` — `X509Certificate` / `X509Certificate[]`.

    import org.rssys.gost.jsse.bridge.CertificateBridge;

## Безопасность реализации

- `GostX509TrustManager` — fail-closed: при отсутствии OCSP-ответа (если
  политика `STAPLING_REQUIRED`) сертификат считается невалидным.

- Constant-time сравнения для verify\_data и PSK binders.

- Пустой `getAcceptedIssuers()` — не раскрываем список доверенных CA
  клиенту (защита от fingerprinting).

- Затирание ключевого материала при close, fatal alert, exception.

- OCSP-кэш с TTL (1 час по умолчанию).

- Защита от downgrade: только TLSv1.3, только ГОСТ-наборы.

## Ограничения

- Только TLS 1.3 (TLS 1.2 и ниже не поддерживаются).

- Только ГОСТ-наборы (`TLS_KUZNYECHIK_MGM_STREEBOG_256_L/S`).

- PSK-тикеты одноразовые (RFC 8446 §8.1).

- KeyManagerFactory — только алгоритм `GostX509` (не `PKIX`, не
  `NewSunX509`).

- Проверка nonce в OCSP-ответах — ответственность приложения (RFC 8954).

## Примеры интеграции с серверами приложений

Все примеры интеграции с популярными серверами находятся в модуле
`examples/jsse` и запускаются через Makefile из его корня:

    # Все 4 сервера последовательно (Netty, Jetty, Undertow, Tomcat)
    make -C examples/jsse all

    # По одному
    make -C examples/jsse netty
    make -C examples/jsse jetty
    make -C examples/jsse undertow
    make -C examples/jsse tomcat

    # Spring Boot — интерактивно
    make -C examples/jsse springboot

    # Spring Boot — CI-тест (@SpringBootTest + GostSSLSocket)
    make -C examples/jsse test

Каждый сервер поднимается на случайном порту, выполняет TLS 1.3
handshake с ГОСТ-наборами, выводит `SUCCESS` и останавливается.
Исключение — `make springboot` (бесконечный цикл, останов через Ctrl+C).

HTTP-серверы (Jetty, Undertow, Tomcat) проверяют только TLS handshake.
`GostSSLEngine` не совместим с JDK HttpClient (SSLFlowDelegate) — полный
HTTP-обмен доступен через ручной запуск и
`curl -k --tlsv1.3 --https...`.

## Запуск интеграционных тестов

Интеграционные тесты проверяют конкурентность shared state
(`GostSSLSessionContext`, `GostX509KeyManager`), mTLS через Jetty, PSK
resumption, reconnect под нагрузкой и таймауты в сетевых условиях.

Все тесты помечены `@Tag("integration")` — запуск одной командой:

    # Все интеграционные тесты JSSE (19 тестов, 7 файлов)
    make -C examples/jsse test-int-all

    # Или напрямую через Maven:
    mvn test -pl crypto-gost-jsse,examples/jsse -am -Dgroups="integration" -Dsurefire.excludedGroups=

    # Отдельные группы:
    make -C examples/jsse test-integration   # 16 тестов examples/jsse
    make -C examples/jsse test-keymanager    # 3 теста GostX509KeyManager
    make -C examples/jsse test-concurrent    # 100 параллельных handshake'ов

## Запуск стресс-теста

Стресс-тест предназначен для выявления: утечек памяти, зависаний,
корректности имплементации TLS 1.3 протокола, устойчивость к аварийным
обрывам, выявлени максимума одновременных сессий.

Описание методики стресс-теста приведено [в
документе](doc/stress-test.md).

    # Полный прогон (5 минут)
    make -C examples/jsse test-stress

    # Быстрый прогон (1 минута)
    make -C examples/jsse test-stress ARGS=-Dstress.duration=1

    # Через Maven напрямую
    mvn test -pl examples/jsse \
      -Dtest="JsseStressTest#stressTest" \
      -Dsurefire.excludedGroups="" \
      -Dstress.duration=5 \
      -Dstress.cacheSize=5000

Дополнительный стресс-тест через реальный HTTP-сервер Undertow:

    # Undertow: HTTP-профили, Connection: keep-alive (5 минут)
    make -C examples/jsse test-undertow-stress

    # Быстрый прогон (1 минута)
    mvn test -pl examples/jsse -am -Dtest="UndertowStressTest#stressTest" \
      -Dstress.duration=1 -Dsurefire.failIfNoSpecifiedTests=false

    # Через Maven напрямую
    mvn test -pl examples/jsse -am \
      -Dtest="UndertowStressTest#stressTest" \
      -Dstress.duration=5 -Dsurefire.failIfNoSpecifiedTests=false

Jetty 12 с `GostSSLSocket` при keep-alive соединениях под нагрузкой не
сбрасывает TLS-буфер после `response.write()` — зашифрованные данные не
доставляются клиенту. Одиночные запросы (`Connection: close`) работают
корректно. Для production-использования рекомендуется Undertow или
Netty. Баг воспроизводится в Jetty 12.0.19, корень проблемы — в
`SslConnection.flush()`.

## Запуск фаззинг-тестов для всех модулей

Фаззинг-тесты используют Jazzer (libFuzzer + JUnit) для поиска багов.
Каждый `@FuzzTest` содержит seed-файлы (corpus) и при обычном запуске
Maven прогоняет только их — автоматически для всех `@FuzzTest` в модуле:

Для удобства есть Makefile-цели:

    # Один модуль, 30 минут (DUR в секундах). Можно указывать модули: core, pkix, tls13, jsse :
    make fuzz MODULE=tls13 DUR=1800 JOBS=4

    # Все 4 модуля параллельно, логи в fuzz-*.log, 1 час:
    make fuzz-all DUR=3600 JOBS=4

## Поддержать проект

Если проект оказался полезным, вы можете поддержать проект на
[**Boosty**](https://boosty.to/mike_ananev/donate)

## Лицензия

Автор: Михаил Ананьев.  

Данный проект распространяется под *Открытой лицензией на программное
обеспечение "Рэд старс системс"*, версия 1.0.  
Текст лицензии находится в файле LICENSE или по
[ссылке](https://gitflic.ru/project/red-stars-systems/licenses/blob?file=open-license%2FLICENSE).
