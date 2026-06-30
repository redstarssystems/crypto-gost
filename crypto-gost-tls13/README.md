# Реализация протокола TLS 1.3 с ГОСТ алгоритмами в соответствии с RFC 9367 — crypto-gost-tls13

Модуль `crypto-gost-tls13` содержит реализацию **TLS 1.3** (RFC 8446 +
RFC 9367) с ГОСТ-криптографией:

1.  **Протоколы:**

    - **Handshake**: полный (client/server), сокращённый (`PSK`),
      взаимный (`mTLS`).

    - **ALPN (RFC 7301)** — согласование протокола прикладного уровня
      (HTTP/2, HTTP/1.1).

    - **SNI (RFC 6066)** — указание имени сервера для multi-tenant
      развёртываний.

    - **KeyUpdate (RFC 8446 §4.6.3)** — обновление ключей шифрования
      трафика.

    - **Cipher suites**: `TLS_KUZNYECHIK_MGM_STREEBOG_256_L/S`.

    - **ECDHE**: CryptoPro-A (256-bit), CryptoPro-B (512-bit)

    - **Per-record TLSTREE re-keying** — смена ключа шифрования на
      каждую TLS-запись.

    - **Фрагментация и сборка** рукопожатий и записей (RFC 8446 §5.1).

    - **Session resumption**: `PSK` через `NewSessionTicket`
      (`InMemoryPskStore` in-memory, single-use).

    - **OCSP stapling**: сервер прикладывает OCSP-ответ к сертификату.

    - **Post-handshake messages**: `NewSessionTicket` (сохранение для
      `PSK`).

    - **HRR (RFC 8446 §4.1.3)** — смена ECDHE-группы через
      HelloRetryRequest, включая пересчёт PSK binder для второго
      ClientHello.

2.  **Криптография**:

    - **Key schedule**: `HKDF-Streebog` (RFC 5869) по схеме TLS 1.3 (RFC
      8446 §7.1).

    - **Защита записей**: `MGM-AEAD` (Kuznyechik) с nonce по RFC 8446
      §5.3.

    - Эфемерные ключи затираются после использования.

3.  **Сертификаты:**

    - Парсинг X.509v3 (GOST R 34.10-2012) — делегирован в
      `GostCertificate` (модуль `crypto-gost-pkix`).

    - Валидация цепочки: подписи, DN (issuer → subject),
      `Basic Constraints`, `Key Usage`, `Extended Key Usage`
      (`serverAuth` / `clientAuth`), pathLen.

    - Проверка hostname: dNSName + iPAddress (RFC 6125).

    - Верификация OCSP-ответов (RFC 6960).

4.  **Транспорт:**

    - `TlsTransport` — интерфейс.

    - `InMemoryTlsTransport` — для тестов и однопроцессных сценариев
      (in-memory очередь).

    - `SocketTlsTransport` — blocking I/O через `java.net.Socket`.

    - `ChannelTlsTransport` — NIO `SocketChannel`-based transport
      (blocking mode, interruptible).

5.  **Пошаговый handshake:**

    - `TlsHandshakeEngine` — state machine для handshake (отвязан от
      I/O). Используется `TlsSession` как оркестратор; пригоден для
      интеграции с JSSE (`SSLEngine`).

6.  **ByteBuffer API:**

    - `TlsRecord.protect/unprotect` — ByteBuffer-перегрузки для
      zero-copy интеграции с NIO.

7.  **Загрузка ключей:**

    - `GostPkcs12Loader` — чтение PFX (PKCS#12) с нативной поддержкой
      ГОСТ PBE: PBKDF2-HMAC-Streebog + Кузнечик CTR-ACPKM (RFC
      9337/9548) и fallback на JDK KeyStore.

8.  **Завершение сессии:**

    - `close_notify` — корректное закрытие по протоколу.

    - Затирание ключевого материала при закрытии или ошибке.

    - Обработка alert: `fatal` — немедленное закрытие + затирание.

9.  **Безопасность реализации:**

    - Constant-time сравнения для verify\_data и PSK binders (защита от
      timing attacks)

    - Затирание ключевого материала при close, fatal alert, exception в
      handshake

    - Защита от DoS: лимиты на длину цепочки сертификатов (10),
      post-handshake messages, размер записей.

10. **Ограничения:**

    - Только resumption PSK (0-RTT и external PSK не поддерживаются).

    - Только `psk_dhe_ke` (pure PSK без ECDHE не поддерживается).

    - Только ГОСТ (non-GOST cipher suites не поддерживаются).

    Все криптографические операции выполняются встроенными средствами
    библиотеки — без внешних зависимостей.

Для работы TLS необходим транспортный уровень — реализация интерфейса
`TlsTransport`:

    public interface TlsTransport extends AutoCloseable {
        /** Отправляет полную TLS-запись: [header(5) || body(length)]. */
        void sendRecord(byte[] record) throws IOException;
        /** Блокирующее чтение: [header(5) || body(length)]. */
        byte[] receiveRecord() throws IOException;
        void close() throws IOException;
    }

Реализация `receiveRecord()` должна сначала прочитать 5-байтовый
заголовок записи (RFC 8446 §5), извлечь длину тела из байт `[3..4]`,
затем дочитать тело. Рекомендуется `InputStream.readNBytes()`.

## Создание TlsTransport для TCP

Готовый адаптер `SocketTlsTransport` в пакете
`org.rssys.gost.tls13.transport`:

    import org.rssys.gost.tls13.transport.SocketTlsTransport;
    import java.net.Socket;

    Socket socket = new Socket("host", 443);
    socket.setSoTimeout(5000);  // обязательно!
    TlsTransport transport = new SocketTlsTransport(socket);

Реализация `receiveRecord()` использует явный цикл read loop (не
`readFully`/`readNBytes`) и проверяет флаг закрытия на каждой итерации.
Перед использованием обязательно установите `socket.setSoTimeout()` —
без таймаута злоумышленник может повесить сессию навсегда.

Для сценариев, требующих прерывания потока при блокирующем чтении
(InterruptibleChannel), используйте `ChannelTlsTransport` (пакет
`org.rssys.gost.tls13.transport`), который работает в блокирующем режиме
поверх `SocketChannel` и поддерживает `Thread.interrupt()`:

    import org.rssys.gost.tls13.transport.ChannelTlsTransport;
    import java.net.InetSocketAddress;
    import java.nio.channels.SocketChannel;

    SocketChannel channel = SocketChannel.open(new InetSocketAddress("host", 443));
    channel.configureBlocking(true);
    TlsTransport transport = new ChannelTlsTransport(channel);

Для тестов и взаимодействия в рамках одной JVM используйте
`InMemoryTlsTransport` (пакет `org.rssys.gost.tls13.transport`):

    import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

    // Single-ended
    InMemoryTlsTransport transport = new InMemoryTlsTransport();
    transport.inject(record);  // эмулировать входящую запись
    byte[] recv = transport.receiveRecord();

    // Двунаправленный (клиент-сервер)
    InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
    TlsTransport clientTransport = pair.getClientTransport();
    TlsTransport serverTransport = pair.getServerTransport();

## Серверная сессия с цепочкой сертификатов

Сервер использует `TlsServerConfig` для конфигурации. Цепочка
сертификатов передаётся списком: серверный сертификат (end-entity),
затем промежуточные CA, последним — корневой CA.

    import org.rssys.gost.tls13.*;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import org.rssys.gost.pkix.cert.GostCertificate;
    import org.rssys.gost.tls13.config.TlsServerConfig;
    import org.rssys.gost.tls13.transport.SocketTlsTransport;
    import java.net.ServerSocket;
    import java.nio.charset.StandardCharsets;
    import java.nio.file.Files;
    import java.nio.file.Paths;
    import java.util.List;

    // Загружаем сертификаты (серверный + промежуточные + корневой)
    byte[] certDer = Files.readAllBytes(Paths.get("server.der"));
    byte[] caDer   = Files.readAllBytes(Paths.get("intermediate.der"));
    byte[] rootDer = Files.readAllBytes(Paths.get("root.der"));
    byte[] keyDer  = Files.readAllBytes(Paths.get("server.key"));

    List<GostCertificate> chain = List.of(
            new GostCertificate(certDer),      // серверный (leaf)
            new GostCertificate(caDer),        // промежуточный CA
            new GostCertificate(rootDer));      // корневой CA (самоподписанный)

    PrivateKeyParameters priv = org.rssys.gost.jca.spec.GostDerCodec.decodePrivateKey(keyDer);
    byte[] ocspDer = Files.readAllBytes(Paths.get("ocsp.der"));

    // Принимаем TCP-подключение
    ServerSocket ss = new ServerSocket(8443);
    Socket socket = ss.accept();
    SocketTlsTransport transport = new SocketTlsTransport(socket);

    // Сервер через TlsServerConfig
    TlsSession server = TlsSession.createServer(
            new TlsServerConfig(
                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                    chain, priv)
                    .withOcspStaplingResponse(ocspDer), transport);  // OCSP stapling (RFC 6960)

    try {
        server.handshakeAsServer();

        // Принимаем данные от клиента
        byte[] request = server.read();
        System.out.println("Получено: " + new String(request, StandardCharsets.UTF_8));

        // Отвечаем
        server.write("Hello from GOST TLS 1.3 server!".getBytes(StandardCharsets.UTF_8));
    } finally {
        server.close();
        ss.close();
    }

Сервер не валидирует свою цепочку — она проверяется клиентом. Для
проверки со стороны клиента используйте `withCaPublicKey()` в
`TlsClientConfig` (см. «Клиент с полной валидацией»).

Для multi-tenant серверов (разные сертификаты под разные SNI)
используйте `TlsServerConfig.withSniSelector()`:

    import org.rssys.gost.tls13.*;
    import org.rssys.gost.tls13.config.TlsServerConfig;
    import org.rssys.gost.tls13.config.TlsServerCredentials;

    TlsSession server = TlsSession.createServer(
        new TlsServerConfig(cs, defaultChain, defaultKey)
            .withSniSelector(sni -> {
                if ("foo.example.com".equals(sni))
                    return new TlsServerCredentials(fooChain, fooKey, null);
                return null; // fallback на default-сертификат
            }), transport);

## Клиентская сессия (анонимная)

Анонимный клиент (без сертификата) подключается к серверу через
`TlsClientConfig`.

    import org.rssys.gost.tls13.*;
    import org.rssys.gost.tls13.config.TlsClientConfig;
    import org.rssys.gost.tls13.transport.SocketTlsTransport;
    import java.net.Socket;
    import java.nio.charset.StandardCharsets;

    Socket socket = new Socket("gost-server.example.com", 8443);
    SocketTlsTransport transport = new SocketTlsTransport(socket);

    TlsSession client = TlsSession.createClient(
            new TlsClientConfig(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L),
            transport);

    try {
        client.handshakeAsClient();
        client.write("Hello from client!".getBytes(StandardCharsets.UTF_8));

        byte[] response = client.read();
        System.out.println("Ответ: " + new String(response, StandardCharsets.UTF_8));
    } finally {
        client.close();
    }

Клиент с полной валидацией сертификата сервера (CA-ключ + hostname +
OCSP):

    import org.rssys.gost.tls13.*;
    import org.rssys.gost.signature.PublicKeyParameters;
    import org.rssys.gost.pkix.cert.GostCertificate;
    import org.rssys.gost.tls13.config.TlsClientConfig;
    import java.net.Socket;
    import java.nio.charset.StandardCharsets;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    // Загружаем ключ CA для проверки сертификата сервера
    byte[] caDer = Files.readAllBytes(Paths.get("ca.der"));
    GostCertificate caCert = new GostCertificate(caDer);
    PublicKeyParameters caKey = caCert.getPublicKey();

    TlsSession client = TlsSession.createClient(new TlsClientConfig(
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L)
            .withCaPublicKey(caKey)
            .withServerHostname("gost.example.com")
            .withRequireOcspStapling(true), transport);

    try {
        client.handshakeAsClient();
        client.write("Hello!".getBytes(StandardCharsets.UTF_8));
        byte[] response = client.read();
    } finally {
        client.close();
    }

Упрощённые фабрики — для сценариев без расширенных настроек (без SNI,
ALPN, OCSP, mTLS):

    // Клиент (без валидации сервера)
    TlsSession client = TlsSession.createClient(
        transport, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
        null, null);

    // Клиент (с валидацией по CA)
    TlsSession client = TlsSession.createClient(
        transport, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
        null, null, caPublicKey);

    // Сервер
    TlsSession server = TlsSession.createServer(
        transport, TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
        serverCert, privateKey);

Для SNI, ALPN, OCSP stapling, mTLS и выбора клиентского сертификата по
OID-фильтрам используйте `TlsClientConfig` / `TlsServerConfig`.

ALPN: клиент предлагает протоколы прикладного уровня:

    TlsSession client = TlsSession.createClient(
        new TlsClientConfig(cs)
            .withAlpnProtocols(List.of("h2", "http/1.1")), transport);

Сервер настраивается через `TlsServerConfig.withAlpnProtocols()`. После
handshake согласованный протокол доступен через
`session.getAlpnProtocol()`.

Для снижения фрагментации на каналах с малым MTU (IoT, спутниковая
связь) клиент может запросить уменьшенный размер фрагмента через
`session.setMaxFragmentLengthRequest(TlsConstants.MAX_FRAG_LEN_512)` до
handshake. Поддерживаются значения 512, 1024, 2048, 4096 (RFC 6066 §4).
Согласованное значение доступно через `session.getMaxFragmentLength()`.

## Взаимная аутентификация узлов (mTLS)

Сервер запрашивает сертификат клиента через `withCaPublicKey()` в
`TlsServerConfig`.

Клиент передаёт свой сертификат и закрытый ключ через
`withClientCertificateChain()` (один сертификат или полная цепочка) и
`withClientPrivateKey()`.

    // Сервер (mTLS)
    import org.rssys.gost.tls13.*;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import org.rssys.gost.signature.PublicKeyParameters;
    import org.rssys.gost.pkix.cert.GostCertificate;
    import org.rssys.gost.tls13.config.TlsServerConfig;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    byte[] caDer   = Files.readAllBytes(Paths.get("ca.der"));
    byte[] certDer = Files.readAllBytes(Paths.get("server.der"));
    byte[] keyDer  = Files.readAllBytes(Paths.get("server.key"));

    PublicKeyParameters caKey    = new GostCertificate(caDer).getPublicKey();
    PrivateKeyParameters priv    = org.rssys.gost.jca.spec.GostDerCodec.decodePrivateKey(keyDer);
    List<GostCertificate> chain  = List.of(new GostCertificate(certDer));

    TlsSession server = TlsSession.createServer(
            new TlsServerConfig(
                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                    chain, priv)
            .withCaPublicKey(caKey), transport);  // ← запрашивать сертификат клиента

    try {
        server.handshakeAsServer();
        // После handshake сертификат клиента проверен
        List<GostCertificate> peerCerts = server.getPeerCertificates();
        // peerCerts.get(0) — сертификат клиента
        byte[] data = server.read();
    } finally {
        server.close();
    }

    // Клиент (mTLS)
    import org.rssys.gost.tls13.*;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import org.rssys.gost.pkix.cert.GostCertificate;
    import org.rssys.gost.tls13.config.TlsClientConfig;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    byte[] clientCertDer = Files.readAllBytes(Paths.get("client.der"));
    byte[] clientKeyDer  = Files.readAllBytes(Paths.get("client.key"));

    GostCertificate clientCert   = new GostCertificate(clientCertDer);
    PrivateKeyParameters clientPriv = org.rssys.gost.jca.spec.GostDerCodec.decodePrivateKey(clientKeyDer);

    TlsSession client = TlsSession.createClient(
            new TlsClientConfig(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L)
            .withClientCertificateChain(clientCert)
            .withClientPrivateKey(clientPriv), transport);

    try {
        client.handshakeAsClient();
        client.write("Hello from mTLS client!".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    } finally {
        client.close();
    }

Для цепочки из нескольких сертификатов (leaf + промежуточные CA)
используйте
`withClientCertificateChain(List.of(leaf, intermediate, root))`.

## Выбор клиентского сертификата по OID-фильтрам (oid\_filters)

Сервер может включить в `CertificateRequest` расширение `oid_filters`
(RFC 8446 §4.2.5) — список OID-критериев для выбора подходящего
клиентского сертификата. Типичный ГОСТ-сценарий: сервер требует
сертификат с CertificatePolicies KC1 (`1.2.643.100.113.1`) или KC2
(`1.2.643.100.113.2`).

Сервер — передать фильтры через `withOidFilters()`:

    import org.rssys.gost.tls13.config.TlsServerConfig;
    import org.rssys.gost.tls13.config.OIDFilter;
    import org.rssys.gost.pkix.cert.GostDerParser;

    // Фильтр: клиент должен предъявить сертификат с CertificatePolicies KC1
    // filterOid = OID расширения CertificatePolicies (2.5.29.32), filterValues = DER SEQUENCE { OID KC1 }
    byte[] oidTlv = new byte[2 + GostDerParser.KC1_OID_BYTES.length];
    oidTlv[0] = 0x06; // TAG_OID
    oidTlv[1] = (byte) GostDerParser.KC1_OID_BYTES.length;
    System.arraycopy(GostDerParser.KC1_OID_BYTES, 0, oidTlv, 2, GostDerParser.KC1_OID_BYTES.length);
    byte[] filterValues = new byte[2 + oidTlv.length];
    filterValues[0] = 0x30; // TAG_SEQUENCE
    filterValues[1] = (byte) oidTlv.length;
    System.arraycopy(oidTlv, 0, filterValues, 2, oidTlv.length);

    OIDFilter kc1Filter = new OIDFilter(GostDerParser.CP_OID_BYTES, filterValues);

    TlsSession server = TlsSession.createServer(
            new TlsServerConfig(ciphersuite, chain, priv)
                    .withCaPublicKey(caKey)
                    .withOidFilters(List.of(kc1Filter)),
            transport);
    server.handshakeAsServer();

Клиент — передать `ClientCertificateSelector` через
`withClientCertificateSelector()`:

    import org.rssys.gost.tls13.config.TlsClientConfig;
    import org.rssys.gost.tls13.config.ClientCertificateSelector;
    import org.rssys.gost.tls13.config.TlsClientCredentials;
    import org.rssys.gost.tls13.cert.TlsCertUtils;

    // Два сертификата: KC1 (clientAuth + KC1 CertificatePolicies) и обычный (clientAuth)
    ClientCertificateSelector selector = (caDns, oidFilters) -> {
        for (var entry : List.of(
                Map.entry(kc1Cert, kc1Key),
                Map.entry(simpleCert, simpleKey))) {
            GostCertificate cert = entry.getKey();
            boolean ok = oidFilters.stream().allMatch(f -> TlsCertUtils.matchesOidFilter(cert, f));
            if (ok) return new TlsClientCredentials(List.of(cert), entry.getValue());
        }
        return null; // нет подходящего → отправляется пустой certificate_list
    };

    TlsSession client = TlsSession.createClient(
            new TlsClientConfig(ciphersuite)
                    .withClientCertificateSelector(selector),
            transport);
    client.handshakeAsClient();

Если `selector` возвращает `null` — клиент отправляет пустой
`certificate_list` (RFC 8446 §4.4.2). Сервер сам решает, прерывать ли
handshake.

Встроенные константы OID: `GostOids.POLICY_KC1` = `1.2.643.100.113.1`,
`GostOids.POLICY_KC2` = `1.2.643.100.113.2`. Байтовые константы:
`GostDerParser.KC1_OID_BYTES`, `GostDerParser.KC2_OID_BYTES`,
`GostDerParser.CP_OID_BYTES`. Фильтр по EKU остаётся — используйте
`GostDerParser.EKU_OID_BYTES` с `GostDerParser.CLIENT_AUTH_OID_BYTES`
для clientAuth.

## Возобновление сессии по предварительно согласованному ключу (PSK session resumption)

После полного *handshake* сервер автоматически отправляет клиенту
PSK-билет (сообщение `NewSessionTicket`) При следующем подключении
клиент может использовать этот билет для сокращённого *handshake* — без
*ECDHE* и проверки сертификатов. Это заменяет дорогую асимметричную
криптографию на симметричную HMAC-операцию, что значительно ускоряет
повторные подключения и снижает нагрузку на ЦП.

Для этого сервер и клиент имеют независимые `PskStore`. Сервер сохраняет
тикет с PSK при отправке `NewSessionTicket`, клиент — при получении:

    import org.rssys.gost.tls13.*;
    import org.rssys.gost.tls13.psk.PskStore;
    import org.rssys.gost.tls13.psk.InMemoryPskStore;

    InMemoryPskStore serverStore = new InMemoryPskStore(1000); // макс. 1000 PSK-тикетов (см. PskStore javadoc)

    // Сервер
    TlsSession server1 = TlsSession.createServer(/* TlsServerConfig */, transport);
    server1.setPskStore(serverStore);
    server1.handshakeAsServer();
    server1.write("ready".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    server1.close();

    // клиент
    InMemoryPskStore clientStore = new InMemoryPskStore(100);  // макс. 100 PSK-тикетов (см. PskStore javadoc)

    TlsSession client1 = TlsSession.createClient(/* TlsClientConfig */, transport);
    client1.setPskStore(clientStore);
    client1.handshakeAsClient();
    // read() обрабатывает NST внутри, возвращает данные сервера
    byte[] data = client1.read();
    client1.close();

    // Второе подключение — сокращённый handshake (PSK)
    // Клиент автоматически находит тикет в PskStore
    TlsSession client2 = TlsSession.createClient(/* TlsClientConfig */, transport);
    client2.setPskStore(clientStore);
    client2.handshakeAsClient();
    boolean resumed = client2.wasResumed(); // true — сокращённый, false — полный handshake
    client2.write("Resumed!".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    client2.close();

    TlsSession server2 = TlsSession.createServer(/* TlsServerConfig */, transport);
    server2.setPskStore(serverStore);
    server2.handshakeAsServer();
    server2.close();

PSK-билеты одноразовые (RFC 8446 §8.1).  
После успешного сокращённого рукопожатия *handshake* билет удаляется из
`PskStore`.

Если билет не подошёл или устарел, сервер автоматически выполнит обычный
полный handshake — без ошибки.

Метод `read()` обрабатывает не более 8 post-handshake сообщений за один
вызов (`MAX_POST_HANDSHAKE`). Это защита от flood-атак: если пир шлёт 9+
сообщений подряд, `read()` бросает
`TlsException(ALERT_UNEXPECTED_MESSAGE)`. При необходимости обработать
больше 8 билетов вызывайте `read()` повторно — счётчик сбрасывается.

## Потоковая передача данных

Методы `read()` и `write()` можно вызывать многократно — одна TLS-сессия
поддерживает произвольное количество записей в обе стороны.

### Серверный цикл обработки

Сервер принимает несколько запросов от клиента, на каждый отвечает:

    import org.rssys.gost.tls13.*;
    import org.rssys.gost.util.AuthenticationException;
    import java.io.IOException;
    import java.nio.charset.StandardCharsets;

    // после handshakeAsServer()
    while (true) {
        try {
            byte[] request = server.read();
            server.write(process(request).getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            if (e.getCause() instanceof AuthenticationException) {
                System.err.println("Ошибка целостности записи — возможна атака");
            }
            break;
        }
    }

### Передача файла

Клиент читает файл с диска и отправляет его частями. Сервер собирает
части и записывает в новый файл. В примере клиент сначала передаёт длину
файла (8 байт, `long`), затем сами данные. Такой подход надёжнее, чем
маркер конца.

    // Клиент
    import org.rssys.gost.tls13.*;
    import java.nio.*;
    import java.nio.file.*;

    client.handshakeAsClient();

    byte[] fileBytes = Files.readAllBytes(Paths.get("data.bin"));

    // Сначала длина файла
    client.write(ByteBuffer.allocate(8).putLong(fileBytes.length).array());

    // MAX_PLAINTEXT_LENGTH - 1: 1 байт резервируется под inner_type (RFC 8446 §5.2)
    int chunkSize = TlsConstants.MAX_PLAINTEXT_LENGTH - 1; // 16383 — макс. payload одного TLS-record
    for (int off = 0; off < fileBytes.length; off += chunkSize) {
        int len = Math.min(chunkSize, fileBytes.length - off);
        byte[] chunk = new byte[len];
        System.arraycopy(fileBytes, off, chunk, 0, len);
        client.write(chunk);
    }

    // Сервер
    import org.rssys.gost.tls13.*;
    import java.io.*;
    import java.nio.*;
    import java.nio.file.*;

    server.handshakeAsServer();

    // Читаем длину файла
    byte[] lenBytes = server.read();
    long fileLength = ByteBuffer.wrap(lenBytes).getLong();

    ByteArrayOutputStream data = new ByteArrayOutputStream();
    long totalRead = 0;
    while (totalRead < fileLength) {
        // read() возвращает данные из одного TLS record.
        // Клиент может дробить данные через write() на части любого размера —
        // сервер всё равно получит их целиком, просто вызывайте read() в цикле,
        // пока сумма chunk.length не сравняется с fileLength.
        // Идея в том, что TLS — потоковый протокол с гарантией доставки, поэтому куски гарантированно соберутся.
        byte[] chunk = server.read();
        data.write(chunk);
        totalRead += chunk.length;
    }

    Files.write(Paths.get("received.bin"), data.toByteArray());

### Обновление ключей шифрования (KeyUpdate)

Для длительных сессий можно принудительно сменить трафик-ключи через
`initiateKeyUpdate()`. Если параметр `request == true`, удалённая
сторона также обновит свои ключи отправки:

    // После передачи большого объёма данных
    session.initiateKeyUpdate(true); // запросить встречное обновление
    // Ключи записи/чтения обновлены; старые данные более не расшифруются
    session.write("data after key update".getBytes(StandardCharsets.UTF_8));

Старые ключи затираются немедленно — данные, зашифрованные до вызова, не
могут быть расшифрованы после.

## Обработка ошибок

Методы `handshakeAsClient()`, `handshakeAsServer()`, `read()` и
`write()` бросают `IOException`. При нарушении целостности записи
(подмена ciphertext, неверный тег MGM) в `getCause()` находится
исключение `AuthenticationException`. Удалённой стороне при этом
отправляется *fatal alert* с кодом ошибки (`decrypt_error`,
`bad_certificate` и т.д.)

Когда узел штатно закрывает сессию (`close_notify`), то метод `read()`
бросает `EOFException` — это нормальный сигнал завершения сессии. При
получении *fatal alert* от узла выбрасывается `IOException`, а ключи
сессии уничтожаются.

Для протокольных ошибок используется `TlsException extends IOException`
с методом `getAlertCode()`, возвращающим код алерта по RFC 8446
(`ALERT_DECRYPT_ERROR`, `ALERT_BAD_CERTIFICATE` и т.д.).

Максимальный размер TLS-записи ограничен 16640 байтами
(`MAX_CIPHERTEXT_LENGTH`, `ALERT_RECORD_OVERFLOW`). Записи большего
размера отклоняются с алертом — защита от OOM через поддельный заголовок
длины.

Рекомендуется оборачивать в try/catch всю сессию целиком.

    import org.rssys.gost.tls13.*;
    import org.rssys.gost.tls13.config.TlsServerConfig;
    import org.rssys.gost.util.AuthenticationException;
    import java.io.IOException;
    import java.nio.charset.StandardCharsets;
    import java.util.List;

    try (TlsSession server = TlsSession.createServer(
            new TlsServerConfig(cs, chain, priv), transport)) {
        server.handshakeAsServer();
        byte[] request = server.read();
        server.write("OK".getBytes(StandardCharsets.UTF_8));
    } catch (IOException e) {
        if (e.getCause() instanceof AuthenticationException) {
            System.err.println("Ошибка целостности данных");
        } else {
            System.err.println("Ошибка протокола: " + e.getMessage());
        }
    }

## Потокобезопасность (Thread safety)

`TlsSession` не thread-safe! Используйсте один экземпляр на одну
TLS-сессию в одном потоке. Для параллельных соединений используйте
отдельный `TlsSession` на каждое подключение.

`InMemoryPskStore` thread-safe: его можно разделять между сессиями
(например, для PSK resumption на сервере).

`TlsTransport` — thread safety определяется реализацией. Встроенные
транспорты (`InMemoryTlsTransport`, `SocketTlsTransport`,
`ChannelTlsTransport`) не thread-safe.

## Загрузка сертификата

Серверный сертификат передаётся в формате DER (X.509 с ГОСТ R 34.10-2012
ключом).

Пример загрузки ключа из файла:

    import org.rssys.gost.pkix.cert.GostCertificate;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    byte[] certDer = Files.readAllBytes(Paths.get("server.der"));
    GostCertificate cert = new GostCertificate(certDer);

    // Открытый ключ из сертификата
    org.rssys.gost.signature.PublicKeyParameters pubKey = cert.getPublicKey();

    // Проверка самоподписанного сертификата (CA = тот же ключ)
    boolean valid = cert.verify(pubKey);

    // В типовом сценарии серверный сертификат проверяется по CA:
    GostCertificate caCert = new GostCertificate(Files.readAllBytes(Paths.get("ca.der")));
    GostCertificate serverCert = new GostCertificate(Files.readAllBytes(Paths.get("server.der")));
    boolean serverValid = serverCert.verify(caCert.getPublicKey());

Пример загрузки из PKCS#12-файла — рекомендуется для production (ключ и
цепочка в одном файле):

    import org.rssys.gost.pkix.cert.GostPkcs12Loader;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    GostPkcs12Loader.Result p12 = GostPkcs12Loader.load(
            Files.readAllBytes(Paths.get("server.p12")), "password".toCharArray(), true);
    PrivateKeyParameters key   = p12.getPrivateKey();
    List<GostCertificate> chain = p12.getCertificateChain(); // leaf — первый элемент

ГОСТ PBE поддерживается нативно: PBKDF2-HMAC-Стрибог-512 + Кузнечик
CTR-ACPKM(-OMAC) по RFC 9337/9548. Не-ГОСТ схемы — прозрачный fallback
на JDK KeyStore.

Пример создания PFX-контейнера ГОСТ — для упаковки сгенерированного
ключа и сертификата:

    import org.rssys.gost.pkix.cert.GostPkcs12Builder;
    import java.nio.file.Path;

    // Минимальный вариант: ключ + leaf-сертификат
    byte[] pfx = GostPkcs12Builder.create()
            .key(privateKey)
            .certificate(leafCert)
            .password("changeit".toCharArray())
            .build();

    // С цепочкой CA и записью в файл
    GostPkcs12Builder.create()
            .key(privateKey)
            .certificate(leafCert)
            .caCertificate(intermediateCert)
            .caCertificate(rootCert)
            .password("changeit".toCharArray())
            .friendlyName("server-cert")
            .buildAndWriteTo(Path.of("server.p12")); // temp + atomic rename

По умолчанию используются: Кузнечик CTR-ACPKM-OMAC, 2000 итераций
PBKDF2.

Для совместимости с системами без поддержки OMAC —
`.encScheme(GostOids.KUZ_CTR_ACPKM)`. Созданный PFX читается
`GostPkcs12Loader.load(..., true)` и проходит структурную валидацию
OpenSSL.

Для тестовой разработки можно использовать самоподписанный сертификат:
`TlsTestHelper.createCertWithKey(params)` (класс находится в `src/test/`
— **недоступен в production-сборке**, только для тестов).

## Проверка сертификата

После загрузки сертификата доступны следующие методы для проверки:

    import org.rssys.gost.pkix.cert.GostCertificate;

    GostCertificate cert = new GostCertificate(certDer);

    // Срок действия (RFC 5280 §4.1.2.5)
    boolean expired = cert.isExpired();

    // Hostname по SubjectAltName/dNSName (RFC 6125)
    boolean hostnameOk = cert.verifyHostname("gost.example.com");   // точное совпадение
    boolean wildcardOk = cert.verifyHostname("www.gost.example.com"); // *.gost.example.com

    // IP-адрес (iPAddress в SAN, RFC 5280 §4.2.1.6)
    boolean ipOk = cert.verifyHostname("192.168.1.1");
    byte[][] sanIps = cert.getSanIpAddresses(); // 4 или 16 байт (IPv4/IPv6)

    // KeyUsage: digitalSignature обязателен для TLS (RFC 5246 §7.4.6)
    boolean kuValid = cert.isKeyUsageValid();

    // ExtendedKeyUsage: serverAuth для серверного сертификата
    boolean ekuServer = cert.isEkuValidForServer();
    // ExtendedKeyUsage: clientAuth для клиентского сертификата (mTLS)
    boolean ekuClient = cert.isEkuValidForClient();

    // CA-сертификат: BasicConstraints + keyCertSign (RFC 5280 §4.2.1.9, §4.2.1.2)
    boolean isCA = cert.isCA();
    int pathLen = cert.getPathLen(); // -1 если не задано
    boolean hasKeyCertSign = cert.isKeyCertSignSet();

    // Distinguished Name (RFC 5280 §4.1.2.4, §4.1.2.6)
    // Возвращается как DER-кодированный SEQUENCE — подходит для сравнения Arrays.equals
    byte[] issuer  = cert.getIssuerDnBytes();
    byte[] subject = cert.getSubjectDnBytes();
    // Проверка issuer == subject предыдущего сертификата в цепочке
    boolean dnMatch = Arrays.equals(issuer, parentSubject);

    // OCSP Stapling (RFC 6960): проверка ответа
    // cert.getOcspResponse() — сырой OCSPResponse из CertificateEntry
    // cert.verifyOcspResponse(caKey) — проверяет подпись и serialNumber

    // Проверка консистентности алгоритма (RFC 5280 §4.1.1.2)
    boolean algOk = cert.isAlgConsistent();

    // Проверка подписи сертификата (CA = издатель)
    boolean sigValid = cert.verify(caPublicKey);

## Выбор API

Для работы с TLS рекомендуется **`TlsSession`** — единая точка входа,
которая закрывает весь цикл: рукопожатие *handshake*, шифрование
записей, фрагментацию, закрытие сессии.

**TlsSession** подходит для большинства сценариев:

- Клиент-серверное взаимодействие поверх TCP (Socket / SocketChannel).

- Односторонняя / взаимная аутентификация, PSK resumption.

- Одно TLS-соединение — один экземпляр `TlsSession`.

    try (TlsSession session = TlsSession.createClient(config, transport)) {
        session.handshakeAsClient();
        session.write(data);
        byte[] response = session.read();
    }

**`TlsHandshakeEngine`** — это более сложная пошаговая стейт машина,
отвязанная от I/O. Она предназначена для нестандартных сценариев:
асинхронный транспорт, собственный selector-цикл, интеграция с JSSE
(`SSLEngine`). `TlsSession` использует `TlsHandshakeEngine` внутри. .

## Запуск тестов производительности и устойчивости

Модуль включает два теста, помеченных `@Tag("stress")`, которые
исключены из обычного прогона `mvn test` (через
`surefire.excludedGroups`).

### Пропускная способность (throughput)

Однопоточный замер скорости передачи данных через `TlsSession`.

Описание методики: [Методика измерения
throughput](doc/tls-session-stress.md).

    # По умолчанию: 5 прогонов × ~20 с ≈ 100 с
    make test-stress-tlssession

    # Управление временем (прогрев, замер, число прогонов)
    make test-stress-tlssession ARGS="-Dstress.warmup=2 -Dstress.measure=10 -Dstress.iters=3"

    # Через Maven напрямую
    mvn test -pl crypto-gost-tls13 -am \
      -Dtest="org.rssys.gost.tls13.stress.TlsSessionStreamTest" \
      -Dsurefire.excludedGroups= \
      -Dsurefire.failIfNoSpecifiedTests=false

### Смешанная нагрузка (стресс-тест)

Проверка устойчивости `TlsSession` под смешанной нагрузкой: утечки
памяти, зависания, обрывы, максимум одновременных сессий.  

Описание методики: [Методика измерения стабильности под смешнанной
нагрузкой](doc/tls-session-stress-mixed.md).

Управление длительностью и параметрами через свойства `-Dstress.*`:

    # Полный прогон (5 минут)
    make test-stress-tlssession-mixed

    # Быстрый прогон (1 минута)
    make test-stress-tlssession-mixed ARGS=-Dstress.duration=1

    # Прогон для вердикта об утечке (30 минут)
    make test-stress-tlssession-mixed ARGS=-Dstress.duration=30

    # Через Maven напрямую
    mvn test -pl crypto-gost-tls13 -am \
      -Dtest="org.rssys.gost.tls13.stress.TlsSessionStressTest" \
      -Dsurefire.excludedGroups= \
      -Dsurefire.failIfNoSpecifiedTests=false \
      -Dstress.duration=5

Доступные параметры:

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 16%" />
<col style="width: 33%" />
</colgroup>
<tbody>
<tr>
<td style="text-align: left;"><p>Свойство</p></td>
<td style="text-align: left;"><p>По умолч.</p></td>
<td style="text-align: left;"><p>Описание</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>stress.duration</code></p></td>
<td style="text-align: left;"><p>5</p></td>
<td style="text-align: left;"><p>Длительность смешанной нагрузки,
минут</p></td>
</tr>
<tr>
<td
style="text-align: left;"><p><code>stress.maxSessions</code></p></td>
<td style="text-align: left;"><p>10000</p></td>
<td style="text-align: left;"><p>Потолок цикла в
maxConcurrentSessions</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><code>stress.step</code></p></td>
<td style="text-align: left;"><p>50</p></td>
<td style="text-align: left;"><p>Шаг наращивания в
maxConcurrentSessions</p></td>
</tr>
</tbody>
</table>

## Кросс-валидация

### PKCS#12 (PFX-контейнеры)

Для модуля `crypto-gost-tls13` выполнена двусторонняя кросс-валидация
формата PFX (PKCS#12) с ГОСТ-алгоритмами.

**OpenSSL → crypto-gost**: `GostPkcs12Loader` загружает PFX, созданный
OpenSSL (`genpkey` → `req` → `pkcs12 -export`). Проверяется: чтение
ключа и сертификата, соответствие публичного ключа (`Q = d×G`),
подпись/верификация, реакция на повреждённые данные и неверный пароль.

**crypto-gost → OpenSSL**: `GostPkcs12Builder` создаёт PFX, OpenSSL
выполняет структурную валидацию (`pkcs12 -info`). Затем PFX
перечитывается `GostPkcs12Loader` и выполняется roundtrip sign/verify.
Покрыты все 5 кривых ГОСТ.

Все тесты в модуле `x-validation-tests/pkcs12`. OpenSSL должен быть
собран с [поддержкой
ГОСТ](../x-validation-tests/doc/openssl-3.6-gost-how-to.md).

    mvn -Pcrossval -pl x-validation-tests/pkcs12 -am test -Dexec.skip=true

# Поддержать проект

Если проект оказался полезным, вы можете поддержать проект на
[**Boosty**](https://boosty.to/mike_ananev/donate)

# Лицензия

Автор: Михаил Ананьев.  

Данный проект распространяется под *Открытой лицензией на программное
обеспечение "Рэд старс системс"*, версия 1.0.  
Текст лицензии находится в файле LICENSE или по
[ссылке](https://gitflic.ru/project/red-stars-systems/licenses/blob?file=open-license%2FLICENSE).
