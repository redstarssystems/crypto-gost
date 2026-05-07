# Реализация протокола TLS 1.3 с ГОСТ алгоритмами в соответствии с RFC 9367 — crypto-gost-tls13

Модуль `crypto-gost-tls13` реализует защищённый протокол TLS 1.3 с
ГОСТ-профилем (RFC 9367).

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
поверх `SocketChannel` и поддерживает `Thread.interrupt()`.

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
    import org.rssys.gost.tls13.cert.TlsCertificate;
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

    List<TlsCertificate> chain = List.of(
            new TlsCertificate(certDer),      // серверный (leaf)
            new TlsCertificate(caDer),        // промежуточный CA
            new TlsCertificate(rootDer));      // корневой CA (самоподписанный)

    PrivateKeyParameters priv = org.rssys.gost.jca.spec.GostDerCodec.decodePrivateKey(keyDer);
    byte[] ocspDer = Files.readAllBytes(Paths.get("ocsp.der"));

    // Принимаем TCP-подключение
    ServerSocket ss = new ServerSocket(8443);
    Socket socket = ss.accept();
    SocketTlsTransport transport = new SocketTlsTransport(socket);

    // Сервер через TlsServerConfig
    TlsSession server = TlsSession.createServer(
            new TlsServerConfig(transport,
                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                    chain, priv)
                    .withOcspResponse(ocspDer));  // OCSP stapling (RFC 6960)

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
используйте `SniCertificateSelector` — функциональный интерфейс, который
по hostname возвращает `TlsServerCredentials` (цепочка + ключ +
OCSP-ответ).

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
            new TlsClientConfig(transport,
                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));

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
    import org.rssys.gost.tls13.cert.TlsCertificate;
    import org.rssys.gost.tls13.config.TlsClientConfig;
    import java.net.Socket;
    import java.nio.charset.StandardCharsets;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    // Загружаем ключ CA для проверки сертификата сервера
    byte[] caDer = Files.readAllBytes(Paths.get("ca.der"));
    TlsCertificate caCert = new TlsCertificate(caDer);
    PublicKeyParameters caKey = caCert.getPublicKey();

    TlsSession client = TlsSession.createClient(new TlsClientConfig(
            transport,
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L)
            .withCaPublicKey(caKey)
            .withServerHostname("gost.example.com")
            .withRequireOcspStapling(true));

    try {
        client.handshakeAsClient();
        client.write("Hello!".getBytes(StandardCharsets.UTF_8));
        byte[] response = client.read();
    } finally {
        client.close();
    }

## Взаимная аутентификация узлов (mTLS)

Сервер запрашивает сертификат клиента через `withCaPublicKey()` в
`TlsServerConfig`.

Клиент передаёт свой сертификат и закрытый ключ через
`withClientCertificate()` (или `withClientCertificateChain(chain)` для
полной цепочки) и `withClientPrivateKey()`.

    // Сервер (mTLS)
    import org.rssys.gost.tls13.*;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import org.rssys.gost.signature.PublicKeyParameters;
    import org.rssys.gost.tls13.cert.TlsCertificate;
    import org.rssys.gost.tls13.config.TlsServerConfig;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    byte[] caDer   = Files.readAllBytes(Paths.get("ca.der"));
    byte[] certDer = Files.readAllBytes(Paths.get("server.der"));
    byte[] keyDer  = Files.readAllBytes(Paths.get("server.key"));

    PublicKeyParameters caKey    = new TlsCertificate(caDer).getPublicKey();
    PrivateKeyParameters priv    = org.rssys.gost.jca.spec.GostDerCodec.decodePrivateKey(keyDer);
    List<TlsCertificate> chain  = List.of(new TlsCertificate(certDer));

    TlsSession server = TlsSession.createServer(
            new TlsServerConfig(transport,
                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                    chain, priv)
            .withCaPublicKey(caKey));  // ← запрашивать сертификат клиента

    try {
        server.handshakeAsServer();
        // После handshake сертификат клиента проверен
        byte[] data = server.read();
    } finally {
        server.close();
    }

    // Клиент (mTLS)
    import org.rssys.gost.tls13.*;
    import org.rssys.gost.signature.PrivateKeyParameters;
    import org.rssys.gost.tls13.cert.TlsCertificate;
    import org.rssys.gost.tls13.config.TlsClientConfig;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    byte[] clientCertDer = Files.readAllBytes(Paths.get("client.der"));
    byte[] clientKeyDer  = Files.readAllBytes(Paths.get("client.key"));

    TlsCertificate clientCert   = new TlsCertificate(clientCertDer);
    PrivateKeyParameters clientPriv = org.rssys.gost.jca.spec.GostDerCodec.decodePrivateKey(clientKeyDer);

    TlsSession client = TlsSession.createClient(
            new TlsClientConfig(transport,
                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L)
            .withClientCertificate(clientCert)
            .withClientPrivateKey(clientPriv));

    try {
        client.handshakeAsClient();
        client.write("Hello from mTLS client!".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    } finally {
        client.close();
    }

Для цепочки из нескольких сертификатов (leaf + промежуточные CA)
используйте
`withClientCertificateChain(List.of(leaf, intermediate, root))`.

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

    PskStore serverStore = new PskStore(1000); // макс. 1000 PSK-тикетов (см. PskStore javadoc)

    // Сервер
    TlsSession server1 = TlsSession.createServer(/* TlsServerConfig */);
    server1.setPskStore(serverStore);
    server1.handshakeAsServer();
    server1.write("ready".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    server1.close();

    // клиент
    PskStore clientStore = new PskStore(100);  // макс. 100 PSK-тикетов (см. PskStore javadoc)

    TlsSession client1 = TlsSession.createClient(/* TlsClientConfig */);
    client1.setPskStore(clientStore);
    client1.handshakeAsClient();
    // read() обрабатывает NST внутри, возвращает данные сервера
    byte[] data = client1.read();
    client1.close();

    // Второе подключение — сокращённый handshake (PSK)
    // Клиент автоматически находит тикет в PskStore
    TlsSession client2 = TlsSession.createClient(/* TlsClientConfig */);
    client2.setPskStore(clientStore);
    client2.handshakeAsClient();
    client2.write("Resumed!".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    client2.close();

    TlsSession server2 = TlsSession.createServer(/* TlsServerConfig */);
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
            new TlsServerConfig(transport, cs, chain, priv))) {
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

`PskStore` thread-safe: его можно разделять между сессиями (например,
для PSK resumption на сервере).

`TlsTransport` — thread safety определяется реализацией. Встроенные
транспорты (`InMemoryTlsTransport`, `SocketTlsTransport`,
`ChannelTlsTransport`) не thread-safe.

## Загрузка сертификата

Серверный сертификат передаётся в формате DER (X.509 с ГОСТ R 34.10-2012
ключом).

Пример загрузки ключа из файла:

    import org.rssys.gost.tls13.cert.TlsCertificate;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    byte[] certDer = Files.readAllBytes(Paths.get("server.der"));
    TlsCertificate cert = new TlsCertificate(certDer);

    // Открытый ключ из сертификата
    org.rssys.gost.signature.PublicKeyParameters pubKey = cert.getPublicKey();

    // Проверка самоподписанного сертификата (CA = тот же ключ)
    boolean valid = cert.verify(pubKey);

    // В типовом сценарии серверный сертификат проверяется по CA:
    TlsCertificate caCert = new TlsCertificate(Files.readAllBytes(Paths.get("ca.der")));
    TlsCertificate serverCert = new TlsCertificate(Files.readAllBytes(Paths.get("server.der")));
    boolean serverValid = serverCert.verify(caCert.getPublicKey());

Пример загрузки из PKCS12-файла — рекомендуется для production (ключ и
цепочка в одном файле):

    import org.rssys.gost.tls13.cert.Pkcs12Loader;
    import java.nio.file.Files;
    import java.nio.file.Paths;

    Pkcs12Loader.Result p12 = Pkcs12Loader.load(
            Files.readAllBytes(Paths.get("server.p12")), "password".toCharArray());
    org.rssys.gost.signature.PrivateKeyParameters key = p12.getPrivateKey();
    java.util.List<TlsCertificate> chain = p12.getCertificateChain();

**Ограничение:** GOST PBE не поддерживается — только PBES2
(PBKDF2-HMAC-SHA256 + AES-256-CBC).

Для тестовой разработки можно использовать самоподписанный сертификат:
`TlsTestHelper.createCertWithKey(params)` (класс находится в `src/test/`
— **недоступен в production-сборке**, только для тестов).

## Проверка сертификата

После загрузки сертификата доступны следующие методы для проверки:

    import org.rssys.gost.tls13.cert.TlsCertificate;

    TlsCertificate cert = new TlsCertificate(certDer);

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

    try (TlsSession session = TlsSession.createClient(config)) {
        session.handshakeAsClient();
        session.write(data);
        byte[] response = session.read();
    }

**`TlsHandshakeEngine`** — это более сложная пошаговая стейт машина,
отвязанная от I/O. Она предназначена для нестандартных сценариев:
асинхронный транспорт, собственный selector-цикл, интеграция с JSSE
(`SSLEngine`). `TlsSession` использует `TlsHandshakeEngine` внутри.

Дополнительная документация:

- [Архитектура модуля](#doc/architecture.adoc) — описание слоёв,
  ключевых классов, handshake flow, threading model, ограничений.

# Лицензия

Автор: Михаил Ананьев.  

Данный проект распространяется под *Открытой лицензией на программное
обеспечение "Рэд старс системс"*, версия 1.0.  
Текст лицензии находится в файле LICENSE или по
[ссылке](https://gitflic.ru/project/red-stars-systems/licenses/blob?file=open-license%2FLICENSE).
