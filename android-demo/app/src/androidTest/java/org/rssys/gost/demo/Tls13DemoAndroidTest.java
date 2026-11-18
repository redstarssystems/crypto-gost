package org.rssys.gost.demo;

import static org.junit.Assert.*;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.LargeTest;

import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import org.rssys.gost.util.CryptoRandom;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Демонстрация {@code crypto-gost-tls13} для Android — 12 тестовых методов,
 * покрывающих все ключевые сценарии использования ГОСТ TLS 1.3.
 * <p>
 * Каждый тест — самодостаточная short story с комментариями «почему».
 * Тесты упорядочены от простого к сложному и используют {@code @BeforeClass setUp()}
 * для общей криптографической фикстуры (CA).
 * <p>
 * Все тесты используют {@link InMemoryTlsTransport.Pair} — не требуют сети
 * или серверных процессов. Это даёт быстрый и надёжный прогон на эмуляторе.
 */
@RunWith(AndroidJUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@LargeTest
public final class Tls13DemoAndroidTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final TlsCiphersuite CS =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final int DEMO_FILE_SIZE = 65536;

    private static PrivateKeyParameters caKey;
    private static PublicKeyParameters caPubKey;
    private static GostCertificate caCert;
    private static byte[] caDn;

    private static byte[] demoData;

    // ========================================================================
    // Инициализация — один раз на весь класс
    // ========================================================================

    @BeforeClass
    public static void setUp() throws Exception {
        Security.removeProvider("RssysGostProvider");
        Security.addProvider(new RssysGostProvider());

        // CA генерируем внутри теста, чтобы исключить рассинхронизацию фикстур
        var caKp = KeyGenerator.generateKeyPair(PARAMS);
        caKey = caKp.getPrivate();
        caPubKey = caKp.getPublic();

        caDn = GostDnParser.encodeDn("CN=Demo TLS Root CA,O=DemoOrg,C=RU");

        // Fluent API: keyUsage/basicConstraints напрямую на билдере
        caCert = GostCertificateBuilder.create(PARAMS, caDn)
                .publicKey(caPubKey)
                .randomSerial()
                .notBeforeNow()
                .validForYears(100)
                .keyUsage(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.CRL_SIGN)
                .basicConstraints(true, 0)
                .sign(caKey);

        demoData = new byte[DEMO_FILE_SIZE];
        CryptoRandom.INSTANCE.nextBytes(demoData);
        System.out.println("[подготовка] CA: " + caCert.getSubjectDn()
                + ", demoData: " + demoData.length + " байт");
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    /**
     * Создаёт серверный сертификат SAN=localhost, подписанный CA.
     * <p>
     * Используем fluent API билдера: {@code .sanDns("localhost").keyUsage(...)} —
     * это компактнее и читаемее, чем сборка расширений через {@code ByteArrayOutputStream}.
     */
    private static GostCertificate createServerCert(PrivateKeyParameters serverKey,
                                                     PublicKeyParameters serverPub) throws Exception {
        return GostCertificateBuilder.create(PARAMS,
                        GostDnParser.encodeDn("CN=Demo Server,O=DemoOrg,C=RU"))
                .publicKey(serverPub)
                .randomSerial()
                .notBeforeNow()
                .validForYears(10)
                .sanDns("localhost")
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .issuerDn(caDn)
                .sign(caKey);
    }

    /** Создаёт клиентский сертификат, подписанный CA. */
    private static GostCertificate createClientCert(PrivateKeyParameters clientKey,
                                                     PublicKeyParameters clientPub) throws Exception {
        return GostCertificateBuilder.create(PARAMS,
                        GostDnParser.encodeDn("CN=Demo Client,O=DemoOrg,C=RU"))
                .publicKey(clientPub)
                .randomSerial()
                .notBeforeNow()
                .validForYears(10)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .issuerDn(caDn)
                .sign(caKey);
    }

    /**
     * Выполняет рукопожатие между двумя {@link TlsSession} через
     * InMemoryTlsTransport и возвращает полезные данные, отправленные клиентом.
     * <p>
     * Сервер выполняется в отдельном потоке (InMemoryTlsTransport блокирующий,
     * поэтому для двустороннего обмена нужны два потока).
     */
    private static byte[] doHandshake(TlsSession client, TlsSession server,
                                       byte[] clientData) throws Exception {
        ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            Future<Void> sf = exec.submit(() -> {
                server.handshakeAsServer();
                return null;
            });
            client.handshakeAsClient();
            sf.get(15, TimeUnit.SECONDS);

            client.write(clientData);
            return server.read();
        } finally {
            exec.shutdown();
            try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
        }
    }

    private static void section(String title) {
        System.out.println("--- " + title + " ---");
    }

    // ========================================================================
    // §1 Анонимный клиент (без проверки сервера)
    // ========================================================================

    /**
     * Анонимный клиент — подключается без проверки сертификата сервера.
     * <p>
     * Портировано из {@code examples/tls/MinimalClient.java}.
     * <p>
     * dev-режим для отладки, когда CA-инфраструктура
     * ещё не развёрнута. Никогда не используйте в production — отсутствие
     * проверки сервера делает возможной MITM-атаку.
     */
    @Test
    public void test01_anonymousClient() throws Exception {
        section("§1 Анонимный клиент (createClientWithoutServerAuth)");

        // Генерируем ключи прямо в тесте — самодостаточная фикстура
        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = createServerCert(serverKp.getPrivate(), serverKp.getPublic());

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        // Сервер с нормальной конфигурацией
        try (TlsSession server = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate()),
                pair.getServerTransport());
             TlsSession client = TlsSession.createClientWithoutServerAuth(
                     pair.getClientTransport(), CS, null, null)) {

            byte[] response = doHandshake(client, server, "Hello from anonymous client".getBytes(
                    StandardCharsets.UTF_8));
            assertNotNull("Данные получены после handshake", response);
            assertTrue("Данные не пустые", response.length > 0);
            System.out.println("  OK: анонимный handshake выполнен, получено "
                    + response.length + " байт");
        }
    }

    // ========================================================================
    // §2 Сервер с проверкой сертификата клиентом
    // ========================================================================

    /**
     * Полный TLS handshake с проверкой сертификата сервера через CA.
     * <p>
     * Портировано из {@code examples/tls/MinimalServer.java}.
     * <p>
     * Это типовой production-сценарий: клиент доверяет CA, сервер
     * предъявляет сертификат, подписанный этим CA. Клиент проверяет
     * цепочку, срок действия, hostname. Без такой проверки соединение
     * уязвимо для MITM.
     */
    @Test
    public void test02_serverWithCA() throws Exception {
        section("§2 Сервер с CA-валидацией (TlsClientConfig)");

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = createServerCert(serverKp.getPrivate(), serverKp.getPublic());

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        try (TlsSession server = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate()),
                pair.getServerTransport());
             TlsSession client = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(caCert))
                             .withServerHostname("localhost"),
                     pair.getClientTransport())) {

            byte[] response = doHandshake(client, server,
                    "Hello from verified client".getBytes(StandardCharsets.UTF_8));
            assertNotNull("Данные получены после handshake", response);
            System.out.println("  OK: CA-валидация пройдена, получено "
                    + response.length + " байт");
        }
    }

    // ========================================================================
    // §3 Взаимная аутентификация (mTLS)
    // ========================================================================

    /**
     * mTLS — обе стороны предъявляют сертификаты.
     * <p>
     * Портировано из {@code examples/tls/MutualTls.java}.
     * <p>
     * банковские и ведомственные API требуют
     * двусторонней аутентификации — не только клиент проверяет сервер,
     * но и сервер проверяет клиента. Сервер запрашивает сертификат
     * через {@code needClientAuth(TrustAnchors)}, клиент отправляет свой
     * через {@code withClientCertificateChain()} + {@code withClientPrivateKey()}.
     */
    @Test
    public void test03_mutualTls() throws Exception {
        section("§3 Взаимная аутентификация (mTLS)");

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = createServerCert(serverKp.getPrivate(), serverKp.getPublic());

        var clientKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate clientCert = createClientCert(clientKp.getPrivate(), clientKp.getPublic());

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        try (TlsSession server = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate())
                        .needClientAuth(TrustAnchors.ofCertificate(caCert)),
                pair.getServerTransport());
             TlsSession client = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(caCert))
                             .withServerHostname("localhost")
                             .withClientCertificateChain(clientCert)
                             .withClientPrivateKey(clientKp.getPrivate()),
                     pair.getClientTransport())) {

            byte[] response = doHandshake(client, server,
                    "mTLS handshake done".getBytes(StandardCharsets.UTF_8));
            assertNotNull("Данные получены после mTLS", response);

            // Сервер видит сертификат клиента — это essential для mTLS
            List<GostCertificate> peerCerts = server.getPeerCertificates();
            assertNotNull("Сервер получил сертификат клиента", peerCerts);
            assertFalse("Сертификат клиента не пуст", peerCerts.isEmpty());
            System.out.println("  OK: mTLS выполнен, сервер проверил сертификат клиента: "
                    + peerCerts.get(0).getSubjectDn());
        }
    }

    // ========================================================================
    // §4 PSK session resumption
    // ========================================================================

    /**
     * Возобновление сессии по PSK (Pre-Shared Key).
     * <p>
     * Портировано из {@code examples/tls/PskResumption.java}.
     * <p>
     * мобильные приложения часто переподключаются
     * к серверу после коротких разрывов связи. Полный handshake с
     * ECDHE — дорогой (асимметричная криптография). PSK resumption
     * заменяет его на симметричную HMAC-операцию — в разы быстрее.
     * <p>
     * Сценарий: полный handshake → сервер отправляет NewSessionTicket →
     * тикет сохраняется в PskStore → второе соединение использует
     * аббревиатурный handshake без ECDHE и сертификатов.
     */
    @Test
    public void test04_pskResumption() throws Exception {
        section("§4 PSK session resumption");

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = createServerCert(serverKp.getPrivate(), serverKp.getPublic());

        // Раздельные хранилища, как в production: запись клиента (с привязкой) и запись сервера затирали бы друг друга
        PskStore serverStore = new InMemoryPskStore(256);
        PskStore clientStore = new InMemoryPskStore(256);

        // ---- Первое соединение: полный handshake + NewSessionTicket ----
        InMemoryTlsTransport.Pair pair1 = InMemoryTlsTransport.newPair();
        try (TlsSession server1 = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate())
                        .withTicketsToSend(1),
                pair1.getServerTransport());
             TlsSession client1 = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(caCert)).withServerHostname("localhost"),
                     pair1.getClientTransport())) {
            server1.setPskStore(serverStore);
            client1.setPskStore(clientStore);

            doHandshake(client1, server1, "first".getBytes(StandardCharsets.UTF_8));

            // NewSessionTicket - сообщение после рукопожатия: клиент разбирает его только при
            // чтении. Без обратного обмена тикет остался бы необработанным к проверке хранилища.
            server1.write("ticket".getBytes(StandardCharsets.UTF_8));
            client1.read();
        }

        assertTrue("PSK сохранён после первого handshake", clientStore.size() > 0);
        System.out.println("  После первого handshake PSK-тикетов: " + clientStore.size());

        // ---- Второе соединение: аббревиатурный handshake (PSK) ----
        InMemoryTlsTransport.Pair pair2 = InMemoryTlsTransport.newPair();
        try (TlsSession server2 = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate())
                        .withTicketsToSend(1),
                pair2.getServerTransport());
             TlsSession client2 = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(caCert)).withServerHostname("localhost"),
                     pair2.getClientTransport())) {
            server2.setPskStore(serverStore);
            client2.setPskStore(clientStore);

            byte[] response = doHandshake(client2, server2,
                    "resumed via PSK".getBytes(StandardCharsets.UTF_8));
            assertNotNull("Данные получены после PSK resumption", response);

            // wasResumed() возвращает true, если handshake был сокращённым
            assertTrue("Handshake должен быть сокращённым (PSK)",
                    client2.wasResumed());
            System.out.println("  OK: PSK resumption выполнен");
        }
    }

    // ========================================================================
    // §5 OCSP stapling
    // ========================================================================

    /**
     * OCSP stapling — проверка статуса сертификата без обращения к респондеру.
     * <p>
     * Портировано из {@code examples/tls/OcspStapling.java}.
     * <p>
     * клиенту не нужно самому ходить на OCSP-респондер —
     * сервер прикладывает заранее полученный OCSP-ответ к своему сертификату
     * прямо в handshake. Это быстрее, надёжнее (нет лишнего сетевого запроса)
     * и снижает нагрузку на OCSP-инфраструктуру.
     */
    @Test
    public void test05_ocspStapling() throws Exception {
        section("§5 OCSP stapling");

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = createServerCert(serverKp.getPrivate(), serverKp.getPublic());

        // Строим OCSP-ответ через GostOcspResponseBuilder
        byte[] serialNum = serverCert.getSerialNumber();
        byte[] ocspDer = GostOcspResponseBuilder.create(serialNum)
                .issuerDn(caDn)
                .sign(caKey);

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        try (TlsSession server = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate())
                        .withOcspStaplingResponse(ocspDer),
                pair.getServerTransport());
             TlsSession client = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(caCert)).withServerHostname("localhost"),
                     pair.getClientTransport())) {

            byte[] response = doHandshake(client, server,
                    "OCSP stapling verified".getBytes(StandardCharsets.UTF_8));
            assertNotNull("Данные получены", response);
            System.out.println("  OK: OCSP staple принят клиентом");
        }
    }

    // ========================================================================
    // §6 ALPN — согласование протокола прикладного уровня
    // ========================================================================

    /**
     * ALPN (Application-Layer Protocol Negotiation, RFC 7301).
     * <p>
     * без ALPN клиент и сервер не могут договориться
     * об использовании HTTP/2 или WebSocket поверх одного TLS-соединения.
     * ALPN — единственный стандартный способ согласовать протокол
     * прикладного уровня внутри TLS handshake.
     * <p>
     * Клиент предлагает ["h2", "http/1.1"], сервер выбирает "http/1.1".
     */
    @Test
    public void test06_alpn() throws Exception {
        section("§6 ALPN (RFC 7301)");

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = createServerCert(serverKp.getPrivate(), serverKp.getPublic());

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        try (TlsSession server = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate())
                        .withAlpnProtocols(List.of("http/1.1")),
                pair.getServerTransport());
             TlsSession client = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(caCert))
                             .withServerHostname("localhost")
                             .withAlpnProtocols(List.of("h2", "http/1.1")),
                     pair.getClientTransport())) {

            byte[] response = doHandshake(client, server,
                    "ALPN test".getBytes(StandardCharsets.UTF_8));
            assertNotNull("Данные получены", response);

            // После handshake согласованный протокол доступен через getAlpnProtocol()
            String alpn = client.getAlpnProtocol();
            assertEquals("Согласован http/1.1", "http/1.1", alpn);
            System.out.println("  OK: согласован ALPN-протокол: " + alpn);
        }
    }

    // ========================================================================
    // §7 KeyUpdate — обновление ключей шифрования
    // ========================================================================

    /**
     * KeyUpdate (RFC 8446 §4.6.3) — принудительная смена ключей трафика.
     * <p>
     * в длительных сессиях (файловый стриминг,
     * видеоконференция) компрометация одного ключа не должна
     * раскрывать весь трафик. KeyUpdate позволяет сменить ключи
     * без нового handshake. Старые ключи затираются немедленно.
     */
    @Test
    public void test07_keyUpdate() throws Exception {
        section("§7 KeyUpdate (RFC 8446 §4.6.3)");

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = createServerCert(serverKp.getPrivate(), serverKp.getPublic());

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        try (TlsSession server = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate()),
                pair.getServerTransport());
             TlsSession client = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(caCert)).withServerHostname("localhost"),
                     pair.getClientTransport())) {

            // Handshake
            ExecutorService exec = Executors.newSingleThreadExecutor();
            try {
                Future<Void> sf = exec.submit(() -> { server.handshakeAsServer(); return null; });
                client.handshakeAsClient();
                sf.get(15, TimeUnit.SECONDS);

                // Отправляем данные до KeyUpdate
                client.write("before update".getBytes(StandardCharsets.UTF_8));
                byte[] before = server.read();
                assertNotNull("Данные до KeyUpdate", before);

                // Принудительно обновляем ключи отправки у клиента
                // Старые ключи затираются немедленно — данные, зашифрованные
                // до вызова, не могут быть расшифрованы после
                client.initiateKeyUpdate(false);

                // Отправляем данные после KeyUpdate
                client.write("after update".getBytes(StandardCharsets.UTF_8));
                byte[] after = server.read();
                assertNotNull("Данные после KeyUpdate", after);
                System.out.println("  OK: KeyUpdate выполнен, данные до и после прочитаны");
            } finally {
                exec.shutdown();
                try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            }
        }
    }

    // ========================================================================
    // §8 Трёхуровневая цепочка сертификатов
    // ========================================================================

    /**
     * Цепочка из трёх уровней: root CA → intermediate CA → server cert.
     * <p>
     * Портировано из {@code examples/tls/ThreeCertChain.java}.
     * <p>
     * реальная PKI с УЦ (удостоверяющим центром)
     * почти никогда не подписывает серверные сертификаты напрямую
     * корневым CA. Корневой CA хранится офлайн, промежуточные CA —
     * онлайн. Клиент должен уметь верифицировать цепочку произвольной
     * длины. Этот тест проверяет 3-уровневую цепочку — самый
     * распространённый сценарий.
     */
    @Test
    public void test08_threeLevelChain() throws Exception {
        section("§8 Трёхуровневая цепочка (root→intermediate→leaf)");

        // 1. Корневой CA (самоподписанный, pathLen=null — без ограничения)
        var rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = GostDnParser.encodeDn("CN=Demo Root CA,O=DemoOrg,C=RU");
        GostCertificate rootCert = GostCertificateBuilder.create(PARAMS, rootDn)
                .publicKey(rootKp.getPublic())
                .randomSerial().notBeforeNow().validForYears(100)
                .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                .basicConstraints(true, null)
                .sign(rootKp.getPrivate());

        // 2. Промежуточный CA (подписан корнем, pathLen=0 — может подписывать leaf, но не других CA)
        var interKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] interDn = GostDnParser.encodeDn("CN=Demo Intermediate CA,O=DemoOrg,C=RU");
        GostCertificate interCert = GostCertificateBuilder.create(PARAMS, interDn)
                .publicKey(interKp.getPublic())
                .randomSerial().notBeforeNow().validForYears(10)
                .basicConstraints(true, 0)
                .issuerDn(rootDn)
                .sign(rootKp.getPrivate());

        // 3. Серверный сертификат (подписан промежуточным CA)
        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = GostCertificateBuilder.create(PARAMS,
                        GostDnParser.encodeDn("CN=Demo Server,O=DemoOrg,C=RU"))
                .publicKey(serverKp.getPublic())
                .randomSerial().notBeforeNow().validForYears(1)
                .sanDns("localhost")
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .issuerDn(interDn)
                .sign(interKp.getPrivate());

        // 4. Сервер отправляет цепочку {leaf, intermediate, root}
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        try (TlsSession server = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert, interCert, rootCert),
                        serverKp.getPrivate()),
                pair.getServerTransport());
             TlsSession client = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(rootCert))
                             .withServerHostname("localhost"),
                     pair.getClientTransport())) {

            byte[] response = doHandshake(client, server,
                    "3-level chain verified".getBytes(StandardCharsets.UTF_8));
            assertNotNull("Данные получены", response);
            System.out.println("  OK: трёхуровневая цепочка проверена");
        }
    }

    // ========================================================================
    // §9 IP SAN — сертификат с IP-адресом в SubjectAltName
    // ========================================================================

    /**
     * Верификация сертификата, у которого SAN содержит IP-адрес вместо DNS.
     * <p>
     * Портировано из {@code examples/tls/IpSan.java}.
     * <p>
     * во внутренних сетях (mesh-сервисы, Kubernetes Pod)
     * часто нет DNS-имён — соединение идёт по IP-адресу.
     * Без поддержки IP SAN такие сертификаты не прошли бы hostname verification.
     */
    @Test
    public void test09_ipSan() throws Exception {
        section("§9 IP SAN (сертификат с IP-адресом)");

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);

        // Fluent API: sanDns + sanIp прямо на билдере
        GostCertificate serverCert = GostCertificateBuilder.create(PARAMS,
                        GostDnParser.encodeDn("CN=Demo IP Server,O=DemoOrg,C=RU"))
                .publicKey(serverKp.getPublic())
                .randomSerial().notBeforeNow().validForYears(10)
                .sanDns("localhost")
                .sanIp("127.0.0.1")
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .issuerDn(caDn)
                .sign(caKey);

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        try (TlsSession server = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate()),
                pair.getServerTransport());
             TlsSession client = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(caCert))
                             .withServerHostname("127.0.0.1"),
                     pair.getClientTransport())) {

            byte[] response = doHandshake(client, server,
                    "Connected via IP SAN".getBytes(StandardCharsets.UTF_8));
            assertNotNull("Данные получены", response);
            System.out.println("  OK: handshake по IP-адресу выполнен");
        }
    }

    // ========================================================================
    // §10 Потоковая передача данных
    // ========================================================================

    /**
     * Передача данных через TLS — многократные read/write, большой объём.
     * <p>
     * TLS — это не «отправил-закрыл». В реальном
     * приложении через одно TLS-соединение проходит много сообщений
     * (HTTP-запросы/ответы, RPC, файловый стриминг). Каждое сообщение —
     * отдельная TLS-запись. Тест проверяет, что read/write можно
     * вызывать многократно, и данные не теряются.
     */
    @Test
    public void test10_fileTransfer() throws Exception {
        section("§10 Потоковая передача данных");

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = createServerCert(serverKp.getPrivate(), serverKp.getPublic());

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        try (TlsSession server = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate()),
                pair.getServerTransport());
             TlsSession client = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(caCert)).withServerHostname("localhost"),
                     pair.getClientTransport())) {

            ExecutorService exec = Executors.newSingleThreadExecutor();
            try {
                Future<Void> sf = exec.submit(() -> { server.handshakeAsServer(); return null; });
                client.handshakeAsClient();
                sf.get(15, TimeUnit.SECONDS);

                // Отправляем большой блок данных (64 КБ — размер demoData).
                // write() сам фрагментирует по TLS-записям (макс. 16383 байт payload),
                // поэтому сервер должен читать в цикле, пока не соберёт все байты.
                client.write(demoData);

                // Сервер читает в цикле до полного получения всех байт
                java.io.ByteArrayOutputStream acc = new java.io.ByteArrayOutputStream();
                byte[] chunk;
                while (acc.size() < demoData.length) {
                    chunk = server.read();
                    if (chunk == null || chunk.length == 0) break;
                    acc.write(chunk);
                }
                byte[] received = acc.toByteArray();

                assertNotNull("Данные получены сервером", received);
                assertArrayEquals("Данные совпадают", demoData, received);
                System.out.println("  OK: передано " + demoData.length + " байт, данные совпадают");

                // Отвечаем обратно — двусторонний обмен
                server.write("response".getBytes(StandardCharsets.UTF_8));
                byte[] clientResponse = client.read();
                assertEquals("Серверный ответ получен",
                        "response", new String(clientResponse, StandardCharsets.UTF_8));
                System.out.println("  OK: двусторонний обмен данными выполнен");
            } finally {
                exec.shutdown();
                try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            }
        }
    }

    // ========================================================================
    // §11 Fail-closed — обработка ошибок
    // ========================================================================

    /**
     * Fail-closed: при нарушении целостности зашифрованной записи
     * соединение немедленно закрывается, данные не раскрываются.
     * <p>
     * Основное свойство TLS 1.3: каждая запись защищена AEAD-тегом
     * (MGM для Кузнечика). Если злоумышленник подменил хотя бы один
     * байт ciphertext — получатель обязан отбросить запись и закрыть
     * соединение с alert (ALERT_BAD_RECORD_MAC), а не расшифровывать
     * мусор как прикладные данные.
     */
    @Test
    public void test11_failClosed() throws Exception {
        section("§11 Fail-closed — подмена ciphertext");

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = createServerCert(serverKp.getPrivate(), serverKp.getPublic());

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        try (TlsSession server = TlsSession.createServer(
                new TlsServerConfig(CS, List.of(serverCert), serverKp.getPrivate()),
                pair.getServerTransport());
             TlsSession client = TlsSession.createClient(
                     new TlsClientConfig(CS, TrustAnchors.ofCertificate(caCert)).withServerHostname("localhost"),
                     pair.getClientTransport())) {

            ExecutorService exec = Executors.newSingleThreadExecutor();
            try {
                Future<Void> sf = exec.submit(() -> { server.handshakeAsServer(); return null; });
                client.handshakeAsClient();
                sf.get(15, TimeUnit.SECONDS);

                // 1. Легитимные данные проходят
                client.write("ping".getBytes(StandardCharsets.UTF_8));
                byte[] resp = server.read();
                assertArrayEquals("Легитимные данные приняты",
                        "ping".getBytes(StandardCharsets.UTF_8), resp);

                // 2. Подмена ciphertext: клиент шлёт запись, мы перехватываем
                // её из транспорта ДО того, как её прочитал сервер,
                // подменяем байт ciphertext и возвращаем обратно.
                // Сервер должен выбросить IOException из-за несовпадения MGM-тега.
                client.write("tampered".getBytes(StandardCharsets.UTF_8));

                // Забираем запись из очереди server←client (Q1)
                byte[] record = pair.getServerTransport().receiveRecord();
                assertNotNull("Запись перехвачена", record);
                assertTrue("Запись достаточно длинная для подмены", record.length > 10);

                // Подменяем байт в теле ciphertext
                record[record.length / 2] ^= 0xFF;

                // Возвращаем подменённую запись в ту же очередь (через client → send)
                pair.getClientTransport().sendRecord(record);

                // Сервер должен выбросить исключение
                try {
                    server.read();
                    fail("Сервер обязан выбросить исключение при подмене ciphertext");
                } catch (IOException e) {
                    // В TLS 1.3 AuthenticationException обёрнуто в IOException
                    assertTrue("Исключение при подмене ciphertext: " + e.getMessage(), true);
                    System.out.println("  OK: сервер отклонил подменённую запись: " + e.getMessage());
                }

            } finally {
                exec.shutdown();
                try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            }
        }
    }

    // ========================================================================
    // §12 Проверка сертификата
    // ========================================================================

    /**
     * Проверка сертификата: срок действия, hostname, issuer/subject DN,
     * KeyUsage, подпись. Все проверки, которые в production выполняются
     * автоматически, здесь показаны явно для понимания.
     * <p>
     * разработчик должен понимать, какие проверки
     * выполняются при каждом TLS-соединении. Это помогает диагностировать
     * проблемы: «сертификат истёк», «hostname не совпадает», «не тот CA».
     */
    @Test
    public void test12_certificateChecks() throws Exception {
        section("§12 Проверка сертификата");

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate serverCert = createServerCert(serverKp.getPrivate(), serverKp.getPublic());

        // 1. Срок действия
        assertFalse("Сертификат не должен быть просрочен", serverCert.isExpired());
        System.out.println("  OK: срок действия в норме");

        // 2. Hostname verification (RFC 6125)
        // В серверном сертификате SAN = localhost
        assertTrue("localhost проходит проверку hostname",
                serverCert.verifyHostname("localhost"));
        System.out.println("  OK: hostname localhost проверен");

        // 3. Issuer / Subject DN
        assertNotNull("Issuer DN не пуст", serverCert.getIssuerDn());
        assertNotNull("Subject DN не пуст", serverCert.getSubjectDn());
        System.out.println("  OK: DN извлечены");

        // 4. KeyUsage: digitalSignature обязателен для TLS
        assertTrue("KeyUsage digitalSignature должен быть установлен",
                serverCert.isKeyUsageValid());
        System.out.println("  OK: KeyUsage digitalSignature");

        // 5. Проверка подписи сертификата по CA
        assertTrue("Подпись сертификата должна быть валидна",
                serverCert.verifySignature(caPubKey));
        System.out.println("  OK: подпись сертификата проверена по CA");

        // 6. Проверка цепочки issuer → CA (DN сравнение)
        assertNotNull("CA DN не пуст", caCert.getSubjectDn());
        byte[] issuerDn = serverCert.getIssuerDnBytes();
        byte[] caSubjectDn = caCert.getSubjectDnBytes();
        assertTrue("Issuer сертификата должен совпадать с Subject CA",
                Arrays.equals(issuerDn, caSubjectDn));
        System.out.println("  OK: issuer→CA соответствие");
    }
}
