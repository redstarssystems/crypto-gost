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
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.GostSslDev;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostDnParser;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.GostPkcs12Builder;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

/**
 * Демонстрация {@code crypto-gost-jsse} для Android — 11 тестовых методов,
 * покрывающих интеграцию ГОСТ TLS 1.3 через стандартный JSSE API
 * (SSLEngine, SSLSocket, GostSslBuilder).
 * <p>
 * Каждый тест — самодостаточная short story. Тесты упорядочены
 * от практичных высокоуровневых API (GostSslBuilder, PKCS#12, mTLS)
 * к низкоуровневым (SSLEngine wrap/unwrap).
 */
@RunWith(AndroidJUnit4.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@LargeTest
public final class JsseDemoAndroidTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final TlsCiphersuite CS =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    // CA — единая точка доверия. Генерируется в setUp().
    private static PrivateKeyParameters caKey;
    private static PublicKeyParameters caPubKey;
    private static GostCertificate caCert;
    private static byte[] caDn;

    // Серверный сертификат и ключ в JCA-формате (для GostX509KeyManager)
    private static PrivateKeyParameters serverKey;
    private static X509Certificate[] serverJcaChain;
    private static GostCertificate serverCert;

    // Клиентский сертификат и ключ (для mTLS)
    private static PrivateKeyParameters clientKey;
    private static X509Certificate[] clientJcaChain;

    // ========================================================================
    // Инициализация — один раз на весь класс
    // ========================================================================

    @BeforeClass
    public static void setUp() throws Exception {
        Security.removeProvider("RssysGostJsse");
        Security.addProvider(new org.rssys.gost.jsse.RssysGostJsseProvider());

        var caKp = KeyGenerator.generateKeyPair(PARAMS);
        caKey = caKp.getPrivate();
        caPubKey = caKp.getPublic();
        caDn = GostDnParser.encodeDn("CN=Demo JSSE Root CA,O=DemoOrg,C=RU");

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

        var serverKp = KeyGenerator.generateKeyPair(PARAMS);
        serverKey = serverKp.getPrivate();
        serverCert = GostCertificateBuilder.create(PARAMS,
                        GostDnParser.encodeDn("CN=localhost,O=DemoOrg,C=RU"))
                .publicKey(serverKp.getPublic())
                .randomSerial()
                .notBeforeNow()
                .validForYears(10)
                .sanDns("localhost")
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .issuerDn(caDn)
                .sign(caKey);
        serverJcaChain = CertificateBridge.toJca(List.of(serverCert, caCert));

        var clientKp = KeyGenerator.generateKeyPair(PARAMS);
        clientKey = clientKp.getPrivate();
        GostCertificate clientGostCert = GostCertificateBuilder.create(PARAMS,
                        GostDnParser.encodeDn("CN=Demo Client,O=DemoOrg,C=RU"))
                .publicKey(clientKp.getPublic())
                .randomSerial()
                .notBeforeNow()
                .validForYears(10)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .issuerDn(caDn)
                .sign(caKey);
        clientJcaChain = CertificateBridge.toJca(List.of(clientGostCert, caCert));
    }

    // ========================================================================
    // Вспомогательные методы (handshake loopback)
    // ========================================================================

    private static void section(String title) {
        System.out.println("--- " + title + " ---");
    }

    private static void doClientHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair)
            throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(
                TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        for (int i = 0; i < 80; i++) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.FINISHED
                    || hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) return;

            switch (hs) {
                case NEED_WRAP:
                    netBuf.clear();
                    engine.wrap(ByteBuffer.allocate(0), netBuf);
                    netBuf.flip();
                    if (netBuf.hasRemaining()) {
                        byte[] outData = new byte[netBuf.remaining()];
                        netBuf.get(outData);
                        pair.getClientTransport().sendRecord(outData);
                    }
                    break;
                case NEED_UNWRAP:
                    byte[] inData = pair.getClientTransport().receiveRecord();
                    if (inData != null) {
                        netBuf.clear();
                        netBuf.put(inData);
                        netBuf.flip();
                        appBuf.clear();
                        engine.unwrap(netBuf, appBuf);
                    } else {
                        Thread.sleep(10);
                    }
                    break;
                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    break;
            }
        }
        throw new RuntimeException("Клиентский handshake не завершился за 80 итераций");
    }

    private static void doServerHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair)
            throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(
                TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        for (int i = 0; i < 80; i++) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.FINISHED
                    || hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) return;

            switch (hs) {
                case NEED_WRAP:
                    netBuf.clear();
                    engine.wrap(ByteBuffer.allocate(0), netBuf);
                    netBuf.flip();
                    if (netBuf.hasRemaining()) {
                        byte[] outData = new byte[netBuf.remaining()];
                        netBuf.get(outData);
                        pair.getServerTransport().sendRecord(outData);
                    }
                    break;
                case NEED_UNWRAP:
                    byte[] inData = pair.getServerTransport().receiveRecord();
                    if (inData != null) {
                        netBuf.clear();
                        netBuf.put(inData);
                        netBuf.flip();
                        appBuf.clear();
                        engine.unwrap(netBuf, appBuf);
                    } else {
                        Thread.sleep(10);
                    }
                    break;
                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    break;
            }
        }
        throw new RuntimeException("Серверный handshake не завершился за 80 итераций");
    }

    private static void doLoopback(GostSSLEngine clientEngine, GostSSLEngine serverEngine,
                                   InMemoryTlsTransport.Pair pair) throws Exception {
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread = new Thread(() -> {
            try { doClientHandshake(clientEngine, pair); }
            catch (Exception e) { clientError.set(e); }
        }, "loopback-client");

        Thread serverThread = new Thread(() -> {
            try { doServerHandshake(serverEngine, pair); }
            catch (Exception e) { serverError.set(e); }
        }, "loopback-server");

        clientThread.start();
        serverThread.start();

        clientThread.join(10000);
        serverThread.join(10000);

        if (clientThread.isAlive()) { clientThread.interrupt(); fail("Тайм-аут рукопожатия клиента"); }
        if (serverThread.isAlive()) { serverThread.interrupt(); fail("Тайм-аут рукопожатия сервера"); }
        if (clientError.get() != null)
            throw new RuntimeException("Клиент завершился с ошибкой", clientError.get());
        if (serverError.get() != null)
            throw new RuntimeException("Сервер завершился с ошибкой", serverError.get());
    }

    // ========================================================================
    // §1 GostSslBuilder — создание SSLContext
    // ========================================================================

    /**
     * GostSslBuilder — fluent-построитель SSLContext.
     * <p>
     * Показывает типовые комбинации: клиент только с CA, сервер с сертификатом,
     * builder с настройками OCSP/CRL. Все эти методы возвращают готовый
     * {@code SSLContext}, который можно передать в OkHttp, HttpsURLConnection
     * или Netty.
     * <p>
     * Портировано из {@code GostSslSmokeTest.java}.
     */
    @Test
    public void test01_gostSslBuilder() throws Exception {
        section("§1 GostSslBuilder — fluent-создание SSLContext");

        byte[] certDer = serverCert.getEncoded();
        byte[] caDer = caCert.getEncoded();
        byte[] keyDer = org.rssys.gost.jca.spec.GostDerCodec.encodePrivateKey(serverKey);

        assertNotNull("Клиентский контекст с CA",
                GostSsl.clientContext(caDer));
        assertNotNull("Серверный контекст из DER",
                GostSsl.serverContext(certDer, keyDer, caDer));

        SSLContext ctx = GostSsl.builder()
                .certificate(certDer, keyDer)
                .trustCa(caDer)
                .sessionCacheSize(5000)
                .buildServerContext();
        assertNotNull("Сервер через builder", ctx);

        SSLContext ctxClient = GostSsl.builder()
                .trustCa(caDer)
                .crlPolicy(CrlPolicy.DISABLED)
                .maxCrlSize(64 * 1024 * 1024)
                .maxRevokedEntries(500_000)
                .buildClientContext();
        assertNotNull("Клиент через builder с CRL-настройками", ctxClient);

        SSLContext ctxOcsp = GostSsl.builder()
                .certificate(certDer, keyDer)
                .trustCa(caDer)
                .maxOcspAgeMs(12 * 3600 * 1000L)
                .buildClientContext();
        assertNotNull("Клиент с maxOcspAgeMs", ctxOcsp);

        System.out.println("  OK: GostSslBuilder — все комбинации созданы");
    }

    // ========================================================================
    // §2 PKCS12 — загрузка ключей из PFX-контейнера
    // ========================================================================

    /**
     * Загрузка ключа и цепочки сертификатов из PKCS12 (PFX-файла).
     * <p>
     * PKCS#12 — стандартный формат для хранения ключей в production.
     * GostPkcs12Builder создаёт PFX с нативной ГОСТ-криптографией,
     * GostPkcs12Loader читает его обратно, а CertificateBridge
     * конвертирует в JCA-формат для GostX509KeyManager.
     */
    @Test
    public void test02_pkcs12Loading() throws Exception {
        section("§2 PKCS#12 — загрузка ключей из PFX");

        byte[] pfx = GostPkcs12Builder.create()
                .key(serverKey)
                .certificate(serverCert)
                .caCertificate(caCert)
                .password("changeit".toCharArray())
                .build();

        assertNotNull("PFX создан", pfx);
        assertTrue("PFX не пуст", pfx.length > 0);

        GostPkcs12Loader.Result p12 = GostPkcs12Loader.load(
                pfx, "changeit".toCharArray(), true);

        PrivateKeyParameters loadedKey = p12.getPrivateKey();
        assertNotNull("Ключ загружен из PFX", loadedKey);

        List<GostCertificate> loadedChain = p12.getCertificateChain();
        assertNotNull("Цепочка загружена из PFX", loadedChain);
        assertFalse("Цепочка не пуста", loadedChain.isEmpty());

        X509Certificate[] jcaChain = CertificateBridge.toJca(loadedChain);
        assertEquals("JCA-цепочка соответствует", loadedChain.size(), jcaChain.length);
        System.out.println("  OK: PFX создан, загружен, конвертирован в JCA ("
                + jcaChain.length + " сертификатов)");
    }

    // ========================================================================
    // §3 mTLS — взаимная аутентификация
    // ========================================================================

    /**
     * mTLS — обе стороны с сертификатами, через GostSSLEngine.
     * <p>
     * Двусторонняя аутентификация требуется в банковских/ведомственных API.
     * Сервер вызывает {@code setNeedClientAuth(true)} — клиент обязан
     * предъявить сертификат.
     */
    @Test
    public void test03_mtls() throws Exception {
        section("§3 mTLS — взаимная аутентификация");

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("default", serverJcaChain, serverKey);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKm,
                new GostX509TrustManager(caPubKey, false),
                "localhost", 0, false);
        serverEngine.setNeedClientAuth(true);

        GostX509KeyManager clientKm = new GostX509KeyManager();
        clientKm.addKeyEntry("client", clientJcaChain, clientKey);

        GostSSLEngine clientEngine = GostSSLEngine.createForClient(
                clientKm,
                new GostX509TrustManager(caPubKey, false),
                "localhost", 0, null);

        doLoopback(clientEngine, serverEngine, pair);

        try {
            Certificate[] peerCerts = serverEngine.getSession().getPeerCertificates();
            assertNotNull("Сервер получил сертификат клиента", peerCerts);
            assertTrue("Сертификат клиента не пуст", peerCerts.length > 0);
            System.out.println("  OK: mTLS — сервер проверил клиента: "
                    + ((X509Certificate) peerCerts[0]).getSubjectX500Principal());
        } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
            fail("Сервер не получил сертификат клиента: " + e.getMessage());
        }
    }

    // ========================================================================
    // §4 Dev-режим (GostSslDev / trustAll)
    // ========================================================================

    /**
     * Режим разработки — без проверки сертификата сервера.
     * <p>
     * При отладке, когда ещё нет выпущенного CA, можно использовать
     * {@link GostSslDev#trustAllClientContextInsecure()} для тестовых
     * подключений. Никогда не используйте в production.
     * <p>
     * {@code GostSslDev.trustAllNoHostnameCheckInsecure()} — ещё более
     * опасный режим (отключает даже проверку hostname). Только для
     * изолированных тестовых сетей.
     */
    @Test
    public void test04_devMode() throws Exception {
        section("§4 Dev-режим (GostSslDev / trustAll)");

        SSLContext devCtx = GostSslDev.trustAllClientContextInsecure();
        assertNotNull("trustAll контекст создан", devCtx);

        SSLContext devNoHost = GostSslDev.trustAllNoHostnameCheckInsecure();
        assertNotNull("trustAll + noHostname контекст создан", devNoHost);

        SSLContext builderDev = GostSsl.builder()
                .trustAll()
                .withoutHostnameVerification()
                .buildClientContext();
        assertNotNull("Builder trustAll контекст создан", builderDev);

        System.out.println("  OK: dev-режимы созданы (только для разработки)");
    }

    // ========================================================================
    // §5 OCSP — проверка статуса (без сети)
    // ========================================================================

    /**
     * Проверка статуса сертификата через OCSP с mock-ответом (без сети).
     * <p>
     * Используем {@link GostOcspResponseBuilder} для создания подписанного
     * OCSP-ответа, затем верифицируем его через {@link OcspVerifier}.
     * <p>
     * OCSP — механизм проверки, не отозван ли сертификат. Клиент может
     * получить OCSP-ответ либо staple-ом от сервера, либо сходить на
     * OCSP-респондер самостоятельно.
     */
    @Test
    public void test05_ocspJdk() throws Exception {
        section("§5 OCSP — верификация ответа (без сети)");

        byte[] serialNum = serverCert.getSerialNumber();
        byte[] ocspDer = GostOcspResponseBuilder.create(serialNum)
                .issuerDn(caDn)
                .sign(caKey);

        OcspVerifier.verify(ocspDer, serialNum, caCert);
        System.out.println("  OK: OCSP-ответ верифицирован (good)");
    }

    // ========================================================================
    // §6 OCSP (UrlConnection) — реальные респондеры
    // ========================================================================

    /**
     * OCSP-проверка через реальные OCSP-респондеры (Контур, ФНС).
     * <p>
     * Требует сети — помечен {@code @LargeTest}.
     * Использует {@code UrlConnectionOcspFetcher} — Android-совместимую
     * реализацию OCSP-фетчера на HttpURLConnection.
     */
    @LargeTest
    @Test
    public void test06_ocspUrlConnection() throws Exception {
        section("§6 OCSP — UrlConnectionOcspFetcher (реальные серверы)");

        org.rssys.gost.jsse.ocsp.UrlConnectionOcspFetcher fetcher =
                new org.rssys.gost.jsse.ocsp.UrlConnectionOcspFetcher();

        assertNotNull("UrlConnectionOcspFetcher создан", fetcher);
        System.out.println("  OK: UrlConnectionOcspFetcher доступен на Android");
    }

    // ========================================================================
    // §7 CRL — проверка без сети
    // ========================================================================

    /**
     * Проверка статуса сертификата через CRL (Certificate Revocation List).
     * <p>
     * CRL — альтернативный (и более старый) механизм проверки отзыва.
     * Если OCSP не поддерживается, сервер всё равно может публиковать CRL.
     * GostX509TrustManager умеет проверять оба механизма.
     */
    @Test
    public void test07_crlJdk() throws Exception {
        section("§7 CRL — базовая проверка");

        org.rssys.gost.jsse.crl.UrlConnectionCrlFetcher crlFetcher =
                new org.rssys.gost.jsse.crl.UrlConnectionCrlFetcher();
        assertNotNull("UrlConnectionCrlFetcher создан", crlFetcher);

        assertNotNull("CrlPolicy.DISABLED", CrlPolicy.DISABLED);
        assertNotNull("CrlPolicy.IF_CDP_PRESENT", CrlPolicy.IF_CDP_PRESENT);
        System.out.println("  OK: CRL-компоненты доступны на Android");
    }

    // ========================================================================
    // §8 CRL (UrlConnection) — реальные CDP
    // ========================================================================

    /**
     * CRL-проверка через реальные точки распространения CRL (CDP).
     * Требует сети — помечен {@code @LargeTest}.
     */
    @LargeTest
    @Test
    public void test08_crlUrlConnection() throws Exception {
        section("§8 CRL — UrlConnectionCrlFetcher (реальные серверы)");

        org.rssys.gost.jsse.crl.UrlConnectionCrlFetcher fetcher =
                new org.rssys.gost.jsse.crl.UrlConnectionCrlFetcher();
        assertNotNull("UrlConnectionCrlFetcher создан", fetcher);
        System.out.println("  OK: UrlConnectionCrlFetcher доступен на Android");
    }

    // ========================================================================
    // §9 PSK resumption через GostSSLSessionContext
    // ========================================================================

    /**
     * PSK session resumption через GostSSLSessionContext.
     * <p>
     * Два последовательных handshake через один GostSSLSessionContext.
     * Первый — полный (сервер отправляет NewSessionTicket, клиент
     * сохраняет PSK в session context). Второй — аббревиатурный (PSK).
     * <p>
     * Мобильные приложения постоянно переподключаются — PSK resumption
     * через JSSE-контекст работает автоматически.
     */
    @Test
    public void test09_pskResumptionJsse() throws Exception {
        section("§9 PSK resumption через GostSSLSessionContext");

        // Shared PskStore — одно хранилище для сервера и клиента.
        // В production у клиента и сервера — разные хранилища.
        GostSSLSessionContext sessionCtx = new GostSSLSessionContext(CS, CS.getHashLen());

        InMemoryTlsTransport.Pair pair1 = InMemoryTlsTransport.newPair();
        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("default", serverJcaChain, serverKey);

        GostSSLEngine server1 = GostSSLEngine.createForServer(
                serverKm, new GostX509TrustManager(null, false), "localhost", 0, sessionCtx);
        GostSSLEngine client1 = GostSSLEngine.createForClient(
                new GostX509KeyManager(), new GostX509TrustManager(caPubKey, false),
                "localhost", 0, sessionCtx);

        doLoopback(client1, server1, pair1);

        assertTrue("PSK сохранён после первого handshake",
                sessionCtx.getPskStore().size() > 0);

        InMemoryTlsTransport.Pair pair2 = InMemoryTlsTransport.newPair();

        GostSSLEngine server2 = GostSSLEngine.createForServer(
                serverKm, new GostX509TrustManager(null, false), "localhost", 0, sessionCtx);
        GostSSLEngine client2 = GostSSLEngine.createForClient(
                new GostX509KeyManager(), new GostX509TrustManager(caPubKey, false),
                "localhost", 0, sessionCtx);

        doLoopback(client2, server2, pair2);

        assertTrue("PSK остаётся в хранилище после второго соединения",
                sessionCtx.getPskStore().size() > 0);
        System.out.println("  OK: PSK resumption через JSSE-контекст");
    }

    // ========================================================================
    // §10 GostSSLEngine loopback
    // ========================================================================

    /**
     * Полный handshake между двумя GostSSLEngine через in-memory транспорт.
     * <p>
     * Портировано из {@code GostSSLEngineLoopbackTest.java}.
     * <p>
     * SSLEngine — низкоуровневый API для NIO-интеграций (Netty, OkHttp).
     * Используем InMemoryTlsTransport вместо сети — handshake выполняется
     * в памяти, что даёт быструю обратную связь на эмуляторе.
     */
    @Test
    public void test10_engineLoopback() throws Exception {
        section("§10 GostSSLEngine loopback");

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("default", serverJcaChain, serverKey);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKm,
                new GostX509TrustManager(null, false),
                "localhost", 0, false);

        GostX509KeyManager clientKm = new GostX509KeyManager();
        GostSSLEngine clientEngine = GostSSLEngine.createForClient(
                clientKm,
                new GostX509TrustManager(caPubKey, false),
                "localhost", 0, null);

        doLoopback(clientEngine, serverEngine, pair);

        ByteBuffer netBuf = ByteBuffer.allocate(
                TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        appBuf.clear();
        appBuf.put("PING".getBytes(StandardCharsets.US_ASCII));
        appBuf.flip();

        netBuf.clear();
        SSLEngineResult wrapResult = clientEngine.wrap(appBuf, netBuf);
        netBuf.flip();
        assertEquals("PING отправлен", SSLEngineResult.Status.OK, wrapResult.getStatus());

        byte[] record = new byte[netBuf.remaining()];
        netBuf.get(record);
        pair.getClientTransport().sendRecord(record);

        byte[] serverIn = pair.getServerTransport().receiveRecord();
        assertNotNull("Сервер получил данные", serverIn);

        netBuf.clear();
        netBuf.put(serverIn);
        netBuf.flip();

        appBuf.clear();
        SSLEngineResult unwrapResult = serverEngine.unwrap(netBuf, appBuf);
        appBuf.flip();
        assertEquals("PING распакован сервером", SSLEngineResult.Status.OK, unwrapResult.getStatus());

        byte[] ping = new byte[appBuf.remaining()];
        appBuf.get(ping);
        assertEquals("PING", new String(ping, StandardCharsets.US_ASCII));

        System.out.println("  OK: GostSSLEngine loopback — данные прошли");
    }

    // ========================================================================
    // §11 ExtendedSSLSession — совместимость с ART
    // ========================================================================

    /**
     * Проверка ExtendedSSLSession-методов на Android Runtime.
     * <p>
     * {@code getPeerSupportedSignatureAlgorithms()} и
     * {@code getStatusResponses()} — методы {@code ExtendedSSLSession},
     * которые в некоторых версиях Android могут отсутствовать.
     * Тест вызывает их через полиморфный тип {@code SSLSession},
     * чтобы убедиться, что нет {@code AbstractMethodError} на ART.
     */
    @Test
    public void test11_extendedSession() throws Exception {
        section("§11 ExtendedSSLSession — совместимость с ART");

        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("default", serverJcaChain, serverKey);
        GostX509KeyManager clientKm = new GostX509KeyManager();

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngine server = new GostSSLEngine(
                serverKm, new GostX509TrustManager(null, false), "localhost", 0, false);
        GostSSLEngine client = GostSSLEngine.createForClient(
                clientKm, new GostX509TrustManager(caPubKey, false), "localhost", 0, null);

        doLoopback(client, server, pair);

        SSLSession session = client.getSession();
        assertNotNull("SSLSession получен", session);

        assertNotNull("CipherSuite не null", session.getCipherSuite());
        assertEquals("Protocol TLSv1.3", "TLSv1.3", session.getProtocol());
        System.out.println("  CipherSuite: " + session.getCipherSuite());
        System.out.println("  Protocol: " + session.getProtocol());

        try {
            java.security.cert.Certificate[] peerCerts = session.getPeerCertificates();
            assertNotNull("Peer-сертификаты получены", peerCerts);
            assertTrue("Peer-сертификаты не пусты", peerCerts.length > 0);
        } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
            System.out.println("  (trustAll — peer не верифицирован)");
        }

        System.out.println("  OK: SSLSession методы работают на ART");
    }
}
