package org.rssys.gost.crossval.tls13;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostPkcs12Loader;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.cert.TlsCertUtils;
import org.rssys.gost.tls13.config.ClientCertificateRequest;
import org.rssys.gost.tls13.config.ClientOcspPolicy;
import org.rssys.gost.tls13.config.OIDFilter;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsClientCredentials;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

@DisplayName("TLS 1.3: кросс-валидация crypto-gost <-> OpenSSL")
class OpenSslTls13CrossValidationTest {

    private static final String SUITE_L = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    private static final String SUITE_S = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S";
    private static final int SUITE_L_ID = 0xC103;
    private static final int SUITE_S_ID = 0xC105;
    private static final long TIMEOUT_MS = 30_000;

    /** Объём эха: заметно больше 8 записей в каждую сторону (порог смены ключа TLSTREE у S). */
    private static final int ECHO_PAYLOAD_SIZE = 200_000;

    record CurveSpec(String ianaName, int groupId, ECParameters params, String algo, String paramset, String sigalgsName) {}

    // OpenSSL paramset:A для gost2012_256 ≡ CryptoPro-A ≡ GRP_GC256B (0x0023).
    // Для 512-бит маппинг прямой: paramset A/B ≡ TC26-512A/B.
    // GC256A и GC512C имеют кофактор 4: ECDHE на них считается как (h·d)·Q (RFC 9367 §6.1.1),
    // кривые с h = 1 такую ошибку не выявляют. Для TC26-256-A paramset в gostprov называется TCA.
    // Порядок важен: mTLS-тесты берут ALL_CURVES.get(0) (GC256B)
    static final List<CurveSpec> ALL_CURVES = List.of(
            new CurveSpec("GC256B", TlsConstants.GRP_GC256B, ECParameters.cryptoProA(), "gost2012_256", "A", "gostr34102012_256b"),
            new CurveSpec("GC512A", TlsConstants.GRP_GC512A, ECParameters.tc26a512(), "gost2012_512", "A", "gostr34102012_512a"),
            new CurveSpec("GC512B", TlsConstants.GRP_GC512B, ECParameters.tc26b512(), "gost2012_512", "B", "gostr34102012_512b"),
            new CurveSpec("GC256A", TlsConstants.GRP_GC256A, ECParameters.tc26a256(), "gost2012_256", "TCA", "gostr34102012_256a"),
            new CurveSpec("GC512C", TlsConstants.GRP_GC512C, ECParameters.tc26c512(), "gost2012_512", "C", "gostr34102012_512c")
    );

    @BeforeAll
    static void preconditions() {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslTls13Helper.assumeGostTls13();
    }

    static Stream<Arguments> allCurves() {
        return ALL_CURVES.stream().map(c -> Arguments.of(c.ianaName, c.groupId));
    }


    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            SUITE_L + "; " + SUITE_L_ID + "; GC256B",
            SUITE_S + "; " + SUITE_S_ID + "; GC256B"
    })
    @DisplayName("сервер crypto-gost + s_client: handshake + GET -> INTEROP_OK")
    void testServerRoundtrip(String suiteName, int suiteId, String curveName) throws Exception {
        runServerTest(suiteName, suiteId, curveName, false, 0);
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("сервер crypto-gost + s_client: все кривые (включая GC256A и GC512C с кофактором 4)")
    void testServerAllCurves(String curveName, int groupId) throws Exception {
        // gostprov не кладёт GC512A/GC512B в key_share начального ClientHello: сервер выбирает
        // группу по supported_groups клиента (при необходимости отправляет HRR на группу вне
        // key_share, RFC 8446 §4.2.8).
        runServerTest(SUITE_L, SUITE_L_ID, curveName, false, 0);
    }

    @Test
    @DisplayName("сервер crypto-gost + s_client: oid_filters (wire-формат)")
    void testServerOidFilters() throws Exception {
        CurveSpec curve = findCurve("GC256B");
        int port = OpenSslTls13Helper.findFreePort();

        TempDirUtils.withTempDir("tls13-oidf-", tmpDir -> {
            PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(curve.params);

            // Клиентский сертификат Java API с KC1 в CertificatePolicies
            PkixCertTestHelper.CertBundle clientBundle = PkixCertTestHelper.createCertWithKey(
                    curve.params, "20240101120000Z", "21060101120000Z",
                    null, new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_CLIENT_AUTH}, null, new String[]{GostOids.POLICY_KC1});
            Path clientCertPem = tmpDir.resolve("client-cert.pem");
            Path clientKeyPem = tmpDir.resolve("client-key.pem");
            Files.writeString(clientCertPem, clientBundle.cert.toPem());
            Files.writeString(clientKeyPem,
                    OpenSslTls13Helper.privateKeyToPem(
                            GostDerCodec.encodePrivateKey(clientBundle.priv)));

            // OID filter: KC1 (filterOid = CertificatePolicies 2.5.29.32, value = { 1.2.643.100.113.1 })
            byte[] kc1FilterValues = buildEkuFilterValues(oidContent(GostOids.POLICY_KC1));
            OIDFilter kc1Filter = new OIDFilter(oidContent(GostOids.EXT_CP), kc1FilterValues);
            List<OIDFilter> filters = Collections.singletonList(kc1Filter);

            startJavaServerWithOidFilters(port, SUITE_L_ID, curve, bundle.cert, bundle.priv,
                    filters, clientBundle.cert);

            Thread.sleep(200);

            List<String> clientExtraArgs = List.of(
                    "-cert", clientCertPem.toString(),
                    "-key", clientKeyPem.toString(),
                    "-sigalgs", curve.sigalgsName);
            String clientOutput = OpenSslTls13Helper.runSClientWithHttpGet(port,
                    SUITE_L, curve.ianaName, TIMEOUT_MS,
                    clientExtraArgs.toArray(new String[0]));

            assertTrue(clientOutput.contains("INTEROP_OK"),
                    "s_client output должен содержать INTEROP_OK: " + clientOutput);
            return null;
        });
    }

    @Test
    @DisplayName("сервер crypto-gost + s_client -status: OCSP-staple принят OpenSSL (RFC 6066 §8)")
    void testServerOcspStaple() throws Exception {
        CurveSpec curve = findCurve("GC256B");
        int port = OpenSslTls13Helper.findFreePort();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(curve.params);
        // Минимальный OCSPResponse: responseStatus = successful, без responseBytes.
        byte[] ocspResponse = {0x30, 0x03, 0x0A, 0x01, 0x00};

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        Thread serverThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setSoTimeout(15000);
                try (Socket s = ss.accept();
                     SocketTlsTransport tp = new SocketTlsTransport(s);
                     TlsSession session = TlsSession.createServer(
                             new TlsServerConfig(TlsCiphersuite.byId(SUITE_L_ID),
                                     Collections.singletonList(bundle.cert), bundle.priv)
                                     .withOcspStaplingResponse(ocspResponse), tp)) {
                    session.handshakeAsServer();
                    session.read();
                    session.write("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nINTEROP_OK"
                            .getBytes(StandardCharsets.UTF_8));
                }
            } catch (Exception e) {
                serverError.set(e);
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        Thread.sleep(200);

        String clientOutput = OpenSslTls13Helper.runSClientWithHttpGet(port,
                SUITE_L, curve.ianaName, TIMEOUT_MS, "-status");
        serverThread.join(5000);

        assertNull(serverError.get(), "Server error: " + serverError.get());
        // s_client печатает разобранный ответ только если uint24-длина в CertificateStatus верна.
        assertTrue(clientOutput.contains("OCSP Response Status: successful"),
                "OpenSSL должен разобрать staple: " + clientOutput);
        assertTrue(clientOutput.contains("INTEROP_OK"),
                "handshake со staple должен завершиться: " + clientOutput);
    }

    @Test
    @DisplayName("сервер crypto-gost [REQUEST] + s_client: status_request в CertificateRequest терпим для OpenSSL")
    void testServerMtlsClientOcspRequest() throws Exception {
        CurveSpec curve = findCurve("GC256B");
        int port = OpenSslTls13Helper.findFreePort();

        TempDirUtils.withTempDir("tls13-mtls-ocsp-", tmpDir -> {
            PkixCertTestHelper.CertBundle serverBundle = PkixCertTestHelper.createCertWithKey(curve.params);
            // Клиент: самоподписанный сертификат, сервер доверяет ему напрямую
            PkixCertTestHelper.CertBundle clientBundle = PkixCertTestHelper.createCertWithKey(
                    curve.params, "20240101120000Z", "21060101120000Z",
                    null, new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_CLIENT_AUTH}, null, null);
            Path clientCertPem = tmpDir.resolve("client-cert.pem");
            Path clientKeyPem = tmpDir.resolve("client-key.pem");
            Files.writeString(clientCertPem, clientBundle.cert.toPem());
            Files.writeString(clientKeyPem,
                    OpenSslTls13Helper.privateKeyToPem(
                            GostDerCodec.encodePrivateKey(clientBundle.priv)));

            AtomicReference<Throwable> serverError = new AtomicReference<>();
            Thread serverThread = new Thread(() -> {
                try (ServerSocket ss = new ServerSocket(port)) {
                    ss.setSoTimeout(15000);
                    try (Socket s = ss.accept();
                         SocketTlsTransport tp = new SocketTlsTransport(s);
                         TlsSession session = TlsSession.createServer(
                                 new TlsServerConfig(TlsCiphersuite.byId(SUITE_L_ID),
                                         Collections.singletonList(serverBundle.cert), serverBundle.priv)
                                         .needClientAuth(TrustAnchors.ofCertificate(clientBundle.cert))
                                         .withClientOcspPolicy(ClientOcspPolicy.REQUEST), tp)) {
                        session.handshakeAsServer();
                        session.read();
                        session.write("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nINTEROP_OK"
                                .getBytes(StandardCharsets.UTF_8));
                    }
                } catch (Exception e) {
                    serverError.set(e);
                }
            });
            serverThread.setDaemon(true);
            serverThread.start();
            Thread.sleep(200);

            String clientOutput = OpenSslTls13Helper.runSClientWithHttpGet(port,
                    SUITE_L, curve.ianaName, TIMEOUT_MS,
                    "-cert", clientCertPem.toString(),
                    "-key", clientKeyPem.toString(),
                    "-sigalgs", curve.sigalgsName, "-trace");
            serverThread.join(5000);

            assertNull(serverError.get(), "Server error: " + serverError.get());
            // -trace печатает расширения CertificateRequest: подтверждает, что запрос ушёл в сообщение.
            assertTrue(clientOutput.contains("status_request"),
                    "CertificateRequest должен содержать status_request: " + clientOutput);
            assertTrue(clientOutput.contains("INTEROP_OK"),
                    "OpenSSL должен пройти handshake с status_request в CertificateRequest: "
                            + clientOutput);
            return null;
        });
    }

    @Test
    @DisplayName("сервер crypto-gost + s_client: mTLS (взаимная аутентификация)")
    void testServerMtls() throws Exception {
        AtomicReference<List<GostCertificate>> peerCerts = new AtomicReference<>();
        runServerTest(SUITE_L, SUITE_L_ID, "GC256B", true, 0, peerCerts);
        // Проверяем что сертификат клиента удовлетворяет KC1 фильтру
        List<GostCertificate> certs = peerCerts.get();
        assertNotNull(certs, "Должен быть peer-сертификат");
        assertFalse(certs.isEmpty(), "Peer-сертификаты не пусты");
        byte[] kc1FilterValues = buildEkuFilterValues(oidContent(GostOids.POLICY_KC1));
        OIDFilter kc1Filter = new OIDFilter(oidContent(GostOids.EXT_CP), kc1FilterValues);
        assertTrue(TlsCertUtils.matchesOidFilter(certs.get(0), kc1Filter),
                "Клиентский сертификат должен удовлетворять KC1 фильтру");
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 15, 16, 1024, 12_000, 16_383, 16_384, 16_385, 32_768})
    @DisplayName("сервер crypto-gost + s_client: размеры payload (TLSTREE re-keying)")
    void testServerPayload(int size) throws Exception {
        runServerPayloadTest(SUITE_L, SUITE_L_ID, "GC256B", size);
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            SUITE_S + "; " + SUITE_L,
            SUITE_L + "; " + SUITE_S
    })
    @DisplayName("сервер crypto-gost + s_client с одним набором: эхо 200 КБ при наборе сервера, отличном от выбранного")
    void testServerEchoWhenClientOffersOtherSuite(String serverSuiteName, String clientSuiteName)
            throws Exception {
        // s_client предлагает ровно один набор, поэтому сервер выбирает его, а не настроенный:
        // записи сервера обязаны строиться по выбранному набору. У S ключ записи меняется каждые
        // 8 записей, у L нет, и с 9-й записи при несогласованном наборе ключи расходятся.
        CurveSpec curve = findCurve("GC256B");
        int port = OpenSslTls13Helper.findFreePort();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(curve.params);

        byte[] payload = new byte[ECHO_PAYLOAD_SIZE];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) i;
        }

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        AtomicReference<byte[]> serverReceived = new AtomicReference<>();
        Thread serverThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setSoTimeout(15000);
                try (Socket s = ss.accept();
                     SocketTlsTransport tp = newTimedTransport(s);
                     TlsSession session = TlsSession.createServer(
                             new TlsServerConfig(TlsCiphersuite.byId(suiteNameToId(serverSuiteName)),
                                     Collections.singletonList(bundle.cert), bundle.priv), tp)) {
                    session.handshakeAsServer();
                    ByteArrayOutputStream acc = new ByteArrayOutputStream(payload.length);
                    long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(TIMEOUT_MS);
                    while (acc.size() < payload.length) {
                        if (System.nanoTime() > deadline) {
                            throw new IllegalStateException(
                                    "Получено " + acc.size() + " из " + payload.length + " байт");
                        }
                        acc.write(session.read());
                    }
                    byte[] data = acc.toByteArray();
                    serverReceived.set(data);
                    session.write(data);
                }
            } catch (Exception e) {
                serverError.set(e);
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        Thread.sleep(200);

        OpenSslTls13Helper.SClientEcho echo = OpenSslTls13Helper.runSClientEcho(
                port, clientSuiteName, curve.ianaName, payload, 120_000);

        serverThread.join(5000);

        assertNull(serverError.get(),
                "Ошибка сервера: " + serverError.get() + "\nstderr s_client: " + echo.stderr());
        assertArrayEquals(payload, serverReceived.get(),
                "Сервер должен получить от s_client ровно отправленные байты");
        assertArrayEquals(payload, echo.stdout(),
                "s_client должен получить от сервера ровно те же байты: " + echo.stderr());
    }

    @Test
    @DisplayName("s_server без общего набора шифров + клиент crypto-gost: открытый alert пира, а не обрыв")
    void testClientReceivesPlaintextAlertFromOpenSsl() throws Exception {
        // s_server предлагает только стандартный набор, которого наш клиент не предлагает:
        // общего набора нет, и сервер отвечает fatal alert открытой записью до установки ключей.
        // Клиент обязан увидеть настоящий alert пира, а не ошибку разбора или EOF
        CurveSpec curve = findCurve("GC256B");
        int port = OpenSslTls13Helper.findFreePort();

        TempDirUtils.withTempDir("tls13-alert-", tmpDir -> {
            OpenSslTls13Helper.generateGostCert(tmpDir, curve.algo, curve.paramset);
            Process sServer = OpenSslTls13Helper.startSServer(port,
                    "TLS_AES_256_GCM_SHA384", curve.ianaName,
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString());
            try {
                assertTrue(OpenSslTls13Helper.waitForString(sServer, "ACCEPT", 10_000),
                        "s_server не запустился");

                try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port);
                     SocketTlsTransport tp = new SocketTlsTransport(socket);
                     TlsSession client = TlsSession.createClientWithoutServerAuth(
                             tp, TlsCiphersuite.byId(SUITE_L_ID), null, null)) {
                    TlsException error = assertThrows(TlsException.class, client::handshakeAsClient);

                    assertTrue(error.isFromPeer(),
                            "Alert пришёл от s_server, а не найден локально: " + error);
                    assertEquals(TlsConstants.ALERT_HANDSHAKE_FAILURE, error.getAlertCode(),
                            "Нет общего набора шифров: ожидается handshake_failure");
                    assertTrue(client.isClosed(), "Сессия должна быть закрыта");
                }
            } finally {
                OpenSslTls13Helper.destroyProcess(sServer);
            }
            return null;
        });
    }

    @Test
    @DisplayName("сервер crypto-gost + s_client без схемы сертификата: сервер видит настоящий alert OpenSSL")
    void testServerSeesPlaintextAlertFromOpenSslClient() throws Exception {
        // Сервер подписывает схемой своей кривой GC256B, а s_client предлагает только схему
        // GC256A и сам отвергает подпись (политика сервера при отсутствии общей схемы остаётся
        // прежней). Alert клиент шлёт открытой записью, когда ключ записи рукопожатия у него ещё
        // не включён, а наш сервер к этому моменту уже читает зашифрованные записи
        CurveSpec certCurve = findCurve("GC256B");
        CurveSpec clientCurve = findCurve("GC256A");
        int port = OpenSslTls13Helper.findFreePort();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(certCurve.params);

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        Thread serverThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setSoTimeout(15000);
                try (Socket s = ss.accept();
                     SocketTlsTransport tp = newTimedTransport(s);
                     TlsSession session = TlsSession.createServer(
                             new TlsServerConfig(TlsCiphersuite.byId(SUITE_L_ID),
                                     Collections.singletonList(bundle.cert), bundle.priv), tp)) {
                    session.handshakeAsServer();
                }
            } catch (Throwable e) {
                serverError.set(e);
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        Thread.sleep(200);

        String clientOutput = OpenSslTls13Helper.runSClientWithHttpGet(port,
                SUITE_L, certCurve.ianaName, TIMEOUT_MS, "-sigalgs", clientCurve.sigalgsName);
        serverThread.join(10_000);

        assertFalse(clientOutput.contains("INTEROP_OK"),
                "s_client не должен пройти рукопожатие: " + clientOutput);
        TlsException error = assertInstanceOf(TlsException.class, serverError.get(),
                "Сервер должен увидеть alert клиента, а не ошибку разбора: " + serverError.get()
                        + "; вывод клиента: " + clientOutput);
        assertTrue(error.isFromPeer(), "Alert пришёл от s_client: " + error);
        // Сборка OpenSSL 3.6.0-gost отвечает на неподходящую схему подписи именно handshake_failure
        assertEquals(TlsConstants.ALERT_HANDSHAKE_FAILURE, error.getAlertCode(),
                "Сервер должен увидеть настоящий код s_client, а не ошибку разбора: " + error);
    }

    @Test
    @DisplayName("клиент crypto-gost отвергает сертификат s_server: s_server видит настоящий код alert")
    void testSServerSeesClientCertificateRejection() throws Exception {
        CurveSpec curve = findCurve("GC256B");
        int port = OpenSslTls13Helper.findFreePort();

        TempDirUtils.withTempDir("tls13-reject-", tmpDir -> {
            OpenSslTls13Helper.generateGostCert(tmpDir, curve.algo, curve.paramset);
            PkixCertTestHelper.CertBundle otherBundle = PkixCertTestHelper.createCertWithKey(curve.params);
            Process sServer = OpenSslTls13Helper.startSServer(port,
                    SUITE_L, curve.ianaName,
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString());
            try {
                assertTrue(OpenSslTls13Helper.waitForString(sServer, "ACCEPT", 10_000),
                        "s_server не запустился");
                try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port);
                     SocketTlsTransport tp = new SocketTlsTransport(socket);
                     TlsSession client = TlsSession.createClient(
                             new TlsClientConfig(TlsCiphersuite.byId(SUITE_L_ID),
                                     TrustAnchors.ofCertificate(otherBundle.cert))
                                     .withoutHostnameVerification(), tp)) {
                    TlsException error = assertThrows(TlsException.class, client::handshakeAsClient);
                    assertFalse(error.isFromPeer(), "Отказ найден клиентом локально: " + error);
                    assertEquals(TlsConstants.ALERT_UNKNOWN_CA, error.getAlertCode(),
                            "Сертификат s_server вне доверенных: unknown_ca");
                }
                // До смены ключа записи клиент шлёт alert открытым, а s_server обязан принять его
                // и назвать настоящий код (SSL alert number 48 - unknown_ca)
                assertTrue(OpenSslTls13Helper.waitForString(sServer,
                                "alert number " + (TlsConstants.ALERT_UNKNOWN_CA & 0xFF), 5_000),
                        "s_server должен увидеть alert клиента с кодом unknown_ca");
            } finally {
                OpenSslTls13Helper.destroyProcess(sServer);
            }
            return null;
        });
    }

    @Test
    @DisplayName("s_server -Verify предлагает только 512-битную схему: клиент crypto-gost с 256-битным ключом шлёт пустой Certificate")
    void testClientSendsEmptyCertificateWhenSchemeNotOffered() throws Exception {
        // RFC 8446 §4.4.3: схема CertificateVerify клиента обязана быть из списка CertificateRequest,
        // §4.4.2.3: подходящего сертификата нет - пустой Certificate. s_server с одной 512-битной
        // схемой (его собственный ключ тоже 512-битный) и обязательной проверкой клиента отвечает
        // certificate_required, а не принимает подпись схемой вне списка
        CurveSpec serverCurve = findCurve("GC512A");
        CurveSpec clientCurve = findCurve("GC256B");
        int port = OpenSslTls13Helper.findFreePort();
        PkixCertTestHelper.CertBundle clientBundle = PkixCertTestHelper.createCertWithKey(clientCurve.params);

        TempDirUtils.withTempDir("tls13-client-scheme-", tmpDir -> {
            OpenSslTls13Helper.generateGostCert(tmpDir, serverCurve.algo, serverCurve.paramset);
            Path clientCertPem = tmpDir.resolve("client-cert.pem");
            Files.writeString(clientCertPem, clientBundle.cert.toPem());
            Process sServer = OpenSslTls13Helper.startSServer(port,
                    SUITE_L, serverCurve.ianaName,
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    "-sigalgs", serverCurve.sigalgsName,
                    "-Verify", "1", "-CAfile", clientCertPem.toString());
            try {
                assertTrue(OpenSslTls13Helper.waitForString(sServer, "ACCEPT", 10_000),
                        "s_server не запустился");

                try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port);
                     SocketTlsTransport tp = newTimedTransport(socket);
                     TlsSession client = TlsSession.createClientWithoutServerAuth(
                             tp, TlsCiphersuite.byId(SUITE_L_ID), clientBundle.cert, clientBundle.priv)) {
                    client.handshakeAsClient();
                    // Наш Finished уходит и без клиентского сертификата, отказ приходит alert-ом
                    TlsException error = assertThrows(TlsException.class, client::read);
                    assertTrue(error.isFromPeer(), "Отказ пришёл от s_server: " + error);
                    assertEquals(TlsConstants.ALERT_CERTIFICATE_REQUIRED, error.getAlertCode(),
                            "Пустой клиентский Certificate при -Verify: certificate_required");
                }
            } finally {
                OpenSslTls13Helper.destroyProcess(sServer);
            }
            return null;
        });
    }

    @ParameterizedTest(name = "список CA отключён: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("s_server -Verify предлагает только 512-битную схему: клиент с 256- и 512-битным сертификатами отправляет 512-битный")
    void testClientSelectsCertificateByServerSchemes(boolean noCaNames) throws Exception {
        // RFC 8446 §4.4.3: схема CertificateVerify обязана быть из списка CertificateRequest.
        // Сервер с 256-битным сертификатом просит клиентскую подпись только схемой 512
        // (-client_sigalgs). Первым идёт 256-битный сертификат клиента:
        // без выбора по схемам сервера клиент отправил бы его и получил certificate_required.
        // Заодно проверяется, что с -CAfile список CA доходит до селектора, а с -no_ca_names пуст
        CurveSpec serverCurve = findCurve("GC256B");
        PkixCertTestHelper.CertBundle client256 = PkixCertTestHelper.createCertWithKey(serverCurve.params);
        PkixCertTestHelper.CertBundle client512 =
                PkixCertTestHelper.createCertWithKey(findCurve("GC512A").params);
        int port = OpenSslTls13Helper.findFreePort();

        TempDirUtils.withTempDir("tls13-client-selection-", tmpDir -> {
            OpenSslTls13Helper.generateGostCert(tmpDir, serverCurve.algo, serverCurve.paramset);
            Path clientCas = tmpDir.resolve("client-cas.pem");
            Files.writeString(clientCas, client256.cert.toPem() + client512.cert.toPem());
            GostCertificate srvCert =
                    GostCertificate.fromPemOrDer(Files.readAllBytes(tmpDir.resolve("cert.pem")));

            // -sigalgs ограничивает схему подписи самого сервера (без него OpenSSL берёт схему
            // 256a для ключа другой кривой), а -client_sigalgs - список в CertificateRequest
            List<String> extra = new java.util.ArrayList<>(List.of(
                    "-sigalgs", serverCurve.sigalgsName,
                    "-client_sigalgs", findCurve("GC512A").sigalgsName,
                    "-Verify", "1", "-CAfile", clientCas.toString()));
            if (noCaNames) {
                extra.add("-no_ca_names");
            }
            Process sServer = OpenSslTls13Helper.startSServer(port,
                    SUITE_L, serverCurve.ianaName,
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    extra.toArray(new String[0]));
            AtomicReference<ClientCertificateRequest> seen = new AtomicReference<>();
            String serverOutput;
            List<TlsClientCredentials> candidates = List.of(
                    new TlsClientCredentials(List.of(client256.cert), client256.priv),
                    new TlsClientCredentials(List.of(client512.cert), client512.priv));
            try {
                assertTrue(OpenSslTls13Helper.waitForString(sServer, "ACCEPT", 10_000),
                        "s_server не запустился");

                // Селектор задан явно: без него TlsSession взял бы цепочку из конфигурации и
                // тест ничего не сказал бы о выборе
                TlsClientConfig config = new TlsClientConfig(TlsCiphersuite.byId(SUITE_L_ID),
                        TrustAnchors.ofCertificate(srvCert))
                        .withoutHostnameVerification()
                        .withClientCertificateSelector(request -> {
                            seen.set(request);
                            for (TlsClientCredentials candidate : candidates) {
                                int scheme = TlsCertUtils.leafSignatureScheme(candidate.chain());
                                if (TlsCertUtils.isSchemeOffered(request.signatureSchemes(), scheme)) {
                                    return candidate;
                                }
                            }
                            return null;
                        });
                try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port);
                     SocketTlsTransport tp = newTimedTransport(socket);
                     TlsSession client = TlsSession.createClient(config, tp)) {
                    client.handshakeAsClient();
                    client.write("GET / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.UTF_8));
                    byte[] response = client.read();
                    assertTrue(response.length > 0, "s_server ответил по установленному соединению");
                }
                // s_server печатает принятый сертификат клиента; читаем до завершения процесса
                serverOutput = drainOutput(sServer, 1_500).replaceAll("\\s", "");
            } finally {
                OpenSslTls13Helper.destroyProcess(sServer);
            }

            ClientCertificateRequest request = seen.get();
            assertNotNull(request, "селектор получил CertificateRequest от s_server");
            assertEquals(noCaNames ? 0 : 2, request.caDns().size(),
                    "список CA: два из -CAfile, пусто при -no_ca_names");
            assertArrayEquals(new int[] {TlsConstants.SIG_GOST_TC26_512_A},
                    request.signatureSchemes(), "s_server предлагает только схему 512");
            assertTrue(serverOutput.contains(acceptedClient(client512.cert)),
                    "s_server принял 512-битный сертификат клиента: " + serverOutput);
            assertFalse(serverOutput.contains("CN=" + commonName(client256.cert)),
                    "256-битный сертификат клиент не отправлял: " + serverOutput);
            return null;
        });
    }

    /** Забирает всё, что процесс успел напечатать за отведённое время, не дожидаясь его выхода. */
    private static String drainOutput(Process process, long timeoutMs) throws Exception {
        StringBuilder out = new StringBuilder();
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        java.io.InputStream in = process.getInputStream();
        while (System.nanoTime() < deadline) {
            int ready = in.available();
            if (ready > 0) {
                out.append(new String(in.readNBytes(ready), StandardCharsets.UTF_8));
            } else {
                Thread.sleep(50);
            }
        }
        return out.toString();
    }

    private static String commonName(GostCertificate certificate) {
        // пробелы убраны: вывод s_server сравнивается тоже без них
        return certificate.getSubjectDnField("2.5.4.3")[0].replaceAll("\\s", "");
    }

    /** Строка проверки клиента в выводе s_server без пробелов: глубина 0, CN, успех. */
    private static String acceptedClient(GostCertificate certificate) {
        return "depth=0CN=" + commonName(certificate) + "verifyreturn:1";
    }

    @Test
    @DisplayName("сервер crypto-gost + s_client: KeyUpdate с update_requested от OpenSSL, обмен продолжается")
    void testServerKeyUpdateRequestedByOpenSsl() throws Exception {
        // Команда K в s_client шлёт KeyUpdate(update_requested): наш сервер обязан ответить одним
        // KeyUpdate и перейти на новые ключи, а OpenSSL - принять ответ и расшифровать эхо
        CurveSpec curve = findCurve("GC256B");
        int port = OpenSslTls13Helper.findFreePort();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(curve.params);

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        AtomicReference<String> serverReceived = new AtomicReference<>("");
        // OpenSSL не требует ответа на update_requested: без смены ключа записи сервера тест
        // остался бы зелёным и при отсутствии ответа, поэтому сравниваем запись до и после
        AtomicReference<Boolean> writerKeyChanged = new AtomicReference<>(false);
        Thread serverThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setSoTimeout(15000);
                try (Socket s = ss.accept();
                     SocketTlsTransport tp = newTimedTransport(s);
                     TlsSession session = TlsSession.createServer(
                             new TlsServerConfig(TlsCiphersuite.byId(SUITE_L_ID),
                                     Collections.singletonList(bundle.cert), bundle.priv), tp)) {
                    session.handshakeAsServer();
                    java.lang.reflect.Field writerField =
                            TlsSession.class.getDeclaredField("writerRecord");
                    writerField.setAccessible(true);
                    Object writerBefore = writerField.get(session);
                    StringBuilder received = new StringBuilder();
                    long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(TIMEOUT_MS);
                    // Две строки данных; KeyUpdate между ними read() обрабатывает сам
                    while (received.toString().split("\n").length < 2
                            || !received.toString().endsWith("\n")) {
                        if (System.nanoTime() > deadline) {
                            throw new IllegalStateException("Получено: " + received);
                        }
                        byte[] chunk = session.read();
                        received.append(new String(chunk, StandardCharsets.UTF_8));
                        session.write(("ECHO:" + new String(chunk, StandardCharsets.UTF_8))
                                .getBytes(StandardCharsets.UTF_8));
                    }
                    serverReceived.set(received.toString());
                    writerKeyChanged.set(writerField.get(session) != writerBefore);
                }
            } catch (Exception e) {
                serverError.set(e);
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        Thread.sleep(200);

        OpenSslTls13Helper.SClientEcho output = OpenSslTls13Helper.runSClientInteractive(
                port, SUITE_L, curve.ianaName,
                List.of("hello-before", "K", "hello-after"), 500,
                List.of("ECHO:hello-before", "ECHO:hello-after"), 15_000);
        serverThread.join(5000);
        String stdout = new String(output.stdout(), StandardCharsets.UTF_8);

        assertNull(serverError.get(),
                "Ошибка сервера: " + serverError.get() + "\nstderr s_client: " + output.stderr());
        // Сообщение о выполненной команде s_client печатает в stderr
        assertTrue(output.stderr().contains("KEYUPDATE"),
                "s_client должен выполнить команду K (иначе тест ничего не проверяет): "
                        + output.stderr());
        assertTrue(writerKeyChanged.get(),
                "Сервер должен ответить на KeyUpdate и сменить ключ записи");
        assertEquals("hello-before\nhello-after\n", serverReceived.get(),
                "Сервер должен получить обе строки по обе стороны KeyUpdate");
        assertTrue(stdout.contains("ECHO:hello-before") && stdout.contains("ECHO:hello-after"),
                "s_client должен расшифровать эхо до и после смены ключа: " + stdout);
    }

    @Test
    @DisplayName("сервер crypto-gost [GC512C] + s_client [GC256B]: выбор общей группы без HRR")
    void testServerGroupMismatch() throws Exception {
        runServerTest(SUITE_L, SUITE_L_ID, "GC256B", false, TlsConstants.GRP_GC512C);
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            SUITE_L + "; " + SUITE_L_ID + "; GC256B",
            SUITE_S + "; " + SUITE_S_ID + "; GC256B"
    })
    @DisplayName("s_server + клиент crypto-gost: handshake + GET -> статус")
    void testClientRoundtrip(String suiteName, int suiteId, String curveName) throws Exception {
        runClientTest(suiteName, suiteId, curveName);
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("s_server + клиент crypto-gost: все кривые (включая GC256A и GC512C с кофактором 4)")
    void testClientAllCurves(String curveName, int groupId) throws Exception {
        runClientTest(SUITE_L, SUITE_L_ID, curveName);
    }

    private void runServerTest(String suiteName, int suiteId, String curveName,
                               boolean mTls, int serverGroup) throws Exception {
        runServerTest(suiteName, suiteId, curveName, mTls, serverGroup, null);
    }

    private void runServerTest(String suiteName, int suiteId, String curveName,
                               boolean mTls, int serverGroup,
                                      AtomicReference<List<GostCertificate>> peerCerts) throws Exception {
        CurveSpec curve = findCurve(curveName);
        int port = OpenSslTls13Helper.findFreePort();

        if (mTls) {
            TempDirUtils.withTempDir("tls13-mtls-", tmpDir -> {
                // Серверный PFX: OpenSSL (проверка wire-формата)
                OpenSslTls13Helper.MtlsPkiResult pki = OpenSslTls13Helper.generateMtlsPKI(
                        tmpDir, curve.algo, curve.paramset);
                GostPkcs12Loader.Result r = GostPkcs12Loader.load(pki.serverPfx, pki.password, true);
                List<GostCertificate> chain = r.getCertificateChain();
                // GostPkcs12Loader уже возвращает List<GostCertificate>

                // Клиент: самоподписанный сертификат (обходит "ca md too weak" в OpenSSL 3.6.0)
                byte[] cliKu = new byte[]{(byte) 0x80}; // digitalSignature
                PkixCertTestHelper.CertBundle clientBundle = PkixCertTestHelper.createCertWithKey(
                        curve.params, "20240101120000Z", "21060101120000Z",
                        null, cliKu, new String[]{GostOids.EXT_CLIENT_AUTH}, null, new String[]{GostOids.POLICY_KC1});
                Path clientCertPem = tmpDir.resolve("client-cert.pem");
                Path clientKeyPem = tmpDir.resolve("client-key.pem");
                Files.writeString(clientCertPem, clientBundle.cert.toPem());
                Files.writeString(clientKeyPem,
                        OpenSslTls13Helper.privateKeyToPem(
                                GostDerCodec.encodePrivateKey(clientBundle.priv)));

                List<String> clientExtraArgs = List.of(
                        "-cert", clientCertPem.toString(),
                        "-key", clientKeyPem.toString(),
                        "-sigalgs", curve.sigalgsName);

                // Сервер доверяет клиентскому сертификату напрямую (самоподписанный)
                runServerTestInner(port, suiteId, curve, chain.get(0), r.getPrivateKey(),
                        clientBundle.cert, serverGroup, clientExtraArgs, peerCerts);
                return null;
            });
        } else {
            PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(curve.params);
            runServerTestInner(port, suiteId, curve, bundle.cert, bundle.priv,
                    null, serverGroup, List.of(), peerCerts);
        }
    }

    private void runServerTestInner(int port, int suiteId, CurveSpec curve,
                                     GostCertificate serverCert, PrivateKeyParameters serverPriv,
                                     GostCertificate caCert, int serverGroup,
                                     List<String> clientExtraArgs) throws Exception {
        runServerTestInner(port, suiteId, curve, serverCert, serverPriv, caCert,
                serverGroup, clientExtraArgs, null);
    }

    private void runServerTestInner(int port, int suiteId, CurveSpec curve,
                                     GostCertificate serverCert, PrivateKeyParameters serverPriv,
                                     GostCertificate caCert, int serverGroup,
                                     List<String> clientExtraArgs,
                                     AtomicReference<List<GostCertificate>> peerCerts) throws Exception {
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch handshakeDone = new CountDownLatch(1);

        Thread serverThread = startJavaServer(port, suiteId, curve, serverCert, serverPriv,
                caCert, serverGroup, serverError, handshakeDone, peerCerts);

        Thread.sleep(200);

        String clientOutput = OpenSslTls13Helper.runSClientWithHttpGet(port,
                suiteIdToName(suiteId), curve.ianaName, TIMEOUT_MS,
                clientExtraArgs.toArray(new String[0]));

        serverThread.join(5000);

        assertNull(serverError.get(), "Server error: " + serverError.get());
        assertTrue(clientOutput.contains("INTEROP_OK"),
                "s_client output должен содержать INTEROP_OK");
    }

    private void runServerPayloadTest(String suiteName, int suiteId, String curveName,
                                      int size) throws Exception {
        CurveSpec curve = findCurve(curveName);
        int port = OpenSslTls13Helper.findFreePort();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(curve.params);

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        AtomicReference<byte[]> serverReceived = new AtomicReference<>();

        Thread serverThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setSoTimeout(15000);
                try (Socket s = ss.accept();
                     SocketTlsTransport tp = new SocketTlsTransport(s);
                     TlsSession session = TlsSession.createServer(
                             new TlsServerConfig(TlsCiphersuite.byId(suiteId),
                                     Collections.singletonList(bundle.cert), bundle.priv), tp)) {
                    session.handshakeAsServer();
                    // Читаем все данные (могут быть фрагментированы в несколько TLS-записей)
                    ByteArrayOutputStream acc = new ByteArrayOutputStream(size);
                    long deadline = System.currentTimeMillis() +
                            (size >= 16_384 ? 60_000 : 10_000);
                    while (acc.size() < size && System.currentTimeMillis() < deadline) {
                        byte[] chunk = session.read();
                        if (chunk.length > 0) {
                            acc.write(chunk);
                        }
                    }
                    byte[] data = acc.toByteArray();
                    serverReceived.set(data);
                    session.write(data);
                }
            } catch (Exception e) {
                serverError.set(e);
            }
        });
        serverThread.start();
        Thread.sleep(200);

        byte[] payload = new byte[size];
        for (int i = 0; i < size; i++) {
            payload[i] = (byte) i;
        }

        // Для больших payload даём больше времени на передачу по TLS + echo.
        long timeout = size >= 16_384 ? 120_000 : TIMEOUT_MS;
        String clientOutput = OpenSslTls13Helper.runSClientWithData(port,
                suiteIdToName(suiteId), curve.ianaName, payload, timeout);

        serverThread.join(5000);

        assertNull(serverError.get(), "Server error: " + serverError.get());
        assertNotNull(serverReceived.get(), "Server должен получить данные");
        assertEquals(size, serverReceived.get().length,
                "Получено " + serverReceived.get().length + " байт, ожидалось " + size);
        assertArrayEquals(payload, serverReceived.get(),
                "Данные сервера должны совпадать с отправленными");
    }

    private void runClientTest(String suiteName, int suiteId, String curveName) throws Exception {
        CurveSpec curve = findCurve(curveName);
        int port = OpenSslTls13Helper.findFreePort();

        TempDirUtils.withTempDir("tls13-server-", tmpDir -> {
            OpenSslTls13Helper.generateGostCert(tmpDir, curve.algo, curve.paramset);

            Process sServer = OpenSslTls13Helper.startSServer(port,
                    suiteIdToName(suiteId), curve.ianaName,
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    "-sigalgs", curve.sigalgsName);

            try {
                boolean accepted = OpenSslTls13Helper.waitForString(sServer, "ACCEPT", 10_000);
                assertTrue(accepted, "s_server не запустился");

                GostCertificate srvCert = GostCertificate.fromPemOrDer(Files.readAllBytes(tmpDir.resolve("cert.pem")));

                try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port);
                     SocketTlsTransport tp = new SocketTlsTransport(socket);
                     TlsSession client = TlsSession.createClient(
                             new TlsClientConfig(
                                     TlsCiphersuite.byId(suiteId),
                                     TrustAnchors.ofCertificate(srvCert)).withoutHostnameVerification(), tp)) {
                    client.handshakeAsClient();
                    client.write("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".getBytes(StandardCharsets.UTF_8));
                    byte[] response = client.read();

                    String respStr = new String(response, StandardCharsets.UTF_8);
                    assertTrue(respStr.contains("TLS") || respStr.contains("HTTP"),
                            "Ответ s_server должен содержать информацию о соединении");
                }
            } finally {
                OpenSslTls13Helper.destroyProcess(sServer);
            }
            return null;
        });
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static CurveSpec findCurve(String name) {
        return ALL_CURVES.stream()
                .filter(c -> c.ianaName.equals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown curve: " + name));
    }

    private static String suiteIdToName(int id) {
        return id == SUITE_L_ID ? SUITE_L : SUITE_S;
    }

    /**
     * Транспорт с таймаутом чтения на принятом сокете: {@code setSoTimeout} серверного сокета
     * действует только на {@code accept()}, и замерший {@code s_client} иначе подвесил бы поток
     * сервера навсегда.
     */
    private static SocketTlsTransport newTimedTransport(Socket socket) throws Exception {
        socket.setSoTimeout((int) TIMEOUT_MS);
        return new SocketTlsTransport(socket);
    }

    private static int suiteNameToId(String name) {
        if (SUITE_L.equals(name)) return SUITE_L_ID;
        if (SUITE_S.equals(name)) return SUITE_S_ID;
        // Опечатка в источнике параметров не должна молча подменять проверяемый набор
        throw new IllegalArgumentException("Неизвестный набор шифров: " + name);
    }

    private static Thread startJavaServer(int port, int suiteId, CurveSpec curve,
                                            GostCertificate cert, PrivateKeyParameters priv,
                                            GostCertificate caCert, int serverGroup,
                                            AtomicReference<Throwable> errorRef,
                                            CountDownLatch handshakeDone) {
        return startJavaServer(port, suiteId, curve, cert, priv, caCert, serverGroup,
                errorRef, handshakeDone, null);
    }

    private static Thread startJavaServer(int port, int suiteId, CurveSpec curve,
                                             GostCertificate cert, PrivateKeyParameters priv,
                                             GostCertificate caCert, int serverGroup,
                                             AtomicReference<Throwable> errorRef,
                                             CountDownLatch handshakeDone,
                                             AtomicReference<List<GostCertificate>> peerCerts) {
        Thread t = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setSoTimeout(15000);
                try (Socket s = ss.accept();
                     SocketTlsTransport tp = new SocketTlsTransport(s)) {

                    TlsServerConfig config = new TlsServerConfig(
                            TlsCiphersuite.byId(suiteId),
                            Collections.singletonList(cert), priv);
                    if (caCert != null) {
                        config.needClientAuth(TrustAnchors.ofCertificate(caCert));
                    }
                    if (serverGroup != 0) {
                        config.withSelectedNamedGroup(serverGroup);
                    }

                    try (TlsSession session = TlsSession.createServer(config, tp)) {
                        session.handshakeAsServer();
                        handshakeDone.countDown();

                        if (peerCerts != null) {
                            peerCerts.set(session.getPeerCertificates());
                        }

                        byte[] req = session.read();
                        String reqStr = new String(req, StandardCharsets.UTF_8);
                        if (reqStr.contains("GET")) {
                            String resp = "HTTP/1.1 200 OK\r\n"
                                    + "Content-Type: text/plain\r\n"
                                    + "Content-Length: 10\r\n"
                                    + "Connection: close\r\n"
                                    + "\r\n"
                                    + "INTEROP_OK";
                            session.write(resp.getBytes(StandardCharsets.UTF_8));
                        }
                    }
                }
            } catch (Exception e) {
                errorRef.set(e);
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    /**
     * Запускает Java-сервер с OID-фильтрами для проверки wire-формата oid_filters.
     */
    private static void startJavaServerWithOidFilters(int port, int suiteId, CurveSpec curve,
                                                       GostCertificate cert, PrivateKeyParameters priv,
                                                       List<OIDFilter> oidFilters,
                                                       GostCertificate clientCaCert) {
        new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setSoTimeout(15000);
                try (Socket s = ss.accept();
                     SocketTlsTransport tp = new SocketTlsTransport(s)) {

                    TlsServerConfig config = new TlsServerConfig(
                            TlsCiphersuite.byId(suiteId),
                            Collections.singletonList(cert), priv);
                    // Включаем mTLS (иначе CertificateRequest не отправляется)
                    config.needClientAuth(TrustAnchors.ofCertificate(clientCaCert));
                    // Добавляем OID-фильтры для отправки в CertificateRequest
                    config.withOidFilters(oidFilters);

                    try (TlsSession session = TlsSession.createServer(config, tp)) {
                        session.handshakeAsServer();
                        byte[] req = session.read();
                        String reqStr = new String(req, StandardCharsets.UTF_8);
                        if (reqStr.contains("GET")) {
                            String resp = "HTTP/1.1 200 OK\r\n"
                                    + "Content-Type: text/plain\r\n"
                                    + "Content-Length: 10\r\n"
                                    + "Connection: close\r\n"
                                    + "\r\n"
                                    + "INTEROP_OK";
                            session.write(resp.getBytes(StandardCharsets.UTF_8));
                        }
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, "java-server-oidf").start();
    }

    /** Содержимое OID (без тега и длины) по точечной записи. */
    private static byte[] oidContent(String dotted) {
        byte[] tlv = org.rssys.gost.util.DerCodec.encodeOid(dotted);
        // длина может занимать несколько байтов: начало содержимого берётся из decodeLength
        int contentStart = 1 + org.rssys.gost.util.DerCodec.decodeLength(tlv, 1)[1];
        return java.util.Arrays.copyOfRange(tlv, contentStart, tlv.length);
    }

    /**
     * Строит DER-кодированное значение для EKU фильтра: SEQUENCE { OID }.
     * oidBytes — OID value (без тега/длины), например содержимое OID класса КС1.
     */
    private static byte[] buildEkuFilterValues(byte[] oidBytes) {
        byte[] oidTlv = new byte[2 + oidBytes.length];
        oidTlv[0] = 0x06; // TAG_OID
        oidTlv[1] = (byte) oidBytes.length;
        System.arraycopy(oidBytes, 0, oidTlv, 2, oidBytes.length);
        byte[] seq = new byte[2 + oidTlv.length];
        seq[0] = 0x30; // TAG_SEQUENCE
        seq[1] = (byte) oidTlv.length;
        System.arraycopy(oidTlv, 0, seq, 2, oidTlv.length);
        return seq;
    }
}
