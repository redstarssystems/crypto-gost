package org.rssys.gost.crossval.tls13;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.crossval.util.TempDirUtils;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.cert.GostPkcs12Loader;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.cert.TlsDerParser;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.config.OIDFilter;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("TLS 1.3: кросс-валидация crypto-gost ↔ OpenSSL")
class OpenSslTls13CrossValidationTest {

    private static final String SUITE_L = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    private static final String SUITE_S = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S";
    private static final int SUITE_L_ID = 0xC103;
    private static final int SUITE_S_ID = 0xC105;
    private static final long TIMEOUT_MS = 30_000;

    record CurveSpec(String ianaName, int groupId, ECParameters params, String algo, String paramset, String sigalgsName) {}

    // OpenSSL paramset:A для gost2012_256 ≡ CryptoPro-A ≡ GRP_GC256B (0x0023).
    // Для 512-бит маппинг прямой: paramset A/B ≡ TC26-512A/B.
    static final List<CurveSpec> ALL_CURVES = List.of(
            new CurveSpec("GC256B", TlsConstants.GRP_GC256B, ECParameters.cryptoProA(), "gost2012_256", "A", "gostr34102012_256b"),
            new CurveSpec("GC512A", TlsConstants.GRP_GC512A, ECParameters.tc26a512(), "gost2012_512", "A", "gostr34102012_512a"),
            new CurveSpec("GC512B", TlsConstants.GRP_GC512B, ECParameters.tc26b512(), "gost2012_512", "B", "gostr34102012_512b")
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
    @DisplayName("сервер crypto-gost + s_client: handshake + GET → INTEROP_OK")
    void testServerRoundtrip(String suiteName, int suiteId, String curveName) throws Exception {
        runServerTest(suiteName, suiteId, curveName, false, 0);
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("сервер crypto-gost + s_client: все кривые (GC256B..GC512B)")
    void testServerAllCurves(String curveName, int groupId) throws Exception {
        // OpenSSL gostprov не включает GC512A/GC512B в key_share начального ClientHello,
        // из-за чего crypto-gost сервер отправляет HRR — gostprov его не осиливает.
        Assumptions.assumeTrue(groupId == TlsConstants.GRP_GC256B,
                "GC512 не поддерживает HRR при тестах с s_server/gostprov");
        runServerTest(SUITE_L, SUITE_L_ID, curveName, false, 0);
    }

    @Test
    @DisplayName("сервер crypto-gost + s_client: oid_filters (wire-формат)")
    void testServerOidFilters() throws Exception {
        CurveSpec curve = findCurve("GC256B");
        int port = OpenSslTls13Helper.findFreePort();

        TempDirUtils.withTempDir("tls13-oidf-", tmpDir -> {
            TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(curve.params);

            // Клиентский сертификат Java API с УКЭП EKU
            TlsTestHelper.CertBundle clientBundle = TlsTestHelper.createCertWithKey(
                    curve.params, "20240101120000Z", "21060101120000Z",
                    null, new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_CLIENT_AUTH, GostOids.EKU_UKEP});
            Path clientCertPem = tmpDir.resolve("client-cert.pem");
            Path clientKeyPem = tmpDir.resolve("client-key.pem");
            Files.writeString(clientCertPem, clientBundle.cert.toPem());
            Files.writeString(clientKeyPem,
                    OpenSslTls13Helper.privateKeyToPem(
                            GostDerCodec.encodePrivateKey(clientBundle.priv)));

            // OID filter: УКЭП (filterOid = EKU 2.5.29.37, value = { 1.2.643.100.113.1 })
            byte[] ukepFilterValues = buildEkuFilterValues(TlsDerParser.UKEP_OID_BYTES);
            OIDFilter ukepFilter = new OIDFilter(TlsDerParser.EKU_OID_BYTES, ukepFilterValues);
            List<OIDFilter> filters = Collections.singletonList(ukepFilter);

            startJavaServerWithOidFilters(port, SUITE_L_ID, curve, bundle.cert, bundle.priv,
                    filters, clientBundle.cert.getPublicKey());

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
    @DisplayName("сервер crypto-gost + s_client: mTLS (взаимная аутентификация)")
    void testServerMtls() throws Exception {
        AtomicReference<List<TlsCertificate>> peerCerts = new AtomicReference<>();
        runServerTest(SUITE_L, SUITE_L_ID, "GC256B", true, 0, peerCerts);
        // Проверяем что сертификат клиента удовлетворяет УКЭП фильтру
        List<TlsCertificate> certs = peerCerts.get();
        assertNotNull(certs, "Должен быть peer-сертификат");
        assertFalse(certs.isEmpty(), "Peer-сертификаты не пусты");
        byte[] ukepFilterValues = buildEkuFilterValues(TlsDerParser.UKEP_OID_BYTES);
        OIDFilter ukepFilter = new OIDFilter(TlsDerParser.EKU_OID_BYTES, ukepFilterValues);
        assertTrue(certs.get(0).matchesOidFilter(ukepFilter),
                "Клиентский сертификат должен удовлетворять УКЭП фильтру");
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 15, 16, 1024, 12_000, 16_383, 16_384, 16_385, 32_768})
    @DisplayName("сервер crypto-gost + s_client: размеры payload (TLSTREE re-keying)")
    void testServerPayload(int size) throws Exception {
        runServerPayloadTest(SUITE_L, SUITE_L_ID, "GC256B", size);
    }

    @Test
    @Disabled("OpenSSL gostprov не поддерживает HRR, необходимый для fallback группы")
    @DisplayName("сервер crypto-gost [GC512C] + s_client [GC256B]: fallback группы")
    void testServerGroupMismatch() throws Exception {
        runServerTest(SUITE_L, SUITE_L_ID, "GC256B", false, TlsConstants.GRP_GC512C);
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            SUITE_L + "; " + SUITE_L_ID + "; GC256B",
            SUITE_S + "; " + SUITE_S_ID + "; GC256B"
    })
    @DisplayName("s_server + клиент crypto-gost: handshake + GET → статус")
    void testClientRoundtrip(String suiteName, int suiteId, String curveName) throws Exception {
        runClientTest(suiteName, suiteId, curveName);
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("s_server + клиент crypto-gost: все кривые (GC256B..GC512B)")
    void testClientAllCurves(String curveName, int groupId) throws Exception {
        runClientTest(SUITE_L, SUITE_L_ID, curveName);
    }

    private void runServerTest(String suiteName, int suiteId, String curveName,
                               boolean mTls, int serverGroup) throws Exception {
        runServerTest(suiteName, suiteId, curveName, mTls, serverGroup, null);
    }

    private void runServerTest(String suiteName, int suiteId, String curveName,
                               boolean mTls, int serverGroup,
                               AtomicReference<List<TlsCertificate>> peerCerts) throws Exception {
        CurveSpec curve = findCurve(curveName);
        int port = OpenSslTls13Helper.findFreePort();

        if (mTls) {
            TempDirUtils.withTempDir("tls13-mtls-", tmpDir -> {
                // Серверный PFX: OpenSSL (проверка wire-формата)
                OpenSslTls13Helper.MtlsPkiResult pki = OpenSslTls13Helper.generateMtlsPKI(
                        tmpDir, curve.algo, curve.paramset);
                GostPkcs12Loader.Result r = GostPkcs12Loader.load(pki.serverPfx, pki.password);
                List<TlsCertificate> chain = r.getCertificateChain();

                // Клиент: самоподписанный сертификат (обходит "ca md too weak" в OpenSSL 3.6.0)
                byte[] cliKu = new byte[]{(byte) 0x80}; // digitalSignature
                TlsTestHelper.CertBundle clientBundle = TlsTestHelper.createCertWithKey(
                        curve.params, "20240101120000Z", "21060101120000Z",
                        null, cliKu, new String[]{GostOids.EXT_CLIENT_AUTH, GostOids.EKU_UKEP});
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
                        clientBundle.cert.getPublicKey(), serverGroup, clientExtraArgs, peerCerts);
                return null;
            });
        } else {
            TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(curve.params);
            runServerTestInner(port, suiteId, curve, bundle.cert, bundle.priv,
                    null, serverGroup, List.of(), peerCerts);
        }
    }

    private void runServerTestInner(int port, int suiteId, CurveSpec curve,
                                     TlsCertificate serverCert, PrivateKeyParameters serverPriv,
                                     PublicKeyParameters caPub, int serverGroup,
                                     List<String> clientExtraArgs) throws Exception {
        runServerTestInner(port, suiteId, curve, serverCert, serverPriv, caPub,
                serverGroup, clientExtraArgs, null);
    }

    private void runServerTestInner(int port, int suiteId, CurveSpec curve,
                                     TlsCertificate serverCert, PrivateKeyParameters serverPriv,
                                     PublicKeyParameters caPub, int serverGroup,
                                     List<String> clientExtraArgs,
                                     AtomicReference<List<TlsCertificate>> peerCerts) throws Exception {
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch handshakeDone = new CountDownLatch(1);

        Thread serverThread = startJavaServer(port, suiteId, curve, serverCert, serverPriv,
                caPub, serverGroup, serverError, handshakeDone, peerCerts);

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
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(curve.params);

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

                try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port);
                     SocketTlsTransport tp = new SocketTlsTransport(socket);
                     TlsSession client = TlsSession.createClient(
                             new TlsClientConfig(TlsCiphersuite.byId(suiteId)), tp)) {
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

    private static Thread startJavaServer(int port, int suiteId, CurveSpec curve,
                                            TlsCertificate cert, PrivateKeyParameters priv,
                                            PublicKeyParameters caPub, int serverGroup,
                                            AtomicReference<Throwable> errorRef,
                                            CountDownLatch handshakeDone) {
        return startJavaServer(port, suiteId, curve, cert, priv, caPub, serverGroup,
                errorRef, handshakeDone, null);
    }

    private static Thread startJavaServer(int port, int suiteId, CurveSpec curve,
                                            TlsCertificate cert, PrivateKeyParameters priv,
                                            PublicKeyParameters caPub, int serverGroup,
                                            AtomicReference<Throwable> errorRef,
                                            CountDownLatch handshakeDone,
                                            AtomicReference<List<TlsCertificate>> peerCerts) {
        Thread t = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setSoTimeout(15000);
                try (Socket s = ss.accept();
                     SocketTlsTransport tp = new SocketTlsTransport(s)) {

                    TlsServerConfig config = new TlsServerConfig(
                            TlsCiphersuite.byId(suiteId),
                            Collections.singletonList(cert), priv);
                    if (caPub != null) {
                        config.withCaPublicKey(caPub);
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
                                                       TlsCertificate cert, PrivateKeyParameters priv,
                                                       List<OIDFilter> oidFilters,
                                                       PublicKeyParameters caPubKey) {
        new Thread(() -> {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setSoTimeout(15000);
                try (Socket s = ss.accept();
                     SocketTlsTransport tp = new SocketTlsTransport(s)) {

                    TlsServerConfig config = new TlsServerConfig(
                            TlsCiphersuite.byId(suiteId),
                            Collections.singletonList(cert), priv);
                    // Включаем mTLS (иначе CertificateRequest не отправляется)
                    config.withCaPublicKey(caPubKey);
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

    /**
     * Строит DER-кодированное значение для EKU фильтра: SEQUENCE { OID }.
     * oidBytes — OID value (без тега/длины), например UKEP_OID_BYTES.
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
