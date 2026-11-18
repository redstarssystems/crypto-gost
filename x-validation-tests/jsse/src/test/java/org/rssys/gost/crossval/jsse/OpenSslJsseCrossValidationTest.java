package org.rssys.gost.crossval.jsse;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
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
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.socket.GostSSLServerSocket;
import org.rssys.gost.jsse.socket.GostSSLSocket;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.config.ClientOcspPolicy;

@DisplayName("JSSE: кросс-валидация crypto-gost JSSE <-> OpenSSL")
class OpenSslJsseCrossValidationTest {

    private static final String SUITE_L = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L";
    private static final String SUITE_S = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S";
    private static final int SUITE_L_ID = 0xC103;
    private static final int SUITE_S_ID = 0xC105;
    private static final long TIMEOUT_MS = 30_000;
    private static final int HANDSHAKE_TIMEOUT_SEC = 15;

    private static TlsCiphersuite csL;
    private static GostSSLSessionContext sessionContext;

    record CurveSpec(String ianaName, int groupId, ECParameters params,
                      String algo, String paramset, String sigalgsName) {}

    // GC256A и GC512C имеют кофактор 4: ECDHE на них считается как (h·d)·Q (RFC 9367 §6.1.1)
    // Порядок важен: mTLS-тесты берут ALL_CURVES.get(0) (GC256B)
    static final List<CurveSpec> ALL_CURVES = List.of(
            new CurveSpec("GC256B", TlsConstants.GRP_GC256B, ECParameters.cryptoProA(),
                    "gost2012_256", "A", "gostr34102012_256b"),
            new CurveSpec("GC512A", TlsConstants.GRP_GC512A, ECParameters.tc26a512(),
                    "gost2012_512", "A", "gostr34102012_512a"),
            new CurveSpec("GC512B", TlsConstants.GRP_GC512B, ECParameters.tc26b512(),
                    "gost2012_512", "B", "gostr34102012_512b"),
            new CurveSpec("GC256A", TlsConstants.GRP_GC256A, ECParameters.tc26a256(),
                    "gost2012_256", "TCA", "gostr34102012_256a"),
            new CurveSpec("GC512C", TlsConstants.GRP_GC512C, ECParameters.tc26c512(),
                    "gost2012_512", "C", "gostr34102012_512c")
    );

    @BeforeAll
    static void preconditions() {
        Security.addProvider(new RssysGostJsseProvider());
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslJsseHelper.assumeGostTls13();
        csL = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        sessionContext = new GostSSLSessionContext(csL);
    }

    static Stream<Arguments> allCurves() {
        return ALL_CURVES.stream().map(c -> Arguments.of(c.ianaName, c.groupId));
    }

    /* ========================================================================
     * Engine-сервер + s_client
     * ======================================================================== */

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            SUITE_L + "; " + SUITE_L_ID + "; GC256B",
            SUITE_S + "; " + SUITE_S_ID + "; GC256B"
    })
    @DisplayName("Engine-сервер + s_client: handshake + GET \u2192 INTEROP_OK")
    void testEngineServerRoundtrip(String suiteName, int suiteId, String curveName) throws Exception {
        runEngineServerTest(suiteId, curveName, false, 0, false);
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("Engine-сервер + s_client: все кривые (включая GC256A и GC512C с кофактором 4)")
    void testEngineServerAllCurves(String curveName, int groupId) throws Exception {
        runEngineServerTest(SUITE_L_ID, curveName, false, groupId, false);
    }

    @Test
    @DisplayName("Engine-сервер + s_client с чужой схемой подписи: приложение получает настоящий код alert")
    void testEngineServerSeesAlertFromClientWithOtherScheme() throws Exception {
        // Сервер подписывает схемой своей кривой GC256B, а s_client предлагает только схему GC256A
        // и сам отвергает подпись. Alert клиент шлёт открытой записью, пока ключ записи рукопожатия
        // у него не включён: движок обязан принять его и отдать приложению код, а не ошибку разбора
        CurveSpec certCurve = findCurve("GC256B");
        CurveSpec clientCurve = findCurve("GC256A");

        OpenSslJsseHelper.ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(certCurve.params);
        GostX509KeyManager km = OpenSslJsseHelper.createKeyManager(
                pki.cert(), pki.caCert(), pki.priv());
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverReady = new CountDownLatch(1);
        int[] portOut = new int[1];
        Thread serverThread = startEngineServer(km, null,
                serverError, serverReady, false, false, portOut, 0, null);
        assertTrue(serverReady.await(HANDSHAKE_TIMEOUT_SEC, TimeUnit.SECONDS),
                "Engine-сервер не запустился");

        String clientOutput = OpenSslJsseHelper.runSClientWithHttpGet(
                portOut[0], SUITE_L, certCurve.ianaName, TIMEOUT_MS,
                "-sigalgs", clientCurve.sigalgsName());
        serverThread.join(10_000);

        assertFalse(clientOutput.contains("INTEROP_OK"),
                "s_client не должен пройти рукопожатие: " + clientOutput);
        Throwable error = serverError.get();
        assertInstanceOf(javax.net.ssl.SSLHandshakeException.class, error,
                "Сервер должен получить исключение рукопожатия с кодом alert клиента: " + error
                        + "; вывод клиента: " + clientOutput);
        // Код 40 на неподходящую схему подписи - особенность сборки OpenSSL 3.6.0-gost, а не
        // требование RFC. "from peer" отличает alert, полученный от s_client, от отказа, который
        // сервер сам назвал бы handshake_failure: без этого проверка прошла бы и на подмене кода
        assertTrue(error.getMessage().contains("alert "
                        + (TlsConstants.ALERT_HANDSHAKE_FAILURE & 0xFF) + " from peer"),
                "Приложение должно увидеть настоящий код alert пира: " + error.getMessage());
    }

    @Test
    @DisplayName("Engine-сервер + s_client -tls1_2: клиент без supported_versions получает protocol_version")
    void testEngineServerRejectsTls12ClientWithProtocolVersion() throws Exception {
        // Клиент TLS 1.2 не шлёт supported_versions; сервер, умеющий только TLS 1.3, обязан ответить
        // protocol_version (RFC 8446 §4.2.1, §6.2), а не missing_extension
        CurveSpec curve = findCurve("GC256B");
        OpenSslJsseHelper.ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(curve.params);
        GostX509KeyManager km = OpenSslJsseHelper.createKeyManager(
                pki.cert(), pki.caCert(), pki.priv());
        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverReady = new CountDownLatch(1);
        int[] portOut = new int[1];
        Thread serverThread = startEngineServer(km, null,
                serverError, serverReady, false, false, portOut, 0, null);
        assertTrue(serverReady.await(HANDSHAKE_TIMEOUT_SEC, TimeUnit.SECONDS),
                "Engine-сервер не запустился");

        String clientOutput = OpenSslJsseHelper.runSClientTls12(portOut[0], TIMEOUT_MS);
        serverThread.join(10_000);

        Throwable error = serverError.get();
        assertInstanceOf(javax.net.ssl.SSLHandshakeException.class, error,
                "Сервер должен отвергнуть клиента TLS 1.2: " + error);
        // Причина на стороне сервера названа точно: ClientHello без supported_versions
        assertTrue(error.getMessage().contains("supported_versions"),
                "Сервер должен назвать причину отказа: " + error.getMessage());
        // Код alert, который увидел s_client (OpenSSL печатает "SSL alert number N"): 70 = protocol_version
        assertTrue(clientOutput.contains("alert number "
                        + (TlsConstants.ALERT_PROTOCOL_VERSION & 0xFF)),
                "s_client должен получить protocol_version (70): " + clientOutput);
    }

    @Test
    @DisplayName("Engine-сервер + s_client: mTLS (взаимная аутентификация)")
    void testEngineServerMtls() throws Exception {
        runEngineServerMtlsTest(ClientOcspPolicy.OFF);
    }

    @Test
    @DisplayName("Engine-сервер [REQUEST] + s_client: status_request в CertificateRequest терпим для OpenSSL")
    void testEngineServerMtlsClientOcspRequest() throws Exception {
        runEngineServerMtlsTest(ClientOcspPolicy.REQUEST);
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 15, 16, 1024, 12_000, 16_383, 16_384, 16_385, 32_768})
    @DisplayName("Engine-сервер + s_client: размеры payload")
    void testEngineServerPayload(int size) throws Exception {
        runEngineServerPayloadTest(SUITE_L_ID, "GC256B", size);
    }

    @Test
    @DisplayName("Engine-сервер [GC512C] + s_client [GC256B]: выбор общей группы без HRR")
    void testEngineServerGroupMismatch() throws Exception {
        runEngineServerTest(SUITE_L_ID, "GC256B", false, TlsConstants.GRP_GC512C, false);
    }

    @Test
    @DisplayName("Engine-сервер + s_client: KeyUpdate после handshake")
    void testEngineServerKeyUpdate() throws Exception {
        runEngineServerTest(SUITE_L_ID, "GC256B", false, 0, true);
    }

    @Test
    @DisplayName("Engine-сервер с sessionContext + s_client: NST отправляется, close_notify корректен")
    void testEngineServerWithSessionContext() throws Exception {
        GostSSLSessionContext sessCtx = new GostSSLSessionContext(csL);
        CurveSpec curve = ALL_CURVES.get(0);
        int suiteId = SUITE_L_ID;

        OpenSslJsseHelper.ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(curve.params);
        GostX509KeyManager km = OpenSslJsseHelper.createKeyManager(
                pki.cert(), pki.caCert(), pki.priv());

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverReady = new CountDownLatch(1);
        int[] portOut = new int[1];

        Thread serverThread = startEngineServer(km, null,
                serverError, serverReady, false, false, portOut, 0, sessCtx);

        assertTrue(serverReady.await(HANDSHAKE_TIMEOUT_SEC, TimeUnit.SECONDS),
                "Engine-сервер не запустился за " + HANDSHAKE_TIMEOUT_SEC + "c");
        int port = portOut[0];

        String clientOutput = OpenSslJsseHelper.runSClientWithHttpGet(
                port, suiteIdToName(suiteId), curve.ianaName, TIMEOUT_MS);

        serverThread.join(5000);

        assertNull(serverError.get(), "Server error: " + serverError.get());
        assertTrue(clientOutput.contains("INTEROP_OK"),
                "s_client output должен содержать INTEROP_OK");
    }

    /* ========================================================================
     * Engine-клиент + s_server
     * ======================================================================== */

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            SUITE_L + "; " + SUITE_L_ID + "; GC256B",
            SUITE_S + "; " + SUITE_S_ID + "; GC256B"
    })
    @DisplayName("s_server + Engine-клиент: handshake + GET \u2192 ответ")
    void testEngineClientRoundtrip(String suiteName, int suiteId, String curveName) throws Exception {
        runEngineClientTest(suiteId, curveName);
    }

    @ParameterizedTest
    @MethodSource("allCurves")
    @DisplayName("s_server + Engine-клиент: все кривые (включая GC256A и GC512C с кофактором 4)")
    void testEngineClientAllCurves(String curveName, int groupId) throws Exception {
        runEngineClientTest(SUITE_L_ID, curveName);
    }

    @Test
    @DisplayName("Dual-engine по TCP: клиент GC256A \u2192 сервер GC512C \u2192 HRR \u2192 handshake")
    void testEngineClientHrr() throws Exception {
        // Два GostSSLEngine через реальный TCP. Клиент шлёт key_share=GC256A,
        // сервер предпочитает GC512C — несовпадение -> сервер отправляет HRR.
        // Проверяет сериализацию/десериализацию HRR-фреймов через реальный
        // транспорт (не in-memory, как в unit-тестах TlsHandshakeEngineTest).
        runEngineTcpHrrTest();
    }

    /* ========================================================================
     * Socket-сервер (GostSSLServerSocket) + s_client
     * ======================================================================== */

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            SUITE_L + "; " + SUITE_L_ID + "; GC256B",
            SUITE_S + "; " + SUITE_S_ID + "; GC256B"
    })
    @DisplayName("Socket-сервер (GostSSLServerSocket) + s_client: handshake + GET \u2192 INTEROP_OK")
    void testSocketServerRoundtrip(String suiteName, int suiteId, String curveName) throws Exception {
        runSocketServerTest(suiteId, curveName, false);
    }

    @Test
    @DisplayName("Socket-сервер (GostSSLServerSocket) + s_client: mTLS")
    void testSocketServerMtls() throws Exception {
        runSocketServerTest(SUITE_L_ID, "GC256B", true);
    }

    /* ========================================================================
     * Socket-клиент (GostSSLSocket) + s_server
     * ======================================================================== */

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
            SUITE_L + "; " + SUITE_L_ID + "; GC256B",
            SUITE_S + "; " + SUITE_S_ID + "; GC256B"
    })
    @DisplayName("s_server + Socket-клиент (GostSSLSocket): handshake + GET \u2192 ответ")
    void testSocketClientRoundtrip(String suiteName, int suiteId, String curveName) throws Exception {
        runSocketClientTest(suiteId, curveName);
    }

    /* ========================================================================
     * Реализация тестов
     * ======================================================================== */

    private static CurveSpec findCurve(String name) {
        return ALL_CURVES.stream()
                .filter(c -> c.ianaName.equals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown curve: " + name));
    }

    private static String suiteIdToName(int id) {
        return id == SUITE_L_ID ? SUITE_L : SUITE_S;
    }

    /* ---- Engine-сервер ---- */

    private void runEngineServerTest(int suiteId, String curveName,
                                      boolean mtls, int serverGroup,
                                      boolean keyUpdate) throws Exception {
        CurveSpec curve = findCurve(curveName);

        OpenSslJsseHelper.ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(curve.params);
        GostX509KeyManager km = OpenSslJsseHelper.createKeyManager(
                pki.cert(), pki.caCert(), pki.priv());

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverReady = new CountDownLatch(1);
        int[] portOut = new int[1];

        Thread serverThread = startEngineServer(km, null,
                serverError, serverReady, false, keyUpdate, portOut, serverGroup, null);

        assertTrue(serverReady.await(HANDSHAKE_TIMEOUT_SEC, TimeUnit.SECONDS),
                "Engine-сервер не запустился за " + HANDSHAKE_TIMEOUT_SEC + "c");
        int port = portOut[0];

        String clientOutput = OpenSslJsseHelper.runSClientWithHttpGet(
                port, suiteIdToName(suiteId), curve.ianaName, TIMEOUT_MS);

        serverThread.join(5000);

        assertNull(serverError.get(), "Server error: " + serverError.get());
        assertTrue(clientOutput.contains("INTEROP_OK"),
                "s_client output должен содержать INTEROP_OK");
    }

    @Test
    @DisplayName("Engine-сервер + s_client с недоверенным сертификатом: s_client получает unknown_ca")
    void testEngineServerRejectsUntrustedClientCertificateAlertReachesClient() throws Exception {
        // Сервер отказывает клиентскому сертификату уже после своего Finished, поэтому alert
        // защищён ключом приложения (RFC 8446 §4.4.4): s_client, отправивший свой Finished, читает
        // им же. Защита ключом рукопожатия дала бы у s_client ошибку расшифровки вместо кода
        TempDirUtils.withTempDir("jsse-engine-mtls-reject-", tmpDir -> {
            CurveSpec curve = ALL_CURVES.get(0);
            OpenSslJsseHelper.ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(curve.params);
            PkixCertTestHelper.CertBundle clientBundle = PkixCertTestHelper.createCertWithKey(
                    curve.params, "20240101120000Z", "21060101120000Z",
                    null, new byte[]{(byte) 0x80}, new String[]{"1.3.6.1.5.5.7.3.2"});
            Path clientCertPem = tmpDir.resolve("client-cert.pem");
            Path clientKeyPem = tmpDir.resolve("client-key.pem");
            Files.writeString(clientCertPem, clientBundle.cert.toPem());
            Files.writeString(clientKeyPem,
                    OpenSslJsseHelper.privateKeyToPem(
                            GostDerCodec.encodePrivateKey(clientBundle.priv)));
            GostX509KeyManager km = OpenSslJsseHelper.createKeyManager(
                    pki.cert(), pki.caCert(), pki.priv());

            AtomicReference<Throwable> serverError = new AtomicReference<>();
            CountDownLatch serverReady = new CountDownLatch(1);
            int[] portOut = new int[1];
            // Сервер доверяет только своему УЦ, клиентский сертификат самоподписан
            Thread serverThread = startEngineServer(km, pki.caCert(),
                    serverError, serverReady, true, false, portOut, 0, null);
            assertTrue(serverReady.await(HANDSHAKE_TIMEOUT_SEC, TimeUnit.SECONDS));

            String clientOutput = OpenSslJsseHelper.runSClientWithHttpGet(
                    portOut[0], SUITE_L, curve.ianaName, TIMEOUT_MS,
                    "-cert", clientCertPem.toString(), "-key", clientKeyPem.toString(),
                    "-sigalgs", curve.sigalgsName());
            serverThread.join(10_000);

            assertInstanceOf(javax.net.ssl.SSLHandshakeException.class, serverError.get(),
                    "Сервер должен отвергнуть сертификат клиента: " + serverError.get());
            assertFalse(clientOutput.contains("INTEROP_OK"), clientOutput);
            assertTrue(clientOutput.contains("alert number "
                            + (TlsConstants.ALERT_UNKNOWN_CA & 0xFF)),
                    "s_client должен получить unknown_ca (48), а не ошибку расшифровки: "
                            + clientOutput);
            return null;
        });
    }

    @Test
    @DisplayName("s_server -Verify отвергает сертификат Engine-клиента: клиент получает код alert")
    void testEngineClientSeesAlertWhenServerRejectsCertificate() throws Exception {
        // s_server отказывает после своего Finished ключом приложения; клиент, принявший Finished
        // сервера, обязан читать этим ключом и отдать приложению настоящий код alert
        CurveSpec curve = findCurve("GC256B");
        int port = OpenSslJsseHelper.findFreePort();
        OpenSslJsseHelper.ServerPkiBundle clientPki =
                OpenSslJsseHelper.createServerPki(curve.params);
        GostX509KeyManager clientKm = OpenSslJsseHelper.createKeyManager(
                clientPki.cert(), clientPki.caCert(), clientPki.priv());

        TempDirUtils.withTempDir("jsse-engine-client-reject-", tmpDir -> {
            OpenSslJsseHelper.generateGostCert(tmpDir, curve.algo, curve.paramset);
            // Доверие s_server - только его собственному сертификату: УЦ клиента ему неизвестен
            Process sServer = OpenSslJsseHelper.startSServer(port,
                    SUITE_L, curve.ianaName,
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    "-sigalgs", curve.sigalgsName(),
                    "-Verify", "1", "-CAfile", tmpDir.resolve("cert.pem").toString(),
                    // Без списка УЦ в CertificateRequest клиент предъявляет свой сертификат, и
                    // s_server отвергает именно его, а не пустой Certificate (certificate_required)
                    "-no_ca_names",
                    // Без этого флага s_server лишь печатает ошибку проверки и продолжает
                    "-verify_return_error");
            try {
                assertTrue(OpenSslJsseHelper.waitForString(sServer, "ACCEPT", 10_000),
                        "s_server не запустился");
                try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port)) {
                    socket.setSoTimeout(15_000);
                    // Клиент доверяет серверу, сервер клиенту - нет
                    GostSSLEngine clientEngine = new GostSSLEngine(
                            clientKm, GostX509TrustManager.insecureTrustAll(),
                            "localhost", port, true);
                    clientEngine.beginHandshake();
                    Exception failure = assertThrows(Exception.class, () -> {
                        OpenSslJsseHelper.doEngineHandshakeOverTcp(clientEngine, socket);
                        OpenSslJsseHelper.sendAppDataAndReceiveOverTcp(clientEngine,
                                "GET / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                                socket);
                    }, "s_server должен отвергнуть сертификат клиента");
                    String alertFromPeer = null;
                    for (Throwable t = failure; t != null; t = t.getCause()) {
                        if (t.getMessage() != null && t.getMessage().contains("from peer")) {
                            alertFromPeer = t.getMessage();
                        }
                    }
                    assertNotNull(alertFromPeer,
                            "Клиент должен получить alert s_server, а не ошибку расшифровки: "
                                    + failure);
                    // Код alert настоящий: недоверенный сертификат клиента - unknown_ca (48).
                    // bad_record_mac (20) значил бы, что клиент читал alert не тем ключом
                    assertTrue(alertFromPeer.contains("alert "
                                    + (TlsConstants.ALERT_UNKNOWN_CA & 0xFF) + " from peer"),
                            "Ожидался unknown_ca (48) от s_server: " + alertFromPeer);
                }
            } finally {
                OpenSslJsseHelper.destroyProcess(sServer);
            }
            return null;
        });
    }

    private void runEngineServerMtlsTest(ClientOcspPolicy clientOcspPolicy) throws Exception {
        TempDirUtils.withTempDir("jsse-engine-mtls-", tmpDir -> {
            ECParameters params = ECParameters.cryptoProA();
            OpenSslJsseHelper.ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(params);

            // Клиентский сертификат (самоподписанный, обходит "ca md too weak" в OpenSSL 3.6)
            byte[] cliKu = new byte[]{(byte) 0x80};
            PkixCertTestHelper.CertBundle clientBundle = PkixCertTestHelper.createCertWithKey(
                    params, "20240101120000Z", "21060101120000Z",
                    null, cliKu, new String[]{"1.3.6.1.5.5.7.3.2"});
            Path clientCertPem = tmpDir.resolve("client-cert.pem");
            Path clientKeyPem = tmpDir.resolve("client-key.pem");
            Files.writeString(clientCertPem, clientBundle.cert.toPem());
            Files.writeString(clientKeyPem,
                    OpenSslJsseHelper.privateKeyToPem(
                            GostDerCodec.encodePrivateKey(clientBundle.priv)));

            GostX509KeyManager km = OpenSslJsseHelper.createKeyManager(
                    pki.cert(), pki.caCert(), pki.priv());
            GostCertificate clientCert = clientBundle.cert;

            AtomicReference<Throwable> serverError = new AtomicReference<>();
            CountDownLatch serverReady = new CountDownLatch(1);
            int[] portOut = new int[1];

            Thread serverThread = startEngineServer(km, clientCert,
                    serverError, serverReady, true, false, portOut, 0, null, clientOcspPolicy);

            assertTrue(serverReady.await(HANDSHAKE_TIMEOUT_SEC, TimeUnit.SECONDS));
            int port = portOut[0];

            CurveSpec curve = ALL_CURVES.get(0);
            boolean ocspRequested = clientOcspPolicy != ClientOcspPolicy.OFF;
            String clientOutput = OpenSslJsseHelper.runSClientWithHttpGet(
                    port, SUITE_L, curve.ianaName, TIMEOUT_MS,
                    // -trace печатает расширения CertificateRequest: видно, что запрос ушёл
                    ocspRequested
                            ? new String[]{"-cert", clientCertPem.toString(),
                                    "-key", clientKeyPem.toString(),
                                    "-sigalgs", curve.sigalgsName(), "-trace"}
                            : new String[]{"-cert", clientCertPem.toString(),
                                    "-key", clientKeyPem.toString(),
                                    "-sigalgs", curve.sigalgsName()});

            serverThread.join(5000);

            assertNull(serverError.get(), "Server error: " + serverError.get());
            if (ocspRequested) {
                assertTrue(clientOutput.contains("status_request"),
                        "CertificateRequest должен содержать status_request: " + clientOutput);
            }
            assertTrue(clientOutput.contains("INTEROP_OK"),
                    "s_client output должен содержать INTEROP_OK при mTLS");
            return null;
        });
    }

    private void runEngineServerPayloadTest(int suiteId, String curveName, int size) throws Exception {
        CurveSpec curve = findCurve(curveName);
        OpenSslJsseHelper.ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(curve.params);

        GostX509KeyManager km = OpenSslJsseHelper.createKeyManager(
                pki.cert(), pki.caCert(), pki.priv());
        GostX509TrustManager tm = OpenSslJsseHelper.createTrustManager(null);

        byte[] payload = new byte[size];
        for (int i = 0; i < size; i++) {
            payload[i] = (byte) i;
        }

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverReady = new CountDownLatch(1);
        int[] portOut = new int[1];

        Thread serverThread = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket()) {
                ss.setReuseAddress(true);
                ss.bind(new java.net.InetSocketAddress(0));
                int effectivePort = ss.getLocalPort();
                portOut[0] = effectivePort;
                ss.setSoTimeout(HANDSHAKE_TIMEOUT_SEC * 1000);
                serverReady.countDown();

                try (Socket s = ss.accept()) {
                    s.setSoTimeout(15_000);

                    GostSSLEngine engine = new GostSSLEngine(km, tm, "localhost", effectivePort, false);
                    engine.beginHandshake();
                    OpenSslJsseHelper.doEngineHandshakeOverTcp(engine, s);

                    byte[] received = OpenSslJsseHelper.sendAppDataAndReceiveOverTcp(
                            engine, payload, s, payload.length);
                    assertArrayEquals(payload, received,
                            "Полученные данные должны совпадать с отправленными");
                }
            } catch (Exception e) {
                serverError.set(e);
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();

        assertTrue(serverReady.await(HANDSHAKE_TIMEOUT_SEC, TimeUnit.SECONDS));
        int port = portOut[0];

        long timeout = size >= 16_384 ? 120_000 : TIMEOUT_MS;
        String clientOutput = OpenSslJsseHelper.runSClientWithData(port,
                suiteIdToName(suiteId), curve.ianaName, payload, timeout);

        serverThread.join(5000);

        assertNull(serverError.get(), "Server error: " + serverError.get());
        assertTrue(clientOutput.length() > 0,
                "s_client output не должен быть пустым");
    }

    private Thread startEngineServer(GostX509KeyManager km,
                                      GostCertificate clientCert,
                                      AtomicReference<Throwable> errorRef,
                                      CountDownLatch serverReady,
                                      boolean mtls, boolean keyUpdate,
                                      int[] portOut,
                                      int preferredGroup,
                                      GostSSLSessionContext sessionCtx) {
        return startEngineServer(km, clientCert, errorRef, serverReady, mtls, keyUpdate,
                portOut, preferredGroup, sessionCtx, ClientOcspPolicy.OFF);
    }

    private Thread startEngineServer(GostX509KeyManager km,
                                      GostCertificate clientCert,
                                      AtomicReference<Throwable> errorRef,
                                      CountDownLatch serverReady,
                                      boolean mtls, boolean keyUpdate,
                                      int[] portOut,
                                      int preferredGroup,
                                      GostSSLSessionContext sessionCtxArg,
                                      ClientOcspPolicy clientOcspPolicy) {
        GostSSLSessionContext sessionCtx = sessionCtxArg;
        if (clientOcspPolicy != ClientOcspPolicy.OFF) {
            TlsCiphersuite cs = TlsCiphersuite.byId(SUITE_L_ID);
            if (sessionCtx == null) {
                sessionCtx = new GostSSLSessionContext(cs);
            }
            sessionCtx.setClientOcspPolicy(clientOcspPolicy);
        }
        GostSSLSessionContext effectiveSessionCtx = sessionCtx;
        Thread t = new Thread(() -> {
            try (ServerSocket ss = new ServerSocket()) {
                ss.setReuseAddress(true);
                ss.bind(new java.net.InetSocketAddress(0));
                int effectivePort = ss.getLocalPort();
                ss.setSoTimeout(HANDSHAKE_TIMEOUT_SEC * 1000);
                if (portOut != null && portOut.length > 0) {
                    portOut[0] = effectivePort;
                }
                serverReady.countDown();

                try (Socket s = ss.accept()) {
                    s.setSoTimeout(15_000);

                    GostX509TrustManager tm = mtls
                            ? GostX509TrustManager.fromTrustAnchors(
                                    TrustAnchors.ofCertificate(clientCert))
                            : GostX509TrustManager.insecureTrustAll();

                    GostSSLEngine engine = effectiveSessionCtx != null
                            ? GostSSLEngine.createForServer(km, tm, "localhost", effectivePort, effectiveSessionCtx)
                            : new GostSSLEngine(km, tm, "localhost", effectivePort, false);
                    if (preferredGroup != 0) {
                        engine.setClientNamedGroup(preferredGroup);
                    }
                    if (mtls) {
                        engine.setNeedClientAuth(true);
                    }
                    engine.beginHandshake();
                    OpenSslJsseHelper.doEngineHandshakeOverTcp(engine, s);

                    if (keyUpdate) {
                        engine.initiateKeyUpdate(false);
                        java.nio.ByteBuffer netBuf = java.nio.ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
                        netBuf.clear();
                        engine.wrap(java.nio.ByteBuffer.allocate(0), netBuf);
                        netBuf.flip();
                        if (netBuf.hasRemaining()) {
                            byte[] keyUpdateData = new byte[netBuf.remaining()];
                            netBuf.get(keyUpdateData);
                            s.getOutputStream().write(keyUpdateData);
                            s.getOutputStream().flush();
                        }
                    }

                    byte[] request = OpenSslJsseHelper.sendAppDataAndReceiveOverTcp(
                            engine, new byte[0], s);

                    String reqStr = new String(request, StandardCharsets.UTF_8);
                    if (reqStr.contains("GET")) {
                        String resp = "HTTP/1.1 200 OK\r\n"
                                + "Content-Type: text/plain\r\n"
                                + "Content-Length: 10\r\n"
                                + "Connection: close\r\n"
                                + "\r\n"
                                + "INTEROP_OK";

                        java.nio.ByteBuffer netBuf = java.nio.ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
                        engine.wrap(java.nio.ByteBuffer.wrap(resp.getBytes(StandardCharsets.UTF_8)), netBuf);
                        netBuf.flip();
                        while (netBuf.hasRemaining()) {
                            s.getOutputStream().write(netBuf.get());
                        }
                        s.getOutputStream().flush();
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

    /* ---- Engine-клиент ---- */

    private void runEngineClientTest(int suiteId, String curveName) throws Exception {
        CurveSpec curve = findCurve(curveName);
        int port = OpenSslJsseHelper.findFreePort();

        TempDirUtils.withTempDir("jsse-engine-client-", tmpDir -> {
            OpenSslJsseHelper.generateGostCert(tmpDir, curve.algo, curve.paramset);

            Process sServer = OpenSslJsseHelper.startSServer(port,
                    suiteIdToName(suiteId), curve.ianaName,
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    "-sigalgs", curve.sigalgsName());

            try {
                boolean accepted = OpenSslJsseHelper.waitForString(sServer, "ACCEPT", 10_000);
                assertTrue(accepted, "s_server не запустился");

                try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port)) {
                    socket.setSoTimeout(15_000);
                    GostSSLEngine clientEngine = new GostSSLEngine(
                            new GostX509KeyManager(),
                            GostX509TrustManager.insecureTrustAll(),
                            "localhost", port, true);
                    clientEngine.beginHandshake();
                    OpenSslJsseHelper.doEngineHandshakeOverTcp(clientEngine, socket);

                    byte[] response = OpenSslJsseHelper.sendAppDataAndReceiveOverTcp(
                            clientEngine,
                            "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                            socket);

                    String respStr = new String(response, StandardCharsets.UTF_8);
                    assertTrue(respStr.contains("TLS") || respStr.contains("HTTP"),
                            "Ответ s_server должен содержать информацию о соединении");
                }
            } finally {
                OpenSslJsseHelper.destroyProcess(sServer);
            }
            return null;
        });
    }

    @Test
    @DisplayName("Engine-клиент: s_server -Verify предлагает только 512-битную схему, клиентский ключ 256-битный - пустой Certificate")
    void testEngineClientSendsEmptyCertificateWhenSchemeNotOffered() throws Exception {
        // RFC 8446 §4.4.3, §4.4.2.3: схемы ключа клиента нет в списке CertificateRequest, поэтому
        // клиент шлёт пустой Certificate, а s_server с обязательной проверкой отвечает
        // certificate_required (116)
        CurveSpec serverCurve = findCurve("GC512A");
        int port = OpenSslJsseHelper.findFreePort();
        OpenSslJsseHelper.ServerPkiBundle clientPki =
                OpenSslJsseHelper.createServerPki(ECParameters.cryptoProA());
        GostX509KeyManager clientKm = OpenSslJsseHelper.createKeyManager(
                clientPki.cert(), clientPki.caCert(), clientPki.priv());

        TempDirUtils.withTempDir("jsse-engine-client-scheme-", tmpDir -> {
            OpenSslJsseHelper.generateGostCert(tmpDir, serverCurve.algo, serverCurve.paramset);
            Path clientCaPem = tmpDir.resolve("client-ca.pem");
            Files.writeString(clientCaPem, clientPki.caCert().toPem());

            Process sServer = OpenSslJsseHelper.startSServer(port,
                    suiteIdToName(SUITE_L_ID), serverCurve.ianaName,
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    "-sigalgs", serverCurve.sigalgsName(),
                    "-Verify", "1", "-CAfile", clientCaPem.toString());
            try {
                assertTrue(OpenSslJsseHelper.waitForString(sServer, "ACCEPT", 10_000),
                        "s_server не запустился");

                try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port)) {
                    socket.setSoTimeout(15_000);
                    GostSSLEngine clientEngine = new GostSSLEngine(
                            clientKm, GostX509TrustManager.insecureTrustAll(),
                            "localhost", port, true);
                    clientEngine.beginHandshake();
                    OpenSslJsseHelper.doEngineHandshakeOverTcp(clientEngine, socket);

                    Exception failure = assertThrows(Exception.class,
                            () -> OpenSslJsseHelper.sendAppDataAndReceiveOverTcp(clientEngine,
                                    "GET / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                                    socket),
                            "s_server должен отказать клиенту без сертификата");
                    boolean certificateRequired = false;
                    for (Throwable t = failure; t != null; t = t.getCause()) {
                        if (t.getMessage() != null && t.getMessage().contains("alert "
                                + (TlsConstants.ALERT_CERTIFICATE_REQUIRED & 0xFF))) {
                            certificateRequired = true;
                        }
                    }
                    assertTrue(certificateRequired,
                            "Ожидался certificate_required (116) от s_server: " + failure);
                }
            } finally {
                OpenSslJsseHelper.destroyProcess(sServer);
            }
            return null;
        });
    }

    @ParameterizedTest(name = "список CA отключён: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("Engine-клиент: s_server -Verify предлагает только 512-битную схему, у клиента сертификаты 256 и 512 - уходит 512-битный")
    void testEngineClientSelectsCertificateByServerSchemes(boolean noCaNames) throws Exception {
        // RFC 8446 §4.4.3: схема CertificateVerify обязана быть из списка CertificateRequest.
        // Раньше engine выбирал сертификат до запроса и брал первый (256-битный), после чего
        // s_server отвечал certificate_required. Теперь выбор делается по запросу сервера;
        // заодно проверяется фильтр по списку CA (-CAfile) и его отсутствие (-no_ca_names)
        CurveSpec serverCurve = findCurve("GC256B");
        int port = OpenSslJsseHelper.findFreePort();
        OpenSslJsseHelper.ServerPkiBundle pki256 =
                OpenSslJsseHelper.createServerPki(ECParameters.cryptoProA());
        OpenSslJsseHelper.ServerPkiBundle pki512 =
                OpenSslJsseHelper.createServerPki(ECParameters.tc26a512());
        GostX509KeyManager clientKm = new GostX509KeyManager();
        clientKm.addKeyEntry("k256",
                CertificateBridge.toJca(List.of(pki256.cert(), pki256.caCert())), pki256.priv());
        clientKm.addKeyEntry("k512",
                CertificateBridge.toJca(List.of(pki512.cert(), pki512.caCert())), pki512.priv());

        TempDirUtils.withTempDir("jsse-engine-client-selection-", tmpDir -> {
            OpenSslJsseHelper.generateGostCert(tmpDir, serverCurve.algo, serverCurve.paramset);
            Path clientCas = tmpDir.resolve("client-cas.pem");
            Files.writeString(clientCas, pki256.caCert().toPem() + pki512.caCert().toPem());

            // -sigalgs ограничивает схему самого сервера, -client_sigalgs - список в запросе
            List<String> extra = new java.util.ArrayList<>(List.of(
                    "-sigalgs", serverCurve.sigalgsName(),
                    "-client_sigalgs", findCurve("GC512A").sigalgsName(),
                    "-Verify", "1", "-CAfile", clientCas.toString()));
            if (noCaNames) {
                extra.add("-no_ca_names");
            }
            Process sServer = OpenSslJsseHelper.startSServer(port,
                    suiteIdToName(SUITE_L_ID), serverCurve.ianaName,
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    extra.toArray(new String[0]));
            String serverOutput;
            try {
                assertTrue(OpenSslJsseHelper.waitForString(sServer, "ACCEPT", 10_000),
                        "s_server не запустился");

                try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port)) {
                    socket.setSoTimeout(15_000);
                    GostSSLEngine clientEngine = new GostSSLEngine(
                            clientKm, GostX509TrustManager.insecureTrustAll(),
                            "localhost", port, true);
                    clientEngine.beginHandshake();
                    OpenSslJsseHelper.doEngineHandshakeOverTcp(clientEngine, socket);
                    byte[] response = OpenSslJsseHelper.sendAppDataAndReceiveOverTcp(clientEngine,
                            "GET / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.UTF_8), socket);
                    assertTrue(response.length > 0, "s_server ответил по установленному соединению");

                    assertEquals(CertificateBridge.toJca(pki512.cert()),
                            clientEngine.getSession().getLocalCertificates()[0],
                            "сессия показывает отправленный 512-битный лист");
                }
                serverOutput = drainOutput(sServer, 1_500);
            } finally {
                OpenSslJsseHelper.destroyProcess(sServer);
            }
            // s_server печатает проверку принятого клиентского сертификата
            assertTrue(serverOutput.replaceAll("\\s", "").contains(acceptedClient(pki512.cert())),
                    "s_server принял 512-битный сертификат клиента: " + serverOutput);
            return null;
        });
    }

    /** Забирает всё, что процесс успел напечатать за отведённое время, не дожидаясь его выхода. */
    private static String drainOutput(Process process, long timeoutMs) throws Exception {
        StringBuilder out = new StringBuilder();
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        InputStream in = process.getInputStream();
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

    /** Строка проверки клиента в выводе s_server без пробелов: глубина 0, CN, успех. */
    private static String acceptedClient(GostCertificate certificate) {
        return "depth=0CN=" + certificate.getSubjectDnField("2.5.4.3")[0].replaceAll("\\s", "")
                + "verifyreturn:1";
    }

    /* ---- Engine engine по TCP (HRR) ---- */

    private void runEngineTcpHrrTest() throws Exception {
        OpenSslJsseHelper.ServerPkiBundle pki =
                OpenSslJsseHelper.createServerPki(ECParameters.cryptoProA());
        GostX509KeyManager serverKm = OpenSslJsseHelper.createKeyManager(
                pki.cert(), pki.caCert(), pki.priv());
        GostX509TrustManager serverTm = GostX509TrustManager.insecureTrustAll();
        GostX509TrustManager clientTm =
                OpenSslJsseHelper.createTrustManager(pki.caCert());

        ServerSocket listener = new ServerSocket(0);
        int port = listener.getLocalPort();

        GostSSLEngine server = new GostSSLEngine(
                serverKm, serverTm, "", port, false);
        server.setClientNamedGroup(TlsConstants.GRP_GC512C);

        GostSSLEngine client = new GostSSLEngine(
                new GostX509KeyManager(), clientTm, "localhost", port, true);
        client.setClientNamedGroup(TlsConstants.GRP_GC256A);

        try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"), port)) {
            socket.setSoTimeout(15_000);

            CompletableFuture<Void> serverTask = CompletableFuture.runAsync(() -> {
                try (Socket peer = listener.accept()) {
                    peer.setSoTimeout(15_000);
                    server.beginHandshake();
                    OpenSslJsseHelper.doEngineHandshakeOverTcp(server, peer);
                    // Сервер пишет "pong", читает "ping" — дуплекс
                    byte[] received = OpenSslJsseHelper.sendAppDataAndReceiveOverTcp(
                            server, "pong".getBytes(StandardCharsets.UTF_8), peer);
                    assertEquals("ping", new String(received, StandardCharsets.UTF_8));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }, Executors.newVirtualThreadPerTaskExecutor());

            client.beginHandshake();
            OpenSslJsseHelper.doEngineHandshakeOverTcp(client, socket);
            // Клиент пишет "ping", читает "pong"
            byte[] response = OpenSslJsseHelper.sendAppDataAndReceiveOverTcp(
                    client, "ping".getBytes(StandardCharsets.UTF_8), socket);
            assertEquals("pong", new String(response, StandardCharsets.UTF_8));

            serverTask.get(15, TimeUnit.SECONDS);
        }
    }

    /* ---- Socket-сервер ---- */

    private void runSocketServerTest(int suiteId, String curveName, boolean mtls) throws Exception {
        CurveSpec curve = findCurve(curveName);

        OpenSslJsseHelper.ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(curve.params);
        GostX509KeyManager km = OpenSslJsseHelper.createKeyManager(
                pki.cert(), pki.caCert(), pki.priv());

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        CountDownLatch serverReady = new CountDownLatch(1);
        int[] actualPort = new int[1];

        GostCertificate mTlsClientCert = null;
        String mtlsCertArg = null;
        String mtlsKeyArg = null;
        if (mtls) {
            byte[] cliKu = new byte[]{(byte) 0x80};
            PkixCertTestHelper.CertBundle clientBundle = PkixCertTestHelper.createCertWithKey(
                    curve.params, "20240101120000Z", "21060101120000Z",
                    null, cliKu, new String[]{"1.3.6.1.5.5.7.3.2"});
            mTlsClientCert = clientBundle.cert;
            byte[] certDer = clientBundle.cert.toPem().getBytes(StandardCharsets.UTF_8);
            byte[] keyDer = OpenSslJsseHelper.privateKeyToPem(
                    GostDerCodec.encodePrivateKey(clientBundle.priv)).getBytes(StandardCharsets.UTF_8);
            Path tmpDir = Files.createTempDirectory("jsse-socket-mtls-");
            tmpDir.toFile().deleteOnExit();
            Path clientCertPem = tmpDir.resolve("client-cert.pem");
            Path clientKeyPem = tmpDir.resolve("client-key.pem");
            Files.write(clientCertPem, certDer);
            Files.write(clientKeyPem, keyDer);
            clientCertPem.toFile().deleteOnExit();
            clientKeyPem.toFile().deleteOnExit();
            mtlsCertArg = clientCertPem.toString();
            mtlsKeyArg = clientKeyPem.toString();
        }

        Thread serverThread = startSocketServer(km, mTlsClientCert,
                serverError, serverReady, mtls, actualPort);

        assertTrue(serverReady.await(HANDSHAKE_TIMEOUT_SEC, TimeUnit.SECONDS),
                "Socket-сервер не запустился");
        int port = actualPort[0];

        List<String> extraArgs = new java.util.ArrayList<>();
        if (mtls) {
            extraArgs.add("-cert");
            extraArgs.add(mtlsCertArg);
            extraArgs.add("-key");
            extraArgs.add(mtlsKeyArg);
            extraArgs.add("-sigalgs");
            extraArgs.add(curve.sigalgsName);
        }

        String clientOutput = OpenSslJsseHelper.runSClientWithHttpGet(
                port, suiteIdToName(suiteId), curve.ianaName, TIMEOUT_MS,
                extraArgs.toArray(new String[0]));

        serverThread.join(5000);

        assertNull(serverError.get(), "Server error: " + serverError.get());
        assertTrue(clientOutput.contains("INTEROP_OK"),
                "s_client output должен содержать INTEROP_OK");
    }

    private Thread startSocketServer(GostX509KeyManager km,
                                      GostCertificate clientCert,
                                      AtomicReference<Throwable> errorRef,
                                      CountDownLatch serverReady,
                                      boolean mtls, int[] portOut) {
        Thread t = new Thread(() -> {
            try {
                GostX509TrustManager tm = mtls
                        ? GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.ofCertificate(clientCert))
                        : GostX509TrustManager.insecureTrustAll();

                try (GostSSLServerSocket ss = new GostSSLServerSocket(0, km, tm, sessionContext)) {
                    portOut[0] = ss.getLocalPort();
                    serverReady.countDown();

                    if (mtls) {
                        ss.setNeedClientAuth(true);
                    }

                    try (GostSSLSocket ssl = (GostSSLSocket) ss.accept()) {
                        ssl.startHandshake();

                        InputStream in = ssl.getInputStream();
                        OutputStream out = ssl.getOutputStream();

                        byte[] buf = new byte[4096];
                        int n = in.read(buf);
                        String reqStr = new String(buf, 0, n);

                        if (reqStr.contains("GET")) {
                            String resp = "HTTP/1.1 200 OK\r\n"
                                    + "Content-Type: text/plain\r\n"
                                    + "Content-Length: 10\r\n"
                                    + "Connection: close\r\n"
                                    + "\r\n"
                                    + "INTEROP_OK";
                            out.write(resp.getBytes(StandardCharsets.UTF_8));
                            out.flush();
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

    /* ---- Socket-клиент ---- */

    private void runSocketClientTest(int suiteId, String curveName) throws Exception {
        CurveSpec curve = findCurve(curveName);
        int port = OpenSslJsseHelper.findFreePort();

        TempDirUtils.withTempDir("jsse-socket-client-", tmpDir -> {
            OpenSslJsseHelper.generateGostCert(tmpDir, curve.algo, curve.paramset);

            Process sServer = OpenSslJsseHelper.startSServer(port,
                    suiteIdToName(suiteId), curve.ianaName,
                    tmpDir.resolve("cert.pem").toString(),
                    tmpDir.resolve("key.pem").toString(),
                    "-sigalgs", curve.sigalgsName());

            try {
                boolean accepted = OpenSslJsseHelper.waitForString(sServer, "ACCEPT", 10_000);
                assertTrue(accepted, "s_server не запустился");

                GostX509TrustManager tm = GostX509TrustManager.insecureTrustAll();

                try (GostSSLSocket client = new GostSSLSocket("localhost", port,
                        new GostX509KeyManager(), tm, sessionContext)) {
                    client.setSoTimeout(10000);
                    client.startHandshake();

                    OutputStream out = client.getOutputStream();
                    out.write("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".getBytes(StandardCharsets.UTF_8));
                    out.flush();

                    InputStream in = client.getInputStream();
                    byte[] buf = new byte[4096];
                    int n = in.read(buf);
                    String respStr = new String(buf, 0, n);

                    assertTrue(respStr.contains("TLS") || respStr.contains("HTTP"),
                            "Ответ s_server должен содержать информацию о соединении");
                }
            } finally {
                OpenSslJsseHelper.destroyProcess(sServer);
            }
            return null;
        });
    }
}
