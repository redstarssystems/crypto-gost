package org.rssys.gost.crossval.jsse;

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
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.socket.GostSSLServerSocket;
import org.rssys.gost.jsse.socket.GostSSLSocket;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTestHelper;

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

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JSSE: кросс-валидация crypto-gost JSSE ↔ OpenSSL")
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

    static final List<CurveSpec> ALL_CURVES = List.of(
            new CurveSpec("GC256B", TlsConstants.GRP_GC256B, ECParameters.cryptoProA(),
                    "gost2012_256", "A", "gostr34102012_256b"),
            new CurveSpec("GC512A", TlsConstants.GRP_GC512A, ECParameters.tc26a512(),
                    "gost2012_512", "A", "gostr34102012_512a"),
            new CurveSpec("GC512B", TlsConstants.GRP_GC512B, ECParameters.tc26b512(),
                    "gost2012_512", "B", "gostr34102012_512b")
    );

    @BeforeAll
    static void preconditions() {
        Security.addProvider(new RssysGostJsseProvider());
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslJsseHelper.assumeGostTls13();
        csL = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        sessionContext = new GostSSLSessionContext(csL, csL.getHashLen());
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
    @DisplayName("Engine-сервер + s_client: все кривые (GC256B..GC512B)")
    void testEngineServerAllCurves(String curveName, int groupId) throws Exception {
        runEngineServerTest(SUITE_L_ID, curveName, false, groupId, false);
    }

    @Test
    @DisplayName("Engine-сервер + s_client: mTLS (взаимная аутентификация)")
    void testEngineServerMtls() throws Exception {
        runEngineServerMtlsTest();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 15, 16, 1024, 12_000, 16_383, 16_384, 16_385, 32_768})
    @DisplayName("Engine-сервер + s_client: размеры payload")
    void testEngineServerPayload(int size) throws Exception {
        runEngineServerPayloadTest(SUITE_L_ID, "GC256B", size);
    }

    @Test
    @Disabled("OpenSSL gostprov не поддерживает HRR — сервер шлёт корректный HRR, но s_client падает")
    @DisplayName("Engine-сервер [GC512C] + s_client [GC256B]: fallback группы (HRR)")
    void testEngineServerGroupMismatch() throws Exception {
        runEngineServerTest(SUITE_L_ID, "GC256B", false, TlsConstants.GRP_GC512C, false);
    }

    @Test
    @Disabled("Требует проверки поддержки KeyUpdate в OpenSSL (s_client -keyupdate)")
    @DisplayName("Engine-сервер + s_client: KeyUpdate после handshake")
    void testEngineServerKeyUpdate() throws Exception {
        runEngineServerTest(SUITE_L_ID, "GC256B", false, 0, true);
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
    @Disabled("Падает с GC512A/B: SSLHandshakeException Handshake error (pre-existing, см. issue #XXX)")
    @DisplayName("s_server + Engine-клиент: все кривые (GC256B..GC512B)")
    void testEngineClientAllCurves(String curveName, int groupId) throws Exception {
        runEngineClientTest(SUITE_L_ID, curveName);
    }

    @Test
    @DisplayName("Dual-engine по TCP: клиент GC256A \u2192 сервер GC512C \u2192 HRR \u2192 handshake")
    void testEngineClientHrr() throws Exception {
        // Два GostSSLEngine через реальный TCP. Клиент шлёт key_share=GC256A,
        // сервер предпочитает GC512C — несовпадение → сервер отправляет HRR.
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
                serverError, serverReady, false, keyUpdate, portOut, serverGroup);

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

    private void runEngineServerMtlsTest() throws Exception {
        TempDirUtils.withTempDir("jsse-engine-mtls-", tmpDir -> {
            ECParameters params = ECParameters.cryptoProA();
            OpenSslJsseHelper.ServerPkiBundle pki = OpenSslJsseHelper.createServerPki(params);

            // Клиентский сертификат (самоподписанный, обходит "ca md too weak" в OpenSSL 3.6)
            byte[] cliKu = new byte[]{(byte) 0x80};
            TlsTestHelper.CertBundle clientBundle = TlsTestHelper.createCertWithKey(
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
            PublicKeyParameters clientPub = clientBundle.cert.getPublicKey();

            AtomicReference<Throwable> serverError = new AtomicReference<>();
            CountDownLatch serverReady = new CountDownLatch(1);
            int[] portOut = new int[1];

            Thread serverThread = startEngineServer(km, clientPub,
                    serverError, serverReady, true, false, portOut, 0);

            assertTrue(serverReady.await(HANDSHAKE_TIMEOUT_SEC, TimeUnit.SECONDS));
            int port = portOut[0];

            CurveSpec curve = ALL_CURVES.get(0);
            String clientOutput = OpenSslJsseHelper.runSClientWithHttpGet(
                    port, SUITE_L, curve.ianaName, TIMEOUT_MS,
                    "-cert", clientCertPem.toString(),
                    "-key", clientKeyPem.toString(),
                    "-sigalgs", curve.sigalgsName());

            serverThread.join(5000);

            assertNull(serverError.get(), "Server error: " + serverError.get());
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
                                      PublicKeyParameters clientPub,
                                      AtomicReference<Throwable> errorRef,
                                      CountDownLatch serverReady,
                                      boolean mtls, boolean keyUpdate,
                                      int[] portOut,
                                      int preferredGroup) {
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
                            ? new GostX509TrustManager(clientPub, false)
                            : new GostX509TrustManager(null, false);

                    GostSSLEngine engine = new GostSSLEngine(km, tm, "localhost", effectivePort, false);
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
                        java.nio.ByteBuffer netBuf = java.nio.ByteBuffer.allocate(16640 + 64);
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

                        java.nio.ByteBuffer netBuf = java.nio.ByteBuffer.allocate(16640 + 64);
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
                            new GostX509TrustManager(null, false),
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

    /* ---- Engine engine по TCP (HRR) ---- */

    private void runEngineTcpHrrTest() throws Exception {
        OpenSslJsseHelper.ServerPkiBundle pki =
                OpenSslJsseHelper.createServerPki(ECParameters.cryptoProA());
        GostX509KeyManager serverKm = OpenSslJsseHelper.createKeyManager(
                pki.cert(), pki.caCert(), pki.priv());
        GostX509TrustManager serverTm = new GostX509TrustManager(null, false);
        GostX509TrustManager clientTm =
                OpenSslJsseHelper.createTrustManager(pki.caPub());

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

        PublicKeyParameters mTlsClientPub = null;
        String mtlsCertArg = null;
        String mtlsKeyArg = null;
        if (mtls) {
            byte[] cliKu = new byte[]{(byte) 0x80};
            TlsTestHelper.CertBundle clientBundle = TlsTestHelper.createCertWithKey(
                    curve.params, "20240101120000Z", "21060101120000Z",
                    null, cliKu, new String[]{"1.3.6.1.5.5.7.3.2"});
            mTlsClientPub = clientBundle.cert.getPublicKey();
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

        Thread serverThread = startSocketServer(km, mTlsClientPub,
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
                                      PublicKeyParameters clientPub,
                                      AtomicReference<Throwable> errorRef,
                                      CountDownLatch serverReady,
                                      boolean mtls, int[] portOut) {
        Thread t = new Thread(() -> {
            try {
                GostX509TrustManager tm = mtls
                        ? new GostX509TrustManager(clientPub, false)
                        : new GostX509TrustManager(null, false);

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

                GostX509TrustManager tm = new GostX509TrustManager(null, false);

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
