package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.socket.GostSSLServerSocket;
import org.rssys.gost.jsse.socket.GostSSLSocket;
import org.rssys.gost.jsse.testkit.EngineSocketPeer;
import org.rssys.gost.jsse.testkit.HandshakeFlightShaper;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;

/**
 * {@link GostSSLSocket} на приёме полёта, нарезанного не по сообщениям: несколько сообщений в
 * одной записи или записи по одному байту. Сокет читает записи сам и сам выполняет задачу
 * проверки сертификата, поэтому этот путь проверяется отдельно от движка.
 *
 * <p>Пиром служит {@link GostSSLEngine} поверх TCP: его полёт перекладывает
 * {@link HandshakeFlightShaper}.
 */
@DisplayName("GostSSLSocket: приём полёта рукопожатия, нарезанного не по сообщениям")
class GostSSLSocketHandshakeFramingTest {

    private static final byte[] REQUEST = "ping".getBytes();
    private static final byte[] RESPONSE = "pong".getBytes();
    private static final int TIMEOUT_MS = 10_000;

    /** Полёт в очереди: у сервера после ClientHello, у клиента после полёта сервера. */
    private static final int FLIGHT_FRAMES = 2;

    private static final int SERVER_HELLO_KEPT = 1;
    private static final int NOTHING_KEPT = 0;
    private static final int ONE_RECORD = HandshakeFlightShaper.ONE_RECORD;
    private static final int ONE_BYTE = 1;

    private static PkixCertTestHelper.CertBundle rootCa;
    private static GostX509KeyManager serverKm;
    private static GostX509KeyManager clientKm;
    private static TlsCiphersuite suite;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        ECParameters params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert = leaf(params, new String[] {"localhost"});
        PkixCertTestHelper.CertBundle clientCert = leaf(params, null);
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        clientKm = new GostX509KeyManager();
        clientKm.addKeyEntry(
                "client",
                CertificateBridge.toJca(List.of(clientCert.cert, rootCa.cert)),
                clientCert.priv);
    }

    private static PkixCertTestHelper.CertBundle leaf(ECParameters params, String[] dns)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                rootCa.priv,
                rootCa.cert.getPublicKey(),
                rootCa.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                dns,
                new byte[] {(byte) 0x80},
                null,
                false,
                null);
    }

    private static GostX509TrustManager trustRoot() {
        return GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert));
    }

    @ParameterizedTest(name = "размер элемента {0}")
    @ValueSource(ints = {ONE_RECORD, ONE_BYTE})
    @DisplayName("Клиент-сокет: зашифрованный полёт сервера одной записью и по одному байту")
    void socketClientReceivesReshapedServerFlight(int chunkSize) throws Exception {
        try (ServerSocket listener = new ServerSocket(0)) {
            CompletableFuture<Void> server =
                    CompletableFuture.runAsync(
                            () -> {
                                try (Socket socket = listener.accept()) {
                                    socket.setSoTimeout(TIMEOUT_MS);
                                    GostSSLEngine engine =
                                            new GostSSLEngine(
                                                    serverKm, trustRoot(), "localhost", 0, false);
                                    EngineSocketPeer.handshake(
                                            engine,
                                            socket,
                                            FLIGHT_FRAMES,
                                            e -> reshape(e, SERVER_HELLO_KEPT, chunkSize));
                                    answer(engine, socket);
                                } catch (Exception e) {
                                    throw new IllegalStateException(e);
                                }
                            });

            try (GostSSLSocket client =
                    new GostSSLSocket(
                            "localhost",
                            listener.getLocalPort(),
                            new GostX509KeyManager(),
                            trustRoot(),
                            new GostSSLSessionContext(suite))) {
                client.setSoTimeout(TIMEOUT_MS);
                client.startHandshake();
                assertExchange(client);
            }
            server.get(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }
    }

    @ParameterizedTest(name = "размер элемента {0}")
    @ValueSource(ints = {ONE_RECORD, ONE_BYTE})
    @DisplayName("Сервер-сокет при mTLS: полёт клиента одной записью и по одному байту")
    void socketServerReceivesReshapedClientFlight(int chunkSize) throws Exception {
        try (GostSSLServerSocket listener =
                new GostSSLServerSocket(
                        0, serverKm, trustRoot(), new GostSSLSessionContext(suite))) {
            listener.setNeedClientAuth(true);
            CompletableFuture<Void> server =
                    CompletableFuture.runAsync(
                            () -> {
                                try (GostSSLSocket accepted = (GostSSLSocket) listener.accept()) {
                                    accepted.setSoTimeout(TIMEOUT_MS);
                                    accepted.startHandshake();
                                    byte[] request =
                                            accepted.getInputStream().readNBytes(REQUEST.length);
                                    assertArrayEquals(REQUEST, request, "запрос клиента дошёл");
                                    accepted.getOutputStream().write(RESPONSE);
                                    accepted.getOutputStream().flush();
                                } catch (IOException e) {
                                    throw new IllegalStateException(e);
                                }
                            });

            try (Socket socket = new Socket("localhost", listener.getLocalPort())) {
                socket.setSoTimeout(TIMEOUT_MS);
                GostSSLEngine engine =
                        GostSSLEngine.createForClient(
                                clientKm, trustRoot(), "localhost", listener.getLocalPort(), null);
                EngineSocketPeer.handshake(
                        engine, socket, FLIGHT_FRAMES, e -> reshape(e, NOTHING_KEPT, chunkSize));
                socket.getOutputStream().write(EngineSocketPeer.wrapData(engine, REQUEST));
                assertArrayEquals(
                        RESPONSE, EngineSocketPeer.readData(engine, socket), "ответ сервера дошёл");
            }
            server.get(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }
    }

    private static void reshape(GostSSLEngine engine, int keepLeading, int chunk) {
        HandshakeFlightShaper.reshape(engine, keepLeading, chunk, new byte[0]);
    }

    private static void answer(GostSSLEngine engine, Socket socket) throws Exception {
        assertArrayEquals(
                REQUEST, EngineSocketPeer.readData(engine, socket), "запрос клиента дошёл");
        socket.getOutputStream().write(EngineSocketPeer.wrapData(engine, RESPONSE));
    }

    private static void assertExchange(GostSSLSocket client) throws IOException {
        client.getOutputStream().write(REQUEST);
        client.getOutputStream().flush();
        byte[] response = client.getInputStream().readNBytes(RESPONSE.length);
        assertArrayEquals(RESPONSE, response, "ответ сервера дошёл");
    }
}
