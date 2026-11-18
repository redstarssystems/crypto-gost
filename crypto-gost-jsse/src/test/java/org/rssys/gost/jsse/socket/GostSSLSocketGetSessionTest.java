package org.rssys.gost.jsse.socket;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.testkit.EngineServerPki;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;

/**
 * Контракт {@code SSLSocket.getSession()}: запускает рукопожатие и ждёт его; из обратного вызова
 * рукопожатия не уходит в рекурсию; при отказе отдаёт пустую сессию без исключения, а сокет
 * закрыт.
 */
@DisplayName("GostSSLSocket: getSession() запускает рукопожатие")
class GostSSLSocketGetSessionTest {

    private static final int TIMEOUT_MS = 10_000;
    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final String ALPN = "h2";

    private static EngineServerPki pki;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        pki = EngineServerPki.create();
    }

    private static GostX509TrustManager trustingRoot() {
        return GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(pki.rootCa().cert));
    }

    private static GostSSLServerSocket listener() throws Exception {
        return new GostSSLServerSocket(
                0,
                pki.serverKm(),
                GostX509TrustManager.insecureTrustAll(),
                new GostSSLSessionContext(SUITE));
    }

    /** Сервер: принимает соединение и завершает рукопожатие, ошибки отдаёт результатом. */
    private static CompletableFuture<Throwable> serve(
            GostSSLServerSocket listener, java.util.function.Consumer<GostSSLSocket> setup) {
        return CompletableFuture.supplyAsync(
                () -> {
                    try (GostSSLSocket accepted = (GostSSLSocket) listener.accept()) {
                        accepted.setSoTimeout(TIMEOUT_MS);
                        setup.accept(accepted);
                        accepted.startHandshake();
                        accepted.getInputStream().read();
                        return null;
                    } catch (Throwable e) {
                        return e;
                    }
                });
    }

    @Test
    @DisplayName("getSession() без startHandshake(): рукопожатие проходит, сессия настоящая")
    void getSessionRunsHandshake() throws Exception {
        try (GostSSLServerSocket listener = listener()) {
            CompletableFuture<Throwable> server = serve(listener, socket -> {});
            try (GostSSLSocket client =
                    new GostSSLSocket(
                            "localhost",
                            listener.getLocalPort(),
                            new GostX509KeyManager(),
                            trustingRoot(),
                            new GostSSLSessionContext(SUITE))) {
                client.setSoTimeout(TIMEOUT_MS);
                SSLSession session = client.getSession();
                assertEquals(SUITE.getIanaName(), session.getCipherSuite());
                assertTrue(session.isValid(), "сессия завершённого рукопожатия действительна");
            }
            server.get(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }
    }

    @Test
    @DisplayName("getSession() из селектора ALPN во время рукопожатия: без рекурсии и зависания")
    void getSessionFromHandshakeCallbackDoesNotRecurse() throws Exception {
        AtomicReference<SSLSession> seenInCallback = new AtomicReference<>();
        AtomicReference<SSLSession> handshakeSessionInCallback = new AtomicReference<>();
        try (GostSSLServerSocket listener = listener()) {
            CompletableFuture<Throwable> server =
                    serve(
                            listener,
                            socket ->
                                    socket.setHandshakeApplicationProtocolSelector(
                                            (self, offered) -> {
                                                seenInCallback.set(self.getSession());
                                                handshakeSessionInCallback.set(
                                                        self.getHandshakeSession());
                                                return offered.get(0);
                                            }));
            try (GostSSLSocket client =
                    new GostSSLSocket(
                            "localhost",
                            listener.getLocalPort(),
                            new GostX509KeyManager(),
                            trustingRoot(),
                            new GostSSLSessionContext(SUITE))) {
                client.setSoTimeout(TIMEOUT_MS);
                SSLParameters parameters = client.getSSLParameters();
                parameters.setApplicationProtocols(new String[] {ALPN});
                client.setSSLParameters(parameters);
                client.startHandshake();
                assertEquals(ALPN, client.getApplicationProtocol());
                assertNull(
                        client.getHandshakeApplicationProtocol(),
                        "после рукопожатия значение handshake-версии не определено (контракт JDK)");
                client.getOutputStream().write(1);
            }
            assertNull(server.get(TIMEOUT_MS, TimeUnit.MILLISECONDS), "сервер без ошибок");
        }
        assertEquals(
                GostJsseConstants.SSL_NULL_CIPHER,
                seenInCallback.get().getCipherSuite(),
                "внутри рукопожатия getSession() отдаёт текущую, ещё пустую сессию");
        assertNotNull(
                handshakeSessionInCallback.get(),
                "getHandshakeSession() во время рукопожатия не null");
    }

    @ParameterizedTest(name = "вход: {0}")
    @ValueSource(strings = {"getSession", "startHandshake"})
    @DisplayName(
            "Отказ рукопожатия: сокет закрыт; getSession() отдаёт пустую сессию без исключения,"
                    + " startHandshake() бросает SSLException")
    void failedHandshakeClosesSocket(String entryPoint) throws Exception {
        // Клиент доверяет чужому корню: сертификат сервера отвергается
        PkixCertTestHelper.CertBundle foreignRoot =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        try (GostSSLServerSocket listener = listener()) {
            CompletableFuture<Throwable> server = serve(listener, socket -> {});
            try (GostSSLSocket client =
                    new GostSSLSocket(
                            "localhost",
                            listener.getLocalPort(),
                            new GostX509KeyManager(),
                            GostX509TrustManager.fromTrustAnchors(
                                    TrustAnchors.ofCertificate(foreignRoot.cert)),
                            new GostSSLSessionContext(SUITE))) {
                client.setSoTimeout(TIMEOUT_MS);
                if ("getSession".equals(entryPoint)) {
                    try (LogCapture log = LogCapture.start(LogCapture.JSSE)) {
                        SSLSession session = client.getSession();
                        assertEquals(GostJsseConstants.SSL_NULL_CIPHER, session.getCipherSuite());
                        // Запись сокета: точное имя логгера и только тип исключения, без текста
                        List<String> socketRecords = log.allMessages("jsse.socket.GostSSLSocket");
                        assertEquals(1, socketRecords.size(), "одна запись: " + socketRecords);
                        assertTrue(
                                socketRecords
                                        .get(0)
                                        .matches(
                                                "\\[conn#\\d+] Handshake for getSession\\(\\)"
                                                        + " failed: \\w+"),
                                "метка соединения и тип без текста исключения: " + socketRecords);
                        assertTrue(
                                log.loggerNames()
                                        .contains("org.rssys.gost.jsse.socket.GostSSLSocket"),
                                "имя логгера по классу: " + log.loggerNames());
                    }
                } else {
                    assertThrows(SSLException.class, client::startHandshake);
                }
                assertTrue(client.isClosed(), "после отказа рукопожатия сокет закрыт");
            }
            server.get(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }
    }

    @Test
    @DisplayName("Сокет закрыт до рукопожатия: getSession() отдаёт пустую сессию без исключения")
    void closedSocketGivesNullSession() throws Exception {
        try (GostSSLServerSocket listener = listener()) {
            CompletableFuture<Throwable> server = serve(listener, socket -> {});
            GostSSLSocket client =
                    new GostSSLSocket(
                            "localhost",
                            listener.getLocalPort(),
                            new GostX509KeyManager(),
                            trustingRoot(),
                            new GostSSLSessionContext(SUITE));
            client.close();
            assertEquals(GostJsseConstants.SSL_NULL_CIPHER, client.getSession().getCipherSuite());
            assertNull(client.getHandshakeSession(), "рукопожатия не было");
            server.get(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }
    }
}
