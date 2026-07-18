package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Проверяет hostname verification на engine-пути через SSLContext.createSSLEngine.
 * <p>
 * Ключевая инвариант (P1-1): engine, созданный через {@code createSSLEngine(host, port)},
 * должен давать те же гарантии проверки имени, что socket-путь — иначе перенос кода
 * с сокетов на engine молча теряет защиту от MITM.
 */
class GostSSLEngineHostnameVerificationTest {

    private static ECParameters params;
    private static TlsTestHelper.CertBundle rootCa;
    private static PublicKeyParameters caPub;
    private static TlsTestHelper.CertBundle serverCertLocalhost;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        params = ECParameters.tc26a256();
        rootCa = TlsTestHelper.createRootCA(params);
        caPub = rootCa.cert.getPublicKey();
        // сертификат сервера с SAN=localhost — по нему проверяется совпадение имени
        serverCertLocalhost =
                TlsTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        caPub,
                        rootCa.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    // ========================================================================
    // Дефолт endpoint identification на engine-пути
    // ========================================================================

    @Test
    @DisplayName("createSSLEngine(host,port): endpointIdentificationAlgorithm=HTTPS по умолчанию")
    void engineWithHostDefaultsToHttps() throws Exception {
        SSLContext ctx = clientContext();
        javax.net.ssl.SSLEngine engine = ctx.createSSLEngine("localhost", 8443);
        assertEquals(
                "HTTPS",
                engine.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "engine с непустым host должен по умолчанию проверять hostname (HTTPS)");
    }

    @Test
    @DisplayName("createSSLEngine() без host: endpoint identification не включается")
    void engineWithoutHostHasNoEndpointId() throws Exception {
        SSLContext ctx = clientContext();
        javax.net.ssl.SSLEngine engine = ctx.createSSLEngine();
        assertNull(
                engine.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "без host проверять нечего — endpoint id остаётся null");
    }

    // ========================================================================
    // Реальный handshake: совпадение и несовпадение имени
    // ========================================================================

    @Test
    @DisplayName("Engine-путь: host=localhost совпадает с SAN — рукопожатие успешно")
    void engineHandshakeMatchingHostSucceeds() throws Exception {
        GostSSLEngine client = (GostSSLEngine) clientContext().createSSLEngine("localhost", 0);
        doLoopback(client, newServerEngine());
        assertTrue(client.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    @Test
    @DisplayName("Engine-путь: host не совпадает с SAN — fatal (защита от MITM)")
    void engineHandshakeWrongHostFails() throws Exception {
        GostSSLEngine client =
                (GostSSLEngine) clientContext().createSSLEngine("wronghost.invalid", 0);
        RuntimeException ex =
                assertThrows(RuntimeException.class, () -> doLoopback(client, newServerEngine()));
        assertInstanceOf(
                SSLException.class,
                ex.getCause(),
                "несовпадение hostname должно приводить к SSLException, причина: " + ex.getCause());
    }

    // ========================================================================
    // Opt-out через session context флаг (endpointIdentificationDisabled)
    // ========================================================================

    @Test
    @DisplayName(
            "SessionContext флаг: wrong host проходит (аналог trustAllNoHostnameCheckInsecure)")
    void disabledFlagOnSessionContextAllowsWrongHost() throws Exception {
        SSLContext ctx = clientContext();
        ((GostSSLSessionContext) ctx.getClientSessionContext())
                .setEndpointIdentificationDisabled(true);
        GostSSLEngine client = (GostSSLEngine) ctx.createSSLEngine("wronghost.invalid", 0);
        doLoopback(client, newServerEngine());
        assertTrue(client.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    @Test
    @DisplayName("SessionContext флаг: matching host всё ещё работает")
    void disabledFlagOnSessionContextWithMatchingHost() throws Exception {
        SSLContext ctx = clientContext();
        ((GostSSLSessionContext) ctx.getClientSessionContext())
                .setEndpointIdentificationDisabled(true);
        GostSSLEngine client = (GostSSLEngine) ctx.createSSLEngine("localhost", 0);
        doLoopback(client, newServerEngine());
        assertTrue(client.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    // ========================================================================
    // Opt-out по контракту SSLParameters: null и "" отключают проверку
    // ========================================================================

    @Test
    @DisplayName(
            "Opt-out: setSSLParameters(endpointId=null) отключает проверку — wrong host проходит")
    void optOutViaNullEndpointId() throws Exception {
        GostSSLEngine client =
                (GostSSLEngine) clientContext().createSSLEngine("wronghost.invalid", 0);
        SSLParameters p = client.getSSLParameters();
        p.setEndpointIdentificationAlgorithm(null);
        client.setSSLParameters(p);
        // проверка отключена явно по контракту -> рукопожатие проходит, несмотря на wrong host
        doLoopback(client, newServerEngine());
        assertTrue(client.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    @Test
    @DisplayName("Opt-out: setSSLParameters(endpointId=\"\") также отключает проверку")
    void optOutViaEmptyEndpointId() throws Exception {
        GostSSLEngine client =
                (GostSSLEngine) clientContext().createSSLEngine("wronghost.invalid", 0);
        SSLParameters p = client.getSSLParameters();
        p.setEndpointIdentificationAlgorithm("");
        client.setSSLParameters(p);
        doLoopback(client, newServerEngine());
        assertTrue(client.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    @Test
    @DisplayName("setSSLParameters(null) очищает ранее выставленный HTTPS (JSSE-контракт)")
    void setSslParametersNullClearsHttps() throws Exception {
        javax.net.ssl.SSLEngine engine = clientContext().createSSLEngine("localhost", 8443);
        assertEquals("HTTPS", engine.getSSLParameters().getEndpointIdentificationAlgorithm());
        SSLParameters p = engine.getSSLParameters();
        p.setEndpointIdentificationAlgorithm(null);
        engine.setSSLParameters(p);
        assertNull(
                engine.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "null по контракту SSLParameters должен отключать endpoint identification");
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    /** Клиентский SSLContext с доверием к rootCa и без клиентского сертификата. */
    private SSLContext clientContext() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
        ctx.init(
                new KeyManager[] {new GostX509KeyManager()},
                new TrustManager[] {new GostX509TrustManager(caPub, false)},
                null);
        return ctx;
    }

    /** Серверный engine с сертификатом SAN=localhost, подписанным rootCa. */
    private GostSSLEngine newServerEngine() throws Exception {
        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCertLocalhost.cert, rootCa.cert)),
                serverCertLocalhost.priv);
        return new GostSSLEngine(skm, new GostX509TrustManager(null, false), "localhost", 0, false);
    }

    private void doLoopback(GostSSLEngine client, GostSSLEngine server) throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        client.beginHandshake();
        server.beginHandshake();

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread =
                new Thread(() -> runHandshake(client, pair, true, clientError), "hv-client");
        Thread serverThread =
                new Thread(() -> runHandshake(server, pair, false, serverError), "hv-server");

        clientThread.start();
        serverThread.start();
        clientThread.join(10000);
        serverThread.join(10000);

        if (clientThread.isAlive()) {
            clientThread.interrupt();
            fail("Тайм-аут рукопожатия клиента");
        }
        if (serverThread.isAlive()) {
            serverThread.interrupt();
            fail("Тайм-аут рукопожатия сервера");
        }
        // клиентская ошибка приоритетна — именно на клиенте проверяется hostname
        if (clientError.get() != null) {
            throw new RuntimeException("Клиент завершился с ошибкой", clientError.get());
        }
        if (serverError.get() != null) {
            throw new RuntimeException("Сервер завершился с ошибкой", serverError.get());
        }
    }

    private void runHandshake(
            GostSSLEngine engine,
            InMemoryTlsTransport.Pair pair,
            boolean clientSide,
            AtomicReference<Throwable> error) {
        InMemoryTlsTransport transport =
                clientSide ? pair.getClientTransport() : pair.getServerTransport();
        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        try {
            for (int i = 0; i < 80; i++) {
                SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
                if (hs == SSLEngineResult.HandshakeStatus.FINISHED
                        || hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                    return;
                }
                switch (hs) {
                    case NEED_WRAP:
                        netBuf.clear();
                        engine.wrap(ByteBuffer.allocate(0), netBuf);
                        netBuf.flip();
                        if (netBuf.hasRemaining()) {
                            byte[] out = new byte[netBuf.remaining()];
                            netBuf.get(out);
                            transport.sendRecord(out);
                        }
                        break;
                    case NEED_UNWRAP:
                        byte[] in = transport.receiveRecord();
                        if (in != null) {
                            netBuf.clear();
                            netBuf.put(in);
                            netBuf.flip();
                            appBuf.clear();
                            engine.unwrap(netBuf, appBuf);
                        } else {
                            Thread.sleep(10);
                        }
                        break;
                    case NEED_TASK:
                        Runnable task = engine.getDelegatedTask();
                        if (task != null) task.run();
                        break;
                }
            }
            throw new RuntimeException(
                    "Рукопожатие не завершилось за 80 итераций, status="
                            + engine.getHandshakeStatus());
        } catch (Exception e) {
            error.set(e);
        }
    }
}
