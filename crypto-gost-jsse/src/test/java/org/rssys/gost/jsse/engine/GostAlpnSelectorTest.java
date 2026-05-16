package org.rssys.gost.jsse.engine;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.manager.GostX509KeyManager;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты ALPN-селектора фазы 5: JSSE BiFunction → tls13 Function.
 */
class GostAlpnSelectorTest {

    private static TlsCiphersuite cs;
    private static TlsTestHelper.CertBundle serverCert;
    private static TlsTestHelper.CertBundle rootCa;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        rootCa = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        serverCert = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), rootCa.priv,
                rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
    }

    @Test
    @DisplayName("ALPN selector: вызывается с правильным client-списком")
    void testSelectorIsCalled() throws Exception {
        AtomicReference<java.util.List<String>> captured = new AtomicReference<>();
        String[] protocols = {"h2", "http/1.1"};

        doSelectorLoopback(protocols, (eng, clientList) -> {
            captured.set(clientList);
            return "h2";
        });

        assertNotNull(captured.get(), "Selector should be called");
        assertEquals(java.util.List.of("h2", "http/1.1"), captured.get(),
                "Selector should receive client ALPN list");
    }

    @Test
    @DisplayName("ALPN selector: null от selector → no ALPN в EE")
    void testSelectorReturnNull() throws Exception {
        String[] protocols = {"h2", "http/1.1"};

        GostSSLEngine clientEngine = doSelectorLoopback(protocols,
                (eng, clientList) -> null);

        assertNull(clientEngine.getApplicationProtocol(),
                "null from selector should result in no ALPN");
    }

    @Test
    @DisplayName("ALPN selector: протокол не из списка клиента → SSLException")
    void testSelectorReturnInvalid() throws Exception {
        String[] protocols = {"h2", "http/1.1"};

        Exception ex = assertThrows(Exception.class, () ->
                doSelectorLoopback(protocols,
                        (eng, clientList) -> "invalid-protocol"));
        // Exception может быть обёрнут в RuntimeException из потока handshake
        boolean foundSslEx = false;
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof SSLException) { foundSslEx = true; break; }
        }
        assertTrue(foundSslEx, "Should contain SSLException in cause chain. Got: " + ex);
    }

    @Test
    @DisplayName("ALPN selector: selector побеждает applicationProtocols")
    void testSelectorWinsOverList() throws Exception {
        // Ставим selector + список — selector должен победить
        AtomicReference<java.util.List<String>> captured = new AtomicReference<>();
        String[] protocols = {"h2", "http/1.1"};

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry("default",
                org.rssys.gost.jsse.bridge.CertificateBridge.toJca(
                        java.util.List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                skm, new GostX509TrustManager(null, false),
                "server", 0, false);
        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "client", 0, true);

        // Ставим selector и список одновременно
        SSLParameters serverParams = new SSLParameters();
        serverParams.setApplicationProtocols(new String[]{"http/1.1"});
        serverEngine.setSSLParameters(serverParams);
        serverEngine.setHandshakeApplicationProtocolSelector(
                (eng, clientList) -> {
                    captured.set(clientList);
                    return "h2"; // selector выбирает h2, хотя список сервера — "http/1.1"
                });

        SSLParameters clientParams = new SSLParameters();
        clientParams.setApplicationProtocols(new String[]{"h2", "http/1.1"});
        clientEngine.setSSLParameters(clientParams);

        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        ByteBuffer netBuf = ByteBuffer.allocate(
                TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        ByteBuffer appBuf = ByteBuffer.allocate(
                TlsConstants.MAX_PLAINTEXT_LENGTH);

        // Прогоняем handshake в двух потоках
        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread = new Thread(() -> {
            try {
                doPump(clientEngine, pair, true);
            } catch (Exception e) {
                clientError.set(e);
            }
        }, "selector-client");
        Thread serverThread = new Thread(() -> {
            try {
                doPump(serverEngine, pair, false);
            } catch (Exception e) {
                serverError.set(e);
            }
        }, "selector-server");

        clientThread.start();
        serverThread.start();

        serverThread.join(500);
        if (serverError.get() != null) {
            clientThread.interrupt();
            clientThread.join(1000);
            throw new RuntimeException(serverError.get());
        }

        clientThread.join(5000);

        if (serverError.get() != null) throw new RuntimeException(serverError.get());
        if (clientError.get() != null) throw new RuntimeException(clientError.get());

        assertEquals("h2", clientEngine.getApplicationProtocol(),
                "Selector choice should win over serverAlpnProtocols");
        assertNotNull(captured.get(), "Selector should be called");
    }

    // ========================================================================
    // Хелперы
    // ========================================================================

    /**
     * Выполняет handshake с ALPN-selector на сервере.
     * <p>
     * Создаёт пару engine, ставит selector на сервер, ALPN-список на клиент,
     * прогоняет handshake в двух потоках. Возвращает clientEngine для проверки
     * согласованного протокола.
     *
     * @param protocols ALPN-протоколы клиента (по ним selector выбирает)
     * @param selector  server-side ALPN-селектор (BiFunction)
     * @return clientEngine после handshake (getApplicationProtocol доступен)
     * @throws Exception при любой ошибке handshake
     */
    private GostSSLEngine doSelectorLoopback(
            String[] protocols,
            java.util.function.BiFunction<SSLEngine,
                    java.util.List<String>, String> selector) throws Exception {

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry("default",
                org.rssys.gost.jsse.bridge.CertificateBridge.toJca(
                        java.util.List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                skm, new GostX509TrustManager(null, false),
                "server", 0, false);
        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "client", 0, true);

        serverEngine.setHandshakeApplicationProtocolSelector(selector);

        SSLParameters clientParams = new SSLParameters();
        clientParams.setApplicationProtocols(protocols);
        clientEngine.setSSLParameters(clientParams);

        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread = new Thread(() -> {
            try {
                doPump(clientEngine, pair, true);
            } catch (Exception e) {
                clientError.set(e);
            }
        }, "alpn-client");
        Thread serverThread = new Thread(() -> {
            try {
                doPump(serverEngine, pair, false);
            } catch (Exception e) {
                serverError.set(e);
            }
        }, "alpn-server");

        clientThread.start();
        serverThread.start();

        // WHY: serverError проверяется первым — см. комментарий ниже.
        serverThread.join(500);
        if (serverError.get() != null) {
            clientThread.interrupt();
            clientThread.join(1000);
            throw new RuntimeException(serverError.get());
        }

        clientThread.join(5000);

        // WHY: при невалидном ALPN протоколе сервер кидает SSLException
        // синхронно в engine.unwrap() сразу после парсинга ClientHello,
        // а клиент в это время ждёт ServerHello. Без этой проверки тест
        // маскирует реальную причину.
        if (serverError.get() != null) throw new RuntimeException(serverError.get());
        if (clientError.get() != null) throw new RuntimeException(clientError.get());

        return clientEngine;
    }

    /**
     * Цикл handshake: wrap/unwrap через in-memory transport.
     * <p>
     * isClient определяет, с какой стороны транспорта читать/писать.
     * 80 итераций — запас для параллельного handshake.
     *
     * @param engine   GostSSLEngine для pump
     * @param pair     транспортная пара
     * @param isClient true = клиентский engine, false = серверный
     * @throws Exception если handshake не завершился за 80 итераций
     */
    private void doPump(GostSSLEngine engine, InMemoryTlsTransport.Pair pair,
                        boolean isClient) throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(
                TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        ByteBuffer appBuf = ByteBuffer.allocate(
                TlsConstants.MAX_PLAINTEXT_LENGTH);

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
                        if (isClient) {
                            pair.getClientTransport().sendRecord(outData);
                        } else {
                            pair.getServerTransport().sendRecord(outData);
                        }
                    }
                    break;
                case NEED_UNWRAP:
                    byte[] inData = isClient
                            ? pair.getClientTransport().receiveRecord()
                            : pair.getServerTransport().receiveRecord();
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
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                    break;
            }
        }
        throw new RuntimeException("Handshake did not complete after 80 iterations, status="
                + engine.getHandshakeStatus());
    }
}
