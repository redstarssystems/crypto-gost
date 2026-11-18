package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Тесты ALPN-селектора фазы 5: JSSE BiFunction -> tls13 Function.
 */
@DisplayName("GostSSLEngine: выбор протокола ALPN")
class GostAlpnSelectorTest {

    private static PkixCertTestHelper.CertBundle serverCert;
    private static PkixCertTestHelper.CertBundle rootCa;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        rootCa = PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    @Test
    @DisplayName("ALPN selector: вызывается с правильным client-списком")
    void testSelectorIsCalled() throws Exception {
        AtomicReference<java.util.List<String>> captured = new AtomicReference<>();
        String[] protocols = {"h2", "http/1.1"};

        doSelectorLoopback(
                protocols,
                (eng, clientList) -> {
                    captured.set(clientList);
                    return "h2";
                });

        assertNotNull(captured.get(), "Селектор должен быть вызван");
        assertEquals(
                java.util.List.of("h2", "http/1.1"),
                captured.get(),
                "Селектор должен получить клиентский список ALPN");
    }

    @Test
    @DisplayName("ALPN selector: null от selector -> отказ, no_application_protocol (120)")
    void testSelectorReturnNull() {
        String[] protocols = {"h2", "http/1.1"};

        Exception ex =
                assertThrows(
                        Exception.class,
                        () -> doSelectorLoopback(protocols, (eng, clientList) -> null));

        assertNotNull(
                findSslException(ex), "В цепочке причин должен быть SSLException. Получено: " + ex);
        TlsException cause = findTlsException(ex);
        assertNotNull(cause, "Причиной отказа должен быть TlsException. Получено: " + ex);
        assertEquals(
                TlsConstants.ALERT_NO_APPLICATION_PROTOCOL,
                cause.getAlertCode(),
                "null от селектора должен давать алерт no_application_protocol (120)");
    }

    @Test
    @DisplayName("ALPN selector: пустая строка -> рукопожатие без ALPN, протокол \"\"")
    void testSelectorReturnEmptyContinuesWithoutAlpn() throws Exception {
        String[] protocols = {"h2", "http/1.1"};

        GostSSLEngine clientEngine = doSelectorLoopback(protocols, (eng, clientList) -> "");

        assertEquals(
                "",
                clientEngine.getApplicationProtocol(),
                "пустая строка от селектора: рукопожатие успешно, протокол не согласован");
    }

    @Test
    @DisplayName("ALPN: до рукопожатия null, без ALPN после рукопожатия пустая строка")
    void testApplicationProtocolNullBeforeAndEmptyAfterWithoutAlpn() throws Exception {
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "client",
                        0,
                        true);
        assertNull(
                clientEngine.getApplicationProtocol(), "до рукопожатия протокол ещё не определён");

        // Селектор есть, а клиент ALPN не предлагает: рукопожатие проходит без ALPN
        GostSSLEngine client = doSelectorLoopback(null, (eng, clientList) -> "h2");
        assertEquals(
                "",
                client.getApplicationProtocol(),
                "ALPN не использовался: после рукопожатия пустая строка, а не null");
    }

    @Test
    @DisplayName("ALPN selector: протокол не из списка клиента -> SSLException")
    void testSelectorReturnInvalid() throws Exception {
        String[] protocols = {"h2", "http/1.1"};

        Exception ex =
                assertThrows(
                        Exception.class,
                        () ->
                                doSelectorLoopback(
                                        protocols, (eng, clientList) -> "invalid-protocol"));
        assertNotNull(
                findSslException(ex),
                "Должен содержать SSLException в цепочке причин. Получено: " + ex);
    }

    @Test
    @DisplayName("ALPN selector: selector побеждает applicationProtocols")
    void testSelectorWinsOverList() throws Exception {
        // Ставим selector + список — selector должен победить
        AtomicReference<java.util.List<String>> captured = new AtomicReference<>();
        String[] protocols = {"h2", "http/1.1"};

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default",
                org.rssys.gost.jsse.bridge.CertificateBridge.toJca(
                        java.util.List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(skm, GostX509TrustManager.insecureTrustAll(), "server", 0, false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "client",
                        0,
                        true);

        // Ставим selector и список одновременно
        SSLParameters serverParams = new SSLParameters();
        serverParams.setApplicationProtocols(new String[] {"http/1.1"});
        serverEngine.setSSLParameters(serverParams);
        serverEngine.setHandshakeApplicationProtocolSelector(
                (eng, clientList) -> {
                    captured.set(clientList);
                    return "h2"; // selector выбирает h2, хотя список сервера — "http/1.1"
                });

        SSLParameters clientParams = new SSLParameters();
        clientParams.setApplicationProtocols(new String[] {"h2", "http/1.1"});
        clientEngine.setSSLParameters(clientParams);

        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        // Прогоняем handshake в двух потоках
        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread =
                new Thread(
                        () -> {
                            try {
                                doPump(clientEngine, pair, true);
                            } catch (Exception e) {
                                clientError.set(e);
                            }
                        },
                        "selector-client");
        Thread serverThread =
                new Thread(
                        () -> {
                            try {
                                doPump(serverEngine, pair, false);
                            } catch (Exception e) {
                                serverError.set(e);
                            }
                        },
                        "selector-server");

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

        assertEquals(
                "h2",
                clientEngine.getApplicationProtocol(),
                "Выбор селектора должен иметь приоритет над serverAlpnProtocols");
        assertNotNull(captured.get(), "Селектор должен быть вызван");
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
    @Test
    @DisplayName("setSSLParameters: плохое имя ALPN отвергается сразу, а не при рукопожатии")
    void testSetSslParametersRejectsInvalidAlpnNames() {
        GostSSLEngine engine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "client",
                        0,
                        true);
        // Пустое имя отсекает сам JDK в SSLParameters.setApplicationProtocols, длину и символы
        // выше U+00FF (не помещаются в один байт) - нет
        for (String[] invalid : new String[][] {{"x".repeat(256)}, {"h2", "h\u0100"}}) {
            SSLParameters params = new SSLParameters();
            params.setApplicationProtocols(invalid);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> engine.setSSLParameters(params),
                    "Недопустимое имя ALPN должно отвергаться при установке параметров");
        }
        SSLParameters withoutAlpn = new SSLParameters();
        engine.setSSLParameters(withoutAlpn);
    }

    private static TlsException findTlsException(Throwable ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof TlsException) {
                return (TlsException) t;
            }
        }
        return null;
    }

    /** Исключение может быть обёрнуто в RuntimeException из потока рукопожатия. */
    private static SSLException findSslException(Throwable ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof SSLException) {
                return (SSLException) t;
            }
        }
        return null;
    }

    private GostSSLEngine doSelectorLoopback(
            String[] protocols,
            java.util.function.BiFunction<SSLEngine, java.util.List<String>, String> selector)
            throws Exception {

        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager skm = new GostX509KeyManager();
        skm.addKeyEntry(
                "default",
                org.rssys.gost.jsse.bridge.CertificateBridge.toJca(
                        java.util.List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(skm, GostX509TrustManager.insecureTrustAll(), "server", 0, false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "client",
                        0,
                        true);

        serverEngine.setHandshakeApplicationProtocolSelector(selector);

        if (protocols != null) {
            SSLParameters clientParams = new SSLParameters();
            clientParams.setApplicationProtocols(protocols);
            clientEngine.setSSLParameters(clientParams);
        }

        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread =
                new Thread(
                        () -> {
                            try {
                                doPump(clientEngine, pair, true);
                            } catch (Exception e) {
                                clientError.set(e);
                            }
                        },
                        "alpn-client");
        Thread serverThread =
                new Thread(
                        () -> {
                            try {
                                doPump(serverEngine, pair, false);
                            } catch (Exception e) {
                                serverError.set(e);
                            }
                        },
                        "alpn-server");

        clientThread.start();
        serverThread.start();

        // serverError проверяется первым — см. комментарий ниже.
        serverThread.join(500);
        if (serverError.get() != null) {
            clientThread.interrupt();
            clientThread.join(1000);
            throw new RuntimeException(serverError.get());
        }

        clientThread.join(5000);

        // при невалидном ALPN протоколе сервер кидает SSLException
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
    private void doPump(GostSSLEngine engine, InMemoryTlsTransport.Pair pair, boolean isClient)
            throws Exception {
        ByteBuffer netBuf =
                ByteBuffer.allocate(
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
                        if (isClient) {
                            pair.getClientTransport().sendRecord(outData);
                        } else {
                            pair.getServerTransport().sendRecord(outData);
                        }
                    }
                    break;
                case NEED_UNWRAP:
                    byte[] inData =
                            isClient
                                    ? pair.getClientTransport().receiveRecord()
                                    : pair.getServerTransport().receiveRecord();
                    netBuf.clear();
                    netBuf.put(inData);
                    netBuf.flip();
                    appBuf.clear();
                    engine.unwrap(netBuf, appBuf);
                    break;
                case NEED_TASK:
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                    break;
            }
        }
        throw new RuntimeException(
                "Рукопожатие не завершено за 80 итераций, status=" + engine.getHandshakeStatus());
    }
}
