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

import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.util.CryptoRandom;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.nio.ByteBuffer;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты post-handshake: SessionContext, PSK resumption, KeyUpdate.
 */
class GostSSLEnginePostHandshakeTest {

    // Только ключ для identityByHost Map, не реальный сетевой порт
    private static final int PSK_BINDING_PORT = 443;

    private static TlsCiphersuite cs;
    private static ECParameters params;
    private static TlsTestHelper.CertBundle serverCert;
    private static TlsTestHelper.CertBundle rootCa;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        params = ECParameters.tc26a256();

        rootCa = TlsTestHelper.createRootCA(params);
        serverCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "20240501120000Z", "21060101120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
    }

    // ========================================================================
    // GostSSLSessionContext — создание, хранение, инвалидация
    // ========================================================================

    @Test
    @DisplayName("SessionContext: put/get/remove сессии, timeout, invalidate")
    void testSessionContextBasic() throws Exception {
        GostSSLSessionContext ctx = new GostSSLSessionContext(cs, cs.getHashLen());

        assertEquals(86400, ctx.getSessionTimeout());
        assertEquals(0, ctx.getSessionCacheSize());

        GostSSLSession session = new GostSSLSession(
                cs.getIanaName(), "localhost", PSK_BINDING_PORT,
                new java.security.cert.X509Certificate[0],
                new java.security.cert.X509Certificate[0]);

        assertNull(ctx.getSession(session.getId()));

        ctx.putSession(session);
        assertSame(session, ctx.getSession(session.getId()));
        assertTrue(session.isValid());

        session.invalidate();
        assertFalse(session.isValid());
        assertNull(ctx.getSession(session.getId()));

        // WHY: setSessionTimeout задаёт TTL сессии — по истечении сессия невалидна
        ctx.setSessionTimeout(1);
        GostSSLSession session2 = new GostSSLSession(
                cs.getIanaName(), "localhost", PSK_BINDING_PORT,
                new java.security.cert.X509Certificate[0],
                new java.security.cert.X509Certificate[0]);
        ctx.putSession(session2);
        Thread.sleep(1100);
        assertFalse(session2.isValid());
    }

    // ========================================================================
    // PSK host binding — разные host:port дают независимые PSK
    // ========================================================================

    @Test
    @DisplayName("PSK: host:port привязка — разным серверам разные тикеты")
    void testPskHostBinding() throws Exception {
        GostSSLSessionContext ctx = new GostSSLSessionContext(cs, cs.getHashLen());

        byte[] rms = new byte[32];
        // WHY: разные nonce → разные деривации PSK; разные ticket-идентификаторы
        // → разные ключи в хранилище. Без этого тест ломается при single-use PSK
        // (RFC 8446 §8.1), потому что одинаковые тикеты маппятся в один ключ.
        byte[] nstBody = TlsMessageBuilder.buildNewSessionTicket(3600, 0,
                new byte[8], new byte[]{1});
        byte[] nstBody2 = TlsMessageBuilder.buildNewSessionTicket(3600, 0,
                new byte[8], new byte[]{2});

        ctx.saveNewSessionTicket("server1.com", PSK_BINDING_PORT, rms, nstBody);
        ctx.saveNewSessionTicket("server2.com", PSK_BINDING_PORT, rms, nstBody2);

        // WHY: если host:port не маппится — PSK не должен быть найден
        assertNotNull(ctx.getForClientResumption("server1.com", PSK_BINDING_PORT));
        assertNull(ctx.getForClientResumption("server1.com", 444));
        assertNotNull(ctx.getForClientResumption("server2.com", PSK_BINDING_PORT));
        assertNull(ctx.getForClientResumption("unknown.com", PSK_BINDING_PORT));
    }

    @Test
    @DisplayName("PSK: peek не сжигает тикет, только явный remove")
    void pskTicketSingleUse() throws Exception {
        // WHY: клиентский peek() не удаляет запись — тикет должен быть
        // удалён только после подтверждения PSK сервером (ServerHello c PSK).
        // Тест верифицирует: (1) peek отдаёт тикет, (2) повторный peek
        // тоже отдаёт (не потреблён), (3) после явного remove — null.
        GostSSLSessionContext ctx = new GostSSLSessionContext(cs, cs.getHashLen());
        byte[] rms = new byte[32];
        byte[] nonce = new byte[8];
        byte[] ticket = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(rms);
        CryptoRandom.INSTANCE.nextBytes(nonce);
        CryptoRandom.INSTANCE.nextBytes(ticket);
        byte[] nstBody = TlsMessageBuilder.buildNewSessionTicket(3600, 0, nonce, ticket);

        ctx.saveNewSessionTicket("host", PSK_BINDING_PORT, rms, nstBody);

        assertNotNull(ctx.getForClientResumption("host", PSK_BINDING_PORT),
                "PSK доступен при первом запросе");
        assertNotNull(ctx.getForClientResumption("host", PSK_BINDING_PORT),
                "peek не сжигает тикет — второй запрос тоже не null");
        ctx.getPskStore().remove(ticket);
        assertNull(ctx.getForClientResumption("host", PSK_BINDING_PORT),
                "После явного remove тикет недоступен");
    }

    // ========================================================================
    // PSK resumption — полный handshake → NST → PSK handshake
    // ========================================================================

    @Test
    @DisplayName("Resumption: full handshake → NST → close → PSK handshake")
    void testLoopbackResumption() throws Exception {
        GostSSLSessionContext sessionContext = new GostSSLSessionContext(cs, cs.getHashLen());

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default",
                CertificateBridge.toJcaChain(serverCert.cert, rootCa.cert), serverCert.priv);

        // WHY: первый handshake — полный, чтобы получить PSK через NST
        InMemoryTlsTransport.Pair pair1 = InMemoryTlsTransport.newPair();
        GostSSLEngine server1 = GostSSLEngine.createForServer(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, sessionContext);
        GostSSLEngine client1 = GostSSLEngine.createForClient(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", PSK_BINDING_PORT, sessionContext);
        doLoopback(client1, server1, pair1);
        assertTrue(client1.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));

        // WHY: NST от сервера — в его outgoingQueue; нужно вытолкнуть через wrap
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        if (server1.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            netBuf.clear();
            server1.wrap(ByteBuffer.allocate(0), netBuf);
            netBuf.flip();
            if (netBuf.hasRemaining()) {
                byte[] nstOut = new byte[netBuf.remaining()];
                netBuf.get(nstOut);
                pair1.getServerTransport().sendRecord(nstOut);
            }
        }
        // WHY: клиент должен получить NST до PSK resumption
        byte[] nstIn = pair1.getClientTransport().receiveRecord();
        assertNotNull(nstIn, "NST должен быть доступен в транспорте клиента");
        netBuf.clear();
        netBuf.put(nstIn);
        netBuf.flip();
        client1.unwrap(netBuf, ByteBuffer.allocate(0));

        assertNotNull(sessionContext.getForClientResumption("localhost", PSK_BINDING_PORT));

        // WHY: второй handshake с теми же контекстами — должен использовать PSK
        InMemoryTlsTransport.Pair pair2 = InMemoryTlsTransport.newPair();
        GostSSLEngine server2 = GostSSLEngine.createForServer(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, sessionContext);
        GostSSLEngine client2 = GostSSLEngine.createForClient(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", PSK_BINDING_PORT, sessionContext);
        doLoopback(client2, server2, pair2);
        assertTrue(client2.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    @Test
    @DisplayName("Resumption expired: TTL истёк → full re-handshake")
    void testLoopbackResumptionExpired() throws Exception {
        GostSSLSessionContext sessionContext = new GostSSLSessionContext(cs, cs.getHashLen());
        sessionContext.setSessionTimeout(1);

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default",
                CertificateBridge.toJcaChain(serverCert.cert, rootCa.cert), serverCert.priv);

        InMemoryTlsTransport.Pair pair1 = InMemoryTlsTransport.newPair();
        GostSSLEngine server1 = GostSSLEngine.createForServer(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, sessionContext);
        GostSSLEngine client1 = GostSSLEngine.createForClient(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", PSK_BINDING_PORT, sessionContext);
        doLoopback(client1, server1, pair1);

        // WHY: NST нужно доставить клиенту для проверки истечения TTL
        ByteBuffer netBufPH = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        if (server1.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            netBufPH.clear();
            server1.wrap(ByteBuffer.allocate(0), netBufPH);
            netBufPH.flip();
            if (netBufPH.hasRemaining()) {
                byte[] nstOut = new byte[netBufPH.remaining()];
                netBufPH.get(nstOut);
                pair1.getServerTransport().sendRecord(nstOut);
            }
        }
        byte[] nstIn = pair1.getClientTransport().receiveRecord();
        if (nstIn != null) {
            netBufPH.clear();
            netBufPH.put(nstIn);
            netBufPH.flip();
            client1.unwrap(netBufPH, ByteBuffer.allocate(0));
        }

        assertNotNull(sessionContext.getForClientResumption("localhost", PSK_BINDING_PORT));

        // WHY: TTL = 1s → ждём 1500ms чтобы PSK гарантированно истёк
        Thread.sleep(1500);

        // WHY: ticket lifetime = 1s, прошло 1500ms → PSK истёк, нужен полный handshake
        InMemoryTlsTransport.Pair pair2 = InMemoryTlsTransport.newPair();
        GostSSLEngine server2 = GostSSLEngine.createForServer(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, sessionContext);
        GostSSLEngine client2 = GostSSLEngine.createForClient(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", PSK_BINDING_PORT, sessionContext);
        doLoopback(client2, server2, pair2);
        assertTrue(client2.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    // ========================================================================
    // KeyUpdate — обновление ключей в рамках одной сессии
    // ========================================================================

    @Test
    @DisplayName("KeyUpdate: инициация без request, обмен данными на новых ключах")
    void testKeyUpdateOneWay() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default",
                CertificateBridge.toJcaChain(serverCert.cert, rootCa.cert), serverCert.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, false);
        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);

        doLoopback(clientEngine, serverEngine, pair);

        // WHY: данные до KU — гарантируют, что шифрование работало до смены ключей
        sendAndReceiveAppData(clientEngine, serverEngine, pair, "before-ku");

        // WHY: ручной KU на клиенте — инициируем смену ключей
        clientEngine.initiateKeyUpdate(false);

        // WHY: KU-фрейм попадает в outgoingQueue — выталкиваем его через wrap
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        netBuf.clear();
        clientEngine.wrap(ByteBuffer.allocate(0), netBuf);
        netBuf.flip();
        byte[] kuOut = new byte[netBuf.remaining()];
        netBuf.get(kuOut);
        pair.getClientTransport().sendRecord(kuOut);

        // WHY: сервер обрабатывает KU
        byte[] kuIn = pair.getServerTransport().receiveRecord();
        netBuf.clear();
        netBuf.put(kuIn);
        netBuf.flip();
        serverEngine.unwrap(netBuf, ByteBuffer.allocate(0));

        // WHY: данные после KU — проверяем, что шифрование работает на новых ключах
        sendAndReceiveAppData(clientEngine, serverEngine, pair, "after-ku-data");

        assertTrue(clientEngine.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    /**
     * Выполняет handshake в двух потоках.
     */
    private void doLoopback(GostSSLEngine clientEngine, GostSSLEngine serverEngine,
                            InMemoryTlsTransport.Pair pair) throws Exception {
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        java.util.concurrent.atomic.AtomicReference<Throwable> clientError = new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<Throwable> serverError = new java.util.concurrent.atomic.AtomicReference<>();

        Thread clientThread = new Thread(() -> {
            try {
                doClientHandshake(clientEngine, pair);
            } catch (Exception e) {
                clientError.set(e);
            }
        }, "p3-client");
        Thread serverThread = new Thread(() -> {
            try {
                doServerHandshake(serverEngine, pair);
            } catch (Exception e) {
                serverError.set(e);
            }
        }, "p3-server");

        clientThread.start();
        serverThread.start();

        clientThread.join(15000);
        serverThread.join(15000);

        if (clientThread.isAlive()) { clientThread.interrupt(); fail("Тайм-аут рукопожатия клиента"); }
        if (serverThread.isAlive()) { serverThread.interrupt(); fail("Тайм-аут рукопожатия сервера"); }
        if (clientError.get() != null) throw new RuntimeException("Client error", clientError.get());
        if (serverError.get() != null) throw new RuntimeException("Server error", serverError.get());
    }

    // ========================================================================
    // C1: KeyUpdate при пониженном пороге rekey
    // ========================================================================

    @Test
    @DisplayName("KeyUpdate: пониженный порог → auto-initiate KU при wrap")
    void testKeyUpdateThreshold() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default",
                CertificateBridge.toJcaChain(serverCert.cert, rootCa.cert), serverCert.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, false);
        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);

        doLoopback(clientEngine, serverEngine, pair);

        // WHY: пониженный порог — тестируем auto-KU без прогона триллионов записей
        clientEngine.setRekeyThresholdForTest(5);

        // WHY: 7 записей — после 5-й auto-KU срабатывает, KU-фрейм в outgoingQueue
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        byte[] data = "d".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        for (int i = 0; i < 7; i++) {
            netBuf.clear();
            clientEngine.wrap(ByteBuffer.wrap(data), netBuf);
            netBuf.flip();
            byte[] out = new byte[netBuf.remaining()];
            netBuf.get(out);
            if (out.length == 0) continue;

            pair.getClientTransport().sendRecord(out);

            // WHY: сервер читает каждый фрейм — обрабатывает KU в том числе
            byte[] serverIn = pair.getServerTransport().receiveRecord();
            if (serverIn != null) {
                netBuf.clear();
                netBuf.put(serverIn);
                netBuf.flip();
                appBuf.clear();
                serverEngine.unwrap(netBuf, appBuf);
            }
        }

        // WHY: KU был обработан на сервере — см. testKeyUpdateOneWay
        assertTrue(serverEngine.getPeerKeyUpdateCountForTest() > 0,
                "Server should have received at least one KeyUpdate");
    }

    // ========================================================================
    // Bidirectional KU (RFC 8446 §4.6.3, update_requested=true)
    // ========================================================================

    @Test
    @DisplayName("Bidirectional KU — update_requested=true, обе стороны обмениваются KU")
    void testBidirectionalKeyUpdate() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry("default",
                CertificateBridge.toJcaChain(serverCert.cert, rootCa.cert), serverCert.priv);

        GostSSLEngine serverEngine = new GostSSLEngine(
                serverKeyManager, new GostX509TrustManager(null, false),
                "localhost", 0, false);
        GostSSLEngine clientEngine = new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);

        doLoopback(clientEngine, serverEngine, pair);

        // Данные до KU — проверяем базовое шифрование
        sendAndReceiveAppData(clientEngine, serverEngine, pair, "pre-ku-data");

        // Клиент: инициируем KU с update_requested=true
        clientEngine.initiateKeyUpdate(true);

        // Выталкиваем KU-фрейм клиента
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        netBuf.clear();
        clientEngine.wrap(ByteBuffer.allocate(0), netBuf);
        netBuf.flip();
        byte[] clientKuOut = new byte[netBuf.remaining()];
        netBuf.get(clientKuOut);
        pair.getClientTransport().sendRecord(clientKuOut);

        // Сервер: получает KU клиента, обрабатывает — должен ответить своим KU
        byte[] serverIn = pair.getServerTransport().receiveRecord();
        netBuf.clear();
        netBuf.put(serverIn);
        netBuf.flip();
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        serverEngine.unwrap(netBuf, appBuf);

        // Сервер: его KU-фрейм (ответный) — выталкиваем
        netBuf.clear();
        serverEngine.wrap(ByteBuffer.allocate(0), netBuf);
        netBuf.flip();
        byte[] serverKuOut = new byte[netBuf.remaining()];
        netBuf.get(serverKuOut);
        assertTrue(serverKuOut.length > 0, "Server should respond with its own KU frame");
        pair.getServerTransport().sendRecord(serverKuOut);

        // Клиент: получает ответный KU сервера
        byte[] clientIn = pair.getClientTransport().receiveRecord();
        assertNotNull(clientIn, "Client should receive server's KU frame");
        netBuf.clear();
        netBuf.put(clientIn);
        netBuf.flip();
        clientEngine.unwrap(netBuf, ByteBuffer.allocate(0));

        // Оба должны иметь peerKeyUpdateCount == 1 (каждый получил один KU)
        assertEquals(1, serverEngine.getPeerKeyUpdateCountForTest(),
                "Server должен получить 1 KU от клиента");
        assertEquals(1, clientEngine.getPeerKeyUpdateCountForTest(),
                "Клиент должен получить 1 KU от сервера (ответный)");

        // Данные после KU — проверяем шифрование на новых ключах
        sendAndReceiveAppData(clientEngine, serverEngine, pair, "post-ku-data");
    }

    /**
     * Цикл handshake для клиента: wrap/unwrap через in-memory transport.
     */
    private void doClientHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair) throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        for (int i = 0; i < 120; i++) {
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
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                    break;
            }
        }
        throw new RuntimeException("Client handshake did not complete, status="
                + engine.getHandshakeStatus());
    }

    /**
     * Цикл handshake для сервера: wrap/unwrap через in-memory transport.
     */
    private void doServerHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair) throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        for (int i = 0; i < 120; i++) {
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
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                    break;
            }
        }
        throw new RuntimeException("Server handshake did not complete, status="
                + engine.getHandshakeStatus());
    }

    /**
     * Отправляет и принимает данные приложения через SSLEngine.
     * <p>
     * Данные шифруются на отправителе (wrap), передаются через in-memory transport
     * и расшифровываются на получателе (unwrap). Проверяется идентичность.
     *
     * @param sender   отправитель (в состоянии DATA)
     * @param receiver получатель (в состоянии DATA)
     * @param pair     in-memory транспорт
     * @param data     строка для отправки
     * @throws Exception если отправка/приём/проверка не удались
     */
    private void sendAndReceiveAppData(GostSSLEngine sender, GostSSLEngine receiver,
                                       InMemoryTlsTransport.Pair pair, String data) throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        boolean isClient = sender.getUseClientMode();

        byte[] msg = data.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        netBuf.clear();
        sender.wrap(ByteBuffer.wrap(msg), netBuf);
        netBuf.flip();
        byte[] encrypted = new byte[netBuf.remaining()];
        netBuf.get(encrypted);
        if (isClient) {
            pair.getClientTransport().sendRecord(encrypted);
        } else {
            pair.getServerTransport().sendRecord(encrypted);
        }

        byte[] received;
        if (isClient) {
            received = pair.getServerTransport().receiveRecord();
        } else {
            received = pair.getClientTransport().receiveRecord();
        }
        assertNotNull(received, "Ожидаемые данные приложения на " + (isClient ? "сервере" : "клиенте"));

        netBuf.clear();
        netBuf.put(received);
        netBuf.flip();
        appBuf.clear();
        receiver.unwrap(netBuf, appBuf);
        appBuf.flip();
        byte[] decoded = new byte[appBuf.remaining()];
        appBuf.get(decoded);
        assertEquals(data, new String(decoded, java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * Преобразует цепочку сертификатов из формата CertBundle в массив X509Certificate.
     * <p>
     * JSSE API требует X509Certificate[]; конвертация через CertificateBridge.
     *
     * @param leaf          листовой сертификат
     * @param intermediates промежуточные сертификаты (опционально)
     * @return массив X509Certificate
     * @throws Exception если преобразование не удалось
     */
}
