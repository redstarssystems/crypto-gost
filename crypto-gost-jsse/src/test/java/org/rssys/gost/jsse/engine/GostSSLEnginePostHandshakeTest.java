package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Тесты post-handshake: SessionContext, PSK resumption, KeyUpdate.
 */
@DisplayName("GostSSLEngine: сообщения после рукопожатия, KeyUpdate и PSK")
class GostSSLEnginePostHandshakeTest {

    private static TlsCiphersuite cs;
    private static ECParameters params;
    private static PkixCertTestHelper.CertBundle serverCert;
    private static PkixCertTestHelper.CertBundle rootCa;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        params = ECParameters.tc26a256();

        rootCa = PkixCertTestHelper.createRootCA(params);
        serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    // ========================================================================
    // PSK resumption — полный handshake -> NST -> PSK handshake
    // ========================================================================

    @Test
    @DisplayName("Возобновление истекло: TTL истёк -> полное повторное рукопожатие")
    void testLoopbackResumptionExpired() throws Exception {
        // Раздельные контексты клиента и сервера и один менеджер доверия: тикет привязан к
        // экземпляру менеджера, а в общем контексте записи клиента и сервера затирают друг друга
        GostSSLSessionContext serverContext = new GostSSLSessionContext(cs);
        GostSSLSessionContext clientContext = new GostSSLSessionContext(cs);
        GostX509TrustManager trust = GostX509TrustManager.insecureTrustAll();
        serverContext.setSessionTimeout(1);
        clientContext.setSessionTimeout(1);

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);

        InMemoryTlsTransport.Pair pair1 = InMemoryTlsTransport.newPair();
        GostSSLEngine server1 =
                GostSSLEngine.createForServer(
                        serverKeyManager, trust, "localhost", 0, serverContext);
        GostSSLEngine client1 =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        trust,
                        "localhost",
                        PskTestSupport.BINDING_PORT,
                        clientContext);
        doLoopback(client1, server1, pair1);

        // NST нужно доставить клиенту для проверки истечения TTL
        ByteBuffer netBufPH =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
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

        assertNotNull(
                clientContext.getForClientResumption(
                        "localhost", PskTestSupport.BINDING_PORT, client1.clientPskBinding()));

        // Срок тикета 1 с: тикет клиента старится на 1,5 с, ждать не нужно
        PskTestSupport.age(
                clientContext,
                clientContext
                        .getForClientResumption(
                                "localhost",
                                PskTestSupport.BINDING_PORT,
                                client1.clientPskBinding())
                        .getTicket(),
                1500);

        // срок тикета истёк: нужен полный handshake
        InMemoryTlsTransport.Pair pair2 = InMemoryTlsTransport.newPair();
        GostSSLEngine server2 =
                GostSSLEngine.createForServer(
                        serverKeyManager, trust, "localhost", 0, serverContext);
        GostSSLEngine client2 =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        trust,
                        "localhost",
                        PskTestSupport.BINDING_PORT,
                        clientContext);
        doLoopback(client2, server2, pair2);
        assertTrue(client2.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
        assertFalse(client2.wasResumed(), "просроченный тикет не должен возобновляться");
    }

    // ========================================================================
    // KeyUpdate — обновление ключей в рамках одной сессии
    // ========================================================================

    @Test
    @DisplayName("KeyUpdate: инициация без request, обмен данными на новых ключах")
    void testKeyUpdateOneWay() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);

        doLoopback(clientEngine, serverEngine, pair);

        // данные до KU — гарантируют, что шифрование работало до смены ключей
        sendAndReceiveAppData(clientEngine, serverEngine, pair, "before-ku");

        // ручной KU на клиенте — инициируем смену ключей
        clientEngine.initiateKeyUpdate(false);

        // KU-фрейм попадает в outgoingQueue — выталкиваем его через wrap
        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        netBuf.clear();
        clientEngine.wrap(ByteBuffer.allocate(0), netBuf);
        netBuf.flip();
        byte[] kuOut = new byte[netBuf.remaining()];
        netBuf.get(kuOut);
        pair.getClientTransport().sendRecord(kuOut);

        // сервер обрабатывает KU
        byte[] kuIn = pair.getServerTransport().receiveRecord();
        netBuf.clear();
        netBuf.put(kuIn);
        netBuf.flip();
        serverEngine.unwrap(netBuf, ByteBuffer.allocate(0));

        // данные после KU — проверяем, что шифрование работает на новых ключах
        sendAndReceiveAppData(clientEngine, serverEngine, pair, "after-ku-data");

        assertTrue(clientEngine.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"));
    }

    // ========================================================================
    // change_cipher_spec после Finished (RFC 8446 §5)
    // ========================================================================

    /** Завершённая пара движков: [0] клиент, [1] сервер. */
    private GostSSLEngine[] completedEngines() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);
        doLoopback(clientEngine, serverEngine, pair);
        return new GostSSLEngine[] {clientEngine, serverEngine};
    }

    // ========================================================================
    // Приёмный лимит max_fragment_length (RFC 6066 §4)
    // ========================================================================

    /** Завершённая пара движков с согласованным max_fragment_length = 512: [0] клиент, [1] сервер. */
    private GostSSLEngine[] completedEnginesWithFragment512() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);
        clientEngine.setClientMaxFragLenRequest(TlsConstants.MAX_FRAG_LEN_512);
        doLoopback(clientEngine, serverEngine, pair);
        assertEquals(TlsConstants.MAX_FRAG_LEN_512, clientEngine.getMaxFragmentLength());
        assertEquals(TlsConstants.MAX_FRAG_LEN_512, serverEngine.getMaxFragmentLength());
        return new GostSSLEngine[] {clientEngine, serverEngine};
    }

    /** Запись приложения, которую отправитель собрал без нарезки по согласованному лимиту. */
    private static byte[] oversizedAppRecord(GostSSLEngine sender) throws Exception {
        sender.disableSendFragmentLimitForTest();
        ByteBuffer net =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        sender.wrap(ByteBuffer.wrap(new byte[2000]), net);
        net.flip();
        byte[] record = new byte[net.remaining()];
        net.get(record);
        return record;
    }

    private static void assertRejectedAsOverflow(GostSSLEngine receiver, byte[] record) {
        javax.net.ssl.SSLException e =
                assertThrows(
                        javax.net.ssl.SSLException.class,
                        () ->
                                receiver.unwrap(
                                        ByteBuffer.wrap(record),
                                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH)),
                        "запись больше согласованного лимита должна быть отвергнута");
        assertTrue(
                String.valueOf(e.getMessage()).contains("max fragment length"),
                "причина - превышение согласованного лимита: " + e.getMessage());
    }

    @Test
    @DisplayName("max_fragment_length: запись больше лимита после рукопожатия -> SSLException")
    void testOversizedRecordRejectedAfterHandshake() throws Exception {
        GostSSLEngine[] engines = completedEnginesWithFragment512();

        assertRejectedAsOverflow(engines[1], oversizedAppRecord(engines[0]));
    }

    @Test
    @DisplayName("max_fragment_length: после KeyUpdate приёмный лимит сохраняется")
    void testOversizedRecordRejectedAfterKeyUpdate() throws Exception {
        GostSSLEngine[] engines = completedEnginesWithFragment512();
        GostSSLEngine client = engines[0];
        GostSSLEngine server = engines[1];

        client.initiateKeyUpdate(false);
        ByteBuffer net =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        client.wrap(ByteBuffer.allocate(0), net);
        net.flip();
        server.unwrap(net, ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));

        assertRejectedAsOverflow(server, oversizedAppRecord(client));
    }

    @Test
    @DisplayName(
            "CCS после Finished отвергается: SSLException(unexpected_message) на обеих сторонах")
    void testCcsAfterFinishedRejected() throws Exception {
        byte[] ccs =
                GostSSLEngine.buildPlaintextRecord(
                        TlsConstants.CT_CHANGE_CIPHER_SPEC, new byte[] {0x01});

        GostSSLEngine[] first = completedEngines();
        assertThrows(
                javax.net.ssl.SSLException.class,
                () ->
                        first[1].unwrap(
                                ByteBuffer.wrap(ccs),
                                ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH)),
                "сервер: CCS после Finished клиента недопустим");

        GostSSLEngine[] second = completedEngines();
        assertThrows(
                javax.net.ssl.SSLException.class,
                () ->
                        second[0].unwrap(
                                ByteBuffer.wrap(ccs),
                                ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH)),
                "клиент: CCS после Finished сервера недопустим");
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    /** Выполняет рукопожатие двух движков через общий хелпер. */
    private void doLoopback(
            GostSSLEngine clientEngine, GostSSLEngine serverEngine, InMemoryTlsTransport.Pair pair)
            throws Exception {
        GostSSLEngineLoopbackTest.doLoopback(clientEngine, serverEngine, pair);
    }

    // ========================================================================
    // KeyUpdate при пониженном пороге rekey
    // ========================================================================

    @Test
    @DisplayName("KeyUpdate: пониженный порог -> auto-initiate KU при wrap")
    void testKeyUpdateThreshold() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);

        doLoopback(clientEngine, serverEngine, pair);

        // пониженный порог — тестируем auto-KU без прогона триллионов записей
        clientEngine.setRekeyThresholdForTest(5);

        // 7 записей — после 5-й auto-KU срабатывает, KU-фрейм в outgoingQueue
        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
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

            // сервер читает каждый фрейм — обрабатывает KU в том числе
            byte[] serverIn = pair.getServerTransport().receiveRecord();
            if (serverIn != null) {
                netBuf.clear();
                netBuf.put(serverIn);
                netBuf.flip();
                appBuf.clear();
                serverEngine.unwrap(netBuf, appBuf);
            }
        }

        // KU был обработан на сервере — см. testKeyUpdateOneWay
        assertTrue(
                serverEngine.getPeerKeyUpdateCountForTest() > 0,
                "Сервер должен получить хотя бы один KeyUpdate");
    }

    // ========================================================================
    // Bidirectional KU (RFC 8446 §4.6.3, update_requested=true)
    // ========================================================================

    @Test
    @DisplayName("Двунаправленный KU — update_requested=true, обе стороны обмениваются KU")
    void testBidirectionalKeyUpdate() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);

        doLoopback(clientEngine, serverEngine, pair);

        // Данные до KU — проверяем базовое шифрование
        sendAndReceiveAppData(clientEngine, serverEngine, pair, "pre-ku-data");

        // Клиент: инициируем KU с update_requested=true
        clientEngine.initiateKeyUpdate(true);

        // Выталкиваем KU-фрейм клиента
        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
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
        assertTrue(serverKuOut.length > 0, "Сервер должен ответить своим KU-фреймом");
        pair.getServerTransport().sendRecord(serverKuOut);

        // Клиент: получает ответный KU сервера
        byte[] clientIn = pair.getClientTransport().receiveRecord();
        assertNotNull(clientIn, "Клиент должен получить KU-фрейм сервера");
        netBuf.clear();
        netBuf.put(clientIn);
        netBuf.flip();
        clientEngine.unwrap(netBuf, ByteBuffer.allocate(0));

        // Оба должны иметь peerKeyUpdateCount == 1 (каждый получил один KU)
        assertEquals(
                1,
                serverEngine.getPeerKeyUpdateCountForTest(),
                "Сервер должен получить 1 KU от клиента");
        assertEquals(
                1,
                clientEngine.getPeerKeyUpdateCountForTest(),
                "Клиент должен получить 1 KU от сервера (ответный)");

        // Данные после KU — проверяем шифрование на новых ключах
        sendAndReceiveAppData(clientEngine, serverEngine, pair, "post-ku-data");
    }

    /** Забирает одну запись, которую движок готов отдать в сеть; пустой массив, если отдавать нечего. */
    private static byte[] wrapRecord(GostSSLEngine engine) throws Exception {
        ByteBuffer net =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        engine.wrap(ByteBuffer.allocate(0), net);
        net.flip();
        byte[] record = new byte[net.remaining()];
        net.get(record);
        return record;
    }

    private static void unwrapRecord(GostSSLEngine engine, byte[] record) throws Exception {
        engine.unwrap(
                ByteBuffer.wrap(record), ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
    }

    @Test
    @DisplayName(
            "Два update_requested подряд до wrap(): один ответный KU, обмен продолжается в обе стороны")
    void testTwoPeerKeyUpdateRequestsGiveSingleResponse() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);
        doLoopback(clientEngine, serverEngine, pair);
        sendAndReceiveAppData(clientEngine, serverEngine, pair, "до обновления");

        // Клиент подряд посылает два KeyUpdate(update_requested): каждый wrap() подтверждает свой
        clientEngine.initiateKeyUpdate(true);
        byte[] firstRequest = wrapRecord(clientEngine);
        clientEngine.initiateKeyUpdate(true);
        byte[] secondRequest = wrapRecord(clientEngine);

        // Сервер принимает оба до своего wrap(): подтверждение смены ключа откладывается до него
        unwrapRecord(serverEngine, firstRequest);
        unwrapRecord(serverEngine, secondRequest);

        List<byte[]> responses = new java.util.ArrayList<>();
        for (byte[] record = wrapRecord(serverEngine);
                record.length > 0;
                record = wrapRecord(serverEngine)) {
            responses.add(record);
        }
        assertEquals(1, responses.size(), "На два запроса подряд должен уйти один ответный KU");
        for (byte[] response : responses) {
            unwrapRecord(clientEngine, response);
        }

        // Ключи сторон согласованы: второй ответ сдвинул бы ключ чтения клиента лишний раз
        sendAndReceiveAppData(serverEngine, clientEngine, pair, "от сервера");
        sendAndReceiveAppData(clientEngine, serverEngine, pair, "от клиента");
    }

    // ========================================================================
    // Rate-limit входящих KeyUpdate (hardening против флуда, RFC 8446bis)
    // ========================================================================

    @Test
    @DisplayName("KeyUpdate rate-limit: флуд входящих KU -> SSLException(unexpected_message)")
    void testKeyUpdateRateLimit() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostX509KeyManager serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);

        GostSSLEngine serverEngine =
                new GostSSLEngine(
                        serverKeyManager,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        false);
        GostSSLEngine clientEngine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);

        doLoopback(clientEngine, serverEngine, pair);

        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        // Клиент шлёт KU потоком (update_requested=false, ответ не требуется), сервер
        // принимает подряд. Цикл укладывается в окно rate-limit -> флуд отсекается.
        SSLException thrown = null;
        int accepted = 0;
        for (int i = 0; i < 30; i++) {
            clientEngine.initiateKeyUpdate(false);
            netBuf.clear();
            clientEngine.wrap(ByteBuffer.allocate(0), netBuf);
            netBuf.flip();
            byte[] ku = new byte[netBuf.remaining()];
            netBuf.get(ku);
            if (ku.length == 0) continue;
            pair.getClientTransport().sendRecord(ku);

            byte[] serverIn = pair.getServerTransport().receiveRecord();
            if (serverIn == null) continue;
            netBuf.clear();
            netBuf.put(serverIn);
            netBuf.flip();
            appBuf.clear();
            try {
                serverEngine.unwrap(netBuf, appBuf);
                accepted++;
            } catch (SSLException e) {
                thrown = e;
                break;
            }
        }

        assertNotNull(thrown, "Флуд KeyUpdate должен привести к SSLException");
        assertTrue(
                thrown.getMessage().toLowerCase().contains("rate limit")
                        || thrown.getMessage().toLowerCase().contains("unexpected"),
                "Сообщение должно указывать на превышение лимита: " + thrown.getMessage());
        assertTrue(
                accepted >= 10,
                "До срабатывания лимита легитимные KU должны приниматься, принято: " + accepted);
        // Окно держит движок и проверяет сообщение до обработки: отвергнутый KeyUpdate ни ключей,
        // ни счётчика не сдвигает
        assertEquals(
                accepted,
                serverEngine.getPeerKeyUpdateCountForTest(),
                "Отвергнутый KeyUpdate не должен попадать в счётчик принятых");
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
    private void sendAndReceiveAppData(
            GostSSLEngine sender,
            GostSSLEngine receiver,
            InMemoryTlsTransport.Pair pair,
            String data)
            throws Exception {
        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
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
        assertNotNull(
                received, "Ожидаемые данные приложения на " + (isClient ? "сервере" : "клиенте"));

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
