package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
 * Контракт закрытия {@link GostSSLEngine}: штатное закрытие даёт {@code CLOSED}, а не исключение;
 * данные, расшифрованные до закрытия, выдаются раньше {@code CLOSED}; после отказа исключение
 * остаётся, а невыданные данные затираются.
 */
@DisplayName("GostSSLEngine: контракт закрытия (CLOSED, невыданные данные, отказ)")
class GostSSLEngineCloseContractTest {

    private static final int BIG_BUFFER =
            4 * (TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);

    private static TlsCiphersuite suite;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
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
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
    }

    private record Peers(GostSSLEngine client, GostSSLEngine server) {}

    private static Peers establish() throws Exception {
        GostSSLEngine client =
                GostSSLEngine.createForClientNoHostnameCheck(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        new GostSSLSessionContext(suite));
        GostSSLEngine server =
                GostSSLEngine.createForServer(
                        serverKm,
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        new GostSSLSessionContext(suite));
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngineLoopbackTest.doLoopback(client, server, pair);
        // записи, отправленные после завершения потоков рукопожатия (билеты сервера), остаются в
        // очередях: без их приёма номера записей у сторон разойдутся
        deliverQueued(pair.getServerToClientQueue(), client);
        deliverQueued(pair.getClientToServerQueue(), server);
        return new Peers(client, server);
    }

    private static ByteBuffer network() {
        return ByteBuffer.allocate(BIG_BUFFER);
    }

    private static byte[] wrapped(GostSSLEngine engine, byte[] payload) throws SSLException {
        ByteBuffer out = network();
        engine.wrap(ByteBuffer.wrap(payload), out);
        out.flip();
        byte[] record = new byte[out.remaining()];
        out.get(record);
        return record;
    }

    private static void deliverQueued(
            java.util.concurrent.LinkedBlockingQueue<byte[]> queue, GostSSLEngine receiver)
            throws SSLException {
        byte[] record;
        while ((record = queue.poll()) != null) {
            receiver.unwrap(
                    ByteBuffer.wrap(record),
                    ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
        }
    }

    @Test
    @DisplayName("Закрытие до рукопожатия: close_notify открытой записью, isOutboundDone по отдаче")
    void closeOutboundBeforeHandshakeDeliversPlaintextCloseNotify() {
        GostSSLEngine engine =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);

        engine.closeOutbound();
        assertFalse(engine.isOutboundDone(), "до рукопожатия есть что отдавать");

        SSLEngineResult result = unchecked(() -> engine.wrap(ByteBuffer.allocate(0), network()));
        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        assertTrue(result.bytesProduced() > 0, "открытый close_notify отдан");
        assertTrue(engine.isOutboundDone(), "после отдачи закрыто");
    }

    @Test
    @DisplayName(
            "Отвечать нечем (ключей записи нет): closeOutbound закрывает выходную сторону сразу")
    void nothingToAnswerClosesOutboundImmediately() throws Exception {
        Peers peers = establish();

        peers.server().closeInbound();
        assertTrue(
                peers.server().isOutboundDone(),
                "после closeInbound() ключей записи нет, wrap() нечего отдавать");
        peers.server().closeOutbound();

        assertTrue(
                peers.server().isOutboundDone(),
                "close_notify отправить нечем: закрытие завершено без отдачи");
        // цикл «пока не isOutboundDone() - wrap()» завершается
        int guard = 0;
        while (!peers.server().isOutboundDone() && guard++ < 3) {
            peers.server().wrap(ByteBuffer.allocate(0), network());
        }
        assertEquals(0, guard, "цикл wrap не должен выполняться ни разу");
        SSLEngineResult result = peers.server().wrap(ByteBuffer.allocate(0), network());
        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        assertEquals(0, result.bytesProduced());
    }

    @Test
    @DisplayName(
            "close_notify пира: unwrap даёт CLOSED, повторный unwrap тоже CLOSED без исключения")
    void peerCloseNotifyGivesClosedWithoutException() throws Exception {
        Peers peers = establish();
        peers.client().closeOutbound();
        ByteBuffer closing = network();
        peers.client().wrap(ByteBuffer.allocate(0), closing);
        closing.flip();

        SSLEngineResult first =
                peers.server()
                        .unwrap(closing, ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
        SSLEngineResult second =
                peers.server()
                        .unwrap(
                                ByteBuffer.allocate(0),
                                ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));

        assertEquals(SSLEngineResult.Status.CLOSED, first.getStatus());
        assertEquals(SSLEngineResult.Status.CLOSED, second.getStatus());
        assertTrue(peers.server().isInboundDone());
    }

    @Test
    @DisplayName("close_notify пира: запись, не поместившаяся в буфер, доставляется до CLOSED")
    void rejectedRecordIsDeliveredBeforeClosedOnPeerCloseNotify() throws Exception {
        Peers peers = establish();
        ByteBuffer wire = network();
        wire.put(wrapped(peers.client(), "0123456789".getBytes()));
        peers.client().closeOutbound();
        peers.client().wrap(ByteBuffer.allocate(0), wire);
        wire.flip();

        // получатель выделил буфер меньше записи: запись целиком остаётся во входе, движок
        // не держит открытый текст между вызовами
        ByteBuffer small = ByteBuffer.allocate(4);
        SSLEngineResult overflow = peers.server().unwrap(wire, small);
        assertEquals(SSLEngineResult.Status.BUFFER_OVERFLOW, overflow.getStatus());
        assertEquals(0, overflow.bytesConsumed(), "запись не потреблена");
        assertEquals(0, small.position(), "частичная выдача недопустима");

        ByteBuffer rest = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLEngineResult data = peers.server().unwrap(wire, rest);
        assertEquals(SSLEngineResult.Status.OK, data.getStatus());
        assertEquals(10, data.bytesProduced(), "запись выдана целиком");
        rest.flip();
        byte[] restBytes = new byte[rest.remaining()];
        rest.get(restBytes);
        assertArrayEquals("0123456789".getBytes(), restBytes, "данные не потеряны и не искажены");
        assertFalse(peers.server().isInboundDone(), "close_notify ещё не обработан");

        SSLEngineResult closed =
                peers.server().unwrap(wire, ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
        assertEquals(SSLEngineResult.Status.CLOSED, closed.getStatus());
        assertTrue(peers.server().isInboundDone(), "после close_notify входная сторона завершена");
    }

    @Test
    @DisplayName(
            "Данные перед close_notify без места в буфере: CLOSED не выдаётся, пока их не приняли")
    void closedIsNotReportedWhileRecordIsWaitingForSpace() throws Exception {
        Peers peers = establish();
        ByteBuffer wire = network();
        wire.put(wrapped(peers.client(), "0123456789".getBytes()));
        peers.client().closeOutbound();
        peers.client().wrap(ByteBuffer.allocate(0), wire);
        wire.flip();
        int before = wire.position();

        // пустой буфер получателя: данные выдать некуда, close_notify за ними не разбирается
        SSLEngineResult noRoom = peers.server().unwrap(wire, ByteBuffer.allocate(0));
        assertEquals(
                SSLEngineResult.Status.BUFFER_OVERFLOW,
                noRoom.getStatus(),
                "запись ждёт места: терминальный статус потерял бы данные");
        assertEquals(before, wire.position(), "вход не сдвинут");
        assertFalse(peers.server().isInboundDone(), "запись ждёт получателя");

        SSLEngineResult data = peers.server().unwrap(wire, ByteBuffer.allocate(16));
        assertEquals(SSLEngineResult.Status.OK, data.getStatus(), "запись принята целиком");
        assertEquals(10, data.bytesProduced());

        SSLEngineResult done = peers.server().unwrap(wire, ByteBuffer.allocate(16));
        assertEquals(SSLEngineResult.Status.CLOSED, done.getStatus(), "теперь close_notify");
        assertTrue(peers.server().isInboundDone());
    }

    @Test
    @DisplayName("closeInbound() после close_notify пира: буфер расшифровки затёрт")
    void closeInboundAfterPeerCloseNotifyWipesDecryptBuffer() throws Exception {
        Peers peers = establish();
        ByteBuffer wire = network();
        wire.put(wrapped(peers.client(), "0123456789".getBytes()));
        peers.client().closeOutbound();
        peers.client().wrap(ByteBuffer.allocate(0), wire);
        wire.flip();
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        peers.server().unwrap(wire, dst);
        peers.server().unwrap(wire, dst);
        assertTrue(peers.server().isInboundDone(), "предусловие: close_notify принят");

        peers.server().closeInbound();

        SSLEngineResult after = peers.server().unwrap(ByteBuffer.allocate(0), dst);
        assertEquals(SSLEngineResult.Status.CLOSED, after.getStatus());
        assertEquals(0, after.bytesProduced(), "после closeInbound() данные не выдаются");
        java.lang.reflect.Field field = GostSSLEngine.class.getDeclaredField("plaintextBuf");
        field.setAccessible(true);
        byte[] decryptBuffer = ((ByteBuffer) field.get(peers.server())).array();
        for (byte b : decryptBuffer) {
            assertEquals(0, b, "буфер расшифровки затёрт целиком");
        }
    }

    @Test
    @DisplayName("closeInbound(): невыданные данные затираются, unwrap выдаёт 0 байтов")
    void closeInboundDiscardsBufferedData() throws Exception {
        Peers peers = establish();
        ByteBuffer record = ByteBuffer.wrap(wrapped(peers.client(), "0123456789".getBytes()));
        peers.server().unwrap(record, ByteBuffer.allocate(4));

        peers.server().closeInbound();

        assertTrue(
                peers.server().isInboundDone(),
                "приложение отказалось читать: входная сторона завершена сразу");
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLEngineResult result = peers.server().unwrap(ByteBuffer.allocate(0), dst);
        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        assertEquals(0, result.bytesProduced(), "невыданные данные не отдаются");
    }

    @Test
    @DisplayName("unwrap на закрытом движке: пока close_notify не отдан, статус NEED_WRAP")
    void unwrapReportsNeedWrapWhileCloseNotifyIsPending() throws Exception {
        Peers peers = establish();
        peers.client().closeOutbound();
        ByteBuffer closing = network();
        peers.client().wrap(ByteBuffer.allocate(0), closing);
        closing.flip();
        peers.server().unwrap(closing, ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));

        peers.server().closeOutbound();
        SSLEngineResult result =
                peers.server()
                        .unwrap(
                                ByteBuffer.allocate(0),
                                ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));

        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        assertEquals(
                SSLEngineResult.HandshakeStatus.NEED_WRAP,
                result.getHandshakeStatus(),
                "собранный close_notify ждёт отдачи: цикл приложения обязан вызвать wrap()");
    }

    @Test
    @DisplayName("Отказ: невыданные данные не отдаются, исключение остаётся при каждом unwrap")
    void failureDiscardsBufferedDataAndKeepsThrowing() throws Exception {
        Peers peers = establish();
        ByteBuffer first = ByteBuffer.wrap(wrapped(peers.client(), "0123456789".getBytes()));
        peers.server().unwrap(first, ByteBuffer.allocate(4));

        // следующая запись клиента искажена: проверка подлинности не пройдёт
        byte[] corrupted = wrapped(peers.client(), "следующие данные".getBytes());
        corrupted[corrupted.length - 1] ^= 0x01;
        assertThrows(
                SSLException.class,
                () ->
                        peers.server()
                                .unwrap(
                                        ByteBuffer.wrap(corrupted),
                                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH)),
                "некорректная запись приводит к отказу");

        assertTrue(peers.server().isInboundDone(), "после отказа ждать данных нечего");
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        assertThrows(
                SSLException.class,
                () -> peers.server().unwrap(ByteBuffer.allocate(0), dst),
                "после отказа исключение остаётся: цикл контейнера не должен принять отказ за успех");
        assertEquals(0, dst.position(), "данные, расшифрованные до отказа, не отдаются");

        // alert пиру отдаётся, затем выходная сторона закрыта
        SSLEngineResult alert = peers.server().wrap(ByteBuffer.allocate(0), network());
        assertEquals(SSLEngineResult.Status.CLOSED, alert.getStatus());
        assertTrue(alert.bytesProduced() > 0, "alert отдан пиру");
        assertEquals(
                0,
                peers.server().wrap(ByteBuffer.allocate(0), network()).bytesProduced(),
                "alert отдаётся один раз");
    }

    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    private static <T> T unchecked(ThrowingSupplier<T> supplier) {
        try {
            return supplier.get();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
