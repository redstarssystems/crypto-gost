package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.testkit.EngineServerPki;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

@DisplayName("GostSSLEngine: параллельные wrap и unwrap")
class GostSSLEngineConcurrentWrapUnwrapTest {

    private static PkixCertTestHelper.CertBundle rootCa;
    private static PkixCertTestHelper.CertBundle serverCert;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        EngineServerPki pki = EngineServerPki.create();
        rootCa = pki.rootCa();
        serverCert = pki.serverCert();
        serverKm = pki.serverKm();
    }

    @Test
    @DisplayName("Параллельная работа + close: closeOutbound после дуплекса")
    void testConcurrentThenClose() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        true);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);

        doHandshake(client, server, pair);

        AtomicBoolean running = new AtomicBoolean(true);
        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        AtomicInteger clientSentSeq = new AtomicInteger(0);
        SeqChecker serverReceived = new SeqChecker();

        Thread clientWrap =
                new Thread(
                        () -> {
                            try {
                                ByteBuffer src =
                                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
                                ByteBuffer net =
                                        ByteBuffer.allocate(
                                                TlsConstants.MAX_CIPHERTEXT_LENGTH
                                                        + TlsConstants.RECORD_BUFFER_HEADROOM);
                                while (running.get()) {
                                    int seq = clientSentSeq.incrementAndGet();
                                    src.clear();
                                    src.putInt(seq);
                                    src.flip();
                                    net.clear();
                                    client.wrap(src, net);
                                    net.flip();
                                    byte[] enc = new byte[net.remaining()];
                                    net.get(enc);
                                    pair.getClientTransport().sendRecord(enc);
                                }
                            } catch (Exception e) {
                                // закрытие серверного транспорта после running.set(false) может
                                // застать поток внутри sendRecord: соединение закрыто, это штатное
                                // завершение, а не ошибка теста
                                if (running.get()) clientError.set(e);
                            }
                        },
                        "client-wrap");

        Thread serverUnwrap =
                new Thread(
                        () -> {
                            try {
                                ByteBuffer net =
                                        ByteBuffer.allocate(
                                                TlsConstants.MAX_CIPHERTEXT_LENGTH
                                                        + TlsConstants.RECORD_BUFFER_HEADROOM);
                                ByteBuffer app =
                                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
                                while (running.get()) {
                                    byte[] enc = pair.getServerTransport().receiveRecord();
                                    if (enc == null) break;
                                    net.clear();
                                    net.put(enc);
                                    net.flip();
                                    app.clear();
                                    SSLEngineResult r = server.unwrap(net, app);
                                    if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                                        assertTrue(
                                                server.isInboundDone(),
                                                "close_notify получен — isInboundDone должен быть true");
                                        break;
                                    }
                                    app.flip();
                                    if (app.remaining() >= 4) {
                                        int seq = app.getInt(0);
                                        serverReceived.check(seq);
                                    }
                                }
                            } catch (Exception e) {
                                // страховка: в норме поток выходит по CLOSED после дренажа
                                // close_notify, но закрытие транспорта не должно ронять тест
                                if (running.get()) serverError.set(e);
                            }
                        },
                        "server-unwrap");

        clientWrap.start();
        serverUnwrap.start();
        int durationMs = Integer.getInteger("stress.duration", 2000);
        Thread.sleep(durationMs);
        running.set(false);

        // Клиент инициирует закрытие
        client.closeOutbound();
        ByteBuffer net =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        SSLEngineResult closeResult = client.wrap(ByteBuffer.allocate(0), net);
        net.flip();
        byte[] enc = new byte[net.remaining()];
        net.get(enc);
        pair.getClientTransport().sendRecord(enc);

        pair.getServerTransport().close();

        clientWrap.interrupt();
        serverUnwrap.interrupt();
        clientWrap.join(5000);
        serverUnwrap.join(5000);

        assertFalse(clientWrap.isAlive(), "clientWrap должен завершиться");
        assertFalse(serverUnwrap.isAlive(), "serverUnwrap должен завершиться");

        if (clientError.get() != null) {
            fail("Ошибка клиента", clientError.get());
        }
        if (serverError.get() != null) {
            fail("Ошибка сервера", serverError.get());
        }
    }

    private static void doHandshake(
            GostSSLEngine client, GostSSLEngine server, InMemoryTlsTransport.Pair pair)
            throws Exception {
        GostSSLEngineLoopbackTest.doLoopback(client, server, pair);
    }

    private static final class SeqChecker {
        private final AtomicInteger lastSeq = new AtomicInteger(0);

        void check(int seq) {
            int prev = lastSeq.getAndSet(seq);
            if (seq <= prev) {
                throw new AssertionError("Sequence нарушена: prev=" + prev + " current=" + seq);
            }
        }
    }
}
