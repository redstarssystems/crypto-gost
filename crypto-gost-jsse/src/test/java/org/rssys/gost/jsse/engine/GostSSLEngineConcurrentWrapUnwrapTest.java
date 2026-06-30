package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

class GostSSLEngineConcurrentWrapUnwrapTest {

    private static TlsTestHelper.CertBundle rootCa;
    private static TlsTestHelper.CertBundle serverCert;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = TlsTestHelper.createRootCA(params);
        serverCert =
                TlsTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
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

    @Test
    @DisplayName("Дуплекс: 4 потока на одной паре GostSSLEngine, sequence numbers")
    void testConcurrentWrapUnwrap() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, new GostX509TrustManager(null, false), "localhost", 0, false);

        doHandshake(client, server, pair);

        AtomicBoolean running = new AtomicBoolean(true);
        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        AtomicInteger clientSentSeq = new AtomicInteger(0);
        AtomicInteger serverSentSeq = new AtomicInteger(0);
        SeqChecker clientReceived = new SeqChecker();
        SeqChecker serverReceived = new SeqChecker();

        // Клиентский wrap — отправка данных на сервер
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
                                // гонка running.set(false) -> transport.close() —
                                // поток может успеть войти в тело цикла после проверки running,
                                // но до закрытия транспорта. Это штатная ситуация завершения,
                                // не ошибка теста.
                                if (running.get()) clientError.set(e);
                            }
                        },
                        "client-wrap");

        // Серверный unwrap — приём данных от клиента
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
                                    if (r.getStatus() == SSLEngineResult.Status.CLOSED) break;
                                    app.flip();
                                    if (app.remaining() >= 4) {
                                        int seq = app.getInt(0);
                                        serverReceived.check(seq);
                                    }
                                }
                            } catch (Exception e) {
                                if (running.get()) serverError.set(e);
                            }
                        },
                        "server-unwrap");

        // Серверный wrap — отправка данных клиенту
        Thread serverWrap =
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
                                    int seq = serverSentSeq.incrementAndGet();
                                    src.clear();
                                    src.putInt(seq);
                                    src.flip();
                                    net.clear();
                                    server.wrap(src, net);
                                    net.flip();
                                    byte[] enc = new byte[net.remaining()];
                                    net.get(enc);
                                    pair.getServerTransport().sendRecord(enc);
                                }
                            } catch (Exception e) {
                                if (running.get()) serverError.set(e);
                            }
                        },
                        "server-wrap");

        // Клиентский unwrap — приём данных от сервера
        Thread clientUnwrap =
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
                                    byte[] enc = pair.getClientTransport().receiveRecord();
                                    if (enc == null) break;
                                    net.clear();
                                    net.put(enc);
                                    net.flip();
                                    app.clear();
                                    SSLEngineResult r = client.unwrap(net, app);
                                    if (r.getStatus() == SSLEngineResult.Status.CLOSED) break;
                                    app.flip();
                                    if (app.remaining() >= 4) {
                                        int seq = app.getInt(0);
                                        clientReceived.check(seq);
                                    }
                                }
                            } catch (Exception e) {
                                if (running.get()) clientError.set(e);
                            }
                        },
                        "client-unwrap");

        clientWrap.start();
        serverUnwrap.start();
        serverWrap.start();
        clientUnwrap.start();

        int durationMs = Integer.getInteger("stress.duration", 15000);
        Thread.sleep(durationMs);
        running.set(false);
        pair.getClientTransport().close();
        pair.getServerTransport().close();

        for (Thread t : new Thread[] {clientWrap, serverUnwrap, serverWrap, clientUnwrap}) {
            t.interrupt();
            t.join(5000);
        }

        // Проверяем, что ни один поток не заблокирован
        assertFalse(clientWrap.isAlive(), "clientWrap должен завершиться");
        assertFalse(serverUnwrap.isAlive(), "serverUnwrap должен завершиться");
        assertFalse(serverWrap.isAlive(), "serverWrap должен завершиться");
        assertFalse(clientUnwrap.isAlive(), "clientUnwrap должен завершиться");

        if (clientError.get() != null) {
            fail("Ошибка клиента", clientError.get());
        }
        if (serverError.get() != null) {
            fail("Ошибка сервера", serverError.get());
        }

        // Проверяем, что данные передавались в обе стороны
        assertTrue(
                clientSentSeq.get() > 10,
                "Должно быть отправлено >10 записей клиентом: " + clientSentSeq.get());
        assertTrue(
                serverSentSeq.get() > 10,
                "Должно быть отправлено >10 записей сервером: " + serverSentSeq.get());
    }

    @Test
    @DisplayName("Параллельная работа + close: closeOutbound после дуплекса")
    void testConcurrentThenClose() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        GostSSLEngine client =
                new GostSSLEngine(
                        new GostX509KeyManager(),
                        new GostX509TrustManager(null, false),
                        "localhost",
                        0,
                        true);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, new GostX509TrustManager(null, false), "localhost", 0, false);

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
                                clientError.set(e);
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
                                serverError.set(e);
                            }
                        },
                        "server-unwrap");

        clientWrap.start();
        serverUnwrap.start();
        int durationMs = Integer.getInteger("stress.duration", 10000);
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
        client.beginHandshake();
        server.beginHandshake();

        AtomicReference<Throwable> clientError = new AtomicReference<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        Thread clientThread =
                new Thread(
                        () -> {
                            try {
                                runHandshakeLoop(client, pair.getClientTransport(), true);
                            } catch (Exception e) {
                                clientError.set(e);
                            }
                        },
                        "hs-client");
        Thread serverThread =
                new Thread(
                        () -> {
                            try {
                                runHandshakeLoop(server, pair.getServerTransport(), false);
                            } catch (Exception e) {
                                serverError.set(e);
                            }
                        },
                        "hs-server");

        clientThread.start();
        serverThread.start();

        clientThread.join(10000);
        serverThread.join(10000);

        if (clientThread.isAlive()) {
            clientThread.interrupt();
            fail("Клиентский handshake не завершился за 10 сек");
        }
        if (serverThread.isAlive()) {
            serverThread.interrupt();
            fail("Серверный handshake не завершился за 10 сек");
        }
        if (clientError.get() != null) {
            throw new RuntimeException("Клиентский handshake упал", clientError.get());
        }
        if (serverError.get() != null) {
            throw new RuntimeException("Серверный handshake упал", serverError.get());
        }
    }

    private static void runHandshakeLoop(
            GostSSLEngine engine, InMemoryTlsTransport transport, boolean isClient)
            throws Exception {
        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

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
                        byte[] outData = new byte[netBuf.remaining()];
                        netBuf.get(outData);
                        transport.sendRecord(outData);
                    }
                    break;
                case NEED_UNWRAP:
                    byte[] inData = transport.receiveRecord();
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
        throw new RuntimeException(
                "Handshake не завершился за 80 итераций, status=" + engine.getHandshakeStatus());
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
