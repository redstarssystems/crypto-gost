package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Диагностика потокобезопасности общего {@code TlsHandshakeEngine} внутри {@link GostSSLEngine}.
 *
 * <p>Контракт {@code SSLEngine} допускает параллельные {@code wrap} и {@code unwrap} одного движка
 * из разных потоков. Движок использует два замка (входной и выходной), а общий
 * {@code TlsHandshakeEngine}, не потокобезопасный, обслуживает обе стороны: {@code unwrap} вызывает
 * {@code receive} и {@code receivePostHandshake}, {@code wrap} вызывает {@code poll},
 * {@code initiateKeyUpdate} и очередь отправки. Тесты ищут сбои на таком совместном
 * использовании: потерю или порчу данных, исключения, нарушение порядка.
 */
@DisplayName("GostSSLEngine: параллельные wrap и unwrap на общем движке рукопожатия")
class GostSSLEngineSharedEngineStressTest {

    private static final int MESSAGE_SIZE = 4;
    private static final long STRESS_DURATION_MS = 4_000;

    /**
     * Пауза между парами инициаций KeyUpdate: каждая сторона получает до 8 чужих обновлений в
     * секунду (запрос и ответ), то есть в пределах окна (10 в секунду).
     */
    private static final long KEY_UPDATE_PAUSE_MS = 250;

    /** Предел очереди записей к пиру: писатель ждёт, пока читатель не разберёт накопленное. */
    private static final int MAX_QUEUED_RECORDS = 64;

    private static final long JOIN_TIMEOUT_MS = 30_000;
    private static final long DELIVERY_TIMEOUT_MS = 10_000;
    private static final int HANDSHAKE_ROUNDS = 25;
    private static final long HANDSHAKE_TIMEOUT_MS = 15_000;

    private static GostX509KeyManager serverKeyManager;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        serverKeyManager = new GostX509KeyManager();
        serverKeyManager.addKeyEntry(
                "default", CertificateBridge.toJca(List.of(leaf.cert, root.cert)), leaf.priv);
    }

    private static GostSSLEngine newClient() {
        return new GostSSLEngine(
                new GostX509KeyManager(),
                GostX509TrustManager.insecureTrustAll(),
                "localhost",
                0,
                true);
    }

    private static GostSSLEngine newServer() {
        return new GostSSLEngine(
                serverKeyManager, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
    }

    /** Односторонний поток данных: нумерованные сообщения, порядок обязан сохраняться. */
    private static final class Direction {
        final AtomicInteger sent = new AtomicInteger();
        final AtomicInteger received = new AtomicInteger();
        final AtomicReference<String> orderViolation = new AtomicReference<>();
    }

    private static ByteBuffer newNetworkBuffer() {
        return ByteBuffer.allocate(
                TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
    }

    /** Отправляет нумерованные сообщения, каждую произведённую запись кладёт в очередь пира. */
    private static void writeLoop(
            GostSSLEngine engine,
            LinkedBlockingQueue<byte[]> toPeer,
            Direction direction,
            AtomicBoolean writing)
            throws Exception {
        ByteBuffer plain = ByteBuffer.allocate(MESSAGE_SIZE);
        ByteBuffer network = newNetworkBuffer();
        while (writing.get()) {
            plain.clear();
            plain.putInt(direction.sent.get() + 1);
            plain.flip();
            // KeyUpdate из очереди движка уходит отдельной записью до данных, поэтому wrap
            // вызывается, пока сообщение не будет принято целиком
            while (plain.hasRemaining()) {
                network.clear();
                SSLEngineResult result = engine.wrap(plain, network);
                // Закрытый движок ничего не принимает и не бросает исключения: без этой проверки
                // писатель крутился бы вечно, а причина закрытия (ошибка читателя) терялась
                if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
                    throw new IllegalStateException("Движок закрыт во время записи");
                }
                network.flip();
                if (network.hasRemaining()) {
                    byte[] record = new byte[network.remaining()];
                    network.get(record);
                    toPeer.add(record);
                }
            }
            direction.sent.incrementAndGet();
            // Обратное давление: окно KeyUpdate считается по времени обработки, а не отправки.
            // Без ограничения очередь пира растёт быстрее, чем читатель её разбирает, KeyUpdate
            // стоят за тысячами записей данных и разбираются пачкой, то есть выходят за предел
            // окна без всякой ошибки движка
            while (toPeer.size() > MAX_QUEUED_RECORDS && writing.get()) {
                Thread.sleep(1);
            }
        }
    }

    /**
     * Принимает записи пира, проверяет порядок нумерованных сообщений. Читатель работает, пока не
     * снят {@code reading} и очередь не пуста: флаг снимается только после остановки писателей и
     * полной доставки, иначе последняя запись писателя могла бы остаться непрочитанной.
     */
    private static void readLoop(
            GostSSLEngine engine,
            LinkedBlockingQueue<byte[]> fromPeer,
            Direction direction,
            AtomicBoolean reading)
            throws Exception {
        ByteBuffer plain = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        while (reading.get() || !fromPeer.isEmpty()) {
            byte[] record = fromPeer.poll(50, TimeUnit.MILLISECONDS);
            if (record == null) {
                continue;
            }
            ByteBuffer network = ByteBuffer.wrap(record);
            while (network.hasRemaining()) {
                plain.clear();
                SSLEngineResult result = engine.unwrap(network, plain);
                if (result.bytesConsumed() == 0 && result.bytesProduced() == 0) {
                    break;
                }
                plain.flip();
                while (plain.remaining() >= MESSAGE_SIZE) {
                    int value = plain.getInt();
                    int expected = direction.received.get() + 1;
                    if (value != expected && direction.orderViolation.get() == null) {
                        direction.orderViolation.set(
                                "ожидалось сообщение " + expected + ", пришло " + value);
                    }
                    direction.received.incrementAndGet();
                }
            }
        }
    }

    private static Thread worker(
            String name, AtomicReference<Throwable> errors, ThrowingTask task) {
        Thread thread =
                new Thread(
                        () -> {
                            try {
                                task.run();
                            } catch (Throwable t) {
                                errors.compareAndSet(null, t);
                            }
                        },
                        name);
        thread.setDaemon(true);
        return thread;
    }

    /** Дожидается потоков и проверяет, что ни один не завис: зависший поток скрыл бы сбой. */
    private static void joinAll(Thread... threads) throws InterruptedException {
        for (Thread thread : threads) {
            thread.join(JOIN_TIMEOUT_MS);
            assertFalse(thread.isAlive(), "Поток завис: " + thread.getName());
        }
    }

    @FunctionalInterface
    private interface ThrowingTask {
        void run() throws Exception;
    }

    @Test
    @Timeout(value = 90, unit = TimeUnit.SECONDS)
    @DisplayName("дуплекс с KeyUpdate: 4 потока данных и обновления ключей с обеих сторон")
    void duplexTrafficWithKeyUpdatesOnSharedEngines() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngine client = newClient();
        GostSSLEngine server = newServer();
        GostSSLEngineLoopbackTest.doLoopback(client, server, pair);

        LinkedBlockingQueue<byte[]> toServer = pair.getClientToServerQueue();
        LinkedBlockingQueue<byte[]> toClient = pair.getServerToClientQueue();
        toServer.clear();
        toClient.clear();
        Direction clientToServer = new Direction();
        Direction serverToClient = new Direction();
        AtomicBoolean writing = new AtomicBoolean(true);
        AtomicBoolean reading = new AtomicBoolean(true);
        AtomicReference<Throwable> errors = new AtomicReference<>();

        Thread clientWriter =
                worker(
                        "client-wrap",
                        errors,
                        () -> writeLoop(client, toServer, clientToServer, writing));
        Thread serverWriter =
                worker(
                        "server-wrap",
                        errors,
                        () -> writeLoop(server, toClient, serverToClient, writing));
        Thread serverReader =
                worker(
                        "server-unwrap",
                        errors,
                        () -> readLoop(server, toServer, clientToServer, reading));
        Thread clientReader =
                worker(
                        "client-unwrap",
                        errors,
                        () -> readLoop(client, toClient, serverToClient, reading));
        Thread keyUpdates =
                worker(
                        "key-update",
                        errors,
                        () -> {
                            long deadline = System.currentTimeMillis() + STRESS_DURATION_MS;
                            while (System.currentTimeMillis() < deadline && errors.get() == null) {
                                // Обе стороны инициируют обновление почти одновременно: встречные
                                // KeyUpdate («crossed in flight») и приём чужого запроса во время
                                // собственной инициации на общем движке
                                client.initiateKeyUpdate(true);
                                server.initiateKeyUpdate(true);
                                Thread.sleep(KEY_UPDATE_PAUSE_MS);
                            }
                            writing.set(false);
                        });

        for (Thread t :
                new Thread[] {serverReader, clientReader, clientWriter, serverWriter, keyUpdates}) {
            t.start();
        }
        // Сначала останавливаем писателей, затем ждём полной доставки и только потом читателей
        joinAll(keyUpdates, clientWriter, serverWriter);
        long deliveryDeadline = System.currentTimeMillis() + DELIVERY_TIMEOUT_MS;
        while ((clientToServer.received.get() != clientToServer.sent.get()
                        || serverToClient.received.get() != serverToClient.sent.get()
                        || !toServer.isEmpty()
                        || !toClient.isEmpty())
                && System.currentTimeMillis() < deliveryDeadline
                && errors.get() == null) {
            Thread.sleep(5);
        }
        reading.set(false);
        joinAll(serverReader, clientReader);

        assertNull(errors.get(), "Сбой в одном из потоков: " + errors.get());
        assertNull(clientToServer.orderViolation.get(), "Нарушен порядок клиент -> сервер");
        assertNull(serverToClient.orderViolation.get(), "Нарушен порядок сервер -> клиент");
        assertEquals(
                clientToServer.sent.get(),
                clientToServer.received.get(),
                "Все сообщения клиента должны дойти до сервера");
        assertEquals(
                serverToClient.sent.get(),
                serverToClient.received.get(),
                "Все сообщения сервера должны дойти до клиента");
        assertTrue(clientToServer.sent.get() > 100, "Поток данных должен быть заметным");
        assertTrue(
                client.getPeerKeyUpdateCountForTest() > 0
                        && server.getPeerKeyUpdateCountForTest() > 0,
                "Обе стороны должны были принять KeyUpdate");
    }

    // ------------------------------------------------------------------ рукопожатие

    private static final class Side {
        final GostSSLEngine engine;
        final LinkedBlockingQueue<byte[]> incoming;
        final LinkedBlockingQueue<byte[]> outgoing;
        final AtomicBoolean finished = new AtomicBoolean();

        Side(
                GostSSLEngine engine,
                LinkedBlockingQueue<byte[]> incoming,
                LinkedBlockingQueue<byte[]> outgoing) {
            this.engine = engine;
            this.incoming = incoming;
            this.outgoing = outgoing;
        }

        void observe(SSLEngineResult result) {
            if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                finished.set(true);
            }
        }

        void runDelegatedTasks() {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
        }
    }

    /** Одна пара потоков на сторону: wrap-поток и unwrap-поток на одном движке. */
    private static void runHandshakeRound(AtomicReference<Throwable> errors, int round)
            throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        Side client =
                new Side(newClient(), pair.getServerToClientQueue(), pair.getClientToServerQueue());
        Side server =
                new Side(newServer(), pair.getClientToServerQueue(), pair.getServerToClientQueue());
        AtomicBoolean running = new AtomicBoolean(true);

        Thread[] threads = new Thread[4];
        int index = 0;
        for (Side side : new Side[] {client, server}) {
            String name = (side == client ? "client" : "server") + "-" + round;
            threads[index++] =
                    worker(
                            name + "-wrap",
                            errors,
                            () -> {
                                ByteBuffer network = newNetworkBuffer();
                                while (running.get()) {
                                    network.clear();
                                    SSLEngineResult result =
                                            side.engine.wrap(ByteBuffer.allocate(0), network);
                                    side.observe(result);
                                    network.flip();
                                    if (network.hasRemaining()) {
                                        byte[] record = new byte[network.remaining()];
                                        network.get(record);
                                        side.outgoing.add(record);
                                    } else {
                                        Thread.sleep(1);
                                    }
                                }
                            });
            threads[index++] =
                    worker(
                            name + "-unwrap",
                            errors,
                            () -> {
                                ByteBuffer plain =
                                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
                                while (running.get()) {
                                    byte[] record = side.incoming.poll(20, TimeUnit.MILLISECONDS);
                                    if (record == null) {
                                        continue;
                                    }
                                    ByteBuffer network = ByteBuffer.wrap(record);
                                    while (network.hasRemaining()) {
                                        plain.clear();
                                        SSLEngineResult result = side.engine.unwrap(network, plain);
                                        side.observe(result);
                                        side.runDelegatedTasks();
                                        if (result.bytesConsumed() == 0
                                                && result.bytesProduced() == 0
                                                && side.engine.getHandshakeStatus()
                                                        != SSLEngineResult.HandshakeStatus
                                                                .NEED_TASK) {
                                            break;
                                        }
                                    }
                                }
                            });
        }
        client.engine.beginHandshake();
        server.engine.beginHandshake();
        for (Thread t : threads) {
            t.start();
        }
        long deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS;
        while ((!client.finished.get() || !server.finished.get())
                && System.currentTimeMillis() < deadline
                && errors.get() == null) {
            Thread.sleep(5);
        }
        running.set(false);
        joinAll(threads);
        assertNull(errors.get(), "Раунд " + round + ": сбой в потоке: " + errors.get());
        assertTrue(
                client.finished.get() && server.finished.get(),
                "Раунд " + round + ": рукопожатие не завершилось за срок");
    }

    @Test
    @Timeout(value = 90, unit = TimeUnit.SECONDS)
    @DisplayName("рукопожатие: wrap и unwrap каждого движка в разных потоках, многократно")
    void handshakeWithSeparateWrapAndUnwrapThreads() throws Exception {
        AtomicReference<Throwable> errors = new AtomicReference<>();
        for (int round = 0; round < HANDSHAKE_ROUNDS; round++) {
            runHandshakeRound(errors, round);
        }
    }
}
