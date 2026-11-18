package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Диагностика отказа соединения в {@link GostSSLEngine}: что получает пир после ошибки в
 * {@code unwrap()}.
 *
 * <p>Тесты делятся на два вида. Первые проверяют, что после ошибки движок отдаёт fatal alert
 * через {@code wrap()} или {@code pollOutboundRecord()}. Вторые защищают штатное закрытие:
 * полузакрытие, штатный {@code close_notify}, закрытие входной стороны без {@code close_notify}.
 */
@DisplayName("GostSSLEngine: fatal alert пиру после ошибки, закрытие и полузакрытие")
class GostSSLEngineFatalAlertTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final int RECORD_HEADER_SIZE = 5;
    private static final int ALERT_BAD_RECORD_MAC = 20;
    private static final int ALERT_UNKNOWN_CA = 48;
    private static final int RACE_TRIALS = 60;

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle otherRoot;
    private static PkixCertTestHelper.CertBundle serverLeaf;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
        otherRoot = PkixCertTestHelper.createRootCA(PARAMS);
        serverLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
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
    }

    /** Пара движков после завершённого рукопожатия. */
    private record Peers(GostSSLEngine client, GostSSLEngine server) {}

    private static GostSSLEngine engine(SSLContext context, boolean clientMode) {
        GostSSLEngine engine = (GostSSLEngine) context.createSSLEngine("localhost", 0);
        engine.setUseClientMode(clientMode);
        return engine;
    }

    private static GostSSLEngine newServer() throws Exception {
        return engine(
                GostSsl.builder()
                        .certificate(
                                serverLeaf.cert.getEncoded(),
                                GostDerCodec.encodePrivateKey(serverLeaf.priv))
                        .trustCa(root.cert.getEncoded())
                        .buildServerContext(),
                false);
    }

    private static GostSSLEngine newClient(PkixCertTestHelper.CertBundle trustedRoot)
            throws Exception {
        return engine(
                GostSsl.builder().trustCa(trustedRoot.cert.getEncoded()).buildClientContext(),
                true);
    }

    private static Peers establish() throws Exception {
        GostSSLEngine server = newServer();
        GostSSLEngine client = newClient(root);
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngineLoopbackTest.doLoopback(client, server, pair);
        // записи, отправленные после завершения потоков рукопожатия (билеты сервера), остаются
        // в очередях: без их приёма номера записей у сторон разойдутся
        deliverPending(pair.getServerToClientQueue(), client);
        deliverPending(pair.getClientToServerQueue(), server);
        return new Peers(client, server);
    }

    private static void deliverPending(
            java.util.concurrent.LinkedBlockingQueue<byte[]> queue, GostSSLEngine receiver)
            throws SSLException {
        byte[] record;
        while ((record = queue.poll()) != null) {
            receiver.unwrap(ByteBuffer.wrap(record), plainBuffer());
        }
    }

    private static ByteBuffer networkBuffer() {
        return ByteBuffer.allocate(
                TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
    }

    private static ByteBuffer plainBuffer() {
        return ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
    }

    private static byte[] drain(ByteBuffer buffer) {
        buffer.flip();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        return bytes;
    }

    /** Запись с данными приложения, испорченная в теле: unwrap даёт bad_record_mac. */
    private static byte[] corruptedRecord(GostSSLEngine sender) throws Exception {
        ByteBuffer network = networkBuffer();
        sender.wrap(ByteBuffer.wrap("искажение".getBytes(StandardCharsets.UTF_8)), network);
        byte[] record = drain(network);
        record[RECORD_HEADER_SIZE + 4] ^= 0x42;
        return record;
    }

    /** Вызывает unwrap испорченной записи на сервере; ошибка обязана быть. */
    private static void failServerWithCorruptedRecord(Peers peers) throws Exception {
        byte[] record = corruptedRecord(peers.client());
        assertThrows(
                SSLException.class,
                () -> peers.server().unwrap(ByteBuffer.wrap(record), plainBuffer()),
                "Испорченная запись должна отвергаться");
    }

    private static SSLEngineResult wrapNothing(GostSSLEngine engine, ByteBuffer network)
            throws SSLException {
        return engine.wrap(ByteBuffer.allocate(0), network);
    }

    private static void assertFatalAlertFromPeer(GostSSLEngine receiver, byte[] record) {
        SSLException error =
                assertThrows(
                        SSLException.class,
                        () -> receiver.unwrap(ByteBuffer.wrap(record), plainBuffer()),
                        "Получатель должен увидеть fatal alert");
        assertTrue(
                error.getMessage().contains("alert " + ALERT_BAD_RECORD_MAC),
                "Ожидался код bad_record_mac (20) из alert пира, получено: " + error.getMessage());
    }

    // ========================================================================
    // Отказ: после ошибки пир должен получить fatal alert
    // ========================================================================

    @Test
    @DisplayName("после ошибки unwrap статус рукопожатия NEED_WRAP, alert ещё не отдан")
    void afterUnwrapErrorStatusNeedWrapUntilAlertDelivered() throws Exception {
        Peers peers = establish();
        failServerWithCorruptedRecord(peers);

        assertEquals(
                SSLEngineResult.HandshakeStatus.NEED_WRAP,
                peers.server().getHandshakeStatus(),
                "Неотданный alert требует wrap()");
        assertFalse(
                peers.server().isOutboundDone(),
                "Пока alert не отдан, выходная сторона не закрыта");
    }

    @Test
    @DisplayName("после ошибки unwrap wrap отдаёт зашифрованный fatal alert")
    void afterUnwrapErrorWrapDeliversEncryptedAlert() throws Exception {
        Peers peers = establish();
        failServerWithCorruptedRecord(peers);

        ByteBuffer network = networkBuffer();
        SSLEngineResult result = wrapNothing(peers.server(), network);

        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus(), "Статус после alert");
        assertEquals(0, result.bytesConsumed(), "Alert не потребляет данные приложения");
        assertTrue(result.bytesProduced() > 0, "Alert должен быть произведён");
        byte[] record = drain(network);
        assertEquals(
                TlsConstants.CT_APPLICATION_DATA,
                record[0] & 0xFF,
                "После рукопожатия alert защищён ключами записи (внешний тип 23)");
        assertTrue(peers.server().isOutboundDone(), "После отдачи alert выходная сторона закрыта");
        assertFatalAlertFromPeer(peers.client(), record);
    }

    @Test
    @DisplayName("повторный wrap после отдачи alert даёт CLOSED и 0 байт")
    void secondWrapAfterAlertProducesNothing() throws Exception {
        Peers peers = establish();
        failServerWithCorruptedRecord(peers);
        wrapNothing(peers.server(), networkBuffer());

        ByteBuffer network = networkBuffer();
        SSLEngineResult second = wrapNothing(peers.server(), network);

        assertEquals(SSLEngineResult.Status.CLOSED, second.getStatus(), "Статус повторного wrap");
        assertEquals(0, second.bytesProduced(), "Второго alert быть не должно");
    }

    @Test
    @DisplayName("слишком маленький буфер даёт BUFFER_OVERFLOW, alert не теряется")
    void smallBufferKeepsAlert() throws Exception {
        Peers peers = establish();
        failServerWithCorruptedRecord(peers);

        SSLEngineResult overflow = wrapNothing(peers.server(), ByteBuffer.allocate(4));
        assertEquals(
                SSLEngineResult.Status.BUFFER_OVERFLOW,
                overflow.getStatus(),
                "Мало места: ожидался BUFFER_OVERFLOW");

        ByteBuffer network = networkBuffer();
        SSLEngineResult result = wrapNothing(peers.server(), network);
        assertTrue(result.bytesProduced() > 0, "Alert должен уйти следующим wrap");
        assertFatalAlertFromPeer(peers.client(), drain(network));
    }

    @Test
    @DisplayName("pollOutboundRecord отдаёт alert, после чего isOutboundDone истинно")
    void pollOutboundRecordDeliversAlert() throws Exception {
        Peers peers = establish();
        failServerWithCorruptedRecord(peers);

        byte[] record = peers.server().pollOutboundRecord();

        assertNotNull(record, "Контейнер, забирающий запись напрямую, должен получить alert");
        assertTrue(peers.server().isOutboundDone(), "Запись отдана: выходная сторона закрыта");
        assertFatalAlertFromPeer(peers.client(), record);
    }

    @Test
    @DisplayName("closeOutbound после ошибки не подменяет alert открытым close_notify")
    void closeOutboundAfterErrorKeepsAlert() throws Exception {
        Peers peers = establish();
        failServerWithCorruptedRecord(peers);

        peers.server().closeOutbound();
        byte[] record = peers.server().pollOutboundRecord();

        assertNotNull(record, "После ошибки пир должен получить запись");
        assertEquals(
                TlsConstants.CT_APPLICATION_DATA,
                record[0] & 0xFF,
                "Запись должна быть зашифрованным alert, а не открытым close_notify");
        assertFatalAlertFromPeer(peers.client(), record);
    }

    @Test
    @DisplayName("closeOutbound до ошибки, затем ошибка unwrap: уходит close_notify, alert нет")
    void closeNotifyIsNotReplacedByAlert() throws Exception {
        Peers peers = establish();
        peers.server().closeOutbound();
        failServerWithCorruptedRecord(peers);

        ByteBuffer network = networkBuffer();
        wrapNothing(peers.server(), network);
        byte[] record = drain(network);

        // порядковый номер записи close_notify уже использован: откат запрещён, поэтому alert
        // после него не ставится, пир получает чистое закрытие
        assertTrue(record.length > 0, "close_notify должен быть отдан");
        SSLEngineResult result = peers.client().unwrap(ByteBuffer.wrap(record), plainBuffer());
        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus(), "Пир видит close_notify");
        ByteBuffer rest = networkBuffer();
        wrapNothing(peers.server(), rest);
        assertEquals(0, drain(rest).length, "Больше записей быть не должно");
    }

    @Test
    @DisplayName("отказ проверки сертификата клиентом доходит до сервера настоящим alert")
    void certificateRejectionReachesPeerAsAlert() throws Exception {
        GostSSLEngine server = newServer();
        // клиент доверяет другому корню: цепочка сервера проверку не пройдёт
        GostSSLEngine client = newClient(otherRoot);
        client.beginHandshake();
        server.beginHandshake();

        AtomicReference<SSLException> clientFailure = new AtomicReference<>();
        ArrayDeque<byte[]> toServer = new ArrayDeque<>();
        ArrayDeque<byte[]> toClient = new ArrayDeque<>();
        List<String> trace = new ArrayList<>();
        List<byte[]> clientSent = new ArrayList<>();
        try {
            for (int step = 0; step < 200 && clientFailure.get() == null; step++) {
                pumpOnce(client, toServer, toClient, true, clientFailure, trace, clientSent);
                pumpOnce(
                        server,
                        toClient,
                        toServer,
                        false,
                        new AtomicReference<>(),
                        trace,
                        new ArrayList<>());
            }
        } catch (SSLException e) {
            clientFailure.set(e);
        }
        assertNotNull(clientFailure.get(), "Клиент обязан отвергнуть сертификат: " + trace);

        // как в JDK: вызов, обнаруживший отказ задачи, бросает исключение, alert отдаёт следующий
        // wrap (в цикле выше исключение уже выбрано, значит alert ещё в движке)
        assertEquals(
                SSLEngineResult.HandshakeStatus.NEED_WRAP,
                client.getHandshakeStatus(),
                "Неотданный alert требует wrap()");
        ByteBuffer network = networkBuffer();
        wrapNothing(client, network);
        byte[] record = drain(network);
        assertTrue(record.length > 0, "Клиент должен отдать alert серверу после отказа: " + trace);
        assertEquals(
                TlsConstants.CT_APPLICATION_DATA,
                record[0] & 0xFF,
                "После ServerHello alert клиента защищён ключом рукопожатия");
        assertTrue(record.length > RECORD_HEADER_SIZE + 2, "Защищённая запись длиннее открытой");
        SSLException serverError =
                assertThrows(
                        SSLException.class,
                        () -> server.unwrap(ByteBuffer.wrap(record), plainBuffer()),
                        "Сервер должен увидеть fatal alert клиента");
        assertTrue(
                serverError.getMessage().contains("alert " + ALERT_UNKNOWN_CA),
                "Сервер должен увидеть настоящий код клиента: " + serverError.getMessage());
    }

    @Test
    @DisplayName("Отказ задачи проверки сертификата параллельно с wrap, unwrap и опросом статуса")
    @Timeout(60)
    void certificateRejectionRacingWithCallsDoesNotHang() throws Exception {
        for (int trial = 0; trial < 20; trial++) {
            GostSSLEngine server = newServer();
            GostSSLEngine client = newClient(otherRoot);
            client.beginHandshake();
            server.beginHandshake();
            ArrayDeque<byte[]> toServer = new ArrayDeque<>();
            ArrayDeque<byte[]> toClient = new ArrayDeque<>();
            List<String> trace = new ArrayList<>();
            AtomicReference<SSLException> ignored = new AtomicReference<>();
            // рукопожатие идёт до момента, когда у клиента появилась задача проверки цепочки
            for (int step = 0;
                    step < 200
                            && client.getHandshakeStatus()
                                    != SSLEngineResult.HandshakeStatus.NEED_TASK;
                    step++) {
                pumpWithoutTasks(client, toServer, toClient, trace);
                pumpWithoutTasks(server, toClient, toServer, trace);
            }
            Runnable task = client.getDelegatedTask();
            assertNotNull(task, "У клиента должна быть задача проверки цепочки: " + trace);

            AtomicReference<Throwable> unexpected = new AtomicReference<>();
            AtomicBoolean taskFailureDelivered = new AtomicBoolean();
            Thread taskThread = new Thread(task, "cert-task");
            taskThread.setDaemon(true);
            taskThread.start();
            // пока задача работает, соседние вызовы не должны ни зависнуть, ни бросить
            // что-либо, кроме SSLException
            for (int i = 0; i < 200 && taskThread.isAlive(); i++) {
                callEngine(client, unexpected, taskFailureDelivered);
            }
            taskThread.join(15_000);
            assertFalse(taskThread.isAlive(), "Задача проверки зависла (взаимная блокировка)");
            // Исключение задачи должно дойти до приложения хотя бы один раз: либо из вызова,
            // шедшего параллельно, либо из ближайшего после задачи
            callEngine(client, unexpected, taskFailureDelivered);
            callEngine(client, unexpected, taskFailureDelivered);
            assertNull(unexpected.get(), "Только SSLException допустимо: " + unexpected.get());
            assertTrue(
                    taskFailureDelivered.get(),
                    "Отказ задачи не дошёл до приложения исключением ни разу (попытка "
                            + trial
                            + ")");
        }
    }

    /** Исключение задачи несёт причину; исключение закрытого движка - нет. */
    private static void callEngine(
            GostSSLEngine engine,
            AtomicReference<Throwable> unexpected,
            AtomicBoolean taskFailureDelivered) {
        try {
            wrapNothing(engine, networkBuffer());
            engine.unwrap(ByteBuffer.allocate(0), plainBuffer());
            engine.getHandshakeStatus();
        } catch (SSLException expected) {
            if (expected.getCause() != null) {
                taskFailureDelivered.set(true);
            }
        } catch (Throwable e) {
            unexpected.set(e);
        }
    }

    private static void pumpWithoutTasks(
            GostSSLEngine engine,
            ArrayDeque<byte[]> inbound,
            ArrayDeque<byte[]> outbound,
            List<String> trace)
            throws SSLException {
        ByteBuffer network = networkBuffer();
        wrapNothing(engine, network);
        byte[] produced = drain(network);
        if (produced.length > 0) {
            outbound.add(produced);
        }
        byte[] record = inbound.poll();
        if (record != null) {
            engine.unwrap(ByteBuffer.wrap(record), plainBuffer());
            trace.add("unwrap " + record.length);
        }
    }

    /** Один шаг рукопожатия движка: задачи, затем wrap или unwrap; сбой пишется в failure. */
    private static void pumpOnce(
            GostSSLEngine engine,
            ArrayDeque<byte[]> inbound,
            ArrayDeque<byte[]> outbound,
            boolean recordFailure,
            AtomicReference<SSLException> failure,
            List<String> trace,
            List<byte[]> sent)
            throws SSLException {
        try {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
            ByteBuffer network = networkBuffer();
            wrapNothing(engine, network);
            byte[] produced = drain(network);
            if (produced.length > 0) {
                outbound.add(produced);
                sent.add(produced);
                trace.add((recordFailure ? "C" : "S") + " wrap " + produced.length);
            }
            byte[] record = inbound.poll();
            if (record != null) {
                engine.unwrap(ByteBuffer.wrap(record), plainBuffer());
                trace.add((recordFailure ? "C" : "S") + " unwrap " + record.length);
            }
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
        } catch (SSLException e) {
            trace.add((recordFailure ? "C" : "S") + " failure " + e.getMessage());
            if (recordFailure) {
                failure.set(e);
            }
        }
    }

    @Test
    @DisplayName("Гонка: ошибка unwrap при параллельном wrap даёт только SSLException")
    @Timeout(120)
    void unwrapErrorWithConcurrentWrapOnlySslException() throws Exception {
        List<Throwable> unexpected = new ArrayList<>();
        for (int trial = 0; trial < RACE_TRIALS; trial++) {
            Peers peers = establish();
            byte[] record = corruptedRecord(peers.client());
            AtomicBoolean stop = new AtomicBoolean();
            CountDownLatch started = new CountDownLatch(1);
            AtomicReference<Throwable> wrapFailure = new AtomicReference<>();
            Thread writer =
                    new Thread(
                            () -> {
                                ByteBuffer plain = ByteBuffer.wrap(new byte[] {1, 2, 3, 4});
                                ByteBuffer network = networkBuffer();
                                started.countDown();
                                while (!stop.get()) {
                                    try {
                                        plain.clear();
                                        network.clear();
                                        peers.server().wrap(plain, network);
                                    } catch (SSLException e) {
                                        // допустимый исход закрытия движка
                                        return;
                                    } catch (Throwable e) {
                                        wrapFailure.set(e);
                                        return;
                                    }
                                }
                            },
                            "race-writer");
            writer.setDaemon(true);
            writer.start();
            started.await();
            try {
                peers.server().unwrap(ByteBuffer.wrap(record), plainBuffer());
            } catch (SSLException expected) {
                // ошибка проверки записи ожидаема
            }
            stop.set(true);
            writer.join(10_000);
            if (wrapFailure.get() != null) {
                unexpected.add(wrapFailure.get());
            }
        }
        assertTrue(
                unexpected.isEmpty(),
                "wrap во время отказа должен бросать только SSLException, получено: " + unexpected);
    }

    // ========================================================================
    // Штатное закрытие: поведение, которое нельзя сломать
    // ========================================================================

    @Test
    @DisplayName("штатный close_notify зашифрован и закрывает приём у пира")
    void regularCloseNotifyIsEncrypted() throws Exception {
        Peers peers = establish();

        peers.client().closeOutbound();
        ByteBuffer network = networkBuffer();
        wrapNothing(peers.client(), network);
        byte[] record = drain(network);

        assertEquals(
                TlsConstants.CT_APPLICATION_DATA,
                record[0] & 0xFF,
                "close_notify после рукопожатия защищён ключами записи");
        SSLEngineResult result = peers.server().unwrap(ByteBuffer.wrap(record), plainBuffer());
        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus(), "Пир видит закрытие");
    }

    @Test
    @DisplayName("полузакрытие - после close_notify пира можно дописать данные")
    void halfCloseAllowsWritingAfterPeerCloseNotify() throws Exception {
        Peers peers = establish();
        peers.client().closeOutbound();
        ByteBuffer closeNetwork = networkBuffer();
        wrapNothing(peers.client(), closeNetwork);
        peers.server().unwrap(ByteBuffer.wrap(drain(closeNetwork)), plainBuffer());

        byte[] payload = "дописано после close_notify".getBytes(StandardCharsets.UTF_8);
        ByteBuffer source = ByteBuffer.wrap(payload);
        ByteBuffer plaintext = plainBuffer();
        // перед данными сервер может отправить служебные записи (билеты): клиент обязан
        // получить их все по порядку, иначе номера записей разойдутся
        for (int attempt = 0; attempt < 10 && source.hasRemaining(); attempt++) {
            ByteBuffer network = networkBuffer();
            SSLEngineResult wrapped = peers.server().wrap(source, network);
            assertEquals(
                    SSLEngineResult.Status.OK,
                    wrapped.getStatus(),
                    "Выходная сторона после close_notify пира остаётся рабочей");
            byte[] record = drain(network);
            if (record.length > 0) {
                peers.client().unwrap(ByteBuffer.wrap(record), plaintext);
            }
        }
        assertFalse(source.hasRemaining(), "Данные должны быть приняты движком");
        assertArrayEquals(payload, drain(plaintext), "Клиент должен прочитать дописанные данные");

        peers.server().closeOutbound();
        assertFalse(
                peers.server().isOutboundDone(),
                "close_notify собран, но ещё не отдан: выходная сторона не закрыта");
        peers.server().wrap(ByteBuffer.allocate(0), networkBuffer());
        assertTrue(
                peers.server().isOutboundDone(),
                "после отдачи close_notify своя сторона закрыта отдельно от входной");
    }

    @Test
    @DisplayName("Пир закрыл первым: closeOutbound отвечает зашифрованным close_notify")
    void answersCloseNotifyWhenPeerClosedFirst() throws Exception {
        Peers peers = establish();
        peers.client().closeOutbound();
        ByteBuffer closeNetwork = networkBuffer();
        wrapNothing(peers.client(), closeNetwork);
        peers.server().unwrap(ByteBuffer.wrap(drain(closeNetwork)), plainBuffer());

        peers.server().closeOutbound();
        ByteBuffer network = networkBuffer();
        wrapNothing(peers.server(), network);
        byte[] record = drain(network);

        assertEquals(
                TlsConstants.CT_APPLICATION_DATA,
                record[0] & 0xFF,
                "Ответный close_notify защищён ключами записи");
        assertTrue(peers.server().isOutboundDone(), "Выходная сторона закрыта");
        SSLEngineResult result = peers.client().unwrap(ByteBuffer.wrap(record), plainBuffer());
        assertEquals(
                SSLEngineResult.Status.CLOSED,
                result.getStatus(),
                "Закрывший первым пир получает ответный close_notify");
        assertTrue(peers.server().recordsDestroyedForTest(), "Ключи разрушены после ответа");
    }

    @Test
    @DisplayName("Исчерпан порядковый номер записи: wrap бросает SSLException, ключи разрушены")
    void exhaustedSequenceNumberClosesEngineWithSslException() throws Exception {
        Peers peers = establish();
        java.lang.reflect.Field field = GostSSLEngine.class.getDeclaredField("writerRecord");
        field.setAccessible(true);
        org.rssys.gost.tls13.record.TlsRecord writer =
                (org.rssys.gost.tls13.record.TlsRecord) field.get(peers.server());
        // последний допустимый знаковый номер: набор с малым SNMAX отказывает сразу, остальным
        // хватает ещё одной записи до переполнения знакового счётчика
        writer.setSequenceNumber(Long.MAX_VALUE);

        SSLException failure = null;
        for (int attempt = 0; attempt < 2 && failure == null; attempt++) {
            try {
                peers.server().wrap(ByteBuffer.wrap(new byte[] {1}), networkBuffer());
            } catch (SSLException e) {
                failure = e;
            }
        }
        assertNotNull(failure, "Исчерпание номера записи должно давать SSLException");

        assertTrue(
                peers.server().recordsDestroyedForTest(),
                "Ключи разрушены, alert этими ключами не ставится");
        assertNull(peers.server().pollOutboundRecord(), "Alert при исчерпании ключей не ставится");
    }

    @Test
    @DisplayName("closeInbound без close_notify не бросает исключение")
    void closeInboundWithoutCloseNotifyDoesNotThrow() throws Exception {
        Peers peers = establish();

        peers.client().closeInbound();

        assertTrue(peers.client().isInboundDone(), "Входная сторона закрыта");
        assertNull(peers.client().pollOutboundRecord(), "closeInbound ничего не отправляет");
    }
}
