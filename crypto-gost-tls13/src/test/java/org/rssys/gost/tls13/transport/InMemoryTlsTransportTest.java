package org.rssys.gost.tls13.transport;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Модульные тесты {@link InMemoryTlsTransport}: закрытие, пробуждение ждущего чтения,
 * дренаж записей и срок ожидания.
 */
@DisplayName("InMemoryTlsTransport: закрытие соединения и срок ожидания")
class InMemoryTlsTransportTest {

    private static final byte[] RECORD_A = {
        0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05
    };
    private static final byte[] RECORD_B = {0x17, 0x03, 0x03, 0x00, 0x01, 0x42};
    private static final byte[] RECORD_C = {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00};

    /** Верхний предел пробуждения: в разы больше кванта опроса, чтобы не мигать на CI. */
    private static final long WAKE_UP_LIMIT_SECONDS = 1;

    // ========================================================================
    // Перенесено из TlsSessionTest
    // ========================================================================

    @Test
    @DisplayName("close() -> receiveRecord() бросает IOException")
    void testClosedTransportThrows() {
        var transport = new InMemoryTlsTransport();
        transport.close();
        assertThrows(IOException.class, transport::receiveRecord);
    }

    @Test
    @DisplayName("Вброс -> закрытие -> receiveRecord возвращает запись (без потерь)")
    void testClosedTransportDrainsQueuedRecords() throws Exception {
        var transport = new InMemoryTlsTransport();
        transport.inject(RECORD_A);
        transport.close();
        assertArrayEquals(RECORD_A, transport.receiveRecord());
        assertThrows(IOException.class, transport::receiveRecord);
    }

    // ========================================================================
    // Пробуждение ждущего чтения
    // ========================================================================

    /** Запускает чтение в отдельном потоке и возвращает результат вместе с защёлкой запуска. */
    private static final class AsyncReceive {
        final AtomicReference<Throwable> error = new AtomicReference<>();
        final AtomicReference<byte[]> record = new AtomicReference<>();
        final CountDownLatch finished = new CountDownLatch(1);
        final CountDownLatch started = new CountDownLatch(1);
        final Thread thread;

        AsyncReceive(InMemoryTlsTransport transport) {
            thread =
                    new Thread(
                            () -> {
                                started.countDown();
                                try {
                                    record.set(transport.receiveRecord());
                                } catch (Throwable e) {
                                    error.set(e);
                                } finally {
                                    finished.countDown();
                                }
                            },
                            "receive-waiter");
            thread.start();
        }
    }

    @Test
    @DisplayName("Ждущий receiveRecord() просыпается после собственного close()")
    void testWaiterWakesUpOnOwnClose() throws Exception {
        var pair = InMemoryTlsTransport.newPair();
        var waiter = new AsyncReceive(pair.getServerTransport());
        assertTrue(waiter.started.await(WAKE_UP_LIMIT_SECONDS, TimeUnit.SECONDS));

        pair.getServerTransport().close();

        assertTrue(
                waiter.finished.await(WAKE_UP_LIMIT_SECONDS, TimeUnit.SECONDS),
                "ждущий поток не проснулся после close() своей стороны");
        assertClosedError(waiter.error.get());
    }

    @Test
    @DisplayName("Ждущий receiveRecord() просыпается после close() пира")
    void testWaiterWakesUpOnPeerClose() throws Exception {
        var pair = InMemoryTlsTransport.newPair();
        var waiter = new AsyncReceive(pair.getServerTransport());
        assertTrue(waiter.started.await(WAKE_UP_LIMIT_SECONDS, TimeUnit.SECONDS));

        pair.getClientTransport().close();

        assertTrue(
                waiter.finished.await(WAKE_UP_LIMIT_SECONDS, TimeUnit.SECONDS),
                "ждущий поток не проснулся после close() пира");
        assertClosedError(waiter.error.get());
    }

    private static void assertClosedError(Throwable error) {
        assertInstanceOf(IOException.class, error, "ожидался IOException");
        assertEquals(
                InMemoryTlsTransport.MSG_TRANSPORT_CLOSED,
                error.getMessage(),
                "ожидалось «закрыт», а не срок или прерывание");
    }

    // ========================================================================
    // Дренаж и порядок
    // ========================================================================

    @Test
    @DisplayName("Записи пира, поставленные до его close(), приходят по порядку, затем IOException")
    void testPeerRecordsDrainedInOrderBeforeError() throws Exception {
        var pair = InMemoryTlsTransport.newPair();
        pair.getClientTransport().sendRecord(RECORD_A);
        pair.getClientTransport().sendRecord(RECORD_B);
        pair.getClientTransport().sendRecord(RECORD_C);
        pair.getClientTransport().close();

        var server = pair.getServerTransport();
        assertArrayEquals(RECORD_A, server.receiveRecord());
        assertArrayEquals(RECORD_B, server.receiveRecord());
        assertArrayEquals(RECORD_C, server.receiveRecord());
        assertClosedError(assertThrows(IOException.class, server::receiveRecord));
        // повторный вызов после закрытия снова бросает
        assertClosedError(assertThrows(IOException.class, server::receiveRecord));
    }

    @Test
    @DisplayName("Запись уходит в очередь пира как копия")
    void testSendRecordCopiesAndDeliversToPeer() throws Exception {
        var pair = InMemoryTlsTransport.newPair();
        byte[] original = RECORD_A.clone();
        pair.getClientTransport().sendRecord(original);
        original[0] = 0;
        assertArrayEquals(RECORD_A, pair.getServerTransport().receiveRecord());
    }

    // ========================================================================
    // sendRecord и close
    // ========================================================================

    @Test
    @DisplayName("sendRecord после close() пира и после собственного close() бросает IOException")
    void testSendAfterCloseThrowsIoException() {
        var pair = InMemoryTlsTransport.newPair();
        pair.getServerTransport().close();
        // пир закрыт
        assertClosedError(
                assertThrows(
                        IOException.class, () -> pair.getClientTransport().sendRecord(RECORD_A)));
        // собственное закрытие
        assertClosedError(
                assertThrows(
                        IOException.class, () -> pair.getServerTransport().sendRecord(RECORD_A)));
    }

    @Test
    @DisplayName(
            "Одиночный транспорт: sendRecord после close() - IOException, inject - IllegalStateException")
    void testSingleTransportSendAfterClose() {
        var transport = new InMemoryTlsTransport();
        transport.close();
        assertClosedError(assertThrows(IOException.class, () -> transport.sendRecord(RECORD_A)));
        assertThrows(IllegalStateException.class, () -> transport.inject(RECORD_A));
    }

    @Test
    @DisplayName("Одиночный транспорт: sendRecord кладёт запись в собственную входящую очередь")
    void testSingleTransportLoopback() throws Exception {
        var transport = new InMemoryTlsTransport();
        transport.sendRecord(RECORD_B);
        assertArrayEquals(RECORD_B, transport.receiveRecord());
    }

    @Test
    @DisplayName("Повторный close() безопасен")
    void testCloseIsIdempotent() {
        var pair = InMemoryTlsTransport.newPair();
        pair.getClientTransport().close();
        assertDoesNotThrow(() -> pair.getClientTransport().close());
        assertDoesNotThrow(() -> pair.getServerTransport().close());
    }

    @Test
    @DisplayName("Конструктор с очередью: своя метка закрытия, исходящие записи в ту же очередь")
    void testQueueConstructorKeepsOwnState() throws Exception {
        var queue = new LinkedBlockingQueue<byte[]>();
        var first = new InMemoryTlsTransport(queue);
        var second = new InMemoryTlsTransport(queue);
        first.sendRecord(RECORD_A);
        first.close();
        // метки не общие: второй транспорт жив и видит запись первого
        assertArrayEquals(RECORD_A, second.receiveRecord());
        assertDoesNotThrow(() -> second.sendRecord(RECORD_B));
    }

    // ========================================================================
    // Срок ожидания
    // ========================================================================

    @Test
    @DisplayName("Срок ожидания истекает с текстом «Receive timeout», срок не сбрасывается")
    void testReceiveTimeout() {
        Duration timeout = Duration.ofMillis(200);
        var transport = new InMemoryTlsTransport(new LinkedBlockingQueue<>(), timeout);

        long start = System.nanoTime();
        // Верхней границы по времени нет: пересчёт срока на каждой итерации дал бы
        // бесконечное ожидание, его ловит предел assertTimeoutPreemptively
        IOException error =
                assertTimeoutPreemptively(
                        Duration.ofSeconds(2),
                        () -> assertThrows(IOException.class, transport::receiveRecord));
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        assertNotEquals(
                "Interrupted",
                error.getMessage(),
                "поток прерван по пределу теста: срок, видимо, сбрасывается");
        assertEquals(InMemoryTlsTransport.MSG_RECEIVE_TIMEOUT, error.getMessage());
        assertTrue(
                elapsedMs >= timeout.toMillis() - 20,
                "срок истёк раньше времени: " + elapsedMs + " мс");
    }

    @Test
    @DisplayName("Нулевой, отрицательный и пустой срок отвергаются")
    void testInvalidTimeoutRejected() {
        var queue = new LinkedBlockingQueue<byte[]>();
        assertThrows(
                IllegalArgumentException.class,
                () -> new InMemoryTlsTransport(queue, Duration.ZERO));
        assertThrows(
                IllegalArgumentException.class,
                () -> new InMemoryTlsTransport(queue, Duration.ofMillis(-1)));
        assertThrows(NullPointerException.class, () -> new InMemoryTlsTransport(queue, null));
    }
}
