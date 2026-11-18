package org.rssys.gost.tls13.transport;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Тесты {@link ChannelTlsTransport} через loopback SocketChannel.
 *
 * <p>Loopback необходим, потому что ChannelTlsTransport принимает
 * {@link SocketChannel} в конструкторе — Pipe.SourceChannel/SinkChannel
 * не являются SocketChannel и не подходят.
 *
 * <p>Тесты на interrupt проверяют, что {@link java.nio.channels.ClosedByInterruptException}
 * не глотается молча: канал закрывается, флаг прерывания восстанавливается,
 * TlsSession получит IOException и не попытается слать данные в закрытый канал.
 */
@DisplayName("ChannelTlsTransport: отправка/получение записей, обработка прерываний")
class ChannelTlsTransportTest {

    private static SocketChannel[] createPair() throws IOException {
        ServerSocketChannel ssc = ServerSocketChannel.open();
        ssc.bind(new InetSocketAddress("localhost", 0));
        SocketChannel client = SocketChannel.open(ssc.getLocalAddress());
        SocketChannel server = ssc.accept();
        ssc.close();
        return new SocketChannel[] {client, server};
    }

    @Test
    @DisplayName("несколько записей подряд: порядок и целостность сохранены")
    void multipleRecordsInSequence() throws IOException {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport a = new ChannelTlsTransport(pair[0]);
        ChannelTlsTransport b = new ChannelTlsTransport(pair[1]);

        byte[][] records = {
            new byte[] {0x15, 0x03, 0x03, 0x00, 0x01, 0x00},
            new byte[] {0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02},
            new byte[] {0x17, 0x03, 0x03, 0x00, 0x03, 0x03, 0x04, 0x05}
        };

        for (byte[] rec : records) {
            a.sendRecord(rec);
        }
        for (byte[] rec : records) {
            assertArrayEquals(rec, b.receiveRecord());
        }

        a.close();
        b.close();
    }

    @Test
    @DisplayName("запись длиннее MAX_CIPHERTEXT_LENGTH: IOException при receiveRecord")
    void oversizedRecordRejected() throws IOException {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport a = new ChannelTlsTransport(pair[0]);
        ChannelTlsTransport b = new ChannelTlsTransport(pair[1]);

        int oversized = TlsConstants.MAX_CIPHERTEXT_LENGTH + 1;
        byte[] header =
                new byte[] {
                    0x17, 0x03, 0x03, (byte) ((oversized >> 8) & 0xFF), (byte) (oversized & 0xFF)
                };
        a.sendRecord(header);

        assertThrows(IOException.class, b::receiveRecord);

        a.close();
        b.close();
    }

    @Test
    @DisplayName("запись размером ровно MAX_CIPHERTEXT_LENGTH проходит")
    void largeRecordUpToLimit() throws IOException {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport a = new ChannelTlsTransport(pair[0]);
        ChannelTlsTransport b = new ChannelTlsTransport(pair[1]);

        int bodyLen = TlsConstants.MAX_CIPHERTEXT_LENGTH;
        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + bodyLen];
        record[0] = 0x17;
        record[1] = 0x03;
        record[2] = 0x03;
        record[3] = (byte) ((bodyLen >> 8) & 0xFF);
        record[4] = (byte) (bodyLen & 0xFF);
        for (int i = 5; i < record.length; i++) {
            record[i] = (byte) (i & 0xFF);
        }

        a.sendRecord(record);
        byte[] received = b.receiveRecord();
        assertArrayEquals(record, received);

        a.close();
        b.close();
    }

    @Test
    @DisplayName("sendRecord после close: IOException")
    void sendAfterCloseThrows() throws IOException {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport t = new ChannelTlsTransport(pair[0]);
        t.close();
        assertThrows(
                IOException.class, () -> t.sendRecord(new byte[] {0x17, 0x03, 0x03, 0x00, 0x00}));
        pair[1].close();
    }

    @Test
    @DisplayName("receiveRecord после close: IOException")
    void receiveAfterCloseThrows() throws IOException {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport t = new ChannelTlsTransport(pair[1]);
        t.close();
        assertThrows(IOException.class, t::receiveRecord);
        pair[0].close();
    }

    @Test
    @DisplayName("close идемпотентен: второй вызов не бросает исключение")
    void closeIsIdempotent() throws IOException {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport t = new ChannelTlsTransport(pair[0]);
        t.close();
        t.close();
        pair[1].close();
    }

    @Test
    @DisplayName("getChannel возвращает тот же канал, что передан в конструктор")
    void getChannelReturnsSame() throws IOException {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport t = new ChannelTlsTransport(pair[0]);
        assertSame(pair[0], t.getChannel());
        t.close();
        pair[1].close();
    }

    @Test
    @DisplayName("non-blocking канал в конструкторе: IllegalArgumentException")
    void nonBlockingChannelThrows() throws IOException {
        SocketChannel ch = SocketChannel.open();
        ch.configureBlocking(false);
        assertThrows(IllegalArgumentException.class, () -> new ChannelTlsTransport(ch));
        ch.close();
    }

    /**
     * Запускает поток, читающий запись, и прерывает его. Порядок «чтение началось» и «прерывание»
     * не важен: у блокирующего канала поток с уже выставленным флагом прерывания тоже получает
     * ClosedByInterruptException, поэтому ожидание по времени не нужно.
     *
     * @param flagAfterFailure получает значение флага прерывания потока после ошибки чтения
     * @return ошибка рабочего потока (в том числе непройденная проверка) или {@code null}
     */
    private static Throwable readAndInterrupt(
            ChannelTlsTransport transport, AtomicBoolean flagAfterFailure) throws Exception {
        AtomicReference<Throwable> workerFailure = new AtomicReference<>();
        CountDownLatch started = new CountDownLatch(1);
        Thread reader =
                new Thread(
                        () -> {
                            started.countDown();
                            try {
                                transport.receiveRecord();
                                workerFailure.set(
                                        new AssertionError(
                                                "receiveRecord должен бросить IOException"));
                            } catch (IOException expected) {
                                flagAfterFailure.set(Thread.interrupted());
                            } catch (Throwable unexpected) {
                                workerFailure.set(unexpected);
                            }
                        });
        reader.start();
        assertTrue(started.await(5, TimeUnit.SECONDS), "читающий поток не запустился");
        reader.interrupt();
        reader.join(5000);
        assertFalse(reader.isAlive(), "читающий поток должен завершиться после прерывания");
        return workerFailure.get();
    }

    @Test
    @DisplayName("прерывание потока во время receiveRecord закрывает транспорт")
    void interruptedReadClosesTransport() throws Exception {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport t = new ChannelTlsTransport(pair[1]);

        Throwable workerFailure = readAndInterrupt(t, new AtomicBoolean());

        assertNull(workerFailure, "рабочий поток: " + workerFailure);
        // ClosedByInterruptException закрывает канал — после него sendRecord
        // упадёт, и TlsSession не попытается слать данные в мёртвый канал
        assertThrows(
                IOException.class, () -> t.sendRecord(new byte[] {0x17, 0x03, 0x03, 0x00, 0x00}));

        pair[0].close();
    }

    @Test
    @DisplayName("флаг прерывания восстанавливается после ClosedByInterruptException")
    void interruptionPreservesFlag() throws Exception {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport t = new ChannelTlsTransport(pair[1]);
        AtomicBoolean flagAfterFailure = new AtomicBoolean();

        Throwable workerFailure = readAndInterrupt(t, flagAfterFailure);

        assertNull(workerFailure, "рабочий поток: " + workerFailure);
        // readFully восстанавливает флаг прерывания, чтобы вызывающий код (TlsSession,
        // ExecutorService) видел, что поток был прерван, и мог корректно завершиться
        assertTrue(flagAfterFailure.get(), "флаг прерывания должен быть восстановлен");

        t.close();
        pair[0].close();
    }

    @Test
    @DisplayName("receiveRecord(ByteBuffer) heap: данные совпадают")
    void receiveRecordHeapBuffer() throws IOException {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport a = new ChannelTlsTransport(pair[0]);
        ChannelTlsTransport b = new ChannelTlsTransport(pair[1]);

        byte[] sent = new byte[] {0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        a.sendRecord(sent);

        java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(256);
        int len = b.receiveRecord(buf);
        buf.flip();
        assertEquals(sent.length, len);
        byte[] received = new byte[len];
        buf.get(received);
        assertArrayEquals(sent, received);

        a.close();
        b.close();
    }

    @Test
    @DisplayName("receiveRecord(ByteBuffer) direct: данные совпадают")
    void receiveRecordDirectBuffer() throws IOException {
        SocketChannel[] pair = createPair();
        ChannelTlsTransport a = new ChannelTlsTransport(pair[0]);
        ChannelTlsTransport b = new ChannelTlsTransport(pair[1]);

        byte[] sent = new byte[] {0x16, 0x03, 0x03, 0x00, 0x03, 0x0A, 0x0B, 0x0C};
        a.sendRecord(sent);

        java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocateDirect(256);
        int len = b.receiveRecord(buf);
        buf.flip();
        assertEquals(sent.length, len);
        byte[] received = new byte[len];
        buf.get(received);
        assertArrayEquals(sent, received);

        a.close();
        b.close();
    }
}
