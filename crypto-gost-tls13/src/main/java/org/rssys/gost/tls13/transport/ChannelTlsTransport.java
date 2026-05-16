package org.rssys.gost.tls13.transport;

import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTransport;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.SocketChannel;
import java.util.Arrays;

/**
 * Транспорт TLS 1.3 поверх {@link SocketChannel} (NIO).
 *
 * <p>Реализует {@link TlsTransport} через NIO-канал. Канал ДОЛЖЕН быть
 * в blocking mode — переключение в non-blocking после первого использования
 * приведёт к {@link IllegalStateException}.
 *
 * <p><b>Timeout:</b> {@link SocketChannel#socket()}.setSoTimeout() НЕ РАБОТАЕТ
 * для SocketChannel в Java 11. Если нужен таймаут чтения — используйте
 * внешний {@link java.nio.channels.Selector} с select(timeout), либо
 * прервите поток через {@link Thread#interrupt()}.
 *
 * <p>Потокобезопасность: не гарантируется. Один экземпляр на одну TLS-сессию.
 */
public final class ChannelTlsTransport implements TlsTransport {

    private final SocketChannel channel;
    private final ByteBuffer headerBuf;
    private final byte[] recordBuf = new byte[TlsConstants.RECORD_HEADER_SIZE + TlsConstants.MAX_CIPHERTEXT_LENGTH];
    private volatile boolean closed;

    /**
     * @param channel установленное TCP-соединение в blocking mode
     */
    public ChannelTlsTransport(SocketChannel channel) throws IOException {
        if (!channel.isBlocking()) {
            throw new IllegalArgumentException("Channel must be in blocking mode");
        }
        this.channel = channel;
        this.headerBuf = ByteBuffer.allocate(TlsConstants.RECORD_HEADER_SIZE);
    }

    /**
     * Отправляет TLS-запись через канал.
     * Цикл для {@link SocketChannel#write(ByteBuffer)} обязателен —
     * канал может записать меньше байт, чем в буфере, при малом SO_SNDBUF.
     *
     * @param record TLS-запись для отправки
     * @throws IOException при ошибке записи в канал
     */
    @Override
    public void sendRecord(byte[] record) throws IOException {
        if (closed) throw new IOException("Transport closed");
        ByteBuffer buf = ByteBuffer.wrap(record);
        while (buf.hasRemaining()) {
            if (closed) throw new IOException("Transport closed");
            channel.write(buf);
        }
    }

    /**
     * Принимает следующую TLS-запись из канала.
     * <p>
     * Читает 5-байтовый заголовок в переиспользуемый {@code headerBuf},
     * проверяет длину, затем читает тело в {@code recordBuf} (без аллокации
     * через {@link ByteBuffer#wrap(byte[], int, int)}). Собирает итоговый
     * массив из заголовка и тела.
     *
     * @return полная TLS-запись с заголовком
     * @throws IOException если чтение из канала не удалось
     */
    @Override
    public byte[] receiveRecord() throws IOException {
        if (closed) throw new IOException("Transport closed");

        headerBuf.clear();
        readFully(headerBuf);
        headerBuf.flip();

        int length = (headerBuf.get(3) & 0xFF) << 8 | (headerBuf.get(4) & 0xFF);
        if (length > TlsConstants.MAX_CIPHERTEXT_LENGTH) {
            throw new IOException("Record too long: " + length
                    + " > " + TlsConstants.MAX_CIPHERTEXT_LENGTH);
        }

        // Читаем тело напрямую в recordBuf через ByteBuffer.wrap (без аллокации)
        ByteBuffer bodyBuf = ByteBuffer.wrap(recordBuf, 0, length);
        readFully(bodyBuf);

        int total = TlsConstants.RECORD_HEADER_SIZE + length;
        byte[] record = new byte[total];
        headerBuf.rewind();
        headerBuf.get(record, 0, TlsConstants.RECORD_HEADER_SIZE);
        System.arraycopy(recordBuf, 0, record, TlsConstants.RECORD_HEADER_SIZE, length);
        return record;
    }

    /**
     * Принимает следующую TLS-запись напрямую в переданный {@link ByteBuffer}.
     * <p>
     * Zero-alloc: заголовок читается в {@code headerBuf}, тело — через
     * {@link SocketChannel#read(ByteBuffer)} напрямую в {@code dst}
     * (native ByteBuffer support). Позиция {@code dst} после вызова сдвинута
     * на длину записи, лимит восстановлен.
     *
     * @param dst буфер для TLS-записи
     * @return длина записи в байтах
     * @throws IOException если чтение из канала не удалось или dst мал
     */
    @Override
    public int receiveRecord(ByteBuffer dst) throws IOException {
        if (closed) throw new IOException("Transport closed");

        headerBuf.clear();
        readFully(headerBuf);
        headerBuf.flip();

        int length = (headerBuf.get(3) & 0xFF) << 8 | (headerBuf.get(4) & 0xFF);
        if (length > TlsConstants.MAX_CIPHERTEXT_LENGTH) {
            throw new IOException("Record too long: " + length
                    + " > " + TlsConstants.MAX_CIPHERTEXT_LENGTH);
        }

        int total = TlsConstants.RECORD_HEADER_SIZE + length;
        if (dst.remaining() < total) {
            throw new IOException("Destination buffer too small: need " + total
                    + ", have " + dst.remaining());
        }

        // Копируем заголовок в dst
        headerBuf.rewind();
        dst.put(headerBuf);

        // Читаем тело напрямую из канала в dst (native ByteBuffer support)
        int bodyLimit = dst.position() + length;
        int origLimit = dst.limit();
        dst.limit(bodyLimit);
        try {
            readFully(dst);
        } finally {
            dst.limit(origLimit);
        }
        return total;
    }

    private void readFully(ByteBuffer buf) throws IOException {
        while (buf.hasRemaining()) {
            if (closed) throw new IOException("Transport closed");
            try {
                int read = channel.read(buf);
                if (read == -1) throw new IOException("Connection closed by peer");
                if (read == 0) throw new IllegalStateException(
                        "Channel switched to non-blocking mode");
            } catch (ClosedByInterruptException e) {
                closed = true;
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted", e);
            }
        }
    }

    /**
     * @return канал для регистрации в {@link java.nio.channels.Selector}.
     * Переключение режима канала после первого sendRecord/receiveRecord запрещено.
     */
    public SocketChannel getChannel() {
        return channel;
    }

    /**
     * Закрывает канал. Идемпотентно.
     */
    @Override
    public void close() {
        closed = true;
        try {
            channel.close();
        } catch (IOException ignored) {
        }
    }
}
