package org.rssys.gost.tls13.transport;

import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTransport;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.SocketChannel;

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
     * Отправляет TLS-запись. Цикл для channel.write() обязателен —
     * SocketChannel.write() может записать меньше байт, чем в буфере,
     * при малом SO_SNDBUF или под нагрузкой.
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
     * Принимает следующую TLS-запись.
     * Читает 5-байтовый заголовок, проверяет длину на превышение
     * {@link TlsConstants#MAX_CIPHERTEXT_LENGTH} (защита от OOM, RFC 8446 §5.1),
     * затем читает тело. Reusable headerBuf для снижения GC pressure.
     *
     * @return полученная TLS-запись (с заголовком)
     * @throws IOException при ошибке чтения из канала
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

        ByteBuffer bodyBuf = ByteBuffer.allocate(length);
        readFully(bodyBuf);
        bodyBuf.flip();

        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + length];
        headerBuf.rewind();
        headerBuf.get(record, 0, TlsConstants.RECORD_HEADER_SIZE);
        bodyBuf.get(record, TlsConstants.RECORD_HEADER_SIZE, length);
        return record;
    }

    /**
     * Читает ровно buf.remaining() байт из канала в буфер.
     * Цикл обязателен для SocketChannel — read() может вернуть меньше байт,
     * чем запрошено. ClosedByInterruptException перехватывается для корректной
     * установки флага closed и флага прерывания потока.
     */
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

    @Override
    public void close() {
        closed = true;
        try {
            channel.close();
        } catch (IOException ignored) {
        }
    }
}
