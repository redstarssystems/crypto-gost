package org.rssys.gost.tls13.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTransport;

/**
 * Транспорт TLS 1.3 поверх блокирующего сокета (TCP).
 *
 * <p>Реализует {@link TlsTransport} через {@link Socket}:
 * {@link #sendRecord(byte[])} пишет в {@link OutputStream},
 * {@link #receiveRecord()} читает 5-байтовый заголовок, определяет длину тела
 * и читает ровно {@code length} байт.
 *
 * <p><b>Важно:</b> перед передачей транспорта в {@code TlsSession} вызовите
 * {@link Socket#setSoTimeout(int)} на сокете. Иначе злонамеренный пир,
 * приславший заголовок с {@code length=2^14} без тела, может повесить
 * вызов {@link #receiveRecord()} навсегда.
 *
 * <p>Потокобезопасность: не гарантируется. Используйте один экземпляр
 * на одну TLS-сессию.
 */
public final class SocketTlsTransport implements TlsTransport {

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private volatile boolean closed;
    private final byte[] headerBuf = new byte[TlsConstants.RECORD_HEADER_SIZE];
    private final byte[] recordBuf =
            new byte[TlsConstants.RECORD_HEADER_SIZE + TlsConstants.MAX_CIPHERTEXT_LENGTH];

    /**
     * @param socket установленное TCP-соединение
     * @throws IOException если сокет не поддерживает I/O
     */
    public SocketTlsTransport(Socket socket) throws IOException {
        this.socket = socket;
        socket.setTcpNoDelay(true);
        this.in = socket.getInputStream();
        this.out = socket.getOutputStream();
    }

    /**
     * Отправляет запись в сокет (OutputStream).
     *
     * @param record полная TLS-запись с заголовком
     * @throws IOException если запись в сокет не удалась
     */
    @Override
    public void sendRecord(byte[] record) throws IOException {
        if (closed) throw new IOException("Transport closed");
        out.write(record);
        out.flush();
    }

    /**
     * Принимает следующую TLS-запись из сокета.
     * <p>
     * Читает 5-байтовый заголовок, проверяет длину на превышение
     * {@link TlsConstants#MAX_CIPHERTEXT_LENGTH}, затем читает тело.
     * Возвращает новый массив (Arrays.copyOf из внутреннего буфера).
     *
     * @return полная TLS-запись с заголовком
     * @throws IOException если чтение из сокета не удалось
     */
    @Override
    public byte[] receiveRecord() throws IOException {
        if (closed) throw new IOException("Transport closed");

        readFully(recordBuf, 0, TlsConstants.RECORD_HEADER_SIZE);

        int length = ((recordBuf[3] & 0xFF) << 8) | (recordBuf[4] & 0xFF);

        if (length > TlsConstants.MAX_CIPHERTEXT_LENGTH) {
            throw new IOException(
                    "Record too long: " + length + " > " + TlsConstants.MAX_CIPHERTEXT_LENGTH);
        }

        readFully(recordBuf, TlsConstants.RECORD_HEADER_SIZE, length);

        return Arrays.copyOf(recordBuf, TlsConstants.RECORD_HEADER_SIZE + length);
    }

    /**
     * Принимает следующую TLS-запись напрямую в переданный {@link ByteBuffer}.
     * <p>
     * Zero-alloc: читает заголовок и тело в переиспользуемый внутренний буфер,
     * затем копирует в {@code dst}. В отличие от {@link #receiveRecord()} не
     * создаёт новый массив для результата — данные уже в {@code dst}.
     * <p>
     * После вызова позиция {@code dst} сдвинута на длину записи.
     *
     * @param dst буфер для TLS-записи
     * @return длина записи в байтах
     * @throws IOException если чтение из сокета не удалось или закрыт транспорт
     */
    @Override
    public int receiveRecord(ByteBuffer dst) throws IOException {
        if (closed) throw new IOException("Transport closed");

        readFully(recordBuf, 0, TlsConstants.RECORD_HEADER_SIZE);

        int length = ((recordBuf[3] & 0xFF) << 8) | (recordBuf[4] & 0xFF);

        if (length > TlsConstants.MAX_CIPHERTEXT_LENGTH) {
            throw new IOException(
                    "Record too long: " + length + " > " + TlsConstants.MAX_CIPHERTEXT_LENGTH);
        }

        readFully(recordBuf, TlsConstants.RECORD_HEADER_SIZE, length);

        int total = TlsConstants.RECORD_HEADER_SIZE + length;
        dst.put(recordBuf, 0, total);
        return total;
    }

    /**
     * Читает ровно {@code len} байт в {@code buf} начиная со смещения {@code off}.
     */
    private void readFully(byte[] buf, int off, int len) throws IOException {
        int end = off + len;
        while (off < end) {
            if (closed) throw new IOException("Transport closed");
            int read = in.read(buf, off, end - off);
            if (read == -1) throw new IOException("Connection closed by peer");
            off += read;
        }
    }

    @Override
    public void close() {
        closed = true;
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }
}
