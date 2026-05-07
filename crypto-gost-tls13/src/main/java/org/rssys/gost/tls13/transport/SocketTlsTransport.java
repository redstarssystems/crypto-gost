package org.rssys.gost.tls13.transport;

import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTransport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

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
     * Принимает следующую TLS-запись из сокета (InputStream).
     * <p>
     * Читает 5-байтовый заголовок (content_type + legacy_version + length),
     * проверяет длину на превышение {@link TlsConstants#MAX_CIPHERTEXT_LENGTH}
     * (защита от OOM, RFC 8446 §5.1), затем читает тело.
     *
     * @return полная TLS-запись с заголовком
     * @throws IOException если чтение из сокета не удалось
     */
    @Override
    public byte[] receiveRecord() throws IOException {
        if (closed) throw new IOException("Transport closed");

        byte[] header = new byte[TlsConstants.RECORD_HEADER_SIZE];
        readFully(header);

        int length = ((header[3] & 0xFF) << 8) | (header[4] & 0xFF);

        // Защита от OOM: reject oversized записей до аллокации (RFC 8446 §5.1).
        // Максимальный ciphertext для любого валидного TLS 1.3 GOST record — 16640 байт.
        // Это transport-level invariant, не TLS-семантика.
        if (length > TlsConstants.MAX_CIPHERTEXT_LENGTH) {
            throw new IOException("Record too long: " + length
                    + " > " + TlsConstants.MAX_CIPHERTEXT_LENGTH);
        }

        byte[] body = new byte[length];
        readFully(body);

        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + length];
        System.arraycopy(header, 0, record, 0, TlsConstants.RECORD_HEADER_SIZE);
        System.arraycopy(body, 0, record, TlsConstants.RECORD_HEADER_SIZE, length);
        return record;
    }

    /**
     * Читает ровно {@code buf.length} байт в буфер.
     * В отличие от {@link java.io.DataInputStream#readFully(byte[])},
     * этот метод использует явный цикл с проверкой {@code closed},
     * что позволяет прервать чтение при закрытии транспорта.
     * <p>
     * Цикл обязателен: InputStream.read() может вернуть меньше байт,
     * чем запрошено, при фрагментации TCP или медленном соединении.
     */
    private void readFully(byte[] buf) throws IOException {
        int offset = 0;
        while (offset < buf.length) {
            if (closed) throw new IOException("Transport closed");
            int read = in.read(buf, offset, buf.length - offset);
            if (read == -1) throw new IOException("Connection closed by peer");
            offset += read;
        }
    }

    /**
     * Закрывает сокет. Идемпотентно.
     */
    @Override
    public void close() {
        closed = true;
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }
}
