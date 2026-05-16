package org.rssys.gost.tls13;

import java.io.IOException;
import java.nio.ByteBuffer;


/**
 * Интерфейс транспортного уровня для TLS 1.3.
 * Абстрагирует передачу записей (TCP socket, Pipe, Mock).
 */
public interface TlsTransport extends AutoCloseable {

    /**
     * Отправляет запись целиком.
     * @param record полная TLS запись (включая заголовок)
     */
    void sendRecord(byte[] record) throws IOException;

    /**
     * Принимает следующую TLS запись.
     *<p>
     * Реализация должна прочитать 5-байтовый заголовок (content_type,
     * legacy_version, length), определить длину тела {@code length}
     * и вернуть массив {@code [header(5) || body(length)]}.
     * Для чтения из InputStream рекомендуется
     * {@link java.io.InputStream#readNBytes(int)}.
     *
     * @return полная TLS запись (заголовок + тело)
     * @throws IOException при ошибке ввода-вывода или таймауте
     */
    byte[] receiveRecord() throws IOException;

    /**
     * Принимает следующую TLS-запись напрямую в {@code dst}.
     * <p>
     * После вызова позиция {@code dst} сдвинута на число записанных байт.
     * Вызывающий код выполняет {@code flip()} перед чтением.
     * <p>
     * Реализации {@link org.rssys.gost.tls13.transport.SocketTlsTransport}
     * и {@link org.rssys.gost.tls13.transport.ChannelTlsTransport} переопределяют
     * этот метод с zero-alloc чтением.
     *
     * @param dst буфер для TLS-записи (position сдвинется на длину записи)
     * @return длина записи в байтах
     * @throws IOException при ошибке ввода-вывода или таймауте
     */
    default int receiveRecord(ByteBuffer dst) throws IOException {
        byte[] record = receiveRecord();
        dst.put(record);
        return record.length;
    }

    /**
     * Закрывает транспорт.
     */
    @Override
    void close() throws IOException;
}
