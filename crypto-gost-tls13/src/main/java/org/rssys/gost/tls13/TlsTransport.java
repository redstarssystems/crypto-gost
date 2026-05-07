package org.rssys.gost.tls13;

import java.io.IOException;

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
     * Закрывает транспорт.
     */
    @Override
    void close() throws IOException;
}
