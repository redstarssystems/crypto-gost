package org.rssys.gost.pkix.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Чтение тела ответа с пределом размера и общим сроком.
 *
 * <p>Срок проверяется между чтениями: блокирующий {@code read()} прервать нельзя, поэтому
 * перерасход срока не больше одного чтения, которое само ограничено таймаутом чтения соединения.
 * Каждый раз проверяется и размер, чтобы тело большого размера не накапливалось в памяти.
 */
public final class BoundedBodyReader {

    private static final int BUFFER_SIZE = 8192;

    private BoundedBodyReader() {}

    /**
     * Читает поток до конца.
     *
     * @param in       поток тела
     * @param maxBytes предел размера в байтах (больше нуля)
     * @param deadline общий срок
     * @return тело целиком
     * @throws DeadlineExceededException если срок вышел до конца тела
     * @throws BodyTooLargeException     если тело больше предела
     * @throws IOException               при сетевой ошибке или прерывании потока
     */
    public static byte[] readAll(InputStream in, int maxBytes, Deadline deadline)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[BUFFER_SIZE];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            // Прерывание принадлежит потоку: блокирующий read() его не замечает, проверяем между
            // чтениями, иначе прерванный поток дочитывал бы чужое тело до конца
            if (Thread.interrupted()) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while reading the response body");
            }
            if (total > maxBytes - n) {
                throw new BodyTooLargeException(maxBytes, BodyTooLargeException.UNKNOWN_SIZE);
            }
            total += n;
            out.write(buf, 0, n);
            if (deadline.isExpired()) {
                throw new DeadlineExceededException("Deadline exceeded while reading the body");
            }
        }
        return out.toByteArray();
    }
}
