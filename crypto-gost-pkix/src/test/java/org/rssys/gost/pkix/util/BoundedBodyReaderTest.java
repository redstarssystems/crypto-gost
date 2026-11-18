package org.rssys.gost.pkix.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("BoundedBodyReader: предел размера и общий срок при чтении тела")
class BoundedBodyReaderTest {

    /** Поток, отдающий по одному байту с паузой: капля, которую таймаут чтения не ловит. */
    private static InputStream drip(int bytes, long pauseMillis) {
        return new InputStream() {
            private int sent;

            @Override
            public int read() throws IOException {
                if (sent >= bytes) {
                    return -1;
                }
                try {
                    Thread.sleep(pauseMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException(e);
                }
                sent++;
                return 1;
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                int c = read();
                if (c < 0) {
                    return -1;
                }
                b[off] = (byte) c;
                return 1;
            }
        };
    }

    @Test
    @DisplayName("Тело в пределах размера и срока читается целиком")
    void readsWholeBody() throws Exception {
        byte[] body = new byte[20_000];
        body[19_999] = 7;

        byte[] read =
                BoundedBodyReader.readAll(
                        new ByteArrayInputStream(body),
                        20_000,
                        Deadline.after(Duration.ofSeconds(5)));

        assertArrayEquals(body, read, "тело должно совпасть");
    }

    @Test
    @DisplayName("Размер ровно на пределе проходит, на байт больше - BodyTooLargeException")
    void sizeBoundary() throws Exception {
        Deadline d = Deadline.after(Duration.ofSeconds(5));

        assertEquals(
                100,
                BoundedBodyReader.readAll(new ByteArrayInputStream(new byte[100]), 100, d).length);
        BodyTooLargeException e =
                assertThrows(
                        BodyTooLargeException.class,
                        () ->
                                BoundedBodyReader.readAll(
                                        new ByteArrayInputStream(new byte[101]), 100, d));
        assertEquals(100, e.limit(), "предел в исключении");
    }

    @Test
    @DisplayName("Капля байтов не держит чтение дольше срока (плюс одно чтение)")
    void dripIsCutByDeadline() {
        long start = System.nanoTime();

        assertThrows(
                DeadlineExceededException.class,
                () ->
                        BoundedBodyReader.readAll(
                                drip(500, 50), 1_000_000, Deadline.after(Duration.ofMillis(300))),
                "капля должна оборваться по сроку");

        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        assertTrue(
                elapsedMs < 2_000, "чтение должно уложиться в срок, заняло " + elapsedMs + " мс");
    }
}
