package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;

@DisplayName("HandshakeMessageAssembler: сборка сообщений рукопожатия из записей")
class HandshakeMessageAssemblerTest {

    private static final boolean DURING_HANDSHAKE = false;
    private static final boolean AFTER_HANDSHAKE = true;
    private static final int CHUNK = TlsConstants.MAX_PLAINTEXT_LENGTH;

    /** Сообщение заданного типа с телом из повторяющегося байта. */
    private static byte[] message(byte type, int bodyLength, byte fill) {
        byte[] m = new byte[TlsConstants.HANDSHAKE_HEADER_SIZE + bodyLength];
        m[0] = type;
        m[1] = (byte) (bodyLength >>> 16);
        m[2] = (byte) (bodyLength >>> 8);
        m[3] = (byte) bodyLength;
        Arrays.fill(m, TlsConstants.HANDSHAKE_HEADER_SIZE, m.length, fill);
        return m;
    }

    private static byte[] header(byte type, int bodyLength) {
        return new byte[] {
            type, (byte) (bodyLength >>> 16), (byte) (bodyLength >>> 8), (byte) bodyLength
        };
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static void appendInChunks(HandshakeMessageAssembler a, byte[] data, int chunk)
            throws TlsException {
        for (int offset = 0; offset < data.length; offset += chunk) {
            a.append(data, offset, Math.min(chunk, data.length - offset));
        }
    }

    @Test
    @DisplayName("Несколько сообщений в одной записи выдаются по очереди, затем буфер пуст")
    void severalMessagesInOneFragment() throws Exception {
        byte[] first = message(TlsConstants.HT_ENCRYPTED_EXTENSIONS, 10, (byte) 1);
        byte[] second = message(TlsConstants.HT_FINISHED, 32, (byte) 2);
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        byte[] glued = concat(first, second);
        a.append(glued, 0, glued.length);

        assertArrayEquals(first, a.nextMessage(DURING_HANDSHAKE));
        assertArrayEquals(second, a.nextMessage(DURING_HANDSHAKE));
        assertNull(a.nextMessage(DURING_HANDSHAKE), "больше сообщений нет");
        assertTrue(a.isEmpty(), "буфер пуст");
    }

    @Test
    @DisplayName("Сообщение из записей по одному байту выдаётся один раз и целым")
    void messageFromOneByteFragments() throws Exception {
        byte[] m = message(TlsConstants.HT_CERTIFICATE_VERIFY, 300, (byte) 7);
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        for (int i = 0; i < m.length - 1; i++) {
            a.append(m, i, 1);
            assertNull(a.nextMessage(DURING_HANDSHAKE), "сообщение ещё не собрано");
        }
        a.append(m, m.length - 1, 1);
        assertArrayEquals(m, a.nextMessage(DURING_HANDSHAKE));
        assertTrue(a.isEmpty());
    }

    @Test
    @DisplayName("Остаток после разобранного сообщения сохраняется при переносе в начало массива")
    void remainderSurvivesCompaction() throws Exception {
        byte[] small = message(TlsConstants.HT_ENCRYPTED_EXTENSIONS, 100, (byte) 1);
        // Больше начальной ёмкости: после разбора первого сообщения нужен перенос и рост массива
        byte[] large =
                message(
                        TlsConstants.HT_CERTIFICATE,
                        4 * TlsConstants.HANDSHAKE_BUFFER_INITIAL_CAPACITY,
                        (byte) 9);
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        int split = 50;
        byte[] firstRecord = concat(small, Arrays.copyOf(large, split));
        a.append(firstRecord, 0, firstRecord.length);
        assertArrayEquals(small, a.nextMessage(DURING_HANDSHAKE));
        assertNull(a.nextMessage(DURING_HANDSHAKE));

        appendInChunks(a, Arrays.copyOfRange(large, split, large.length), 777);
        assertArrayEquals(large, a.nextMessage(DURING_HANDSHAKE), "остаток не повреждён");
    }

    @Test
    @DisplayName("Расшифровка в хвост: writableTail и commit дают то же, что append")
    void writableTailAndCommit() throws Exception {
        byte[] m = message(TlsConstants.HT_FINISHED, 32, (byte) 5);
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        ByteBuffer tail = a.writableTail(CHUNK);
        tail.put(m);
        a.commit(m.length);
        assertArrayEquals(m, a.nextMessage(DURING_HANDSHAKE));
    }

    @Test
    @DisplayName("Пустой фрагмент: unexpected_message и для append, и для commit")
    void emptyFragmentRejected() throws Exception {
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        TlsException viaAppend =
                assertThrows(TlsException.class, () -> a.append(new byte[0], 0, 0));
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, viaAppend.getAlertCode());
        a.writableTail(CHUNK);
        TlsException viaCommit = assertThrows(TlsException.class, () -> a.commit(0));
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, viaCommit.getAlertCode());
    }

    @Test
    @DisplayName("Предел по типу: Certificate до общего предела, прочие до предела ClientHello")
    void limitDependsOnMessageType() throws Exception {
        int certificateMax =
                TlsConstants.MAX_HANDSHAKE_MESSAGE_SIZE - TlsConstants.HANDSHAKE_HEADER_SIZE;
        int otherMax =
                TlsConstants.MAX_HANDSHAKE_NON_CERTIFICATE_MESSAGE_SIZE
                        - TlsConstants.HANDSHAKE_HEADER_SIZE;

        assertHeaderAccepted(TlsConstants.HT_CERTIFICATE, certificateMax, DURING_HANDSHAKE);
        assertHeaderRejected(TlsConstants.HT_CERTIFICATE, certificateMax + 1, DURING_HANDSHAKE);
        assertHeaderAccepted(TlsConstants.HT_CLIENT_HELLO, otherMax, DURING_HANDSHAKE);
        assertHeaderRejected(TlsConstants.HT_CLIENT_HELLO, otherMax + 1, DURING_HANDSHAKE);
        assertHeaderRejected(TlsConstants.HT_ENCRYPTED_EXTENSIONS, otherMax + 1, DURING_HANDSHAKE);
    }

    @Test
    @DisplayName("После рукопожатия предел служебного сообщения, даже для типа Certificate")
    void postHandshakeLimit() throws Exception {
        int postMax =
                TlsConstants.MAX_POST_HANDSHAKE_MESSAGE_SIZE - TlsConstants.HANDSHAKE_HEADER_SIZE;
        assertHeaderAccepted(TlsConstants.HT_NEW_SESSION_TICKET, postMax, AFTER_HANDSHAKE);
        assertHeaderRejected(TlsConstants.HT_NEW_SESSION_TICKET, postMax + 1, AFTER_HANDSHAKE);
        assertHeaderRejected(TlsConstants.HT_CERTIFICATE, postMax + 1, AFTER_HANDSHAKE);
    }

    @Test
    @DisplayName(
            "Certificate наибольшего допустимого размера собирается из записей полного размера")
    void largestCertificateAssembles() throws Exception {
        byte[] m =
                message(
                        TlsConstants.HT_CERTIFICATE,
                        TlsConstants.MAX_HANDSHAKE_MESSAGE_SIZE
                                - TlsConstants.HANDSHAKE_HEADER_SIZE,
                        (byte) 3);
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        for (int offset = 0; offset < m.length; offset += CHUNK) {
            assertNull(a.nextMessage(DURING_HANDSHAKE), "сообщение ещё не собрано");
            a.append(m, offset, Math.min(CHUNK, m.length - offset));
        }
        assertArrayEquals(m, a.nextMessage(DURING_HANDSHAKE));
    }

    @Test
    @DisplayName("Запасной предел: без разбора буфер не растёт дальше сообщения и одной записи")
    void bufferedBytesBackstop() throws Exception {
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        byte[] chunk = new byte[CHUNK];
        TlsException failure =
                assertThrows(
                        TlsException.class,
                        () -> {
                            for (int i = 0; i < 1000; i++) {
                                a.append(chunk, 0, chunk.length);
                            }
                        });
        assertEquals(TlsConstants.ALERT_INTERNAL_ERROR, failure.getAlertCode());
    }

    @Test
    @DisplayName("Граница записи при смене ключа: остаток даёт unexpected_message")
    void recordBoundaryAtKeyChange() throws Exception {
        byte[] m = message(TlsConstants.HT_FINISHED, 32, (byte) 1);
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        a.append(m, 0, m.length);
        a.nextMessage(DURING_HANDSHAKE);
        assertDoesNotThrow(a::requireRecordBoundaryAtKeyChange, "после целого сообщения граница");

        a.append(m, 0, 1);
        TlsException failure =
                assertThrows(TlsException.class, a::requireRecordBoundaryAtKeyChange);
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, failure.getAlertCode());
    }

    @Test
    @DisplayName("reset очищает несобранный остаток")
    void resetClears() throws Exception {
        byte[] m = message(TlsConstants.HT_FINISHED, 32, (byte) 1);
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        a.append(m, 0, 10);
        a.reset();
        assertTrue(a.isEmpty(), "после reset буфер пуст");
        a.append(m, 0, m.length);
        assertArrayEquals(m, a.nextMessage(DURING_HANDSHAKE), "буфер снова пригоден");
    }

    private static void assertHeaderAccepted(byte type, int bodyLength, boolean postHandshake)
            throws TlsException {
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        byte[] h = header(type, bodyLength);
        a.append(h, 0, h.length);
        assertNull(a.nextMessage(postHandshake), "заголовок в пределе: сборщик ждёт тело");
    }

    private static void assertHeaderRejected(byte type, int bodyLength, boolean postHandshake)
            throws TlsException {
        HandshakeMessageAssembler a = new HandshakeMessageAssembler();
        byte[] h = header(type, bodyLength);
        a.append(h, 0, h.length);
        TlsException failure =
                assertThrows(
                        TlsException.class,
                        () -> a.nextMessage(postHandshake),
                        "длина сверх предела отвергается по заголовку");
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, failure.getAlertCode());
    }
}
