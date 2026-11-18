package org.rssys.gost.tls13.message;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.TlsUtils;

/**
 * Сборщик сообщений рукопожатия из фрагментов записей (RFC 8446 §5.1): одна запись может нести
 * несколько сообщений, одно сообщение может быть разрезано на много записей.
 * <p>
 * Общий для {@code TlsSession} и движка JSSE, чтобы пределы размера и граница записи при смене
 * ключей проверялись одинаково.
 * <p>
 * Инварианты:
 * <ul>
 *   <li>длина сообщения сверяется с пределом его типа, как только пришёл заголовок, до тела;</li>
 *   <li>несобранные байты лежат в {@code [readPos, writePos)}; разобранное сообщение сдвигает
 *       только {@code readPos}, остаток переносится в начало массива лишь при нехватке места, так
 *       что сообщение, разрезанное на мелкие записи, собирается за линейное время;</li>
 *   <li>в буфере не больше одного неполного сообщения и одной записи.</li>
 * </ul>
 * Не потокобезопасен: владелец вызывает его под своим замком.
 */
public final class HandshakeMessageAssembler {

    /**
     * Запасной предел несобранных байт: неполное сообщение наибольшего размера и одна запись.
     * При проверке длины по заголовку он не достигается; срабатывание означает ошибку в учёте
     * позиций, поэтому код alert — internal_error.
     */
    private static final int MAX_BUFFERED_BYTES =
            TlsConstants.MAX_HANDSHAKE_MESSAGE_SIZE + TlsConstants.MAX_PLAINTEXT_LENGTH;

    private byte[] buf = new byte[TlsConstants.HANDSHAKE_BUFFER_INITIAL_CAPACITY];
    private int readPos;
    private int writePos;

    /**
     * Наибольший допустимый размер сообщения вместе с заголовком.
     *
     * @param type тип сообщения из заголовка
     * @param postHandshake рукопожатие завершено (допустимы только KeyUpdate и NewSessionTicket)
     * @return предел в байтах
     */
    public static int maxMessageSize(byte type, boolean postHandshake) {
        if (postHandshake) {
            return TlsConstants.MAX_POST_HANDSHAKE_MESSAGE_SIZE;
        }
        return type == TlsConstants.HT_CERTIFICATE
                ? TlsConstants.MAX_HANDSHAKE_MESSAGE_SIZE
                : TlsConstants.MAX_HANDSHAKE_NON_CERTIFICATE_MESSAGE_SIZE;
    }

    /**
     * Добавляет фрагмент из записи рукопожатия.
     *
     * @param data массив с фрагментом
     * @param off смещение фрагмента
     * @param len длина фрагмента, больше нуля
     * @throws TlsException {@code unexpected_message} для пустого фрагмента (RFC 8446 §5.1),
     *         {@code internal_error} при превышении запасного предела
     */
    public void append(byte[] data, int off, int len) throws TlsException {
        requireNonEmptyFragment(len);
        ensureFree(len);
        System.arraycopy(data, off, buf, writePos, len);
        writePos += len;
    }

    /**
     * Свободный хвост буфера для расшифровки записи прямо в него, без промежуточной копии.
     * После расшифровки вызывающий подтверждает записанное через {@link #commit(int)}.
     *
     * @param maxLen наибольшая длина, которая может быть записана
     * @return буфер с позицией в начале свободного места и пределом {@code maxLen}
     * @throws TlsException {@code internal_error} при превышении запасного предела
     */
    public ByteBuffer writableTail(int maxLen) throws TlsException {
        ensureFree(maxLen);
        return ByteBuffer.wrap(buf, writePos, maxLen);
    }

    /**
     * Подтверждает {@code len} байт, записанных в хвост из {@link #writableTail(int)}.
     *
     * @param len число записанных байт
     * @throws TlsException {@code unexpected_message} для пустого фрагмента
     */
    public void commit(int len) throws TlsException {
        requireNonEmptyFragment(len);
        if (len > buf.length - writePos) {
            throw new IllegalArgumentException("Committed length exceeds reserved tail");
        }
        writePos += len;
    }

    /**
     * Выдаёт следующее целое сообщение (заголовок и тело) или {@code null}, если оно ещё не
     * собрано. Предел размера проверяется по заголовку, до прихода тела.
     *
     * @param postHandshake рукопожатие завершено
     * @return копия сообщения либо {@code null}
     * @throws TlsException {@code decode_error}, если заявленная длина больше предела типа
     */
    public byte[] nextMessage(boolean postHandshake) throws TlsException {
        int available = writePos - readPos;
        if (available < TlsConstants.HANDSHAKE_HEADER_SIZE) {
            return null;
        }
        byte type = buf[readPos];
        int bodyLength =
                ((buf[readPos + 1] & 0xFF) << 16)
                        | ((buf[readPos + 2] & 0xFF) << 8)
                        | (buf[readPos + 3] & 0xFF);
        int totalLength = TlsConstants.HANDSHAKE_HEADER_SIZE + bodyLength;
        if (totalLength > maxMessageSize(type, postHandshake)) {
            throw new TlsException(
                    TlsConstants.ALERT_DECODE_ERROR,
                    "Handshake message too large: " + totalLength + " bytes");
        }
        if (available < totalLength) {
            return null;
        }
        byte[] message = Arrays.copyOfRange(buf, readPos, readPos + totalLength);
        readPos += totalLength;
        if (readPos == writePos) {
            // Всё разобрано: затираем открытый текст рукопожатия и начинаем с начала массива
            Arrays.fill(buf, 0, writePos, (byte) 0);
            readPos = 0;
            writePos = 0;
        }
        return message;
    }

    /** @return {@code true}, если несобранных байт нет */
    public boolean isEmpty() {
        return readPos == writePos;
    }

    /**
     * RFC 8446 §5.1: сообщения рукопожатия не пересекают смену ключей, поэтому в момент смены
     * ключа чтения в буфере не должно остаться ни одного байта.
     *
     * @throws TlsException {@code unexpected_message}, если остаток есть
     */
    public void requireRecordBoundaryAtKeyChange() throws TlsException {
        if (!isEmpty()) {
            throw new TlsException(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    "Handshake message does not end at a record boundary before a key change");
        }
    }

    /** Затирает содержимое и возвращает буфер к начальному размеру. */
    public void reset() {
        TlsUtils.wipeArray(buf);
        readPos = 0;
        writePos = 0;
        if (buf.length > TlsConstants.HANDSHAKE_BUFFER_INITIAL_CAPACITY) {
            buf = new byte[TlsConstants.HANDSHAKE_BUFFER_INITIAL_CAPACITY];
        }
    }

    private static void requireNonEmptyFragment(int len) throws TlsException {
        if (len <= 0) {
            throw new TlsException(TlsConstants.ALERT_UNEXPECTED_MESSAGE, "Empty handshake record");
        }
    }

    /**
     * Обеспечивает {@code len} свободных байт после {@code writePos}. Остаток переносится в начало
     * массива только при нехватке места: так перенос случается не чаще удвоения, а не на каждую
     * запись.
     */
    private void ensureFree(int len) throws TlsException {
        int pending = writePos - readPos;
        if (pending + len > MAX_BUFFERED_BYTES) {
            throw new TlsException(
                    TlsConstants.ALERT_INTERNAL_ERROR,
                    "Handshake reassembly buffer limit exceeded");
        }
        if (len <= buf.length - writePos) {
            return;
        }
        if (readPos > 0) {
            System.arraycopy(buf, readPos, buf, 0, pending);
            Arrays.fill(buf, pending, writePos, (byte) 0);
            readPos = 0;
            writePos = pending;
            if (len <= buf.length - writePos) {
                return;
            }
        }
        byte[] grown = Arrays.copyOf(buf, Math.max(buf.length * 2, writePos + len));
        TlsUtils.wipeArray(buf);
        buf = grown;
    }
}
