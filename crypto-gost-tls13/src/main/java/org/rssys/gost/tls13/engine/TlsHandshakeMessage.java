package org.rssys.gost.tls13.engine;

import org.rssys.gost.tls13.TlsConstants;

import java.util.Arrays;

/**
 * Сообщение handshake TLS 1.3 (RFC 8446 Section 4).
 * Формат: handshake_type(1) || length(3) || body.
 */
public final class TlsHandshakeMessage {

    private final byte msgType;
    private final byte[] body;

    /**
     * @param msgType тип handshake-сообщения (HT_CLIENT_HELLO, HT_SERVER_HELLO, ...)
     * @param body    тело сообщения; ПОСЛЕ передачи в конструктор caller НЕ ДОЛЖЕН
     *                модифицировать этот массив — {@code encode()} и {@code getType()}
     *                читают его напрямую без защитного копирования
     */
    public TlsHandshakeMessage(byte msgType, byte[] body) {
        if (body == null) {
            throw new IllegalArgumentException("Body must not be null");
        }
        this.msgType = msgType;
        this.body = body;
    }

    /**
     * @return тип handshake сообщения (HT_CLIENT_HELLO, HT_SERVER_HELLO, ...)
     */
    public byte getType() {
        return msgType;
    }

    /**
     * @return тело сообщения
     */
    public byte[] getBody() {
        return body.clone();
    }

    /**
     * Кодирует handshake сообщение: type(1) || length(3) || body.
     *
     * @return закодированное handshake-сообщение
     */
    public byte[] encode() {
        byte[] msg = new byte[TlsConstants.HANDSHAKE_HEADER_SIZE + body.length];
        msg[0] = msgType;
        msg[1] = (byte) (body.length >>> 16);
        msg[2] = (byte) (body.length >>> 8);
        msg[3] = (byte) body.length;
        System.arraycopy(body, 0, msg, TlsConstants.HANDSHAKE_HEADER_SIZE, body.length);
        return msg;
    }

    /**
     * Декодирует handshake-сообщение из сырых байт.
     * Формат: type(1) || length(3) || body.
     *
     * @param data полное handshake-сообщение
     * @return декодированное сообщение
     */
    public static TlsHandshakeMessage decode(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data must not be null");
        }
        if (data.length < TlsConstants.HANDSHAKE_HEADER_SIZE) {
            throw new IllegalArgumentException("Handshake message too short: " + data.length);
        }
        byte type = data[0];
        int len = ((data[1] & 0xFF) << 16) | ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        if (data.length < TlsConstants.HANDSHAKE_HEADER_SIZE + len) {
            throw new IllegalArgumentException(
                    "Handshake message truncated: expected "
                            + (TlsConstants.HANDSHAKE_HEADER_SIZE + len)
                            + " but got " + data.length);
        }
        byte[] body = Arrays.copyOfRange(data,
                TlsConstants.HANDSHAKE_HEADER_SIZE,
                TlsConstants.HANDSHAKE_HEADER_SIZE + len);
        return new TlsHandshakeMessage(type, body);
    }

    /** Сравнивает по типу и телу (Arrays.equals). */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TlsHandshakeMessage)) return false;
        TlsHandshakeMessage that = (TlsHandshakeMessage) o;
        return msgType == that.msgType && Arrays.equals(body, that.body);
    }

    /** Хеш по типу и телу (Arrays.hashCode). */
    @Override
    public int hashCode() {
        return 31 * (int) msgType + Arrays.hashCode(body);
    }
}
