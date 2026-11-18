package org.rssys.gost.tls13.message;

import org.rssys.gost.tls13.TlsConstants;

/**
 * Тестовый доступ к package-private швам {@link TlsMessageBuilder}: подмена supported_groups и
 * сборка ClientHello без расширения key_share. Лежит в {@code src/test}, поэтому публичный API
 * библиотеки не расширяется.
 */
public final class TlsMessageBuilderTestAccess {

    private TlsMessageBuilderTestAccess() {}

    /** Подменяет список supported_groups в ClientHello, который соберёт {@code builder}. */
    public static void setSupportedGroups(TlsMessageBuilder builder, int... groups) {
        builder.setSupportedGroups(groups);
    }

    /**
     * Собирает тело HelloRetryRequest без key_share, с cookie и пустым {@code legacy_session_id}.
     * Нужен тестам клиента, которым важна обработка cookie, а не запрошенная группа.
     */
    public static byte[] buildHelloRetryRequestWithCookie(
            TlsMessageBuilder builder, int cipherSuiteId, byte[] cookie) {
        return builder.buildHelloRetryRequest(cipherSuiteId, cookie);
    }

    /** Заставляет {@code builder} не писать расширение key_share. */
    public static void omitKeyShare(TlsMessageBuilder builder) {
        builder.setOmitKeyShare(true);
    }

    /** Заставляет {@code builder} не писать расширение supported_groups. */
    public static void omitSupportedGroups(TlsMessageBuilder builder) {
        builder.setOmitSupportedGroups(true);
    }

    /**
     * Подставляет {@code legacy_session_id} в тело ClientHello (штатный клиент всегда шлёт
     * пустой). Остальные поля сдвигаются как есть: длины внутри тела от session id не зависят,
     * поэтому достаточно заменить поле. Полный handshake с таким ClientHello не завершить:
     * транскрипт клиента разойдётся с серверным, шов нужен для проверки ответа сервера.
     */
    public static byte[] withLegacySessionId(byte[] clientHelloBody, byte[] sessionId) {
        int sidLenPos = 2 + TlsConstants.RANDOM_LENGTH;
        int oldSidLen = clientHelloBody[sidLenPos] & 0xFF;
        int tailStart = sidLenPos + 1 + oldSidLen;
        byte[] out =
                new byte[sidLenPos + 1 + sessionId.length + clientHelloBody.length - tailStart];
        System.arraycopy(clientHelloBody, 0, out, 0, sidLenPos);
        out[sidLenPos] = (byte) sessionId.length;
        System.arraycopy(sessionId, 0, out, sidLenPos + 1, sessionId.length);
        System.arraycopy(
                clientHelloBody,
                tailStart,
                out,
                sidLenPos + 1 + sessionId.length,
                clientHelloBody.length - tailStart);
        return out;
    }

    /**
     * Портит последнюю запись key_share в теле ClientHello: длина её ключа становится больше
     * остатка расширения. Штатный билдер пишет только корректные записи, поэтому битую
     * хвостовую запись собираем побайтно.
     */
    public static byte[] corruptLastKeyShareEntry(byte[] clientHelloBody) {
        byte[] b = clientHelloBody.clone();
        int pos = 2 + 32;
        pos += 1 + (b[pos] & 0xFF); // legacy_session_id
        pos += 2 + (((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF)); // cipher_suites
        pos += 1 + (b[pos] & 0xFF); // compression_methods
        int extEnd = pos + 2 + (((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF));
        pos += 2;
        while (pos < extEnd) {
            int type = ((b[pos] & 0xFF) << 8) | (b[pos + 1] & 0xFF);
            int len = ((b[pos + 2] & 0xFF) << 8) | (b[pos + 3] & 0xFF);
            if (type == TlsConstants.EXT_KEY_SHARE) {
                int listOff = pos + 4 + 2;
                int listEnd = pos + 4 + len;
                int lastEntry = listOff;
                while (listOff < listEnd) {
                    lastEntry = listOff;
                    listOff += 4 + (((b[listOff + 2] & 0xFF) << 8) | (b[listOff + 3] & 0xFF));
                }
                b[lastEntry + 2] = (byte) 0xFF;
                b[lastEntry + 3] = (byte) 0xFF;
                return b;
            }
            pos += 4 + len;
        }
        throw new IllegalArgumentException("ClientHello without key_share");
    }
}
