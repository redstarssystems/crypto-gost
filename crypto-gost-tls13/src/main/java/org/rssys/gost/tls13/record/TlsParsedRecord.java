package org.rssys.gost.tls13.record;

import java.util.Arrays;

/**
 * Результат дешифрования TLS-записи.
 * <p>
 * Содержит тип содержимого и открытые данные после снятия MGM-защиты
 * и constant-time удаления padding'а (RFC 8446 §5.2).
 * <p>
 * Публичный — используется в {@link TlsRecord#unprotect(ByteBuffer, ByteBuffer)}
 * для передачи результата без дополнительной копии данных.
 */
public final class TlsParsedRecord {
    private final byte contentType;
    private final byte[] data;

    /**
     * @param contentType тип содержимого (CT_*)
     * @param data        открытые данные (будет обрезан до len байт)
     * @param len         фактическая длина данных после удаления padding'а
     */
    public TlsParsedRecord(byte contentType, byte[] data, int len) {
        this.contentType = contentType;
        this.data = Arrays.copyOf(data, len);
    }

    /**
     * @return тип содержимого (CT_HANDSHAKE, CT_APPLICATION_DATA, CT_ALERT)
     */
    public byte getContentType() {
        return contentType;
    }

    /** @return открытые данные */
    public byte[] getData() {
        return data;
    }
}
