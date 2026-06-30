package org.rssys.gost.tls13.record;

/**
 * Результат дешифрования TLS-записи из {@link TlsRecord#unprotect(ByteBuffer, ByteBuffer)}.
 * <p>
 * Содержит статус и подсказку для продолжения. В отличие от исключений, это
 * нормальный control flow для SSLEngine-совместимости.
 *
 * <p>Семантика полей:
 * <ul>
 *   <li>{@code OK} — данные расшифрованы; {@link #contentType} и позиция
 *       plaintext buffer'а сдвинута на записанные байты. hint = 0.</li>
 *   <li>{@code NEED_MORE_INPUT} — недостаточно данных во входном буфере.
 *       Позиция record buffer'а не изменилась. hint = минимальное количество
 *       байт, необходимое для полной записи.</li>
 *   <li>{@code OUTPUT_TOO_SMALL} — выходной буфер недостаточен. Позиция
 *       record buffer'а восстановлена (input не потреблён). hint = минимальный
 *       размер plaintext buffer'а. Расшифровка будет выполнена заново при retry.</li>
 * </ul>
 */
public final class UnprotectResult {
    public enum Status {
        OK,
        NEED_MORE_INPUT,
        OUTPUT_TOO_SMALL
    }

    public final Status status;
    public final byte contentType;
    public final int hint;

    private UnprotectResult(Status status, byte contentType, int hint) {
        this.status = status;
        this.contentType = contentType;
        this.hint = hint;
    }

    public static UnprotectResult ok(byte contentType) {
        return new UnprotectResult(Status.OK, contentType, 0);
    }

    public static UnprotectResult needMoreInput(int minBytes) {
        return new UnprotectResult(Status.NEED_MORE_INPUT, (byte) 0, minBytes);
    }

    public static UnprotectResult outputTooSmall(int minBytes) {
        return new UnprotectResult(Status.OUTPUT_TOO_SMALL, (byte) 0, minBytes);
    }
}
