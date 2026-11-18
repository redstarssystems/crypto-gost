package org.rssys.gost.tls13.message;

import org.rssys.gost.pkix.cert.GostDnsName;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Проверка имени узла, которое идёт в расширение {@code server_name} (RFC 6066 §3).
 * <p>
 * Одно правило для обеих сторон: сервер превращает отказ в alert {@code unrecognized_name}, клиент
 * в {@link IllegalArgumentException}. Тогда клиент не отправит то, что отвергнет наш же сервер,
 * каким бы путём имя ни пришло (конфигурация, {@code setServerHostname}, прямой вызов сборщика).
 * <p>
 * Проверяются только байты имени: символы управления (в том числе NUL, который в проверках
 * имени сертификата обрывает строку), не-ASCII, общая длина и пустые метки. Остальной синтаксис DNS
 * (длина метки, допустимые символы) не проверяется: это дело проверки имени сертификата.
 */
public final class ServerNameCheck {

    /** Причина отказа имени. */
    enum Violation {
        NON_ASCII("host name contains non-ASCII bytes"),
        CONTROL_CHARACTER("host name contains control characters"),
        TOO_LONG("host name is longer than " + TlsConstants.MAX_SERVER_NAME_LENGTH + " characters"),
        EMPTY_LABEL("host name contains an empty label");

        private final String description;

        Violation(String description) {
            this.description = description;
        }

        String description() {
            return description;
        }
    }

    private static final byte DOT = '.';
    private static final int FIRST_NON_CONTROL = 0x20;
    private static final int DELETE = 0x7F;
    private static final int FIRST_NON_ASCII = 0x80;

    private ServerNameCheck() {}

    /**
     * Проверяет имя на стороне клиента перед записью в {@code server_name}.
     * <p>
     * IP-литералы и пустое имя не проверяются: они в SNI не попадают (RFC 6066 §3, сборщик их
     * пропускает), поэтому ошибкой не являются.
     *
     * @param hostname имя узла или {@code null}
     * @throws IllegalArgumentException если имя не может быть отправлено в SNI; само имя в
     *                                  сообщение не входит, оно приходит извне
     */
    public static void requireValidForSni(String hostname) {
        if (hostname == null || hostname.isEmpty() || GostDnsName.isIpAddress(hostname)) {
            return;
        }
        byte[] bytes = new byte[hostname.length()];
        for (int i = 0; i < bytes.length; i++) {
            char c = hostname.charAt(i);
            if (c >= FIRST_NON_ASCII) {
                throw new IllegalArgumentException(
                        "Invalid server name: " + Violation.NON_ASCII.description());
            }
            bytes[i] = (byte) c;
        }
        Violation violation = check(bytes, 0, bytes.length);
        if (violation != null) {
            throw new IllegalArgumentException("Invalid server name: " + violation.description());
        }
    }

    /**
     * Проверяет байты имени, полученные от пира.
     * <p>
     * Порядок: сначала срезается ровно одна конечная точка (терпим её из совместимости, хотя
     * RFC 6066 §3 требует форму без точки), затем измеряется длина и ищутся пустые метки. Так
     * граница предела однозначна: 253 символа с точкой и без неё равны.
     *
     * @param data   массив с именем
     * @param offset начало имени
     * @param length длина имени
     * @return причина отказа или {@code null}, если имя допустимо
     */
    static Violation check(byte[] data, int offset, int length) {
        int end = offset + length;
        if (length > 0 && data[end - 1] == DOT) {
            end--;
        }
        if (end - offset > TlsConstants.MAX_SERVER_NAME_LENGTH) {
            return Violation.TOO_LONG;
        }
        int labelLength = 0;
        for (int i = offset; i < end; i++) {
            int b = data[i] & 0xFF;
            // Байты, а не String: иначе не-ASCII и NUL различались бы по артефактам декодирования
            if (b >= FIRST_NON_ASCII) {
                return Violation.NON_ASCII;
            }
            if (b < FIRST_NON_CONTROL || b == DELETE) {
                return Violation.CONTROL_CHARACTER;
            }
            if (b == DOT) {
                if (labelLength == 0) {
                    return Violation.EMPTY_LABEL;
                }
                labelLength = 0;
            } else {
                labelLength++;
            }
        }
        // Пустое имя (одни точки или единственная точка) и точка в конце после среза: пустая метка
        return labelLength == 0 ? Violation.EMPTY_LABEL : null;
    }
}
