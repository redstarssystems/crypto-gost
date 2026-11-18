package org.rssys.gost.jsse;

/**
 * Разбор алгоритма endpoint identification (проверки имени узла) в {@code SSLParameters}.
 *
 * <p>Единая точка для engine и trust manager: список поддерживаемых значений не должен
 * расходиться. Поддерживаются {@code HTTPS} и {@code LDAPS} (обе означают сверку имени с SAN
 * dNSName/iPAddress). «Отключено» означает {@code null} или пустую строку (контракт JDK).
 * Любое иное значение, включая {@code LDAP} (сверка по subject DN) и строку из пробелов,
 * отвергается: опечатка не должна молча выключать проверку.</p>
 */
public final class EndpointIdentification {

    /** Максимум символов значения алгоритма в тексте исключения. */
    private static final int MAX_MESSAGE_LENGTH = 32;

    private EndpointIdentification() {}

    /**
     * @param algorithm значение из {@code SSLParameters}
     * @return true, если проверка имени отключена ({@code null} или пустая строка)
     */
    public static boolean isDisabled(String algorithm) {
        return algorithm == null || algorithm.isEmpty();
    }

    /**
     * @param algorithm значение из {@code SSLParameters}
     * @return true, если это HTTPS или LDAPS (без учёта регистра)
     */
    public static boolean isSupported(String algorithm) {
        return GostJsseConstants.ENDPOINT_ID_HTTPS.equalsIgnoreCase(algorithm)
                || GostJsseConstants.ENDPOINT_ID_LDAPS.equalsIgnoreCase(algorithm);
    }

    /**
     * @param algorithm значение из {@code SSLParameters}
     * @return true, если значение непустое и не поддерживается, то есть его нужно отвергнуть
     */
    public static boolean isUnsupported(String algorithm) {
        return !isDisabled(algorithm) && !isSupported(algorithm);
    }

    /**
     * Текст ошибки для неподдерживаемого алгоритма. Значение приходит от пользователя, поэтому
     * оно усекается и очищается от управляющих символов: иначе оно исказило бы лог.
     *
     * @param algorithm неподдерживаемое значение; {@code null} выводится как пустое
     * @return сообщение для исключения
     */
    public static String unsupportedMessage(String algorithm) {
        algorithm = algorithm == null ? "" : algorithm;
        boolean truncated = algorithm.length() > MAX_MESSAGE_LENGTH;
        String head = truncated ? algorithm.substring(0, MAX_MESSAGE_LENGTH) : algorithm;
        StringBuilder sanitized = new StringBuilder(head.length() + 3);
        for (int i = 0; i < head.length(); i++) {
            char c = head.charAt(i);
            sanitized.append(Character.isISOControl(c) ? '?' : c);
        }
        if (truncated) {
            sanitized.append("...");
        }
        return "Unsupported endpoint identification algorithm: '"
                + sanitized
                + "' (supported: "
                + GostJsseConstants.ENDPOINT_ID_HTTPS
                + ", "
                + GostJsseConstants.ENDPOINT_ID_LDAPS
                + ")";
    }
}
