package org.rssys.gost.jsse;

import org.rssys.gost.tls13.TlsCiphersuite;

/**
 * Проверка имён наборов шифров и протоколов для {@code setEnabledCipherSuites} и
 * {@code setEnabledProtocols}.
 * <p>
 * Служебный помощник пакетов {@code engine} и {@code socket}: одна проверка для движка и
 * серверного сокета, чтобы их поведение не расходилось. Публичен только из-за границы пакетов и
 * частью стабильного API не является. Как в JDK, пустой массив допустим (отказ наступит при рукопожатии, а
 * не при настройке), а неизвестное имя отвергается сразу.
 */
public final class SslParameterNames {

    private SslParameterNames() {}

    /**
     * Проверяет имена наборов шифров.
     *
     * @param suites IANA-имена наборов
     * @return копия массива
     * @throws IllegalArgumentException если массив равен null или содержит неизвестное имя
     */
    public static String[] checkedCipherSuites(String[] suites) {
        if (suites == null) {
            throw new IllegalArgumentException("Cipher suites must not be null");
        }
        for (String suite : suites) {
            if (TlsCiphersuite.byIanaName(suite) == null) {
                throw new IllegalArgumentException("Unsupported cipher suite: " + suite);
            }
        }
        return suites.clone();
    }

    /**
     * Проверяет имена протоколов.
     *
     * @param protocols имена протоколов
     * @return копия массива
     * @throws IllegalArgumentException если массив равен null или содержит неподдерживаемый
     *     протокол
     */
    public static String[] checkedProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("Protocols must not be null");
        }
        for (String protocol : protocols) {
            if (!GostJsseConstants.PROTOCOL_TLS_1_3.equals(protocol)) {
                throw new IllegalArgumentException("Unsupported protocol: " + protocol);
            }
        }
        return protocols.clone();
    }
}
