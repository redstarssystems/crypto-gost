package org.rssys.gost.jsse;

import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Константы JSSE-модуля: протоколы, наборы шифров, размеры буферов, имя provider, типы ключей,
 * алгоритмы проверки имени.
 */
public final class GostJsseConstants {

    public static final String PROTOCOL_TLS_1_3 = "TLSv1.3";
    private static final String[] SUPPORTED_PROTOCOLS = {PROTOCOL_TLS_1_3};

    /** Cipher suite для pre-handshake session (JSSE spec §getSession). */
    public static final String SSL_NULL_CIPHER = "SSL_NULL_WITH_NULL_NULL";

    /** Поддерживаемые cipher suite имена — строим из TlsCiphersuite. */
    private static final String[] SUPPORTED_CIPHER_SUITES = buildSupportedCipherSuites();

    /** @return поддерживаемые протоколы; каждый раз новая копия, глобальный список не меняется */
    public static String[] supportedProtocols() {
        return SUPPORTED_PROTOCOLS.clone();
    }

    /** @return IANA-имена поддерживаемых наборов шифров; каждый раз новая копия */
    public static String[] supportedCipherSuites() {
        return SUPPORTED_CIPHER_SUITES.clone();
    }

    private static String[] buildSupportedCipherSuites() {
        TlsCiphersuite[] suites = TlsCiphersuite.values();
        String[] result = new String[suites.length];
        for (int i = 0; i < suites.length; i++) {
            result[i] = suites[i].getIanaName();
        }
        return result;
    }

    /** Алгоритм endpoint identification: сверка имени узла с SAN (RFC 6125). */
    public static final String ENDPOINT_ID_HTTPS = "HTTPS";

    /** Алгоритм endpoint identification для LDAPS: та же сверка с SAN, что и у HTTPS. */
    public static final String ENDPOINT_ID_LDAPS = "LDAPS";

    public static final String KEY_TYPE_ECGOST_256 = "ECGOST3410-2012-256";
    public static final String KEY_TYPE_ECGOST_512 = "ECGOST3410-2012-512";
    public static final String KEY_ALG_ECGOST_2012 = "ECGOST3410-2012";
    public static final String PROTOCOL_GOST_TLS_1_3 = "GOST-TLSv1.3";

    public static final String PROVIDER_NAME = "RssysGostJsse";
    // Android: java.security.Provider имеет только конструктор
    // Provider(String, double, String) с API 1. Вариант с String-версией
    // (Provider(String, String, String)) — JDK 9+, на Android отсутствует.
    public static final double PROVIDER_VERSION = 1.0;
    public static final String PROVIDER_INFO = "Rssys GOST JSSE Provider";

    /**
     * Размер сетевого буфера: заголовок записи, наибольшее тело записи и запас движка. Совпадает
     * со значением {@code SSLSession.getPacketBufferSize()}; буфер меньшего размера не вместит
     * запись наибольшей длины.
     */
    public static final int DEFAULT_PACKET_BUFFER_SIZE =
            TlsConstants.RECORD_HEADER_SIZE
                    + TlsConstants.MAX_CIPHERTEXT_LENGTH
                    + TlsConstants.RECORD_BUFFER_HEADROOM;

    /** Размер буфера прикладных данных: наибольшая длина открытого текста одной записи. */
    public static final int DEFAULT_APPLICATION_BUFFER_SIZE = TlsConstants.MAX_PLAINTEXT_LENGTH;

    /**
     * Наибольшая длина контекста экспорта ключевого материала через JSSE. Совпадает с пределом
     * JDK 25 ({@code ExtendedSSLSession.exportKeyingMaterialData}), хотя слой tls13 принимает
     * больше: код, написанный под JSSE, не должен получать значение там, где JDK бросает
     * исключение.
     */
    public static final int EXPORT_CONTEXT_MAX_LENGTH = 255;

    private GostJsseConstants() {}
}
