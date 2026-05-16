package org.rssys.gost.jsse;

import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Константы JSSE-модуля: протоколы, размеры буферов, provider.
 */
public final class GostJsseConstants {

    public static final String PROTOCOL_TLS_1_3 = "TLSv1.3";
    public static final String[] SUPPORTED_PROTOCOLS = {PROTOCOL_TLS_1_3};

    /** IANA-имена cipher suites — из TlsConstants, не дублировать. */
    public static final String IANA_CIPHER_SUITE_L =
            TlsConstants.IANA_TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    /** Cipher suite для pre-handshake session (JSSE spec §getSession). */
    public static final String SSL_NULL_CIPHER = "SSL_NULL_WITH_NULL_NULL";

    public static final String IANA_CIPHER_SUITE_S =
            TlsConstants.IANA_TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;

    /** Поддерживаемые cipher suite имена — строим из TlsCiphersuite. */
    public static final String[] SUPPORTED_CIPHER_SUITES = buildSupportedCipherSuites();

    private static String[] buildSupportedCipherSuites() {
        TlsCiphersuite[] suites = TlsCiphersuite.values();
        String[] result = new String[suites.length];
        for (int i = 0; i < suites.length; i++) {
            result[i] = suites[i].getIanaName();
        }
        return result;
    }

    public static final String KEY_TYPE_ECGOST_256 = "ECGOST3410-2012-256";
    public static final String KEY_TYPE_ECGOST_512 = "ECGOST3410-2012-512";
    public static final String KEY_ALG_ECGOST_2012 = "ECGOST3410-2012";
    public static final String PROTOCOL_GOST_TLS_1_3 = "GOST-TLSv1.3";

    public static final String PROVIDER_NAME = "RssysGostJsse";
    public static final String PROVIDER_VERSION = "1.0";
    public static final String PROVIDER_INFO = "Rssys GOST JSSE Provider";

    public static final int DEFAULT_PACKET_BUFFER_SIZE = TlsConstants.MAX_CIPHERTEXT_LENGTH;
    public static final int DEFAULT_APPLICATION_BUFFER_SIZE = TlsConstants.MAX_PLAINTEXT_LENGTH;

    private GostJsseConstants() {}
}
