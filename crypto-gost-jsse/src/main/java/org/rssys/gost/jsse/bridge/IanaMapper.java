package org.rssys.gost.jsse.bridge;

import org.rssys.gost.tls13.TlsConstants;
import static org.rssys.gost.jsse.GostJsseConstants.KEY_TYPE_ECGOST_256;
import static org.rssys.gost.jsse.GostJsseConstants.KEY_TYPE_ECGOST_512;

/**
 * Маппинг signature scheme → JSSE keyType для X509KeyManager.
 */
public final class IanaMapper {

    public static String signatureSchemeToKeyType(int sigScheme) {
        switch (sigScheme) {
            case TlsConstants.SIG_GOST_TC26_A_256:
            case TlsConstants.SIG_GOST_CRYPTOPRO_A:
            case TlsConstants.SIG_GOST_CRYPTOPRO_B:
            case TlsConstants.SIG_GOST_CRYPTOPRO_C:
                return KEY_TYPE_ECGOST_256;
            case TlsConstants.SIG_GOST_TC26_512_A:
            case TlsConstants.SIG_GOST_TC26_512_B:
            case TlsConstants.SIG_GOST_TC26_512_C:
                return KEY_TYPE_ECGOST_512;
            default:
                return null;
        }
    }

    private IanaMapper() {}
}
