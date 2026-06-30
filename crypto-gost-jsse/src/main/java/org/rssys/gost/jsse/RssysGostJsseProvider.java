package org.rssys.gost.jsse;

import java.security.Provider;
import org.rssys.gost.jsse.engine.GostSSLContextSpi;
import org.rssys.gost.jsse.manager.GostKeyManagerFactorySpi;
import org.rssys.gost.jsse.manager.GostTrustManagerFactorySpi;

/**
 * JSSE Provider для ГОСТ TLS 1.3.
 * <p>
 * Регистрирует SSLContext, KeyManagerFactory и TrustManagerFactory
 * только для ГОСТ-алгоритмов.
 * <p>
 * Использование:
 * <pre>{@code
 * Security.addProvider(new RssysGostJsseProvider());
 * SSLContext ctx = SSLContext.getInstance("TLSv1.3", "RssysGostJsse");
 * }</pre>
 */
public final class RssysGostJsseProvider extends Provider {

    private static final long serialVersionUID = 1L;

    public RssysGostJsseProvider() {
        super(
                GostJsseConstants.PROVIDER_NAME,
                GostJsseConstants.PROVIDER_VERSION,
                GostJsseConstants.PROVIDER_INFO);

        // SSLContext — только явные имена, без алиаса "TLS"
        put("SSLContext." + GostJsseConstants.PROTOCOL_TLS_1_3, GostSSLContextSpi.class.getName());
        put(
                "SSLContext." + GostJsseConstants.PROTOCOL_GOST_TLS_1_3,
                GostSSLContextSpi.class.getName());

        // KeyManager — только GostX509, без алиаса PKIX
        put("KeyManagerFactory.GostX509", GostKeyManagerFactorySpi.class.getName());

        // TrustManager — только GostX509, без алиаса PKIX
        put("TrustManagerFactory.GostX509", GostTrustManagerFactorySpi.class.getName());
    }
}
