package org.rssys.gost.tls13.cert;

import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.signature.PrivateKeyParameters;

import java.security.PrivateKey;
import java.security.Security;

/**
 * Загрузчик PKCS12 (PFX) для GOST.
 * <p>
 * Делегирует {@link GostPkcs12Loader} для нативной поддержки RFC 9337/9548.
 * Сохранён для обратной совместимости.
 */
public final class Pkcs12Loader {

    static {
        if (Security.getProvider("RssysGostProvider") == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    private Pkcs12Loader() {}

    /**
     * Загружает PFX, делегируя {@link GostPkcs12Loader#load(byte[], char[])}.
     *
     * @return результат загрузки
     */
    public static GostPkcs12Loader.Result load(byte[] pfxData, char[] password) {
        return GostPkcs12Loader.load(pfxData, password);
    }

    public static PrivateKeyParameters adaptPrivateKey(PrivateKey jdkKey) {
        return GostPkcs12Loader.adaptPrivateKey(jdkKey);
    }
}
