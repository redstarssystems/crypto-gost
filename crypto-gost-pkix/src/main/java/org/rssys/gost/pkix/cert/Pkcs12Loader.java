package org.rssys.gost.pkix.cert;

import java.security.PrivateKey;
import java.security.Security;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.signature.PrivateKeyParameters;

/**
 * Загрузчик PKCS12 (PFX) для GOST.
 * <p>
 * Делегирует {@link GostPkcs12Loader} для нативной поддержки RFC 9337/9548.
 *
 * @deprecated Используйте {@link GostPkcs12Loader#load(byte[], char[], boolean)}
 *             и {@link GostPkcs12Loader#adaptPrivateKey(java.security.PrivateKey)} напрямую.
 *             Сохранён для возможности загрузки PFX через JDK.
 */
@Deprecated(since = "0.6.0", forRemoval = false)
public final class Pkcs12Loader {

    static {
        if (Security.getProvider("RssysGostProvider") == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    private Pkcs12Loader() {}

    /**
     * Загружает PFX с явным контролем JDK-fallback.
     *
     * @param pfxData           DER-байты PFX
     * @param password          пароль
     * @param allowJdkFallback  {@code true} — разрешить fallback на JDK KeyStore для не-ГОСТ контейнеров
     * @return результат загрузки
     */
    public static GostPkcs12Loader.Result load(
            byte[] pfxData, char[] password, boolean allowJdkFallback) {
        return GostPkcs12Loader.load(pfxData, password, allowJdkFallback);
    }

    public static PrivateKeyParameters adaptPrivateKey(PrivateKey jdkKey) {
        return GostPkcs12Loader.adaptPrivateKey(jdkKey);
    }
}
