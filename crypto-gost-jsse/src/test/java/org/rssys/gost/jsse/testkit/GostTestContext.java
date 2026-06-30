package org.rssys.gost.jsse.testkit;

import java.security.Security;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * Создание SSLContext с ГОСТ-ключами для тестов и примеров.
 * <p>
 * Провайдер регистрируется при первом вызове — JDK игнорирует повторные
 * {@code addProvider()} (insertion-ordered, ProviderList.add() не добавляет дубликат).
 * Все последующие вызовы {@code getInstance("TLSv1.3", "RssysGostJsse")}
 * прозрачно получают наш провайдер.
 */
public final class GostTestContext {

    private GostTestContext() {}

    /**
     * Создаёт {@link SSLContext} из готовых сертификата и CA.
     *
     * @param serverChain цепочка серверных сертификатов (JCA)
     * @param serverKey   приватный ключ сервера
     * @param caPublicKey публичный ключ CA (для TrustManager)
     * @return инициализированный SSLContext
     */
    public static SSLContext buildSslContext(
            X509Certificate[] serverChain,
            PrivateKeyParameters serverKey,
            PublicKeyParameters caPublicKey)
            throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry("default", serverChain, serverKey);
        GostX509TrustManager tm = new GostX509TrustManager(caPublicKey, false);
        SSLContext ctx =
                SSLContext.getInstance(
                        GostJsseConstants.PROTOCOL_TLS_1_3, GostJsseConstants.PROVIDER_NAME);
        ctx.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);
        return ctx;
    }

    /**
     * Перегрузка для {@link GostTestCerts.CertChain} — конвертирует цепочку
     * в JCA-формат и вызывает {@link #buildSslContext(X509Certificate[], PrivateKeyParameters, PublicKeyParameters)}.
     */
    public static SSLContext buildSslContext(GostTestCerts.CertChain certs) throws Exception {
        return buildSslContext(certs.toJca(), certs.key(), certs.caKey());
    }
}
