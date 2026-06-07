package org.rssys.gost.jsse.examples;

import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.examples.ExampleUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Демонстрационный хелпер для примеров JSSE: генерирует CA + серверный
 * сертификат для localhost и собирает SSLContext с ГОСТ TLS 1.3.
 * <p>
 * Использует только production API: KeyGenerator, Signature, TlsCertificate.
 * Не предназначен для production-использования — только для примеров и тестов.
 */
public final class ExamplesCertHelper {

    private final CertChain certs;
    private final SSLContext sslContext;

    public ExamplesCertHelper() throws Exception {
        this.certs = createServerCert();
        Security.addProvider(new RssysGostJsseProvider());
        GostX509KeyManager km = new GostX509KeyManager();
        km.addKeyEntry("default", certs.toJca(), certs.key());
        GostX509TrustManager tm = new GostX509TrustManager(certs.caKey(), false);
        SSLContext ctx = SSLContext.getInstance(GostJsseConstants.PROTOCOL_TLS_1_3,
                GostJsseConstants.PROVIDER_NAME);
        ctx.init(new KeyManager[]{km}, new TrustManager[]{tm}, null);
        this.sslContext = ctx;
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    public GostX509KeyManager createKeyManager() {
        GostX509KeyManager km = new GostX509KeyManager();
        try {
            km.addKeyEntry("default", certs.toJca(), certs.key());
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        return km;
    }

    public GostX509TrustManager createTrustManager() {
        return new GostX509TrustManager(certs.caKey(), false);
    }

    /** DER серверного сертификата. */
    public byte[] getCertDer() {
        return certs.chain().get(0).getEncoded();
    }

    /** DER закрытого ключа (PKCS#8 PrivateKeyInfo). */
    public byte[] getKeyDer() {
        return GostDerCodec.encodePrivateKey(certs.key());
    }

    /** DER CA-сертификата. */
    public byte[] getCaCertDer() {
        return certs.caCert().getEncoded();
    }

    // ========================================================================
    // Генерация сертификатов
    // ========================================================================

    private static CertChain createServerCert() throws Exception {
        return createServerCert(ECParameters.tc26a256());
    }

    private static CertChain createServerCert(ECParameters params) throws Exception {
        ExampleUtils.CertBundle ca = ExampleUtils.createRootCABundle();
        ExampleUtils.CertBundle server = ExampleUtils.createServerCertBundle(ca);
        List<TlsCertificate> chain = new ArrayList<>();
        chain.add(server.cert());
        return new CertChain(chain, server.priv(), ca.pub(), ca.cert());
    }

    // ========================================================================
    // Внутреннее представление цепочки сертификатов
    // ========================================================================

    public record CertChain(
            List<TlsCertificate> chain,
            PrivateKeyParameters key,
            PublicKeyParameters caKey,
            TlsCertificate caCert
    ) {
        public X509Certificate[] toJca() throws CertificateException {
            List<X509Certificate> result = new ArrayList<>(chain.size());
            for (TlsCertificate c : chain) {
                result.add(CertificateBridge.toJca(c));
            }
            return result.toArray(new X509Certificate[0]);
        }
    }
}
