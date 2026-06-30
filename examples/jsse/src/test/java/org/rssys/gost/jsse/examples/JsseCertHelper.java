package org.rssys.gost.jsse.examples;

import javax.net.ssl.SSLContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.testkit.GostTestCerts;
import org.rssys.gost.jsse.testkit.GostTestContext;

public final class JsseCertHelper {

    private final GostTestCerts.CertChain certs;
    private final SSLContext sslContext;

    public JsseCertHelper() throws Exception {
        this.certs = GostTestCerts.createServerCert();
        this.sslContext = GostTestContext.buildSslContext(certs);
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    public GostX509KeyManager createKeyManager() {
        GostX509KeyManager km = new GostX509KeyManager();
        try {
            km.addKeyEntry("default", certs.toJca(), certs.key());
        } catch (java.security.cert.CertificateException e) {
            throw new RuntimeException(e);
        }
        return km;
    }

    public GostX509TrustManager createTrustManager() {
        return new GostX509TrustManager(certs.caKey(), false);
    }
}
