package org.rssys.bench;

import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsTestHelper;

import org.rssys.gost.jca.RssysGostProvider;
import java.security.Security;

class BenchHelper {
    static {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    static class Bundle {
        final TlsCertificate cert;
        final PrivateKeyParameters priv;
        final PublicKeyParameters caPublicKey;
        Bundle(TlsCertificate cert, PrivateKeyParameters priv,
               PublicKeyParameters caPublicKey) {
            this.cert = cert;
            this.priv = priv;
            this.caPublicKey = caPublicKey;
        }
    }

    static TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    static Bundle createBundle() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(),
                root.priv, root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                null, null, null, false, null);
        return new Bundle(leaf.cert, leaf.priv, root.cert.getPublicKey());
    }
}
