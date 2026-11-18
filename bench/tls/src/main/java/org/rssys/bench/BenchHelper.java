package org.rssys.bench;

import java.security.Security;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;

class BenchHelper {
    static {
        if (Security.getProvider(RssysGostProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    static class Bundle {
        final GostCertificate cert;
        final PrivateKeyParameters priv;
        final GostCertificate caCert;
        Bundle(GostCertificate cert, PrivateKeyParameters priv,
               GostCertificate caCert) {
            this.cert = cert;
            this.priv = priv;
            this.caCert = caCert;
        }
    }

    static TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    static Bundle createBundle() throws Exception {
        PkixCertTestHelper.CertBundle root = PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf = PkixCertTestHelper.createCertSignedBy(
                ECParameters.tc26a256(),
                root.priv, root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                null, null, null, false, null);
        return new Bundle(leaf.cert, leaf.priv, root.cert);
    }
}
