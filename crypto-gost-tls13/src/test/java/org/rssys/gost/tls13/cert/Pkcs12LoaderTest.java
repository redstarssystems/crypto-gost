package org.rssys.gost.tls13.cert;

import org.rssys.gost.tls13.TlsTestHelper;
import static org.rssys.gost.tls13.TlsTestHelper.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.signature.ECParameters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Pkcs12Loader — загрузка PFX-контейнеров через JDK KeyStore")
class Pkcs12LoaderTest {

    static {
        if (Security.getProvider("RssysGostProvider") == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    private static final char[] PASSWORD = "changeit".toCharArray();

    @Test
    @DisplayName("GOST PFX: полный roundtrip — load возвращает ключ и сертификат")
    void testGostRoundtrip() throws Exception {
        byte[] pfx = buildGostPfxViaJdk();
        GostPkcs12Loader.Result result = Pkcs12Loader.load(pfx, PASSWORD);

        assertNotNull(result.getPrivateKey(), "private key");
        assertNotNull(result.getCertificateChain(), "cert chain");
        assertFalse(result.getCertificateChain().isEmpty(), "cert chain not empty");
        assertTrue(result.getCertificateChain().get(0).isEkuValidForServer(), "server cert");
    }

    @Test
    @DisplayName("GOST PFX: неверный пароль → IllegalArgumentException")
    void testGostWrongPassword() throws Exception {
        byte[] pfx = buildGostPfxViaJdk();
        assertThrows(IllegalArgumentException.class,
                () -> Pkcs12Loader.load(pfx, "wrong".toCharArray()));
    }

    @Test
    @DisplayName("GOST PFX: цепочка из CA + leaf")
    void testGostChain() throws Exception {
        byte[] pfx = buildGostChainPfxViaJdk();
        GostPkcs12Loader.Result result = Pkcs12Loader.load(pfx, PASSWORD);

        assertNotNull(result.getPrivateKey());
        List<TlsCertificate> chain = result.getCertificateChain();
        assertEquals(2, chain.size(), "chain size");
        assertTrue(chain.get(0).isEkuValidForServer(), "leaf is server cert");
        assertTrue(chain.get(1).isCA(), "second is CA");
    }

    // ---------------------------------------------------------------
    // Построители PFX через JDK KeyStore
    // ---------------------------------------------------------------

    private static byte[] buildGostPfxViaJdk() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        return storePfx("server", bundle.priv, bundle.cert);
    }

    private static byte[] buildGostChainPfxViaJdk() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle ca = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                params, ca.priv, ca.cert.getPublicKey(), ca.subjectDn,
                "20250101000000Z", "21060101120000Z",
                null, null, null, null, false, null);

        return storePfx("leaf", leaf.priv, leaf.cert, ca.cert);
    }

    /** Создаёт PFX через JDK KeyStore. */
    private static byte[] storePfx(String alias,
                                   org.rssys.gost.signature.PrivateKeyParameters priv,
                                   TlsCertificate firstCert,
                                   TlsCertificate... extraCerts) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        // Наш PrivateKey → JDK PrivateKey
        GostECPrivateKey jdkKey = new GostECPrivateKey(priv);

        // Наши TlsCertificate → JDK X509Certificate[]
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        java.security.cert.X509Certificate jdkFirst =
                (java.security.cert.X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(firstCert.getCertData()));
        java.security.cert.X509Certificate[] jdkChain;
        if (extraCerts.length > 0) {
            jdkChain = new java.security.cert.X509Certificate[1 + extraCerts.length];
            jdkChain[0] = jdkFirst;
            for (int i = 0; i < extraCerts.length; i++) {
                jdkChain[1 + i] = (java.security.cert.X509Certificate)
                        cf.generateCertificate(new ByteArrayInputStream(extraCerts[i].getCertData()));
            }
        } else {
            jdkChain = new java.security.cert.X509Certificate[]{jdkFirst};
        }

        ks.setKeyEntry(alias, jdkKey, PASSWORD, jdkChain);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, PASSWORD);
        return out.toByteArray();
    }
}
