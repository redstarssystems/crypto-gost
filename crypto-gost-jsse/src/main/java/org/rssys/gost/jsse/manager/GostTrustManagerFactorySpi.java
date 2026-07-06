package org.rssys.gost.jsse.manager;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.signature.PublicKeyParameters;

/**
 * TrustManagerFactorySpi для ГОСТ-сертификатов.
 * <p>
 * Загружает доверенные CA-ключи из KeyStore. Каждый сертификат
 * с алгоритмом ECGOST3410-2012 конвертируется в PublicKeyParameters.
 */
public final class GostTrustManagerFactorySpi extends TrustManagerFactorySpi {

    private PublicKeyParameters caPublicKey;
    private boolean requireOcspStapling;
    private GostTrustManagerParameters params;

    @Override
    protected void engineInit(KeyStore ks) {
        if (ks == null) return;
        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!ks.isCertificateEntry(alias)) continue;

                Certificate cert = ks.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    X509Certificate x509 = (X509Certificate) cert;
                    if (GostJsseConstants.KEY_ALG_ECGOST_2012.equals(
                            x509.getPublicKey().getAlgorithm())) {
                        // Последний CA-ключ из хранилища (можно улучшить в фазе 3)
                        caPublicKey = new GostCertificate(x509.getEncoded()).getPublicKey();
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to init TrustManagerFactory", e);
        }
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) {
        if (!(spec instanceof GostTrustManagerParameters)) {
            throw new IllegalArgumentException(
                    "Expected GostTrustManagerParameters, got "
                            + (spec == null ? "null" : spec.getClass().getName()));
        }
        this.params = (GostTrustManagerParameters) spec;
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        if (params != null) {
            return new TrustManager[] {
                new GostX509TrustManager(
                        params.getCaPublicKeys(),
                        params.getOcspPolicy(),
                        params.getOcspFetcher(),
                        params.getCrlPolicy(),
                        params.getCrlFetcher(),
                        params.getMaxCrlSize(),
                        params.getMaxRevokedEntries(),
                        params.getMaxOcspAgeMs())
            };
        }
        return new TrustManager[] {new GostX509TrustManager(caPublicKey, requireOcspStapling)};
    }
}
