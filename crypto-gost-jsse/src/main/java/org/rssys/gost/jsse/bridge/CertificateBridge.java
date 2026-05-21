package org.rssys.gost.jsse.bridge;

import org.rssys.gost.tls13.cert.TlsCertificate;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Конверсия между TlsCertificate (tls13-ядро) и X509Certificate (JCA/JSSE).
 */
public final class CertificateBridge {

    private static final String X509_TYPE = "X.509";

    /**
     * TlsCertificate → X509Certificate через DER-encoding.
     *
     * @param cert TlsCertificate (не null)
     * @return X509Certificate
     * @throws CertificateException при ошибке парсинга DER
     */
    public static X509Certificate toJca(TlsCertificate cert) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance(X509_TYPE);
        return (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(cert.getCertData()));
    }

    /**
     * Массив TlsCertificate → X509Certificate[].
     */
    public static X509Certificate[] toJca(List<TlsCertificate> chain) throws CertificateException {
        if (chain == null) return new X509Certificate[0];
        X509Certificate[] result = new X509Certificate[chain.size()];
        for (int i = 0; i < chain.size(); i++) {
            result[i] = toJca(chain.get(i));
        }
        return result;
    }

    /**
     * TlsCertificate + опциональная цепочка промежуточных → X509Certificate[].
     * Удобная перегрузка для тестов, работающих с CertBundle.
     */
    public static X509Certificate[] toJcaChain(TlsCertificate leaf, TlsCertificate... intermediates)
            throws CertificateException {
        if (leaf == null) return new X509Certificate[0];
        int len = 1 + (intermediates != null ? intermediates.length : 0);
        X509Certificate[] result = new X509Certificate[len];
        result[0] = toJca(leaf);
        if (intermediates != null) {
            for (int i = 0; i < intermediates.length; i++) {
                result[1 + i] = toJca(intermediates[i]);
            }
        }
        return result;
    }

    /**
     * X509Certificate → TlsCertificate через getEncoded().
     */
    public static TlsCertificate toTls(X509Certificate cert) {
        try {
            return new TlsCertificate(cert.getEncoded());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to encode X509Certificate", e);
        }
    }

    /**
     * X509Certificate[] → List<TlsCertificate>.
     */
    public static List<TlsCertificate> toTls(X509Certificate[] chain) {
        if (chain == null) return List.of();
        List<TlsCertificate> result = new ArrayList<>(chain.length);
        for (X509Certificate c : chain) {
            result.add(toTls(c));
        }
        return result;
    }

    private CertificateBridge() {}
}
