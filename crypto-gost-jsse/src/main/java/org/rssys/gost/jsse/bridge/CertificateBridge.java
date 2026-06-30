package org.rssys.gost.jsse.bridge;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.rssys.gost.pkix.cert.GostCertificate;

/**
 * Конверсия между GostCertificate (pkix) и X509Certificate (JCA/JSSE).
 */
public final class CertificateBridge {

    private static final String X509_TYPE = "X.509";

    /**
     * GostCertificate -> X509Certificate через DER-encoding.
     *
     * @param cert GostCertificate (не null)
     * @return X509Certificate
     * @throws CertificateException при ошибке парсинга DER
     */
    public static X509Certificate toJca(GostCertificate cert) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance(X509_TYPE);
        return (X509Certificate)
                cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
    }

    /**
     * Список GostCertificate -> массив X509Certificate.
     *
     * @param chain цепочка сертификатов
     * @return массив X509Certificate
     * @throws CertificateException при ошибке парсинга
     */
    public static X509Certificate[] toJca(List<GostCertificate> chain) throws CertificateException {
        if (chain == null) return new X509Certificate[0];
        X509Certificate[] result = new X509Certificate[chain.size()];
        for (int i = 0; i < chain.size(); i++) {
            result[i] = toJca(chain.get(i));
        }
        return result;
    }

    /**
     * X509Certificate -> GostCertificate через getEncoded().
     *
     * @param cert JCA-сертификат
     * @return GostCertificate
     */
    public static GostCertificate toGost(X509Certificate cert) {
        try {
            return new GostCertificate(cert.getEncoded());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to encode X509Certificate", e);
        }
    }

    /**
     * X509Certificate[] -> List&lt;GostCertificate&gt;.
     *
     * @param chain массив JCA-сертификатов
     * @return список GostCertificate
     */
    public static List<GostCertificate> toGost(X509Certificate[] chain) {
        if (chain == null) return List.of();
        List<GostCertificate> result = new ArrayList<>(chain.length);
        for (X509Certificate c : chain) {
            result.add(toGost(c));
        }
        return result;
    }

    private CertificateBridge() {}
}
