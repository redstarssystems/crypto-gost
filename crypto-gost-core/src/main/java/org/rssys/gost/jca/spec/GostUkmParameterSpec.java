package org.rssys.gost.jca.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

/**
 * JCA {@link AlgorithmParameterSpec} для передачи UKM (User Keying Material)
 * в алгоритм согласования ключей VKO_GOSTR3410_2012_256 (RFC 7836 §4.3.1).
 *
 * <p>UKM — целое неотрицательное ненулевое число произвольного размера.
 * Рекомендуемый минимум для статических ключей — 64 бита (8 байт).
 */
public final class GostUkmParameterSpec implements AlgorithmParameterSpec {

    private final BigInteger ukm;

    /**
     * @param ukm значение UKM (не null)
     */
    public GostUkmParameterSpec(BigInteger ukm) {
        if (ukm == null) {
            throw new IllegalArgumentException("UKM must not be null");
        }
        this.ukm = ukm;
    }

    /**
     * @return UKM как {@link BigInteger}
     */
    public BigInteger getUkm() {
        return ukm;
    }
}
