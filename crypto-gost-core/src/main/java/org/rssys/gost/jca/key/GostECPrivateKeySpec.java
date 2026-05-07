package org.rssys.gost.jca.key;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/**
 * Спецификация закрытого ключа ГОСТ Р 34.10-2012 по сырым параметрам.
 * <p>
 * Используется совместно с {@link java.security.KeyFactory} для создания
 * {@link GostECPrivateKey} из скалярного значения закрытого ключа {@code d}
 * и имени кривой:
 * <pre>{@code
 * GostECPrivateKeySpec spec = new GostECPrivateKeySpec(d, "cryptopro-A");
 * PrivateKey priv = KeyFactory.getInstance("ECGOST3410-2012", provider)
 *                             .generatePrivate(spec);
 * }</pre>
 *
 * @see GostECPublicKeySpec
 * @see org.rssys.gost.jca.spec.GostCurves
 */
public final class GostECPrivateKeySpec implements KeySpec {

    /** Закрытый ключ d: целое в диапазоне (0, q). */
    private final BigInteger d;

    /**
     * Имя кривой. Допустимые значения:
     * {@code "tc26-gost-A-256"}, {@code "cryptopro-A"} и т.д.,
     * а также OID-строки вида {@code "1.2.643.2.2.35.1"}.
     */
    private final String curveName;

    /**
     * @param d         закрытый ключ; должен удовлетворять {@code 0 < d < q}
     * @param curveName имя или OID кривой
     */
    public GostECPrivateKeySpec(BigInteger d, String curveName) {
        if (d == null) {
            throw new IllegalArgumentException("d must not be null");
        }
        if (curveName == null || curveName.isEmpty()) {
            throw new IllegalArgumentException("Curve name must not be null or empty");
        }
        this.d         = d;
        this.curveName = curveName;
    }

    /** @return закрытый ключ d */
    public BigInteger getD() {
        return d;
    }

    /** @return имя или OID кривой */
    public String getCurveName() {
        return curveName;
    }
}
