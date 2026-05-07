package org.rssys.gost.jca.key;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/**
 * Спецификация открытого ключа ГОСТ Р 34.10-2012 по сырым параметрам.
 * <p>
 * Используется совместно с {@link java.security.KeyFactory} для создания
 * {@link GostECPublicKey} из аффинных координат точки Q и имени кривой:
 * <pre>{@code
 * GostECPublicKeySpec spec = new GostECPublicKeySpec(x, y, "cryptopro-A");
 * PublicKey pub = KeyFactory.getInstance("ECGOST3410-2012", provider)
 *                           .generatePublic(spec);
 * }</pre>
 *
 * @see GostECPrivateKeySpec
 * @see org.rssys.gost.jca.spec.GostCurves
 */
public final class GostECPublicKeySpec implements KeySpec {

    /** x-координата точки Q открытого ключа (big-endian). */
    private final BigInteger x;

    /** y-координата точки Q открытого ключа (big-endian). */
    private final BigInteger y;

    /**
     * Имя кривой. Допустимые значения:
     * {@code "tc26-gost-A-256"}, {@code "cryptopro-A"} и т.д.,
     * а также OID-строки вида {@code "1.2.643.2.2.35.1"}.
     */
    private final String curveName;

    /**
     * @param x         x-координата точки Q
     * @param y         y-координата точки Q
     * @param curveName имя или OID кривой
     */
    public GostECPublicKeySpec(BigInteger x, BigInteger y, String curveName) {
        if (x == null || y == null) {
            throw new IllegalArgumentException("Coordinates x and y must not be null");
        }
        if (curveName == null || curveName.isEmpty()) {
            throw new IllegalArgumentException("Curve name must not be null or empty");
        }
        this.x         = x;
        this.y         = y;
        this.curveName = curveName;
    }

    /** @return x-координата точки Q */
    public BigInteger getX() {
        return x;
    }

    /** @return y-координата точки Q */
    public BigInteger getY() {
        return y;
    }

    /** @return имя или OID кривой */
    public String getCurveName() {
        return curveName;
    }
}
