package org.rssys.gost.api;

import java.math.BigInteger;
import java.util.Arrays;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.Pack;

/**
 * Согласование ключей по схеме VKO (ГОСТ Р 34.10-2012, RFC 7836 §4.3).
 *
 * <p>Вычисляет общий секрет как X-координату точки {@code (h·d)·Qpeer} в little-endian,
 * где h — кофактор кривой (RFC 7836 §4.3: m/q·UKM·x mod q).
 * Для кривых с h=1 (CryptoPro-A/B/C, TC26-A/B-512) эквивалентно {@code d·Qpeer}.
 * Длина результата — {@code hlen} параметров кривой (32 для
 * 256-битных кривых, 64 для 512-битных).
 *
 * <p>Все методы статические и потокобезопасны.
 * Вызывающий код отвечает за обнуление результата после использования
 * (например, {@code java.util.Arrays.fill(result, (byte) 0)}).
 */
public final class KeyAgreement {

    private KeyAgreement() {}

    /**
     * Вычисляет VKO shared secret: X-координата {@code (h·d)·Qpeer} в little-endian
     * (RFC 7836 §4.3).
     *
     * <p>Скаляр h·d mod q домножается на кофактор h = m/q для защиты от small-subgroup
     * атак. Для всех стандартных ГОСТ-кривых (кроме TC26-C-512) h = 1, поэтому
     * операция эквивалентна {@code d·Qpeer}.
     *
     * <p>Скалярное умножение выполняется через constant-time лестницу Монтгомери
     * ({@link ECPoint#multiply(BigInteger)}).
     *
     * @param myPriv  закрытый ключ локальной стороны
     * @param peerPub открытый ключ удалённой стороны
     * @return X-координата (h·d)·Qpeer в little-endian ({@code hlen} байт)
     * @throws IllegalArgumentException если любой из аргументов {@code null}
     *                                  или параметры кривых ключей не совпадают
     * @throws IllegalStateException    если результат — точка на бесконечности
     */
    public static byte[] computeSharedSecret(
            PrivateKeyParameters myPriv, PublicKeyParameters peerPub) {
        if (myPriv == null || peerPub == null) {
            throw new IllegalArgumentException("Keys must not be null");
        }

        ECParameters myParams = myPriv.getParams();
        ECParameters peerParams = peerPub.getParams();
        if (!curvesMatch(myParams, peerParams)) {
            throw new IllegalArgumentException("Key curve mismatch");
        }

        // RFC 7836 §4.3: K = (m/q · UKM · x mod q) · (y·P)
        // UKM = 1 (raw ECDH), h = m/q
        BigInteger scalar =
                myPriv.getD().multiply(BigInteger.valueOf(myParams.cofactor)).mod(myParams.n);
        ECPoint shared = peerPub.getQ().multiply(scalar);
        shared = shared.normalize();
        if (shared.isInfinity()) {
            throw new IllegalStateException("ECDH shared secret is point at infinity");
        }

        BigInteger x = shared.getX();
        byte[] xRawBe = toFixedLengthBytes(x, myParams.hlen);
        return Pack.reverseBytes(xRawBe);
    }

    /**
     * VKO (Vychislenie Klyuchevykh Obyektov) по ГОСТ Р 34.10-2012:
     * согласование 256-битного ключа по RFC 7836 §4.3.1.
     *
     * <p>Вычисляет общий ключ KEK_VKO по формуле RFC 7836 §4.3.1:
     * <pre>
     * K       = (h · UKM · d mod q) · Qpeer                          // точка на кривой
     * KEK_VKO = H_256(X_LE(K) || Y_LE(K))                             // RFC 7836 §3
     * </pre>
     * где h — кофактор кривой (m/q), UKM — User Keying Material.
     * На вход хэш-функции подаётся весь поинт: X, затем Y, оба в LE (RFC 7836 §3).
     *
     * <p>UKM принимается как {@link BigInteger} без ограничения длины.
     * По RFC 7836 §4.3.1: UKM может принимать любое целое значение от 1 до 2^(n/2)-1.
     * Для статических ключей рекомендован UKM не менее 64 бит (8 байт).
     *
     * <p>Скалярное умножение — constant-time лестница Монтгомери
     * ({@link ECPoint#multiply(BigInteger)}).
     *
     * @param myPriv  закрытый ключ локальной стороны
     * @param peerPub открытый ключ удалённой стороны
     * @param ukm     User Keying Material (не null, не ноль, не отрицательный)
     * @return KEK_VKO, 32 байта
     * @throws IllegalArgumentException если любой из аргументов null,
     *                                  параметры кривых не совпадают,
     *                                  UKM null/отрицательный/равен нулю
     * @throws IllegalStateException    если результат — точка на бесконечности
     */
    public static byte[] vkoGostR3410_2012_256(
            PrivateKeyParameters myPriv, PublicKeyParameters peerPub, BigInteger ukm) {
        if (myPriv == null || peerPub == null) {
            throw new IllegalArgumentException("Keys must not be null");
        }
        if (ukm == null) {
            throw new IllegalArgumentException("UKM must not be null");
        }
        if (ukm.signum() < 0) {
            throw new IllegalArgumentException("UKM must be non-negative");
        }
        if (ukm.signum() == 0) {
            throw new IllegalArgumentException("UKM must not be zero");
        }

        ECParameters myParams = myPriv.getParams();
        ECParameters peerParams = peerPub.getParams();
        if (!curvesMatch(myParams, peerParams)) {
            throw new IllegalArgumentException("Key curve mismatch");
        }

        // RFC 7836 §4.3.1: K = (m/q · UKM · x mod q) · (y·P)
        BigInteger scalar =
                myPriv.getD()
                        .multiply(BigInteger.valueOf(myParams.cofactor))
                        .multiply(ukm)
                        .mod(myParams.n);
        ECPoint shared = peerPub.getQ().multiply(scalar);
        shared = shared.normalize();
        if (shared.isInfinity()) {
            throw new IllegalStateException("ECDH shared secret is point at infinity");
        }

        // RFC 7836 §3: на вход хэш-функции подаётся весь поинт:
        // сначала X, затем Y, оба в little-endian
        BigInteger x = shared.getX();
        BigInteger y = shared.getY();
        byte[] xRawBe = toFixedLengthBytes(x, myParams.hlen);
        byte[] yRawBe = toFixedLengthBytes(y, myParams.hlen);
        byte[] xLe = Pack.reverseBytes(xRawBe);
        byte[] yLe = Pack.reverseBytes(yRawBe);
        byte[] pointLe = new byte[myParams.hlen * 2];
        System.arraycopy(xLe, 0, pointLe, 0, myParams.hlen);
        System.arraycopy(yLe, 0, pointLe, myParams.hlen, myParams.hlen);
        try {
            return Digest.digest256(pointLe);
        } finally {
            Arrays.fill(xLe, (byte) 0);
            Arrays.fill(yLe, (byte) 0);
            Arrays.fill(pointLe, (byte) 0);
        }
    }

    /**
     * Разные кривые дают несвязанные shared secrets — fail-closed.
     * Сравнение по модулю {@code p}, порядку группы {@code n} и длине хэша {@code hlen}
     * однозначно идентифицирует кривую для всех стандартных ГОСТ-кривых.
     */
    private static boolean curvesMatch(ECParameters a, ECParameters b) {
        return a.p.equals(b.p) && a.n.equals(b.n) && a.hlen == b.hlen;
    }

    /**
     * ECDH shared secret обязан быть строго {@code hlen} байт.
     * {@code BigInteger.toByteArray()} может вернуть массив короче (удалён ведущий ноль)
     * или длиннее (добавлен знаковый байт) — без нормализации вызывающий код получит
     * shared secret непредсказуемой длины, что сломает последующий KDF.
     */
    private static byte[] toFixedLengthBytes(BigInteger value, int len) {
        byte[] raw = value.toByteArray();
        if (raw.length == len) {
            return raw;
        }
        byte[] result = new byte[len];
        if (raw.length < len) {
            System.arraycopy(raw, 0, result, len - raw.length, raw.length);
        } else {
            System.arraycopy(raw, raw.length - len, result, 0, len);
        }
        return result;
    }
}
