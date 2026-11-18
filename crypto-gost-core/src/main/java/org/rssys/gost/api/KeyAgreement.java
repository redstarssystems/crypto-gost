package org.rssys.gost.api;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.function.UnaryOperator;
import org.rssys.gost.digest.Streebog512;
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

    /** Нижняя граница {@code hlen} кривой, при которой ограничения нет (допустимы 256 и 512 бит). */
    private static final int MIN_HLEN_ANY = 0;

    private KeyAgreement() {}

    /**
     * Вычисляет VKO shared secret: X-координата {@code (h·d)·Qpeer} в little-endian
     * (RFC 7836 §4.3).
     *
     * <p>Скаляр h·d mod q домножается на кофактор h = m/q для защиты от small-subgroup
     * атак. Для всех стандартных ГОСТ-кривых (кроме TC26-A-256 и TC26-C-512) h = 1, поэтому
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
        // RFC 7836 §4.3: K = (m/q · UKM · x mod q) · (y·P), здесь UKM = 1 (raw ECDH), h = m/q
        ECPoint shared = sharedPoint(myPriv, peerPub, BigInteger.ONE, MIN_HLEN_ANY);
        ECParameters myParams = myPriv.getParams();

        BigInteger x = shared.getX();
        byte[] xRawBe = Pack.toFixedLengthBigEndian(x, myParams.hlen);
        try {
            return Pack.reverseBytes(xRawBe);
        } finally {
            Arrays.fill(xRawBe, (byte) 0);
        }
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
        return vko(myPriv, peerPub, ukm, MIN_HLEN_ANY, Digest::digest256);
    }

    /**
     * VKO GOST R 34.10-2012 на 512-битной кривой (RFC 7836 §4.3.2).
     *
     * <p>Отличается от {@link #vkoGostR3410_2012_256} финальной хэш-функцией
     * (Стрибог-512) и ожидаемой длиной выхода {@code hlen = 64}.
     *
     * <p>RFC 7836 §4.3.2 допускает этот вариант только для 512-битных ключей, поэтому на кривой
     * с {@code hlen != 64} метод отказывает. {@link #vkoGostR3410_2012_256} (§4.3.1), наоборот,
     * допустим для ключей и 256, и 512 бит: именно он используется в JCA-согласовании
     * {@code KeyAgreement.VKOGOST3410-2012-256}, а вариант на 512 бит доступен только здесь.
     *
     * @param myPriv   мой закрытый ключ
     * @param peerPub  публичный ключ пира
     * @param ukm      синхропосылка UKM (множитель, не raw-байты)
     * @return KEK длиной 64 байта
     * @throws IllegalArgumentException если ключи null, UKM невалидный, кривые не совпадают
     *                                  или кривая не 512-битная
     * @throws IllegalStateException    если результат — точка на бесконечности
     */
    public static byte[] vkoGostR3410_2012_512(
            PrivateKeyParameters myPriv, PublicKeyParameters peerPub, BigInteger ukm) {
        return vko(myPriv, peerPub, ukm, Streebog512.DIGEST_SIZE, Digest::digest512);
    }

    /**
     * Общая часть VKO ГОСТ Р 34.10-2012 (RFC 7836 §4.3): варианты на 256 и 512 бит отличаются
     * только хэш-функцией над точкой и допустимыми кривыми, поэтому реализация одна.
     *
     * @param minCurveHlen наименьшая допустимая длина хэша кривой в байтах ({@link #MIN_HLEN_ANY}
     *                     - без ограничения); проверяется до чтения закрытого ключа, чтобы при
     *                     отказе не создавать лишнюю копию {@code d}
     * @param hash         хэш-функция над точкой (Стрибог-256 или Стрибог-512)
     */
    private static byte[] vko(
            PrivateKeyParameters myPriv,
            PublicKeyParameters peerPub,
            BigInteger ukm,
            int minCurveHlen,
            UnaryOperator<byte[]> hash) {
        if (ukm == null) {
            throw new IllegalArgumentException("UKM must not be null");
        }
        if (ukm.signum() < 0) {
            throw new IllegalArgumentException("UKM must be non-negative");
        }
        if (ukm.signum() == 0) {
            throw new IllegalArgumentException("UKM must not be zero");
        }

        // RFC 7836 §4.3.1: K = (m/q · UKM · x mod q) · (y·P)
        ECPoint shared = sharedPoint(myPriv, peerPub, ukm, minCurveHlen);
        ECParameters myParams = myPriv.getParams();

        // RFC 7836 §3: на вход хэш-функции подаётся весь поинт:
        // сначала X, затем Y, оба в little-endian
        BigInteger x = shared.getX();
        BigInteger y = shared.getY();
        byte[] xRawBe = Pack.toFixedLengthBigEndian(x, myParams.hlen);
        byte[] yRawBe = Pack.toFixedLengthBigEndian(y, myParams.hlen);
        byte[] xLe = null;
        byte[] yLe = null;
        byte[] pointLe = null;
        try {
            xLe = Pack.reverseBytes(xRawBe);
            yLe = Pack.reverseBytes(yRawBe);
            pointLe = new byte[myParams.hlen * 2];
            System.arraycopy(xLe, 0, pointLe, 0, myParams.hlen);
            System.arraycopy(yLe, 0, pointLe, myParams.hlen, myParams.hlen);
            return hash.apply(pointLe);
        } finally {
            Arrays.fill(xRawBe, (byte) 0);
            Arrays.fill(yRawBe, (byte) 0);
            wipe(xLe);
            wipe(yLe);
            wipe(pointLe);
        }
    }

    /**
     * Общая часть согласования ключа: точка {@code (h · UKM · d mod q) · Qpeer} в аффинной форме.
     *
     * <p>Валидность точки peerPub (кривая, подгруппа) гарантирует конструктор
     * {@link PublicKeyParameters}, а {@link ECPoint} неизменяем: повторная проверка стоила бы ещё
     * одного {@code multiply(n)} на кривых с кофактором 4.
     *
     * @param minCurveHlen наименьшая допустимая длина хэша кривой в байтах ({@link #MIN_HLEN_ANY}
     *                     - без ограничения); проверяется до чтения закрытого ключа, чтобы при
     *                     отказе не создавать лишнюю копию {@code d}
     */
    private static ECPoint sharedPoint(
            PrivateKeyParameters myPriv,
            PublicKeyParameters peerPub,
            BigInteger ukm,
            int minCurveHlen) {
        if (myPriv == null || peerPub == null) {
            throw new IllegalArgumentException("Keys must not be null");
        }
        ECParameters params = myPriv.getParams();
        // Разные кривые дают несвязанные shared secrets - fail-closed. Сравнение полное (все
        // параметры кривой): эвристика по p/n/hlen пропустила бы самодельную кривую с теми же p, n
        // и длиной хэша.
        if (!params.equals(peerPub.getParams())) {
            throw new IllegalArgumentException("Key curve mismatch");
        }
        // RFC 7836 §4.3.2: вариант на 512 бит допустим только для 512-битных ключей; на 256-битной
        // кривой результат был бы хэшем от 32-байтных координат, то есть не соответствовал бы
        // стандарту
        if (params.hlen < minCurveHlen) {
            throw new IllegalArgumentException(
                    "This VKO variant requires a curve with hash length of at least "
                            + minCurveHlen
                            + " bytes, got "
                            + params.hlen);
        }
        BigInteger scalar =
                myPriv.getD()
                        .multiply(BigInteger.valueOf(params.cofactor))
                        .multiply(ukm)
                        .mod(params.n);
        ECPoint shared = peerPub.getQ().multiply(scalar).normalize();
        if (shared.isInfinity()) {
            throw new IllegalStateException("ECDH shared secret is point at infinity");
        }
        return shared;
    }

    /** Затирает массив, если он уже создан: используется в {@code finally}, где часть могла не успеть. */
    private static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
}
