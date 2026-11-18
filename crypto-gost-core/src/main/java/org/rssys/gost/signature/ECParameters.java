package org.rssys.gost.signature;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;

/**
 * Параметры эллиптической кривой в форме Вейерштрасса для ГОСТ Р 34.10-2012.
 * Ссылки:
 * <ul>
 *   <li>RFC 7836 (параметры ТК-26): https://www.rfc-editor.org/rfc/rfc7836</li>
 *   <li>RFC 4357 (параметры КриптоПро): https://www.rfc-editor.org/rfc/rfc4357</li>
 *   <li>RFC 7091 (алгоритм подписи): https://www.rfc-editor.org/rfc/rfc7091</li>
 *   <li>ГОСТ Р 34.10-2012</li>
 * </ul>
 */
public final class ECParameters {
    public final BigInteger p;
    public final BigInteger a;
    public final BigInteger b;
    public final BigInteger gx;
    public final BigInteger gy;
    public final BigInteger n;
    public final int hlen;

    /** Кофактор h = m/q, где m — полный порядок группы #E(Fp), q — порядок подгруппы. */
    public final int cofactor;

    /** Параметры Монтгомери для поля GF(p). Вычисляются один раз при создании кривой. */
    final FieldElement.MontgomeryParams montParams;

    /** true если a == 0 (ни у одной зарегистрированной кривой ГОСТ). */
    public final boolean aIsZero;

    /**
     * true если a ≡ −3 (mod p), то есть a == p − 3. Верно для CryptoPro-A, -B, -C, TC26-A-512 и
     * TC26-B-512, неверно для TC26-A-256 и TC26-C-512.
     */
    public final boolean aIsMinusThree;

    /**
     * Коэффициент a в форме Монтгомери - используется в ECPoint.twice() для общего случая,
     * когда a не равно −3 и 0.
     */
    final FieldElement fa;

    /**
     * true только у одиночных экземпляров, заданных в этом классе. Для них порядок базовой
     * точки G равен n проверен при публикации параметров, поэтому {@code d·G} заведомо лежит
     * в подгруппе и повторное {@code multiply(n)} не нужно. Не входит в {@link #equals}:
     * равная по значению копия остаётся самодельной кривой.
     */
    private final boolean registered;

    /**
     * Метка домена идентификатора кривой: отделяет его хэш от любых других применений Стрибога.
     * Менять нельзя: от неё зависит нонс всех подписей в обоих режимах. Объявлена выше констант
     * кривых намеренно: их конструкторы читают её при загрузке класса, а статические поля
     * инициализируются в порядке текста; при переносе ниже метка окажется {@code null}.
     */
    private static final byte[] CURVE_BINDING_LABEL =
            "org.rssys.gost.signature.nonce.curve-binding.v1".getBytes(StandardCharsets.US_ASCII);

    /**
     * Идентификатор кривой для затравки нонса: Стрибог-256 от канонической записи параметров
     * (см. {@link #computeCurveBinding}). Нужен, чтобы один закрытый ключ на разных кривых одной
     * длины не давал общий нонс. Производное поле: в {@link #equals} и {@link #hashCode} не
     * входит, потому что равные параметры дают равный идентификатор. Не секрет, затирать не
     * нужно; наружу не отдаётся.
     */
    private final byte[] curveBinding;

    private static final ECParameters TC26_A_256 =
            new ECParameters(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
                    "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
                    "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
                    "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
                    "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
                    "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67",
                    32,
                    4,
                    true);
    private static final ECParameters TC26_A_512 =
            new ECParameters(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
                    "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
                    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
                    "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275",
                    64,
                    1,
                    true);
    private static final ECParameters TC26_B_512 =
            new ECParameters(
                    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F",
                    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C",
                    "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
                    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
                    "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD",
                    "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD",
                    64,
                    1,
                    true);
    private static final ECParameters TC26_C_512 =
            new ECParameters(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
                    "DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3",
                    "B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1",
                    "E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148",
                    "F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F",
                    "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED",
                    64,
                    4,
                    true);
    private static final ECParameters CRYPTO_PRO_A =
            new ECParameters(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
                    "A6",
                    "0000000000000000000000000000000000000000000000000000000000000001",
                    "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
                    32,
                    1,
                    true);
    private static final ECParameters CRYPTO_PRO_B =
            new ECParameters(
                    "8000000000000000000000000000000000000000000000000000000000000C99",
                    "8000000000000000000000000000000000000000000000000000000000000C96",
                    "3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
                    "0000000000000000000000000000000000000000000000000000000000000001",
                    "3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC",
                    "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F",
                    32,
                    1,
                    true);
    private static final ECParameters CRYPTO_PRO_C =
            new ECParameters(
                    "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
                    "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
                    "805A",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67",
                    "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
                    32,
                    1,
                    true);

    /**
     * Создаёт набор параметров кривой из шестнадцатеричных строк.
     * <p>
     * <b>Параметры должны быть доверенными.</b> Конструктор проверяет только согласованность
     * {@code hlen}; не проверяются, что G лежит на кривой, что порядок G равен {@code n},
     * что {@code n} простое и что объявленный кофактор верен. Проверка открытого ключа
     * строится на объявленном кофакторе: при {@code cofactor = 1} подгруппа не проверяется,
     * поэтому ошибка в кофакторе или в G самодельной кривой даст ключи вне подгруппы
     * без отказа. Не создавайте параметры из данных, которым нельзя доверять; для
     * внешнего ввода (DER, TLS) библиотека использует только зарегистрированные кривые.
     * Доверие при выводе открытого ключа ({@code PrivateKeyParameters.derivePublicKey()})
     * получают только зарегистрированные экземпляры, а не созданные этим конструктором.
     *
     * @param pHex  модуль поля (hex)
     * @param aHex  коэффициент a (hex)
     * @param bHex  коэффициент b (hex)
     * @param gxHex x-координата базовой точки G (hex)
     * @param gyHex y-координата базовой точки G (hex)
     * @param nHex    порядок подгруппы q (hex)
     * @param hlen    длина хэша в байтах (32 для 256-bit, 64 для 512-bit); обязана равняться
     *                длине в байтах и модуля поля {@code p}, и порядка {@code n}
     * @param cofactor кофактор h = m/q (1 для большинства GOST-кривых; 4 для TC26-A-256 и TC26-C-512)
     * @throws IllegalArgumentException если {@code hlen} не 32 и не 64 или не совпадает с длиной
     *         {@code p} или {@code n}: иначе секрет ECDH и скаляр молча усекались бы
     */
    public ECParameters(
            String pHex,
            String aHex,
            String bHex,
            String gxHex,
            String gyHex,
            String nHex,
            int hlen,
            int cofactor) {
        this(pHex, aHex, bHex, gxHex, gyHex, nHex, hlen, cofactor, false);
    }

    /**
     * Единственный реальный конструктор. Признак {@code registered} доступен только
     * изнутри класса: снаружи его нельзя выставить, поэтому самодельная кривая никогда
     * не получит доверия, даже если все её параметры совпали с зарегистрированной.
     */
    private ECParameters(
            String pHex,
            String aHex,
            String bHex,
            String gxHex,
            String gyHex,
            String nHex,
            int hlen,
            int cofactor,
            boolean registered) {
        this.p = new BigInteger(pHex, 16);
        this.a = new BigInteger(aHex, 16);
        this.b = new BigInteger(bHex, 16);
        this.gx = new BigInteger(gxHex, 16);
        this.gy = new BigInteger(gyHex, 16);
        this.n = new BigInteger(nHex, 16);
        this.hlen = hlen;
        this.cofactor = cofactor;
        this.registered = registered;
        requireConsistentHlen(this.p, this.n, hlen);
        // Монтгомери-параметры — вычисляются один раз, переиспользуются в ECPoint
        this.montParams = new FieldElement.MontgomeryParams(this.p);
        this.aIsZero = this.a.signum() == 0;
        this.aIsMinusThree = this.a.equals(this.p.subtract(BigInteger.valueOf(3)));
        this.fa = FieldElement.of(this.a, this.montParams);
        this.curveBinding = computeCurveBinding(p, a, b, gx, gy, n, hlen, cofactor);
    }

    /**
     * wNAF-таблица базовой точки {@code G}: {@code table[i] = (2i+1)·G}. Строится при первой
     * проверке подписи на этой кривой и дальше переиспользуется всеми проверяющими: раньше каждая
     * проверка (а {@code Signature.verify} создаёт подписанта на каждый вызов) строила её заново.
     *
     * <p>Поле {@code volatile}, таблица целиком готова до записи и после неё не меняется
     * ({@link ECPoint} неизменяем), поэтому гонка двух потоков безвредна: оба построят
     * одинаковые таблицы, и любая из них годится. Блокировки не нужны. Таблица содержит только
     * открытые данные.
     */
    private volatile ECPoint[] gWnafTable;

    /**
     * Возвращает таблицу {@code (2i+1)·G} для окна {@code w}. Окно зависит только от кривой
     * (задаёт его {@code ECDSASigner}), поэтому таблица одна; при ином окне она перестраивается.
     */
    ECPoint[] gWnafTable(int w) {
        ECPoint[] table = gWnafTable;
        if (table == null || table.length != 1 << (w - 2)) {
            table = ECPoint.affine(gx, gy, this).buildWNafTable(w);
            gWnafTable = table;
        }
        return table;
    }

    /**
     * Идентификатор кривой для {@code ECDSASigner}: тот же массив, что хранится в параметрах, без
     * копирования (вызывающий его только читает). Метод только внутри пакета, чтобы массив нельзя
     * было изменить снаружи.
     */
    byte[] curveBinding() {
        return curveBinding;
    }

    /**
     * Каноническая запись: метка домена, затем в порядке {@code p, a, b, gx, gy, n} каждое
     * значение как {@link BigInteger#toByteArray()} (минимальный дополнительный код, big-endian)
     * с 4-байтным префиксом длины этого массива, затем {@code hlen} и {@code cofactor} как
     * 4-байтные целые big-endian. Значения берутся как есть, без приведения по модулю
     * (согласовано с {@link #equals}); ведущий нулевой байт {@code toByteArray()} входит в
     * длину и в хэш. Префиксы длины обязательны: {@code requireConsistentHlen} проверяет длину
     * только {@code p} и {@code n}, а {@code a}, {@code b}, {@code gx}, {@code gy} могут быть
     * длиннее, и без префиксов склейка соседних значений была бы неоднозначной.
     */
    private static byte[] computeCurveBinding(
            BigInteger p,
            BigInteger a,
            BigInteger b,
            BigInteger gx,
            BigInteger gy,
            BigInteger n,
            int hlen,
            int cofactor) {
        Streebog256 digest = new Streebog256();
        digest.update(CURVE_BINDING_LABEL, 0, CURVE_BINDING_LABEL.length);
        for (BigInteger value : new BigInteger[] {p, a, b, gx, gy, n}) {
            byte[] encoded = value.toByteArray();
            updateInt32(digest, encoded.length);
            digest.update(encoded, 0, encoded.length);
        }
        updateInt32(digest, hlen);
        updateInt32(digest, cofactor);
        byte[] binding = new byte[Streebog256.DIGEST_SIZE];
        digest.doFinal(binding, 0);
        return binding;
    }

    private static void updateInt32(Streebog256 digest, int value) {
        digest.update((byte) (value >>> 24));
        digest.update((byte) (value >>> 16));
        digest.update((byte) (value >>> 8));
        digest.update((byte) value);
    }

    /**
     * @return {@code true} если это один из зарегистрированных одиночных экземпляров кривой
     *         (а не самодельная или равная по значению копия)
     */
    boolean isRegistered() {
        return registered;
    }

    /**
     * hlen определяет длину координат, скаляров и общего секрета; несовпадение с длиной поля или
     * порядка приводит к усечению старших байт без какой-либо ошибки.
     */
    private static void requireConsistentHlen(BigInteger p, BigInteger n, int hlen) {
        if (hlen != Streebog256.DIGEST_SIZE && hlen != Streebog512.DIGEST_SIZE) {
            throw new IllegalArgumentException("hlen must be 32 or 64, got " + hlen);
        }
        int pBytes = (p.bitLength() + Byte.SIZE - 1) / Byte.SIZE;
        int nBytes = (n.bitLength() + Byte.SIZE - 1) / Byte.SIZE;
        if (pBytes != hlen || nBytes != hlen) {
            throw new IllegalArgumentException(
                    "hlen "
                            + hlen
                            + " does not match field size "
                            + pBytes
                            + " bytes and subgroup order size "
                            + nBytes
                            + " bytes");
        }
    }

    /**
     * Структурное равенство: совпадают все параметры, заданные конструктором
     * ({@code p}, {@code a}, {@code b}, {@code gx}, {@code gy}, {@code n}, {@code hlen},
     * {@code cofactor}); производные поля (Монтгомери-параметры и признаки вида {@code a})
     * не участвуют. Математическая эквивалентность не проверяется: например, {@code a = 0}
     * и {@code a = p} описывают одну кривую, но равными не считаются.
     * <p>
     * Зарегистрированные кривые отдаются одиночными экземплярами, поэтому в штатном случае
     * сравнение заканчивается проверкой ссылок. Отображение в канонический OID
     * ({@code GostCurves.oidOf}) по-прежнему идёт по ссылке, а не по значению.
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ECParameters)) {
            return false;
        }
        ECParameters that = (ECParameters) other;
        return hlen == that.hlen
                && cofactor == that.cofactor
                && p.equals(that.p)
                && a.equals(that.a)
                && b.equals(that.b)
                && gx.equals(that.gx)
                && gy.equals(that.gy)
                && n.equals(that.n);
    }

    @Override
    public int hashCode() {
        return Objects.hash(p, a, b, gx, gy, n, hlen, cofactor);
    }

    public static ECParameters tc26a256() {
        return TC26_A_256;
    }

    public static ECParameters tc26a512() {
        return TC26_A_512;
    }

    public static ECParameters tc26b512() {
        return TC26_B_512;
    }

    public static ECParameters tc26c512() {
        return TC26_C_512;
    }

    public static ECParameters cryptoProA() {
        return CRYPTO_PRO_A;
    }

    public static ECParameters cryptoProB() {
        return CRYPTO_PRO_B;
    }

    public static ECParameters cryptoProC() {
        return CRYPTO_PRO_C;
    }
}
