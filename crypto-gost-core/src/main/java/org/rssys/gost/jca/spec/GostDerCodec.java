package org.rssys.gost.jca.spec;

import java.math.BigInteger;
import java.util.Arrays;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.util.Pack;

/**
 * Минимальный DER-кодек для ключей ГОСТ Р 34.10-2012 без внешних зависимостей.
 * <p>
 * Реализует кодирование/декодирование согласно RFC 4491 (обновлённый применительно
 * к ГОСТ Р 34.10-2012) и RFC 5958 (PKCS#8 PrivateKeyInfo).
 *
 * <h3>Формат открытого ключа — SubjectPublicKeyInfo (X.509, RFC 5480 / RFC 4491)</h3>
 * <pre>
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm  AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING          -- содержит OCTET STRING с точкой
 * }
 *
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm   OBJECT IDENTIFIER,       -- id-tc26-gost-3410-2012-256 / -512
 *   parameters  GostR3410-PublicKeyParameters
 * }
 *
 * GostR3410-PublicKeyParameters ::= SEQUENCE {
 *   publicKeyParamSet  OBJECT IDENTIFIER, -- OID кривой
 *   digestParamSet     OBJECT IDENTIFIER  -- OID хэш-функции Стрибог
 * }
 * </pre>
 * Координаты точки в OCTET STRING кодируются в порядке <b>little-endian</b>: x_LE || y_LE
 * (RFC 4491 §2.3.2, RFC 7836 §3).
 *
 * <h3>Формат закрытого ключа — PrivateKeyInfo (PKCS#8, RFC 5958)</h3>
 * <pre>
 * PrivateKeyInfo ::= SEQUENCE {
 *   version    INTEGER (0),
 *   privateKeyAlgorithm AlgorithmIdentifier,  -- тот же что и выше
 *   privateKey OCTET STRING     -- закрытый ключ d, little-endian (OpenSSL gost-engine)
 * }
 * </pre>
 *
 * <p>OID хэш-функции по умолчанию:
 * <ul>
 *   <li>Стрибог-256 ({@code 1.2.643.7.1.1.2.2}) для 256-битных кривых</li>
 *   <li>Стрибог-512 ({@code 1.2.643.7.1.1.2.3}) для 512-битных кривых</li>
 * </ul>
 *
 * <p>DER-инфраструктура (TLV, OID, SEQUENCE, парсинг) делегирована в
 * {@link DerCodec}.
 */
public final class GostDerCodec {

    // значения совпадают с GostOids.DIGEST_256/DIGEST_512 — core не зависит от pkix
    private static final String OID_STREEBOG_256 = "1.2.643.7.1.1.2.2";
    private static final String OID_STREEBOG_512 = "1.2.643.7.1.1.2.3";

    private GostDerCodec() {}

    /**
     * Возвращает биты ключа SubjectPublicKeyInfo без октета unused-bits
     * для хэширования в OCSP (ResponderID.byKey и CertID.issuerKeyHash,
     * RFC 6960 §4.1.1: хэш от значения subjectPublicKey без тега, длины и
     * числа неиспользуемых бит).
     *
     * <p>Формат: DER {@code OCTET STRING(x_LE || y_LE)}, то есть {@code 04 40 ...}
     * для 256-битной кривой. Так считает КриптоПро и совпадает с
     * {@code GostCertificate#getSpkiKeyBits()}.</p>
     *
     * @param pub открытый ключ
     * @return байты ключа SPKI без unused-bits
     */
    public static byte[] encodeSpkiKeyBits(PublicKeyParameters pub) {
        return DerCodec.encodeOctetString(subjectPublicKeyPointBytes(pub));
    }

    /**
     * Извлекает байты точки открытого ключа в формате x_LE || y_LE
     * (little-endian координаты, RFC 4491 §2.3.2).
     *
     * <p>Используется для вычисления Subject Key Identifier (RFC 5280 §4.2.1.2).</p>
     *
     * @param pub открытый ключ
     * @return байты точки (2 × coordLen байт)
     */
    public static byte[] subjectPublicKeyPointBytes(PublicKeyParameters pub) {
        ECParameters params = pub.getParams();
        int coordLen = (params.p.bitLength() + 7) / 8;
        ECPoint q = pub.getQ();
        byte[] xLE = Pack.reverseBytes(Pack.toFixedLengthBigEndian(q.getX(), coordLen));
        byte[] yLE = Pack.reverseBytes(Pack.toFixedLengthBigEndian(q.getY(), coordLen));
        byte[] pointBytes = new byte[coordLen * 2];
        System.arraycopy(xLE, 0, pointBytes, 0, coordLen);
        System.arraycopy(yLE, 0, pointBytes, coordLen, coordLen);
        return pointBytes;
    }

    /**
     * Кодирует открытый ключ в DER SubjectPublicKeyInfo (X.509).
     * <p>
     * Точка кодируется как OCTET STRING c координатами в порядке little-endian:
     * x_LE || y_LE (RFC 4491 §2.3.2).
     *
     * @param pub открытый ключ
     * @return DER-байты SubjectPublicKeyInfo
     * @throws IllegalArgumentException если параметры кривой не распознаны
     */
    public static byte[] encodePublicKey(PublicKeyParameters pub) {
        ECParameters params = pub.getParams();
        String signAlgOid = signAlgOid(params);
        String curveOid = GostCurves.oidOf(params);
        String digestOid = digestOid(params);

        byte[] pointBytes = subjectPublicKeyPointBytes(pub);

        byte[] pubKeyParams =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(curveOid), DerCodec.encodeOid(digestOid));
        byte[] algId = DerCodec.encodeSequence(DerCodec.encodeOid(signAlgOid), pubKeyParams);

        byte[] pointOctetStr = DerCodec.encodeOctetString(pointBytes);
        byte[] bitStr = DerCodec.encodeBitString(pointOctetStr);

        return DerCodec.encodeSequence(algId, bitStr);
    }

    /**
     * Декодирует открытый ключ из DER SubjectPublicKeyInfo (X.509) строго по RFC 9215.
     * <p>
     * Отвергает неоднозначные и неканонические кодировки одного и того же ключа. Допустимые по
     * RFC 9215 варианты OID набора параметров (например, XchA и TC26-B-256 описывают одну кривую)
     * и необязательный {@code digestParamSet} сохраняются, но каждый вариант проверяется по своему
     * правилу. Отвергаются: BER (indefinite-length), байты после SEQUENCE, лишние элементы SEQUENCE,
     * {@code AlgorithmIdentifier} и {@code GostR3410-2012-PublicKeyParameters}, OID алгоритма
     * подписи, не соответствующий размеру кривой (допустимы только
     * {@code 1.2.643.7.1.1.1.1} и {@code 1.2.643.7.1.1.1.2}; наследный OID ГОСТ Р 34.10-2001
     * {@code 1.2.643.2.2.19} не поддерживается), неверное присутствие или значение
     * {@code digestParamSet} (правило зависит от OID набора, см.
     * {@link GostCurves#digestPolicyOf(String)}), ненулевое число неиспользуемых бит BIT STRING,
     * данные внутри BIT STRING кроме одного OCTET STRING с точкой и координаты {@code x} или
     * {@code y}, не меньшие модуля поля {@code p} (иначе {@code x + p} задаёт тот же ключ другими
     * байтами).
     *
     * @param encoded DER-байты
     * @return открытый ключ
     * @throws IllegalArgumentException при ошибке разбора, нарушении перечисленного, неизвестной
     *                                  кривой, точке не на кривой или вне подгруппы порядка n
     */
    public static PublicKeyParameters decodePublicKey(byte[] encoded) {
        // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
        byte[][] outer = DerCodec.parseStrictSequence(encoded);
        if (outer.length != 2) {
            throw new IllegalArgumentException("Invalid SubjectPublicKeyInfo: expected 2 elements");
        }

        // AlgorithmIdentifier ::= SEQUENCE { OID, GostR3410-2012-PublicKeyParameters };
        // parameters обязателен (RFC 9215 §4.2): без него нет OID кривой
        byte[][] algId = DerCodec.parseStrictSequence(outer[0]);
        if (algId.length != 2) {
            throw new IllegalArgumentException("Invalid AlgorithmIdentifier: expected 2 elements");
        }
        // GostR3410-2012-PublicKeyParameters ::= SEQUENCE { OID curve, OID digest OPTIONAL }
        byte[][] pubKeyParams = DerCodec.parseStrictSequence(algId[1]);
        if (pubKeyParams.length < 1 || pubKeyParams.length > 2) {
            throw new IllegalArgumentException("Invalid GostR3410-PublicKeyParameters");
        }
        // OID набора берём как строку до byName: XchA, CryptoPro-A и TC26-B-256 дают один и тот же
        // ECParameters, а правила для digestParamSet у них разные
        String curveOid = DerCodec.parseOid(pubKeyParams[0], 0);
        ECParameters params = GostCurves.byName(curveOid);
        checkSignAlgorithm(DerCodec.parseOid(algId[0], 0), params);
        checkDigestParamSet(curveOid, pubKeyParams, params);

        // BIT STRING -> OCTET STRING с координатами
        DerCodec.BitStringValue bitStr = DerCodec.parseBitStringWithUnused(outer[1], 0);
        if (bitStr.unusedBits() != 0) {
            throw new IllegalArgumentException(
                    "Invalid SubjectPublicKeyInfo: BIT STRING must not have unused bits");
        }
        byte[] bitStrContent = bitStr.data();
        byte[] pointOctetStr = DerCodec.parseOctetString(bitStrContent, 0);
        // Длина TLV минимальна (decodeLength это проверяет), поэтому равенство точное: любой
        // хвост после OCTET STRING внутри BIT STRING означает вторую кодировку того же ключа
        int octetStrTlvLength =
                1 + DerCodec.encodeLength(pointOctetStr.length).length + pointOctetStr.length;
        if (octetStrTlvLength != bitStrContent.length) {
            throw new IllegalArgumentException(
                    "Invalid SubjectPublicKeyInfo: unexpected data after the OCTET STRING in BIT STRING");
        }

        int coordLen = (params.p.bitLength() + 7) / 8;
        if (pointOctetStr.length != coordLen * 2) {
            throw new IllegalArgumentException(
                    "Invalid EC point encoding: expected "
                            + (coordLen * 2)
                            + " bytes, got "
                            + pointOctetStr.length);
        }

        // Координаты в little-endian -> конвертируем в big-endian для BigInteger
        byte[] xLE = Arrays.copyOfRange(pointOctetStr, 0, coordLen);
        byte[] yLE = Arrays.copyOfRange(pointOctetStr, coordLen, coordLen * 2);
        BigInteger x = new BigInteger(1, Pack.reverseBytes(xLE));
        BigInteger y = new BigInteger(1, Pack.reverseBytes(yLE));
        // x и y не меньше p отвергает affine: иначе x+p и y+p (помещаются в поле для
        // CryptoPro-B/C и TC26-B-512) принимались бы как тот же ключ с другой кодировкой
        ECPoint q = ECPoint.affine(x, y, params);
        // принадлежность кривой и подгруппе проверяет конструктор PublicKeyParameters
        return new PublicKeyParameters(q, params);
    }

    /**
     * Кодирует закрытый ключ в DER PrivateKeyInfo (PKCS#8 / RFC 5958).
     * <p>
     * Значение d хранится как OCTET STRING в little-endian порядке (RFC 9548 §5.1,
     * OpenSSL gost-engine convention). Это — стандартный формат для GOST
     * PrivateKeyInfo, отличный от общего BE-порядка PKCS#8.
     *
     * @param priv закрытый ключ
     * @return DER-байты PrivateKeyInfo
     * @throws IllegalArgumentException если параметры кривой не распознаны
     * @throws IllegalStateException    если ключ уничтожен
     */
    public static byte[] encodePrivateKey(PrivateKeyParameters priv) {
        ECParameters params = priv.getParams();
        String signAlgOid = signAlgOid(params);
        String curveOid = GostCurves.oidOf(params);
        String digestOid = digestOid(params);

        int keyLen = (params.n.bitLength() + 7) / 8; // 32 или 64 байта
        byte[] dBytes = Pack.toFixedLengthBigEndian(priv.getD(), keyLen); // BE из BigInteger
        byte[] dLE = Pack.reverseBytes(dBytes); // LE для OpenSSL-совместимости
        byte[] privateKey = null;
        try {
            // Закрытый ключ
            privateKey = DerCodec.encodeOctetString(dLE); // Одна обёртка

            // AlgorithmIdentifier: тот же формат что и для открытого ключа
            byte[] pubKeyParams =
                    DerCodec.encodeSequence(
                            DerCodec.encodeOid(curveOid), DerCodec.encodeOid(digestOid));
            byte[] algId = DerCodec.encodeSequence(DerCodec.encodeOid(signAlgOid), pubKeyParams);

            // PrivateKeyInfo ::= SEQUENCE { version INTEGER(0), algId, privateKey OCTET STRING }
            return DerCodec.encodeSequence(
                    DerCodec.encodeInteger(BigInteger.ZERO), algId, privateKey);
        } finally {
            // промежуточные копии d: возвращается только итоговый DER
            Arrays.fill(dBytes, (byte) 0);
            Arrays.fill(dLE, (byte) 0);
            if (privateKey != null) {
                Arrays.fill(privateKey, (byte) 0);
            }
        }
    }

    /**
     * Декодирует закрытый ключ из DER PrivateKeyInfo (PKCS#8) и OneAsymmetricKey (RFC 5958).
     * <p>
     * Ожидает little-endian порядок d внутри OCTET STRING (OpenSSL gost-engine convention).
     * <p>
     * Разбор строгий (только DER с определённой длиной, без байт после структуры):
     * <ul>
     *   <li>версия 0: допускается только необязательный {@code [0] attributes};</li>
     *   <li>версия 1 (v2 по RFC 5958): необязательный {@code [0] attributes} и обязательный
     *       {@code [1] publicKey}, в этом порядке; открытый ключ сверяется со значением,
     *       вычисленным из d, при несовпадении ключ отвергается;</li>
     *   <li>любые другие версии, элементы, их порядок и повторы отвергаются.</li>
     * </ul>
     * Запись ({@link #encodePrivateKey}) по-прежнему даёт версию 0 без открытого ключа.
     *
     * @param encoded DER-байты
     * @return закрытый ключ
     * @throws IllegalArgumentException      при ошибке разбора, значении d вне диапазона
     *                                       0 &lt; d &lt; n, неканонической длине содержимого
     *                                       (лишние нулевые байты за n) или открытом ключе,
     *                                       не соответствующем d
     * @throws UnsupportedOperationException если ключ замаскирован по RFC 9548 (за n есть
     *                                       ненулевые байты)
     */
    public static PrivateKeyParameters decodePrivateKey(byte[] encoded) {
        PrivateKeyInfoParts parts = parsePrivateKeyInfo(encoded);
        byte[] dBE = null;
        try {
            // Длина проверяется до конструктора: маскированный I (RFC 9548) иначе превратился бы
            // в число, которое конструктор отвергнет с непонятным «d must satisfy 0 < d < n»,
            // а I с нулевой маской вовсе прошёл бы как d = K_M.
            checkKeyLength(parts.params, parts.keyBytes);
            // OpenSSL gost-engine пишет d в little-endian; конвертируем в BE для BigInteger
            dBE = Pack.reverseBytes(parts.keyBytes);
            PrivateKeyParameters priv =
                    new PrivateKeyParameters(new BigInteger(1, dBE), parts.params);
            if (parts.publicKeyElement != null) {
                // Самая дорогая проверка (умножение на базовую точку) идёт последней, после всех
                // дешёвых проверок формы
                try {
                    checkPublicKeyElement(parts.publicKeyElement, priv);
                } catch (RuntimeException e) {
                    priv.destroy();
                    throw e;
                }
            }
            return priv;
        } finally {
            parts.destroy();
            if (dBE != null) Arrays.fill(dBE, (byte) 0);
        }
    }

    /**
     * Проверяет, что закрытый ключ в PrivateKeyInfo не замаскирован
     * (RFC 9548 §5.1). Маскированный ключ имеет |I| > n, где n — длина
     * скаляра для данной кривой. Если ключ замаскирован — бросает
     * {@link UnsupportedOperationException}.
     * <p>
     * Структуру разбирает тот же строгий разбор, что и {@link #decodePrivateKey(byte[])}
     * (версия, порядок и состав полей); метод нужен тем, кто хочет отклонить ключ до
     * расшифрования или вычисления открытого ключа, поэтому форму и значение
     * {@code [1] publicKey} не проверяет (только наличие и порядок полей), сверку с d не выполняет.
     *
     * <p><b>Не удалять как неиспользуемый:</b> внутри библиотеки метод не вызывается намеренно,
     * он оставлен публичной точкой API для внешнего кода.
     *
     * @param encoded DER PrivateKeyInfo
     * @throws UnsupportedOperationException если ключ замаскирован (|I| > n, ненулевые байты за n)
     * @throws IllegalArgumentException      при ошибке разбора DER или неканонической длине I
     */
    public static void checkNotMasked(byte[] encoded) {
        PrivateKeyInfoParts parts = parsePrivateKeyInfo(encoded);
        try {
            checkKeyLength(parts.params, parts.keyBytes);
        } finally {
            parts.destroy();
        }
    }

    /** Тег элемента {@code [0] attributes} (constructed, context-specific 0). */
    private static final int TAG_PKCS8_ATTRIBUTES = 0xA0;

    /** Тег элемента {@code [1] publicKey} (primitive, context-specific 1, IMPLICIT BIT STRING). */
    private static final int TAG_PKCS8_PUBLIC_KEY = 0x81;

    /**
     * Разобранный PrivateKeyInfo. {@code keyBytes} и {@code rawPrivateKeyOctets} - ключевой
     * материал, вызывающий обязан вызвать {@link #destroy()}.
     */
    private static final class PrivateKeyInfoParts {
        final ECParameters params;
        final byte[] keyBytes;
        final byte[] rawPrivateKeyOctets;
        final byte[] publicKeyElement;

        PrivateKeyInfoParts(
                ECParameters params,
                byte[] keyBytes,
                byte[] rawPrivateKeyOctets,
                byte[] publicKeyElement) {
            this.params = params;
            this.keyBytes = keyBytes;
            this.rawPrivateKeyOctets = rawPrivateKeyOctets;
            this.publicKeyElement = publicKeyElement;
        }

        void destroy() {
            Arrays.fill(keyBytes, (byte) 0);
            Arrays.fill(rawPrivateKeyOctets, (byte) 0);
        }
    }

    /**
     * Строгий структурный разбор PrivateKeyInfo / OneAsymmetricKey: общий для
     * {@link #decodePrivateKey(byte[])} и {@link #checkNotMasked(byte[])}, чтобы два метода не
     * расходились в том, какой ключ считать корректным.
     */
    private static PrivateKeyInfoParts parsePrivateKeyInfo(byte[] encoded) {
        // PrivateKeyInfo ::= SEQUENCE { version, privateKeyAlgorithm, privateKey,
        //                               attributes [0] OPTIONAL, publicKey [1] OPTIONAL }
        byte[][] outer = DerCodec.parseStrictSequence(encoded);
        byte[] keyBytes = null;
        try {
            if (outer.length < 3) {
                throw new IllegalArgumentException("Invalid PrivateKeyInfo: expected 3 elements");
            }

            BigInteger version = DerCodec.parseInteger(outer[0], 0);
            boolean versionOne = version.equals(BigInteger.ONE);
            if (!version.equals(BigInteger.ZERO) && !versionOne) {
                throw new IllegalArgumentException("Unsupported PKCS#8 version: " + version);
            }

            // Необязательные поля идут строго в порядке [0], затем [1]; повтор или иной порядок
            // оставляет лишний элемент и отвергается ниже
            int next = 3;
            if (next < outer.length && tagOf(outer[next]) == TAG_PKCS8_ATTRIBUTES) {
                checkAttributesElement(outer[next]);
                next++;
            }
            byte[] publicKeyElement = null;
            if (next < outer.length && tagOf(outer[next]) == TAG_PKCS8_PUBLIC_KEY) {
                if (!versionOne) {
                    throw new IllegalArgumentException(
                            "PKCS#8 publicKey is allowed only in version 1");
                }
                publicKeyElement = outer[next];
                next++;
            }
            if (next != outer.length) {
                throw new IllegalArgumentException(
                        "Unexpected element after privateKey in PrivateKeyInfo");
            }
            if (versionOne && publicKeyElement == null) {
                throw new IllegalArgumentException("PKCS#8 version 1 requires publicKey");
            }

            // AlgorithmIdentifier: SEQUENCE { OID signAlg, SEQUENCE { OID curve, OID digest } };
            // digestParamSet необязателен, поэтому в параметрах один или два элемента
            byte[][] algId = DerCodec.parseStrictSequence(outer[1]);
            if (algId.length != 2) {
                throw new IllegalArgumentException("Invalid AlgorithmIdentifier in PrivateKeyInfo");
            }
            byte[][] pubKeyParams = DerCodec.parseStrictSequence(algId[1]);
            if (pubKeyParams.length < 1 || pubKeyParams.length > 2) {
                throw new IllegalArgumentException(
                        "Invalid GostR3410-2012-PublicKeyParameters in PrivateKeyInfo");
            }
            String curveOid = DerCodec.parseOid(pubKeyParams[0], 0);
            ECParameters params = GostCurves.byName(curveOid);
            // OID алгоритма подписи обязан соответствовать размеру кривой, как и в SPKI
            checkSignAlgorithm(DerCodec.parseOid(algId[0], 0), params);

            keyBytes = DerCodec.parseOctetString(outer[2], 0);
            PrivateKeyInfoParts parts =
                    new PrivateKeyInfoParts(params, keyBytes, outer[2], publicKeyElement);
            keyBytes = null;
            return parts;
        } catch (RuntimeException e) {
            // outer[2] - копия всего OCTET STRING с ключом: затираем и при отказе разбора
            if (outer.length > 2) Arrays.fill(outer[2], (byte) 0);
            if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);
            throw e;
        }
    }

    /**
     * Содержимое {@code [0] attributes} не используется, но обязано быть корректным DER:
     * последовательностью атрибутов (SEQUENCE) с определённой длиной. Иначе мусор внутри элемента
     * проходил бы под видом допустимой структуры.
     */
    private static void checkAttributesElement(byte[] attributesElement) {
        int[] lengthInfo = DerCodec.decodeLength(attributesElement, 1);
        byte[] content =
                Arrays.copyOfRange(attributesElement, 1 + lengthInfo[1], attributesElement.length);
        // Содержимое оборачивается в SEQUENCE: так строгий разбор проверяет границы каждого
        // вложенного TLV
        byte[][] attributes =
                DerCodec.parseStrictSequence(DerCodec.encodeTlv(DerCodec.TAG_SEQUENCE, content));
        for (byte[] attribute : attributes) {
            if (tagOf(attribute) != DerCodec.TAG_SEQUENCE) {
                throw new IllegalArgumentException("Invalid attributes in PrivateKeyInfo");
            }
        }
    }

    private static int tagOf(byte[] element) {
        return element[0] & 0xFF;
    }

    /**
     * Сверяет {@code [1] publicKey} с открытым ключом, вычисленным из d.
     * <p>
     * Содержимое элемента: первый октет и точка x_LE || y_LE. Первый октет в примере A.2
     * RFC 9548 равен 0x01, а его семантика в стандарте не определена, поэтому допускаются 0x00
     * и 0x01 и он не истолковывается как число неиспользуемых бит BIT STRING. Достоверность
     * обеспечивает сверка точки с вычисленной из d, а не разбор этого октета: ключ принимается
     * только при совпадении открытого ключа с вычисленным.
     */
    private static void checkPublicKeyElement(byte[] publicKeyElement, PrivateKeyParameters priv) {
        int[] lengthInfo = DerCodec.decodeLength(publicKeyElement, 1);
        byte[] content =
                Arrays.copyOfRange(publicKeyElement, 1 + lengthInfo[1], publicKeyElement.length);
        int coordLen = (priv.getParams().p.bitLength() + 7) / 8;
        if (content.length != 1 + 2 * coordLen) {
            throw new IllegalArgumentException("PKCS#8 publicKey has invalid length");
        }
        if (content[0] != 0x00 && content[0] != 0x01) {
            throw new IllegalArgumentException("PKCS#8 publicKey has unsupported leading octet");
        }
        byte[] expectedPoint = subjectPublicKeyPointBytes(priv.derivePublicKey());
        if (!Arrays.equals(Arrays.copyOfRange(content, 1, content.length), expectedPoint)) {
            throw new IllegalArgumentException("PKCS#8 publicKey does not match the private key");
        }
    }

    /**
     * Проверяет длину содержимого закрытого ключа I (little-endian) относительно длины
     * скаляра n кривой.
     * <ul>
     *   <li>|I| &le; n — допустимо: короткий I означает обрезанные нулевые старшие байты;</li>
     *   <li>|I| &gt; n, среди I[n..] есть ненулевой байт — маскированный ключ RFC 9548
     *       (I = K_M ‖ M₁ ‖ …), который не поддерживается, либо данные с лишними ненулевыми
     *       байтами; в обоих случаях усечение до n байт дало бы неверный скаляр;</li>
     *   <li>|I| &gt; n, все I[n..] нулевые — неканоническая длина (в том числе нулевая маска,
     *       при которой K = 0): данные некорректны.</li>
     * </ul>
     * Хвост I[n..] — ключевой материал, поэтому он просматривается целиком без раннего
     * выхода и без ветвления внутри цикла; решение принимается один раз после него.
     */
    private static void checkKeyLength(ECParameters params, byte[] iBytes) {
        int n = (params.n.bitLength() + 7) / 8;
        if (iBytes.length <= n) {
            return;
        }
        int tailBits = 0;
        for (int i = n; i < iBytes.length; i++) {
            tailBits |= iBytes[i];
        }
        if (tailBits != 0) {
            throw new UnsupportedOperationException(
                    "Masked GOST keys (k>0) are not supported: "
                            + "key data length "
                            + iBytes.length
                            + " exceeds curve byte length "
                            + n);
        }
        throw new IllegalArgumentException(
                "Non-canonical GOST private key length: "
                        + iBytes.length
                        + " bytes, curve byte length "
                        + n);
    }

    /**
     * Возвращает OID алгоритма подписи по параметрам кривой:
     * 256-бит -> {@code 1.2.643.7.1.1.1.1}, 512-бит -> {@code 1.2.643.7.1.1.1.2}.
     */
    private static String signAlgOid(ECParameters params) {
        return (params.hlen == Streebog256.DIGEST_SIZE)
                ? GostCurves.OID_SIGN_256
                : GostCurves.OID_SIGN_512;
    }

    /**
     * Возвращает OID хэш-функции для digestParamSet:
     * 256-бит -> Стрибог-256, 512-бит -> Стрибог-512.
     */
    private static String digestOid(ECParameters params) {
        return (params.hlen == Streebog256.DIGEST_SIZE) ? OID_STREEBOG_256 : OID_STREEBOG_512;
    }

    /** OID алгоритма подписи в SPKI обязан соответствовать размеру кривой (256 или 512 бит). */
    private static void checkSignAlgorithm(String actualSignAlgOid, ECParameters params) {
        String expected = signAlgOid(params);
        if (!expected.equals(actualSignAlgOid)) {
            throw new IllegalArgumentException(
                    "Unsupported public key algorithm OID: "
                            + actualSignAlgOid
                            + " (expected "
                            + expected
                            + " for this curve)");
        }
    }

    /**
     * Проверяет присутствие и значение {@code digestParamSet} по правилу набора параметров
     * (RFC 9215 §4.2) и совпадение хэша с размером кривой.
     */
    private static void checkDigestParamSet(
            String curveOid, byte[][] pubKeyParams, ECParameters params) {
        boolean present = pubKeyParams.length == 2;
        GostCurves.DigestParamSetPolicy policy = GostCurves.digestPolicyOf(curveOid);
        if (policy == GostCurves.DigestParamSetPolicy.REQUIRED && !present) {
            throw new IllegalArgumentException(
                    "digestParamSet is required for curve " + curveOid + " (RFC 9215 §4.2)");
        }
        if (policy == GostCurves.DigestParamSetPolicy.FORBIDDEN && present) {
            throw new IllegalArgumentException(
                    "digestParamSet must be omitted for curve " + curveOid + " (RFC 9215 §4.2)");
        }
        if (present) {
            String actualDigestOid = DerCodec.parseOid(pubKeyParams[1], 0);
            String expectedDigestOid = digestOid(params);
            if (!expectedDigestOid.equals(actualDigestOid)) {
                throw new IllegalArgumentException(
                        "Unexpected digestParamSet OID: "
                                + actualDigestOid
                                + " (expected "
                                + expectedDigestOid
                                + ")");
            }
        }
    }
}
