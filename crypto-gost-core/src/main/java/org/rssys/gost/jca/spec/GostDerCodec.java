package org.rssys.gost.jca.spec;

import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.util.Pack;

import java.math.BigInteger;
import java.util.Arrays;

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

    private static final String OID_STREEBOG_256 = "1.2.643.7.1.1.2.2";
    private static final String OID_STREEBOG_512 = "1.2.643.7.1.1.2.3";

    private GostDerCodec() {}

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
        ECParameters params  = pub.getParams();
        String signAlgOid    = signAlgOid(params);
        String curveOid      = GostCurves.oidOf(params);
        String digestOid     = digestOid(params);

        // Нормализуем точку в аффинные координаты
        ECPoint q = pub.getQ().normalize();
        int coordLen = (params.p.bitLength() + 7) / 8; // 32 или 64 байта

        // Координаты в little-endian: reverseBytes(big-endian)
        byte[] xLE = Pack.reverseBytes(toFixedBytes(q.getX(), coordLen));
        byte[] yLE = Pack.reverseBytes(toFixedBytes(q.getY(), coordLen));

        // Публичный ключ как OCTET STRING: x_LE || y_LE
        byte[] pointBytes = new byte[coordLen * 2];
        System.arraycopy(xLE, 0, pointBytes, 0,         coordLen);
        System.arraycopy(yLE, 0, pointBytes, coordLen,  coordLen);

        // AlgorithmIdentifier: SEQUENCE { signAlgOID, SEQUENCE { curveOID, digestOID } }
        byte[] pubKeyParams = DerCodec.encodeSequence(DerCodec.encodeOid(curveOid), DerCodec.encodeOid(digestOid));
        byte[] algId        = DerCodec.encodeSequence(DerCodec.encodeOid(signAlgOid), pubKeyParams);

        byte[] pointOctetStr = DerCodec.encodeOctetString(pointBytes);
        byte[] bitStr = DerCodec.encodeBitString(pointOctetStr);

        return DerCodec.encodeSequence(algId, bitStr);
    }

    /**
     * Декодирует открытый ключ из DER SubjectPublicKeyInfo (X.509).
     *
     * @param encoded DER-байты
     * @return открытый ключ
     * @throws IllegalArgumentException при ошибке разбора или неизвестной кривой
     */
    public static PublicKeyParameters decodePublicKey(byte[] encoded) {
        // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
        byte[][] outer = DerCodec.parseSequenceContents(encoded, 0);
        if (outer.length < 2) {
            throw new IllegalArgumentException("Invalid SubjectPublicKeyInfo: expected 2 elements");
        }

        // AlgorithmIdentifier ::= SEQUENCE { OID, SEQUENCE { OID, OID } }
        byte[][] algId      = DerCodec.parseSequenceContents(outer[0], 0);
        if (algId.length < 2) {
            throw new IllegalArgumentException("Invalid AlgorithmIdentifier: expected 2 elements");
        }
        byte[][] pubKeyParams = DerCodec.parseSequenceContents(algId[1], 0);
        if (pubKeyParams.length < 1) {
            throw new IllegalArgumentException("Invalid GostR3410-PublicKeyParameters");
        }
        String curveOid    = DerCodec.parseOid(pubKeyParams[0], 0);
        ECParameters params = GostCurves.byName(curveOid);

        // BIT STRING → OCTET STRING с координатами
        byte[] bitStrContent = DerCodec.parseBitString(outer[1], 0);
        byte[] pointOctetStr = DerCodec.parseOctetString(bitStrContent, 0);

        int coordLen = (params.p.bitLength() + 7) / 8;
        if (pointOctetStr.length != coordLen * 2) {
            throw new IllegalArgumentException(
                "Invalid EC point encoding: expected " + (coordLen * 2)
                + " bytes, got " + pointOctetStr.length);
        }

        // Координаты в little-endian → конвертируем в big-endian для BigInteger
        byte[] xLE = Arrays.copyOfRange(pointOctetStr, 0,         coordLen);
        byte[] yLE = Arrays.copyOfRange(pointOctetStr, coordLen,  coordLen * 2);
        BigInteger x = new BigInteger(1, Pack.reverseBytes(xLE));
        BigInteger y = new BigInteger(1, Pack.reverseBytes(yLE));

        ECPoint q = ECPoint.affine(x, y, params);
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
        ECParameters params  = priv.getParams();
        String signAlgOid    = signAlgOid(params);
        String curveOid      = GostCurves.oidOf(params);
        String digestOid     = digestOid(params);

        int keyLen = (params.n.bitLength() + 7) / 8; // 32 или 64 байта
        byte[] dBytes = toFixedBytes(priv.getD(), keyLen); // BE из BigInteger
        byte[] dLE = Pack.reverseBytes(dBytes); // LE для OpenSSL-совместимости

        // Закрытый ключ
        byte[] privateKey = DerCodec.encodeOctetString(dLE); // Одна обёртка

        // AlgorithmIdentifier: тот же формат что и для открытого ключа
        byte[] pubKeyParams = DerCodec.encodeSequence(DerCodec.encodeOid(curveOid), DerCodec.encodeOid(digestOid));
        byte[] algId        = DerCodec.encodeSequence(DerCodec.encodeOid(signAlgOid), pubKeyParams);

        // PrivateKeyInfo ::= SEQUENCE { version INTEGER(0), algId, privateKey OCTET STRING }
        return DerCodec.encodeSequence(DerCodec.encodeInteger(BigInteger.ZERO), algId, privateKey);
    }

    /**
     * Декодирует закрытый ключ из DER PrivateKeyInfo (PKCS#8).
     * <p>
     * Ожидает little-endian порядок d внутри OCTET STRING (OpenSSL gost-engine convention).
     *
     * @param encoded DER-байты
     * @return закрытый ключ
     * @throws IllegalArgumentException при ошибке разбора
     */
    public static PrivateKeyParameters decodePrivateKey(byte[] encoded) {
        // PrivateKeyInfo ::= SEQUENCE { INTEGER, AlgorithmIdentifier, OCTET STRING }
        byte[][] outer = DerCodec.parseSequenceContents(encoded, 0);
        if (outer.length < 3) {
            throw new IllegalArgumentException("Invalid PrivateKeyInfo: expected 3 elements");
        }

        // Версия — должна быть 0
        BigInteger version = DerCodec.parseInteger(outer[0], 0);
        if (!version.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Unsupported PKCS#8 version: " + version);
        }

        // AlgorithmIdentifier: SEQUENCE { OID signAlg, SEQUENCE { OID curve, OID digest } }
        byte[][] algId       = DerCodec.parseSequenceContents(outer[1], 0);
        if (algId.length < 2) {
            throw new IllegalArgumentException("Invalid AlgorithmIdentifier in PrivateKeyInfo");
        }
        byte[][] pubKeyParams = DerCodec.parseSequenceContents(algId[1], 0);
        String curveOid       = DerCodec.parseOid(pubKeyParams[0], 0);
        ECParameters params   = GostCurves.byName(curveOid);

        byte[] dBytes = DerCodec.parseOctetString(outer[2], 0);
        // OpenSSL gost-engine пишет d в little-endian; конвертируем в BE для BigInteger
        byte[] dBE = Pack.reverseBytes(dBytes);
        BigInteger d = new BigInteger(1, dBE);
        return new PrivateKeyParameters(d, params);
    }

    /**
     * Проверяет, что закрытый ключ в PrivateKeyInfo не замаскирован
     * (RFC 9548 §5.1). Маскированный ключ имеет |I| > n, где n — длина
     * скаляра для данной кривой. Если ключ замаскирован — бросает
     * {@link UnsupportedOperationException}.
     *
     * @param encoded DER PrivateKeyInfo
     * @throws UnsupportedOperationException если ключ замаскирован (|I| > n)
     * @throws IllegalArgumentException      при ошибке разбора DER
     */
    public static void checkNotMasked(byte[] encoded) {
        byte[][] outer = DerCodec.parseSequenceContents(encoded, 0);
        if (outer.length < 3) {
            throw new IllegalArgumentException(
                "Invalid PrivateKeyInfo: expected 3 elements");
        }

        byte[][] algId = DerCodec.parseSequenceContents(outer[1], 0);
        if (algId.length < 2) {
            throw new IllegalArgumentException(
                "Invalid AlgorithmIdentifier in PrivateKeyInfo");
        }
        byte[][] pubKeyParams = DerCodec.parseSequenceContents(algId[1], 0);
        String curveOid = DerCodec.parseOid(pubKeyParams[0], 0);
        ECParameters params = GostCurves.byName(curveOid);
        int n = (params.n.bitLength() + 7) / 8;

        byte[] iBytes = DerCodec.parseOctetString(outer[2], 0);
        if (iBytes.length > n) {
            throw new UnsupportedOperationException(
                "Masked GOST keys (k>0) are not supported: "
                + "key data length " + iBytes.length
                + " exceeds curve byte length " + n);
        }
    }

    /**
     * Возвращает OID алгоритма подписи по параметрам кривой:
     * 256-бит → {@code 1.2.643.7.1.1.1.1}, 512-бит → {@code 1.2.643.7.1.1.1.2}.
     */
    private static String signAlgOid(ECParameters params) {
        return (params.hlen == Streebog256.DIGEST_SIZE) ? GostCurves.OID_SIGN_256 : GostCurves.OID_SIGN_512;
    }

    /**
     * Возвращает OID хэш-функции для digestParamSet:
     * 256-бит → Стрибог-256, 512-бит → Стрибог-512.
     */
    private static String digestOid(ECParameters params) {
        return (params.hlen == Streebog256.DIGEST_SIZE) ? OID_STREEBOG_256 : OID_STREEBOG_512;
    }

    /**
     * Возвращает big-endian представление BigInteger фиксированной длины {@code len} байт.
     * Дополняет нулями слева или усекает ведущий знаковый байт 0x00.
     */
    static byte[] toFixedBytes(BigInteger value, int len) {
        byte[] raw = value.toByteArray();
        if (raw.length == len) {
            return raw;
        }
        byte[] result = new byte[len];
        if (raw.length < len) {
            // Дополняем нулями слева (big-endian)
            System.arraycopy(raw, 0, result, len - raw.length, raw.length);
        } else {
            // Убираем ведущий 0x00 знакового байта BigInteger
            System.arraycopy(raw, raw.length - len, result, 0, len);
        }
        return result;
    }
}
