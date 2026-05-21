package org.rssys.gost.jca.spec;

import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;

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
 *   privateKey OCTET STRING     -- закрытый ключ d, big-endian
 * }
 * </pre>
 *
 * <p>OID хэш-функции по умолчанию:
 * <ul>
 *   <li>Стрибог-256 ({@code 1.2.643.7.1.1.2.2}) для 256-битных кривых</li>
 *   <li>Стрибог-512 ({@code 1.2.643.7.1.1.2.3}) для 512-битных кривых</li>
 * </ul>
 *
 * <p>Класс является package-private; внешний код взаимодействует через
 * {@link org.rssys.gost.jca.key.GostECPublicKey} и {@link org.rssys.gost.jca.key.GostECPrivateKey}.
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
        byte[] xLE = reverseCopy(toFixedBytes(q.getX(), coordLen));
        byte[] yLE = reverseCopy(toFixedBytes(q.getY(), coordLen));

        // Публичный ключ как OCTET STRING: x_LE || y_LE
        byte[] pointBytes = new byte[coordLen * 2];
        System.arraycopy(xLE, 0, pointBytes, 0,         coordLen);
        System.arraycopy(yLE, 0, pointBytes, coordLen,  coordLen);

        // AlgorithmIdentifier: SEQUENCE { signAlgOID, SEQUENCE { curveOID, digestOID } }
        byte[] pubKeyParams = encodeSequence(encodeOid(curveOid), encodeOid(digestOid));
        byte[] algId        = encodeSequence(encodeOid(signAlgOid), pubKeyParams);

        byte[] pointOctetStr = encodeOctetString(pointBytes);
        byte[] bitStr = encodeBitString(pointOctetStr);

        return encodeSequence(algId, bitStr);
    }

    /**
     * Декодирует открытый ключ из DER SubjectPublicKeyInfo (X.509).
     *
     * <p>Если {@code signAlgOid} = {@link GostCurves#OID_SIGN_512}, а размер точки
     * не соответствует OID кривой — применяет {@link #FALLBACK_256_TO_512}
     * (workaround для нестандартных сертификатов Минцифры, где {@code curveOid}
     * содержит 256-битный OID при 512-битном ключе).
     *
     * @param encoded DER-байты
     * @return открытый ключ
     * @throws IllegalArgumentException при ошибке разбора или неизвестной кривой
     */
    public static PublicKeyParameters decodePublicKey(byte[] encoded) {
        // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
        byte[][] outer = parseSequenceContents(encoded, 0);
        if (outer.length < 2) {
            throw new IllegalArgumentException("Invalid SubjectPublicKeyInfo: expected 2 elements");
        }

        // AlgorithmIdentifier ::= SEQUENCE { OID, SEQUENCE { OID, OID } }
        byte[][] algId      = parseSequenceContents(outer[0], 0);
        if (algId.length < 2) {
            throw new IllegalArgumentException("Invalid AlgorithmIdentifier: expected 2 elements");
        }
        String algoOid     = parseOid(algId[0], 0);
        byte[][] pubKeyParams = parseSequenceContents(algId[1], 0);
        if (pubKeyParams.length < 1) {
            throw new IllegalArgumentException("Invalid GostR3410-PublicKeyParameters");
        }
        String curveOid    = parseOid(pubKeyParams[0], 0);
        ECParameters params = GostCurves.byName(curveOid);

        // BIT STRING → OCTET STRING с координатами
        byte[] bitStrContent = parseBitString(outer[1], 0);
        byte[] pointOctetStr = parseOctetString(bitStrContent, 0);

        int coordLen = (params.p.bitLength() + 7) / 8;
        if (pointOctetStr.length != coordLen * 2) {
            // Несоответствие: OID кривой ожидает coordLen байт на координату,
            // а реальная точка больше. Если сертификат подписан алгоритмом ГОСТ
            // с 512-битным модулем — пытаемся подобрать 512-битный вариант кривой
            // через FALLBACK_256_TO_512 (workaround для сертификатов Минцифры).
            if (GostCurves.OID_SIGN_512.equals(algoOid)) {
                String oid512 = to512bitCurveOid(curveOid);
                if (oid512 != null) {
                    params = GostCurves.byName(oid512);
                    coordLen = (params.p.bitLength() + 7) / 8;
                }
            }
            if (pointOctetStr.length != coordLen * 2) {
                throw new IllegalArgumentException(
                    "Invalid EC point encoding: expected " + (coordLen * 2)
                    + " bytes, got " + pointOctetStr.length);
            }
        }

        // Координаты в little-endian → конвертируем в big-endian для BigInteger
        byte[] xLE = Arrays.copyOfRange(pointOctetStr, 0,         coordLen);
        byte[] yLE = Arrays.copyOfRange(pointOctetStr, coordLen,  coordLen * 2);
        BigInteger x = new BigInteger(1, reverseCopy(xLE));
        BigInteger y = new BigInteger(1, reverseCopy(yLE));

        ECPoint q = ECPoint.affine(x, y, params);
        return new PublicKeyParameters(q, params);
    }
     /**
     * Кодирует закрытый ключ в DER PrivateKeyInfo (PKCS#8 / RFC 5958).
     * <p>
     * Значение d хранится как OCTET STRING в big-endian порядке внутри
     * внешнего OCTET STRING (вложенное кодирование по аналогии с RFC 5958).
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
        byte[] dBytes = toFixedBytes(priv.getD(), keyLen);

        // Закрытый ключ
        byte[] privateKey = encodeOctetString(dBytes); // Одна обёртка

        // AlgorithmIdentifier: тот же формат что и для открытого ключа
        byte[] pubKeyParams = encodeSequence(encodeOid(curveOid), encodeOid(digestOid));
        byte[] algId        = encodeSequence(encodeOid(signAlgOid), pubKeyParams);

        // PrivateKeyInfo ::= SEQUENCE { version INTEGER(0), algId, privateKey OCTET STRING }
        return encodeSequence(encodeInteger(BigInteger.ZERO), algId, privateKey);
    }

    /**
     * Декодирует закрытый ключ из DER PrivateKeyInfo (PKCS#8).
     *
     * @param encoded DER-байты
     * @return закрытый ключ
     * @throws IllegalArgumentException при ошибке разбора
     */
    public static PrivateKeyParameters decodePrivateKey(byte[] encoded) {
        // PrivateKeyInfo ::= SEQUENCE { INTEGER, AlgorithmIdentifier, OCTET STRING }
        byte[][] outer = parseSequenceContents(encoded, 0);
        if (outer.length < 3) {
            throw new IllegalArgumentException("Invalid PrivateKeyInfo: expected 3 elements");
        }

        // Версия — должна быть 0
        BigInteger version = parseInteger(outer[0], 0);
        if (!version.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Unsupported PKCS#8 version: " + version);
        }

        // AlgorithmIdentifier: SEQUENCE { OID signAlg, SEQUENCE { OID curve, OID digest } }
        byte[][] algId       = parseSequenceContents(outer[1], 0);
        if (algId.length < 2) {
            throw new IllegalArgumentException("Invalid AlgorithmIdentifier in PrivateKeyInfo");
        }
        byte[][] pubKeyParams = parseSequenceContents(algId[1], 0);
        String curveOid       = parseOid(pubKeyParams[0], 0);
        ECParameters params   = GostCurves.byName(curveOid);

        byte[] dBytes = parseOctetString(outer[2], 0);

        BigInteger d = new BigInteger(1, dBytes);
        return new PrivateKeyParameters(d, params);
    }

    /** Кодирует INTEGER. */
    static byte[] encodeInteger(BigInteger value) {
        return encodeTlv(0x02, value.toByteArray());
    }

    /**
     * Кодирует BIT STRING без неиспользуемых бит.
     * Первый байт содержимого — 0x00 (ноль неиспользуемых бит).
     */
    static byte[] encodeBitString(byte[] data) {
        byte[] content = new byte[1 + data.length];
        content[0] = 0x00; // количество неиспользуемых бит = 0
        System.arraycopy(data, 0, content, 1, data.length);
        return encodeTlv(0x03, content);
    }

    /** Кодирует OCTET STRING. */
    static byte[] encodeOctetString(byte[] data) {
        return encodeTlv(0x04, data);
    }

    /** Кодирует OID из строки вида {@code "1.2.643.7.1.1.1.1"}. */
    static byte[] encodeOid(String oidStr) {
        String[] parts = oidStr.split("\\.");
        int[]    arcs  = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            arcs[i] = Integer.parseInt(parts[i]);
        }
        return encodeTlv(0x06, encodeOidBody(arcs));
    }

    /** Кодирует SEQUENCE из одного или нескольких уже-кодированных элементов. */
    static byte[] encodeSequence(byte[]... elements) {
        int total = 0;
        for (byte[] e : elements) total += e.length;
        byte[] content = new byte[total];
        int off = 0;
        for (byte[] e : elements) {
            System.arraycopy(e, 0, content, off, e.length);
            off += e.length;
        }
        return encodeTlv(0x30, content);
    }

    /**
     * Разбирает SEQUENCE и возвращает вложенные элементы как массив DER-байт каждого.
     *
     * @param data   исходный массив
     * @param offset смещение тега SEQUENCE (0x30)
     */
    static byte[][] parseSequenceContents(byte[] data, int offset) {
        checkTag(data, offset, 0x30, "SEQUENCE");
        int[] lenInfo    = decodeLength(data, offset + 1);
        int contentOff   = offset + 1 + lenInfo[1];
        int contentEnd   = contentOff + lenInfo[0];

        java.util.List<byte[]> elements = new java.util.ArrayList<>();
        int pos = contentOff;
        while (pos < contentEnd) {
            int[] childLen  = decodeLength(data, pos + 1);
            int childTotal  = 1 + childLen[1] + childLen[0];
            elements.add(Arrays.copyOfRange(data, pos, pos + childTotal));
            pos += childTotal;
        }
        return elements.toArray(new byte[0][]);
    }

    /**
     * Разбирает BIT STRING и возвращает содержимое без ведущего байта
     * (числа неиспользуемых бит).
     */
    static byte[] parseBitString(byte[] data, int offset) {
        checkTag(data, offset, 0x03, "BIT STRING");
        int[] lenInfo   = decodeLength(data, offset + 1);
        int contentOff  = offset + 1 + lenInfo[1];
        // Пропускаем первый байт — число неиспользуемых бит
        return Arrays.copyOfRange(data, contentOff + 1, contentOff + lenInfo[0]);
    }

    /** Разбирает OCTET STRING и возвращает содержимое. */
    static byte[] parseOctetString(byte[] data, int offset) {
        checkTag(data, offset, 0x04, "OCTET STRING");
        int[] lenInfo   = decodeLength(data, offset + 1);
        int contentOff  = offset + 1 + lenInfo[1];
        return Arrays.copyOfRange(data, contentOff, contentOff + lenInfo[0]);
    }

    /** Разбирает OID и возвращает строку вида {@code "1.2.643.7.1.1.1.1"}. */
    static String parseOid(byte[] data, int offset) {
        checkTag(data, offset, 0x06, "OID");
        int[] lenInfo   = decodeLength(data, offset + 1);
        int contentOff  = offset + 1 + lenInfo[1];
        int contentEnd  = contentOff + lenInfo[0];

        StringBuilder sb = new StringBuilder();
        // Первый байт кодирует первые два компонента: 40*a0 + a1
        int first = data[contentOff] & 0xFF;
        sb.append(first / 40).append('.').append(first % 40);

        long value = 0;
        for (int i = contentOff + 1; i < contentEnd; i++) {
            int b = data[i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                sb.append('.').append(value);
                value = 0;
            }
        }
        return sb.toString();
    }

    /** Разбирает INTEGER и возвращает BigInteger. */
    static BigInteger parseInteger(byte[] data, int offset) {
        checkTag(data, offset, 0x02, "INTEGER");
        int[] lenInfo  = decodeLength(data, offset + 1);
        int contentOff = offset + 1 + lenInfo[1];
        return new BigInteger(Arrays.copyOfRange(data, contentOff, contentOff + lenInfo[0]));
    }

    /** Кодирует TLV: тег (1 байт) + DER-длина + содержимое. */
    private static byte[] encodeTlv(int tag, byte[] content) {
        byte[] lenBytes = encodeLength(content.length);
        byte[] result   = new byte[1 + lenBytes.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1,                   lenBytes.length);
        System.arraycopy(content,  0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    /** Кодирует DER-длину. Short form (≤ 127), long form (81/82). */
    private static byte[] encodeLength(int len) {
        if (len <= 0x7F) {
            return new byte[]{ (byte) len };
        } else if (len <= 0xFF) {
            return new byte[]{ (byte) 0x81, (byte) len };
        } else if (len <= 0xFFFF) {
            return new byte[]{ (byte) 0x82, (byte) (len >> 8), (byte) len };
        }
        throw new IllegalArgumentException("DER length too large: " + len);
    }

    /**
     * Декодирует DER-длину начиная с позиции {@code offset}.
     *
     * @return {@code int[2]}: [длина_содержимого, байт_под_длину]
     */
    private static int[] decodeLength(byte[] data, int offset) {
        int first = data[offset] & 0xFF;
        if (first <= 0x7F) {
            return new int[]{ first, 1 };
        } else if (first == 0x81) {
            return new int[]{ data[offset + 1] & 0xFF, 2 };
        } else if (first == 0x82) {
            int len = ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
            return new int[]{ len, 3 };
        }
        throw new IllegalArgumentException(
            "Unsupported DER length encoding: 0x" + Integer.toHexString(first));
    }

    /** Кодирует тело OID (без тега и длины) из массива компонентов. */
    private static byte[] encodeOidBody(int[] arcs) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        // Первые два компонента объединяются в один байт: 40*a0 + a1
        buf.write(40 * arcs[0] + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            long val = arcs[i];
            if (val < 0x80) {
                buf.write((int) val);
            } else {
                // Base-128 кодирование с установленным старшим битом у всех кроме последнего
                int bits = 0;
                long tmp = val;
                while (tmp > 0) { bits += 7; tmp >>= 7; }
                for (int shift = bits - 7; shift > 0; shift -= 7) {
                    buf.write((int) (0x80 | ((val >> shift) & 0x7F)));
                }
                buf.write((int) (val & 0x7F));
            }
        }
        return buf.toByteArray();
    }

    /**
     * Проверяет тег DER-структуры по смещению.
     *
     * @throws IllegalArgumentException если тег не совпадает
     */
    private static void checkTag(byte[] data, int offset, int expectedTag, String name) {
        if ((data[offset] & 0xFF) != expectedTag) {
            throw new IllegalArgumentException(
                "Expected " + name + " (0x" + Integer.toHexString(expectedTag)
                + ") at offset " + offset
                + ", got 0x" + Integer.toHexString(data[offset] & 0xFF));
        }
    }

    /**
     * Workaround для нестандартных сертификатов УЦ Минцифры, где
     * {@code curveOid} содержит OID 256-битной кривой при 512-битном ключе
     * (signAlgOid = {@link GostCurves#OID_SIGN_512}), а реальная точка —
     * 128 байт (512-битная кривая).
     *
     * <p>Маппинг: {@code OID_TC26_A_256 → OID_TC26_A_512}.
     * Аналогично поведению OpenSSL gostprov, который при несоответствии размера
     * точки доверяет signAlgOid, а не curveOid.
     */
    private static final Map<String, String> FALLBACK_256_TO_512 = Map.of(
            GostCurves.OID_TC26_A_256, GostCurves.OID_TC26_A_512
    );

    private static String to512bitCurveOid(String oid256) {
        return FALLBACK_256_TO_512.get(oid256);
    }

    /**
     * Возвращает OID алгоритма подписи по параметрам кривой:
     * 256-бит → {@code 1.2.643.7.1.1.1.1}, 512-бит → {@code 1.2.643.7.1.1.1.2}.
     */
    private static String signAlgOid(ECParameters params) {
        return (params.hlen == 32) ? GostCurves.OID_SIGN_256 : GostCurves.OID_SIGN_512;
    }

    /**
     * Возвращает OID хэш-функции для digestParamSet:
     * 256-бит → Стрибог-256, 512-бит → Стрибог-512.
     */
    private static String digestOid(ECParameters params) {
        return (params.hlen == 32) ? OID_STREEBOG_256 : OID_STREEBOG_512;
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

    /**
     * Возвращает новый массив с байтами в обратном порядке (little-endian ↔ big-endian).
     */
    static byte[] reverseCopy(byte[] src) {
        byte[] dst = new byte[src.length];
        for (int i = 0; i < src.length; i++) {
            dst[i] = src[src.length - 1 - i];
        }
        return dst;
    }
}
