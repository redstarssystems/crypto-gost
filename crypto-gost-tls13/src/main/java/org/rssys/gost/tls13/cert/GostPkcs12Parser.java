package org.rssys.gost.tls13.cert;

import org.rssys.gost.tls13.GostOids;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Разбор PFX-контейнера (PKCS#12, RFC 7292) без JDK KeyStore.
 * <p>
 * Поддерживает разбор структуры: PFX → AuthenticatedSafe → SafeContents → SafeBag
 * (pkcs8ShroudedKeyBag, certBag), MacData, EncryptedPrivateKeyInfo, PBES2-params.
 */
public final class GostPkcs12Parser {

    private GostPkcs12Parser() {}

    /** Результат разбора PFX. */
    public static final class PfxData {
        private final int version;
        private final AuthenticatedSafeData authSafe;
        private final MacData macData;
        private final byte[] authSafeRawContent;

        PfxData(int version, AuthenticatedSafeData authSafe, MacData macData,
                byte[] authSafeRawContent) {
            this.version = version;
            this.authSafe = authSafe;
            this.macData = macData;
            this.authSafeRawContent = authSafeRawContent;
        }

        public int getVersion() { return version; }
        public AuthenticatedSafeData getAuthSafe() { return authSafe; }
        public MacData getMacData() { return macData; }
        /** @return BER-кодировка AuthenticatedSafe (raw байты, с которых считается MAC) */
        public byte[] getAuthSafeRawContent() { return authSafeRawContent; }
    }

    /** AuthenticatedSafe: список ContentInfo. */
    public static final class AuthenticatedSafeData {
        private final List<ContentInfoData> contentInfos;

        AuthenticatedSafeData(List<ContentInfoData> contentInfos) {
            this.contentInfos = contentInfos;
        }

        public List<ContentInfoData> getContentInfos() { return contentInfos; }
    }

    /** ContentInfo: contentType + content (raw). */
    public static final class ContentInfoData {
        private final String contentType;
        private final byte[] content;

        ContentInfoData(String contentType, byte[] content) {
            this.contentType = contentType;
            this.content = content;
        }

        public String getContentType() { return contentType; }
        public byte[] getContent() { return content; }
    }

    /** MacData из PFX. */
    public static final class MacData {
        private final byte[] salt;
        private final int iterations;
        private final String digestAlgorithm;
        private final byte[] digestValue;

        MacData(byte[] salt, int iterations, String digestAlgorithm, byte[] digestValue) {
            this.salt = salt;
            this.iterations = iterations;
            this.digestAlgorithm = digestAlgorithm;
            this.digestValue = digestValue;
        }

        public byte[] getSalt() { return salt; }
        public int getIterations() { return iterations; }
        public String getDigestAlgorithm() { return digestAlgorithm; }
        public byte[] getDigestValue() { return digestValue; }
    }

    /** EncryptedPrivateKeyInfo (PKCS8ShroudedKeyBag). */
    public static final class EncryptedPrivateKeyInfo {
        private final String encryptionAlgorithmOid;
        private final byte[] encryptionParams;
        private final byte[] encryptedData;

        EncryptedPrivateKeyInfo(String encryptionAlgorithmOid, byte[] encryptionParams,
                                byte[] encryptedData) {
            this.encryptionAlgorithmOid = encryptionAlgorithmOid;
            this.encryptionParams = encryptionParams;
            this.encryptedData = encryptedData;
        }

        public String getEncryptionAlgorithmOid() { return encryptionAlgorithmOid; }
        public byte[] getEncryptionParams() { return encryptionParams; }
        public byte[] getEncryptedData() { return encryptedData; }
    }

    /** PBES2-params (RFC 9337 §7.2). */
    public static final class Pbes2Params {
        private final byte[] salt;
        private final int iterationCount;
        private final String prfOid;
        private final String encryptionSchemeOid;
        private final byte[] ukm;

        Pbes2Params(byte[] salt, int iterationCount, String prfOid,
                    String encryptionSchemeOid, byte[] ukm) {
            this.salt = salt;
            this.iterationCount = iterationCount;
            this.prfOid = prfOid;
            this.encryptionSchemeOid = encryptionSchemeOid;
            this.ukm = ukm;
        }

        public byte[] getSalt() { return salt; }
        public int getIterationCount() { return iterationCount; }
        public String getPrfOid() { return prfOid; }
        public String getEncryptionSchemeOid() { return encryptionSchemeOid; }
        public byte[] getUkm() { return ukm; }
    }

    /** SafeBag: bagId + содержимое + аттрибуты. */
    public static final class SafeBagData {
        private final String bagId;
        private final byte[] bagValue;
        private final List<BagAttribute> attributes;

        SafeBagData(String bagId, byte[] bagValue, List<BagAttribute> attributes) {
            this.bagId = bagId;
            this.bagValue = bagValue;
            this.attributes = attributes;
        }

        public String getBagId() { return bagId; }
        public byte[] getBagValue() { return bagValue; }
        public List<BagAttribute> getAttributes() { return attributes; }
    }

    public static final class BagAttribute {
        private final String attrId;
        private final byte[][] attrValues;

        BagAttribute(String attrId, byte[][] attrValues) {
            this.attrId = attrId;
            this.attrValues = attrValues;
        }

        public String getAttrId() { return attrId; }
        public byte[][] getAttrValues() { return attrValues; }
    }

    // ========================================================================
    // Главный метод
    // ========================================================================

    /**
     * Разбирает PFX-контейнер.
     *
     * @param pfxData DER-байты PFX
     * @return разобранные данные
     */
    public static PfxData parsePfx(byte[] pfxData) {
        int[] pos = new int[]{0};
        byte[][] seq = parseSequence(pfxData, pos);
        if (seq.length < 2) {
            throw new IllegalArgumentException("PFX: expected at least 2 elements");
        }

        int version = parseInteger(seq[0], new int[]{0}).intValue();
        if (version != 3) {
            throw new IllegalArgumentException("PFX: unsupported version " + version);
        }

        // ContentInfo: SEQUENCE { OID, [0] EXPLICIT content }
        byte[] authSafeCi = seq[1];
        ContentInfoData authSafeCiData = parseContentInfo(authSafeCi);

        // Raw content of AuthSafe OCTET STRING (BER-encoded AuthenticatedSafe)
        byte[] authSafeRaw = unwrapOctetString(authSafeCiData.getContent());

        // Parse the AuthenticatedSafe from the raw content
        AuthenticatedSafeData authSafe = parseAuthenticatedSafe(authSafeRaw);

        MacData macData = null;
        if (seq.length > 2) {
            macData = parseMacData(seq[2]);
        }

        return new PfxData(version, authSafe, macData, authSafeRaw);
    }

    // ========================================================================
    // AuthenticatedSafe
    // ========================================================================

    private static AuthenticatedSafeData parseAuthenticatedSafe(byte[] data) {
        int[] pos = new int[]{0};
        byte[][] contentInfos = parseSequence(data, pos);
        List<ContentInfoData> list = new ArrayList<>();
        for (byte[] ci : contentInfos) {
            list.add(parseContentInfo(ci));
        }
        return new AuthenticatedSafeData(list);
    }

    private static ContentInfoData parseContentInfo(byte[] data) {
        int[] pos = new int[]{0};
        byte[][] seq = parseSequence(data, pos);
        if (seq.length < 2) {
            throw new IllegalArgumentException("ContentInfo: expected at least 2 elements");
        }
        String oid = parseOid(seq[0], new int[]{0});
        byte[] content = unwrapContextSpecific(seq[1]);
        return new ContentInfoData(oid, content);
    }

    // ========================================================================
    // MacData
    // ========================================================================

    private static MacData parseMacData(byte[] data) {
        int[] pos = new int[]{0};
        byte[][] seq = parseSequence(data, pos);
        if (seq.length < 2) {
            throw new IllegalArgumentException("MacData: expected at least 2 elements");
        }

        // DigestInfo: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
        byte[][] di = parseSequence(seq[0], new int[]{0});
        byte[][] diAlgId = parseSequence(di[0], new int[]{0});
        String digestAlgorithm = parseOid(diAlgId[0], new int[]{0});
        byte[] digestValue = parseOctetString(di[1], new int[]{0});

        byte[] salt = parseOctetString(seq[1], new int[]{0});

        int iterations = 1;
        if (seq.length > 2) {
            iterations = parseInteger(seq[2], new int[]{0}).intValue();
        }

        return new MacData(salt, iterations, digestAlgorithm, digestValue);
    }

    // ========================================================================
    // SafeContents → safeBags
    // ========================================================================

    /**
     * Разбирает SafeContents (SEQUENCE OF SafeBag).
     */
    public static List<SafeBagData> parseSafeContents(byte[] data) {
        int[] pos = new int[]{0};
        byte[][] bags = parseSequence(data, pos);
        List<SafeBagData> result = new ArrayList<>();
        for (byte[] bag : bags) {
            result.add(parseSafeBag(bag));
        }
        return result;
    }

    private static SafeBagData parseSafeBag(byte[] data) {
        int[] pos = new int[]{0};
        byte[][] seq = parseSequence(data, pos);
        if (seq.length < 2) {
            throw new IllegalArgumentException("SafeBag: expected at least 2 elements");
        }

        String bagId = parseOid(seq[0], new int[]{0});
        byte[] bagValue = unwrapContextSpecific(seq[1]);

        List<BagAttribute> attrs = new ArrayList<>();
        if (seq.length > 2) {
            int[] ap = new int[]{0};
            byte[][] attrSet = parseSet(seq[2], ap);
            for (byte[] attr : attrSet) {
                attrs.add(parseAttribute(attr));
            }
        }

        return new SafeBagData(bagId, bagValue, attrs);
    }

    private static BagAttribute parseAttribute(byte[] data) {
        int[] pos = new int[]{0};
        byte[][] seq = parseSequence(data, pos);
        if (seq.length < 2) {
            throw new IllegalArgumentException("Attribute: expected at least 2 elements");
        }
        String attrId = parseOid(seq[0], new int[]{0});
        int[] sp = new int[]{0};
        byte[][] values = parseSet(seq[1], sp);
        return new BagAttribute(attrId, values);
    }

    // ========================================================================
    // EncryptedPrivateKeyInfo (для pkcs8ShroudedKeyBag)
    // ========================================================================

    /**
     * Разбирает EncryptedPrivateKeyInfo.
     */
    public static EncryptedPrivateKeyInfo parseEncryptedPrivateKeyInfo(byte[] data) {
        int[] pos = new int[]{0};
        byte[][] seq = parseSequence(data, pos);
        if (seq.length < 2) {
            throw new IllegalArgumentException("EncryptedPrivateKeyInfo: expected 2 elements");
        }

        // EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
        byte[][] algId = parseSequence(seq[0], new int[]{0});
        String encAlgOid = parseOid(algId[0], new int[]{0});
        byte[] encParams = null;
        if (algId.length > 1) {
            encParams = algId[1];
        }

        byte[] encryptedData = parseOctetString(seq[1], new int[]{0});
        return new EncryptedPrivateKeyInfo(encAlgOid, encParams, encryptedData);
    }

    // ========================================================================
    // PBES2-params
    // ========================================================================

    /**
     * Разбирает PBES2-params.
     */
    public static Pbes2Params parsePbes2Params(byte[] data) {
        int[] pos = new int[]{0};
        byte[][] seq = parseSequence(data, pos);
        if (seq.length < 2) {
            throw new IllegalArgumentException("PBES2-params: expected 2 elements");
        }

        // keyDerivationFunc ::= AlgorithmIdentifier (PBKDF2)
        byte[][] kdfAlgId = parseSequence(seq[0], new int[]{0});
        String kdfOid = parseOid(kdfAlgId[0], new int[]{0});
        if (!GostOids.PBKDF2.equals(kdfOid)) {
            throw new IllegalArgumentException("PBES2: expected PBKDF2, got " + kdfOid);
        }
        byte[] kdfParams = kdfAlgId.length > 1 ? kdfAlgId[1] : null;

        // encryptionScheme ::= AlgorithmIdentifier
        byte[][] encAlgId = parseSequence(seq[1], new int[]{0});
        String encOid = parseOid(encAlgId[0], new int[]{0});
        byte[] encParams = encAlgId.length > 1 ? encAlgId[1] : null;

        byte[] ukm = null;
        if (encParams != null) {
            int[] ep = new int[]{0};
            byte[][] encSeq = parseSequence(encParams, ep);
            if (encSeq.length > 0) {
                ukm = parseOctetString(encSeq[0], new int[]{0});
            }
        }

        // PBKDF2-params
        byte[] salt = null;
        int iterationCount = 0;
        String prfOid = null;

        if (kdfParams != null) {
            int[] kp = new int[]{0};
            checkTag(kdfParams, kp, 0x30);
            int kdfLen = decodeLength(kdfParams, kp);
            int end = kp[0] + kdfLen;

            // salt: всегда присутствует
            if (kp[0] < end) {
                salt = parseOctetString(kdfParams, kp);
            }
            // iterationCount: всегда присутствует
            if (kp[0] < end) {
                iterationCount = parseInteger(kdfParams, kp).intValue();
            }
            // keyLength OPTIONAL (INTEGER 0x02) или сразу prf
            if (kp[0] < end) {
                int tag = kdfParams[kp[0]] & 0xFF;
                if (tag == 0x02) {
                    parseInteger(kdfParams, kp);
                }
            }
            // prf OPTIONAL (SEQUENCE 0x30) — на [2] или [3]
            if (kp[0] < end) {
                byte[][] prfId = parseSequence(kdfParams, kp);
                prfOid = parseOid(prfId[0], new int[]{0});
            }
        }

        return new Pbes2Params(salt, iterationCount, prfOid, encOid, ukm);
    }

    // ========================================================================
    // CertBag → DER-сертификат
    // ========================================================================

    /**
     * Разбирает CertBag и возвращает DER-байты сертификата.
     */
    public static byte[] parseCertBag(byte[] data) {
        int[] pos = new int[]{0};
        byte[][] seq = parseSequence(data, pos);
        if (seq.length < 2) {
            throw new IllegalArgumentException("CertBag: expected 2 elements");
        }
        String certId = parseOid(seq[0], new int[]{0});
        if (!GostOids.PKCS9_X509_CERT.equals(certId)) {
            throw new IllegalArgumentException("CertBag: expected x509Certificate, got " + certId);
        }
        byte[] certValue = unwrapContextSpecific(seq[1]);
        return parseOctetString(certValue, new int[]{0});
    }

    // ========================================================================
    // DER traversal utilities
    // ========================================================================

    /**
     * Разбирает SEQUENCE (tag 0x30) и возвращает массив вложенных элементов.
     * Каждый элемент — полный DER-блок (tag + length + content).
     *
     * @param data массив DER-байт, начинающийся с тега SEQUENCE
     * @param pos  текущая позиция (мутабельный счётчик). После вызова
     *             {@code pos[0]} указывает на байт за SEQUENCE
     * @return массив DER-элементов содержимого SEQUENCE
     */
    public static byte[][] parseSequence(byte[] data, int[] pos) {
        return parseConstructed(data, pos, 0x30);
    }

    private static byte[][] parseSet(byte[] data, int[] pos) {
        return parseConstructed(data, pos, 0x31);
    }

    private static byte[][] parseConstructed(byte[] data, int[] pos, int expectedTag) {
        checkTag(data, pos, expectedTag);
        int contentLen = decodeLength(data, pos);
        int end = pos[0] + contentLen;
        List<byte[]> elements = new ArrayList<>();
        while (pos[0] < end) {
            int elemStart = pos[0];
            int tag = data[pos[0]] & 0xFF;
            int[] lenInfo = peekLength(data, pos[0] + 1);
            int totalLen = 1 + lenInfo[1] + lenInfo[0];
            byte[] elem = Arrays.copyOfRange(data, elemStart, elemStart + totalLen);
            elements.add(elem);
            pos[0] = elemStart + totalLen;
        }
        return elements.toArray(new byte[0][]);
    }

    private static BigInteger parseInteger(byte[] data, int[] pos) {
        checkTag(data, pos, 0x02);
        int len = decodeLength(data, pos);
        byte[] bytes = Arrays.copyOfRange(data, pos[0], pos[0] + len);
        pos[0] += len;
        return new BigInteger(bytes);
    }

    /**
     * Разбирает OBJECT IDENTIFIER (tag 0x06) в строку вида {@code "1.2.643.7.1.1.5.2.1"}.
     *
     * @param data массив DER-байт, начинающийся с тега OID
     * @param pos  текущая позиция (мутабельный счётчик). После вызова
     *             {@code pos[0]} указывает на байт за OID
     * @return строковое представление OID
     */
    public static String parseOid(byte[] data, int[] pos) {
        checkTag(data, pos, 0x06);
        int len = decodeLength(data, pos);
        int start = pos[0];
        int end = start + len;

        StringBuilder sb = new StringBuilder();
        int first = data[start] & 0xFF;
        sb.append(first / 40).append('.').append(first % 40);

        long value = 0;
        for (int i = start + 1; i < end; i++) {
            int b = data[i] & 0xFF;
            value = (value << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                sb.append('.').append(value);
                value = 0;
            }
        }
        pos[0] = end;
        return sb.toString();
    }

    private static byte[] parseOctetString(byte[] data, int[] pos) {
        checkTag(data, pos, 0x04);
        int len = decodeLength(data, pos);
        byte[] result = Arrays.copyOfRange(data, pos[0], pos[0] + len);
        pos[0] += len;
        return result;
    }

    /**
     * Раскрывает [0] EXPLICIT (tag 0xA0): возвращает содержимое.
     */
    private static byte[] unwrapContextSpecific(byte[] data) {
        int[] pos = new int[]{0};
        if ((data[pos[0]] & 0xFF) != 0xA0) {
            throw new IllegalArgumentException("Expected [0] EXPLICIT (tag 0xA0)");
        }
        pos[0]++; // skip tag
        int len = decodeLength(data, pos);
        // Tag 0xA0 is constructed mode — return the inner content as-is
        return Arrays.copyOfRange(data, pos[0], pos[0] + len);
    }

    /**
     * Извлекает содержимое OCTET STRING (tag 0x04), отбрасывая tag и length.
     *
     * @param data массив DER-байт, начинающийся с тега OCTET STRING
     * @return содержимое OCTET STRING (без tag и length)
     */
    public static byte[] unwrapOctetString(byte[] data) {
        int[] pos = new int[]{0};
        checkTag(data, pos, 0x04);
        int len = decodeLength(data, pos);
        byte[] result = Arrays.copyOfRange(data, pos[0], pos[0] + len);
        pos[0] += len;
        return result;
    }

    /**
     * Извлекает localKeyId из атрибутов SafeBag.
     * localKeyId — OCTET STRING (RFC 7292 §B.3) для связывания ключа с сертификатом.
     *
     * @param attrs список атрибутов SafeBag (null-safe)
     * @return содержимое localKeyId или null, если атрибут не найден или повреждён
     */
    public static byte[] findLocalKeyId(List<BagAttribute> attrs) {
        if (attrs == null) return null;
        for (BagAttribute attr : attrs) {
            if (GostOids.ATTR_LOCAL_KEY_ID.equals(attr.getAttrId())) {
                byte[][] values = attr.getAttrValues();
                if (values == null || values.length == 0) return null;
                try {
                    return unwrapOctetString(values[0]);
                } catch (Exception e) {
                    return null;
                }
            }
        }
        return null;
    }

    private static int[] peekLength(byte[] data, int offset) {
        int first = data[offset] & 0xFF;
        if (first <= 0x7F) return new int[]{first, 1};
        if (first == 0x81) return new int[]{data[offset + 1] & 0xFF, 2};
        if (first == 0x82) {
            int len = ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
            return new int[]{len, 3};
        }
        throw new IllegalArgumentException("Unsupported DER length encoding: 0x" + Integer.toHexString(first));
    }

    private static int decodeLength(byte[] data, int[] pos) {
        int first = data[pos[0]] & 0xFF;
        pos[0]++;
        if (first <= 0x7F) return first;
        if (first == 0x81) return data[pos[0]++] & 0xFF;
        if (first == 0x82) {
            int len = ((data[pos[0]] & 0xFF) << 8) | (data[pos[0] + 1] & 0xFF);
            pos[0] += 2;
            return len;
        }
        throw new IllegalArgumentException("Unsupported DER length encoding: 0x" + Integer.toHexString(first));
    }

    private static void checkTag(byte[] data, int[] pos, int expectedTag) {
        int tag = data[pos[0]] & 0xFF;
        if (tag != expectedTag) {
            throw new IllegalArgumentException(
                "Expected tag 0x" + Integer.toHexString(expectedTag)
                + " at offset " + pos[0] + ", got 0x" + Integer.toHexString(tag));
        }
        pos[0]++; // consume tag
    }
}
