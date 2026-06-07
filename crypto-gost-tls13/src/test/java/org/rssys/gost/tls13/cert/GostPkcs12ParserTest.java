package org.rssys.gost.tls13.cert;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.GostOids;
import org.rssys.gost.tls13.cert.GostPkcs12Parser.*;

import java.io.ByteArrayOutputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.tls13.TlsTestHelper.*;

/**
 * Тесты разбора синтетического PFX-контейнера (RFC 7292).
 * <p>
 * DER-построение — через {@link org.rssys.gost.tls13.TlsTestHelper}.
 */
@DisplayName("GostPkcs12Parser — разбор синтетического PFX")
class GostPkcs12ParserTest {

    private static final byte[] FAKE_CERT_DER = hex(
            "30 82 01 01 02 01 01 30 0A 06 08 2A 85 03 07 01 02 01 01 30 0C 06 08 " +
            "2A 85 03 07 01 02 01 02 04 00 30 0C 06 08 2A 85 03 07 01 02 01 03 04 " +
            "00 02 01 00");

    // ========================================================================
    // Помощники DER
    // ========================================================================

    private static byte[] derInteger(int value) {
        byte[] bytes;
        if (value == 0) {
            bytes = new byte[]{0};
        } else {
            int bits = 32 - Integer.numberOfLeadingZeros(value);
            int byteLen = Math.max(1, (bits + 7) / 8);
            bytes = new byte[byteLen];
            for (int i = byteLen - 1; i >= 0; i--) {
                bytes[i] = (byte) (value & 0xFF);
                value >>>= 8;
            }
        }
        return derTlv(0x02, bytes);
    }

    /** Корректный DER-кодер OID (в отличие от TlsTestHelper.derOid, который не поддерживает > 2 байт). */
    private static byte[] encodeOid(String oidStr) {
        String[] parts = oidStr.split("\\.");
        int[] arcs = new int[parts.length];
        for (int i = 0; i < parts.length; i++) arcs[i] = Integer.parseInt(parts[i]);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(40 * arcs[0] + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            long v = arcs[i] & 0xFFFFFFFFL;
            int bits = 64 - Long.numberOfLeadingZeros(v);
            int groups = Math.max(1, (bits + 6) / 7);
            for (int g = groups - 1; g >= 0; g--) {
                int shift = g * 7;
                int b = (int) ((v >>> shift) & 0x7F);
                if (g > 0) b |= 0x80;
                body.write(b);
            }
        }
        return derTlv(0x06, body.toByteArray());
    }
    private static byte[] ctx0(byte[] content) {
        return derTlv(0xA0, content);
    }

    /** DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING } */
    private static byte[] buildDigestInfo(String digestOid, byte[] digestValue) {
        return derSequence(
                derSequence(encodeOid(digestOid)),
                derOctetString(digestValue));
    }

    /** MacData ::= SEQUENCE { DigestInfo, OCTET STRING salt, INTEGER OPTIONAL } */
    private static byte[] buildMacData(byte[] salt, int iterations,
                                        String digestOid, byte[] digestValue) {
        byte[] macData = derSequence(
                buildDigestInfo(digestOid, digestValue),
                derOctetString(salt),
                derInteger(iterations));
        return macData;
    }

    /** EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING } */
    private static byte[] buildEncryptedPrivateKeyInfo(
            String encAlgOid, byte[] encParams, byte[] encryptedData) {
        return derSequence(
                derSequence(encodeOid(encAlgOid), encParams),
                derOctetString(encryptedData));
    }

    /** PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme } */
    private static byte[] buildPbes2Params(
            byte[] salt, int iterationCount, byte[] ukm,
            String prfOid, String encOid) {
        byte[] prfAlgId = derSequence(encodeOid(prfOid));
        byte[] encParams = derSequence(derOctetString(ukm));
        byte[] encAlgId = derSequence(encodeOid(encOid), encParams);

        byte[] kdfAlgId = derSequence(
                encodeOid(GostOids.PBKDF2),
                derSequence(
                        derOctetString(salt),
                        derInteger(iterationCount),
                        prfAlgId));
        return derSequence(kdfAlgId, encAlgId);
    }

    /** CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING } */
    private static byte[] buildCertBag(String certOid, byte[] certDer) {
        return derSequence(
                encodeOid(certOid),
                ctx0(derOctetString(certDer)));
    }

    /** SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT, attributes SET OPTIONAL } */
    private static byte[] buildSafeBag(String bagId, byte[] bagValue) {
        return derSequence(encodeOid(bagId), ctx0(bagValue));
    }

    /** SafeBag с аттрибутами (SET of SEQUENCE). */
    private static byte[] buildSafeBagWithAttrs(String bagId, byte[] bagValue,
                                                  byte[]... attrs) {
        byte[][] all = new byte[3 + attrs.length][];
        all[0] = encodeOid(bagId);
        all[1] = ctx0(bagValue);
        byte[] attrContent = new byte[0];
        for (byte[] attr : attrs) {
            byte[] tmp = new byte[attrContent.length + attr.length];
            System.arraycopy(attrContent, 0, tmp, 0, attrContent.length);
            System.arraycopy(attr, 0, tmp, attrContent.length, attr.length);
            attrContent = tmp;
        }
        all[2] = Set(attrContent);
        return derSequence(all);
    }

    /** SafeContents ::= SEQUENCE OF SafeBag */
    private static byte[] buildSafeContents(byte[]... bags) {
        if (bags.length == 0) return derSequence();
        return derSequence(bags);
    }

    /** ContentInfo (pkcs7-data) ::= SEQUENCE { OID, [0] EXPLICIT OCTET STRING } */
    private static byte[] buildDataContentInfo(byte[] contentOctets) {
        return derSequence(
                encodeOid(GostOids.PKCS7_DATA),
                ctx0(derOctetString(contentOctets)));
    }

    /** AuthenticatedSafe ::= SEQUENCE OF ContentInfo */
    private static byte[] buildAuthSafe(byte[]... contentInfos) {
        return derSequence(contentInfos);
    }

    /**
     * Собирает полный PFX из SafeContents.
     * Структура: PFX -> ContentInfo(pkcs7-data) -> [0] { OCTET STRING {
     *   AuthenticatedSafe (SEQUENCE) -> ContentInfo(pkcs7-data) -> [0] { OCTET STRING {
     *     SafeContents }}}}
     */
    private static byte[] buildFullPfx(byte[] safeContents, byte[] macData) {
        byte[] innerCi = buildDataContentInfo(safeContents);
        byte[] authSafe = buildAuthSafe(innerCi);
        byte[] outerCi = buildDataContentInfo(authSafe);
        if (macData != null) {
            return derSequence(derInteger(3), outerCi, macData);
        }
        return derSequence(derInteger(3), outerCi);
    }

    // ========================================================================
    // Тесты
    // ========================================================================

    @Test
    @DisplayName("parsePfx: версия, AuthSafe, MacData")
    void testParsePfx() {
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] digestVal = hex("AA BB CC DD");
        byte[] macData = buildMacData(salt, 100,
                GostOids.HMAC_STREEBOG_512, digestVal);

        byte[] pfx = buildFullPfx(derSequence(), macData);

        PfxData result = GostPkcs12Parser.parsePfx(pfx);

        assertEquals(3, result.getVersion());
        assertNotNull(result.getMacData());
        assertNotNull(result.getAuthSafeRawContent());

        MacData md = result.getMacData();
        assertEquals(100, md.getIterations());
        assertArrayEquals(salt, md.getSalt());
        assertEquals(GostOids.HMAC_STREEBOG_512, md.getDigestAlgorithm());
        assertArrayEquals(digestVal, md.getDigestValue());

        List<ContentInfoData> cis = result.getAuthSafe().getContentInfos();
        assertEquals(1, cis.size());
        assertEquals(GostOids.PKCS7_DATA, cis.get(0).getContentType());
    }

    @Test
    @DisplayName("parsePfx: без MacData -> macData == null")
    void testParsePfxNoMac() {
        byte[] pfx = buildFullPfx(derSequence(), null);

        PfxData result = GostPkcs12Parser.parsePfx(pfx);
        assertEquals(3, result.getVersion());
        assertNull(result.getMacData());
    }

    @Test
    @DisplayName("parsePfx: неверная версия -> IllegalArgumentException")
    void testParsePfxWrongVersion() {
        byte[] pfx = derSequence(derInteger(2), derSequence(encodeOid(GostOids.PKCS7_DATA), ctx0(derOctetString(new byte[1]))));
        assertThrows(IllegalArgumentException.class,
                () -> GostPkcs12Parser.parsePfx(pfx));
    }

    @Test
    @DisplayName("parseMacData: без поля iterations -> default 1")
    void testParseMacDataNoIterations() {
        byte[] salt = hex("01 02 03 04");
        byte[] digestVal = hex("11 22 33 44");
        // MacData без iterations: SEQUENCE { DigestInfo, OCTET STRING salt }
        byte[] macData = derSequence(
                buildDigestInfo(GostOids.HMAC_STREEBOG_512, digestVal),
                derOctetString(salt));

        byte[] pfx = buildFullPfx(derSequence(), macData);
        PfxData result = GostPkcs12Parser.parsePfx(pfx);
        assertNotNull(result.getMacData());
        assertEquals(1, result.getMacData().getIterations());
    }

    @Test
    @DisplayName("parseSafeContents: pkcs8ShroudedKeyBag + certBag")
    void testParseSafeContents() {
        byte[] ukm = new byte[16];
        byte[] salt = hex("01 02 03 04");
        byte[] encData = hex("AB CD EF");

        byte[] pbes2Params = buildPbes2Params(salt, 1000, ukm,
                GostOids.HMAC_STREEBOG_512, GostOids.KUZ_CTR_ACPKM_OMAC);
        byte[] epki = buildEncryptedPrivateKeyInfo(
                GostOids.PBES2, pbes2Params, encData);

        byte[] keyBag = buildSafeBag(GostOids.BAG_PKCS8_SHROUDED_KEY, epki);
        byte[] certBag = buildSafeBag(GostOids.BAG_CERT,
                buildCertBag(GostOids.PKCS9_X509_CERT, FAKE_CERT_DER));

        byte[] safeContents = buildSafeContents(keyBag, certBag);
        byte[] pfx = buildFullPfx(safeContents, null);

        PfxData result = GostPkcs12Parser.parsePfx(pfx);

        // Достаём SafeContents из разобранных данных
        List<ContentInfoData> cis = result.getAuthSafe().getContentInfos();
        assertEquals(1, cis.size());

        byte[] innerCts = GostPkcs12Parser.unwrapOctetString(cis.get(0).getContent());
        List<SafeBagData> bags = GostPkcs12Parser.parseSafeContents(innerCts);
        assertEquals(2, bags.size());

        assertEquals(GostOids.BAG_PKCS8_SHROUDED_KEY, bags.get(0).getBagId());
        assertEquals(GostOids.BAG_CERT, bags.get(1).getBagId());
    }

    @Test
    @DisplayName("parseSafeContents: пустой SEQUENCE {} -> пустой список")
    void testParseSafeContentsEmpty() {
        byte[] empty = derSequence(); // SEQUENCE {}
        List<SafeBagData> bags = GostPkcs12Parser.parseSafeContents(empty);
        assertTrue(bags.isEmpty());
    }

    @Test
    @DisplayName("parseEncryptedPrivateKeyInfo: PBES2, OID, encryptedData")
    void testParseEncryptedPrivateKeyInfo() {
        byte[] ukm = new byte[16];
        byte[] salt = hex("01 02 03 04");
        byte[] encData = hex("AB CD EF 01 02");
        byte[] pbes2Params = buildPbes2Params(salt, 1000, ukm,
                GostOids.HMAC_STREEBOG_512, GostOids.KUZ_CTR_ACPKM_OMAC);
        byte[] epkiDer = buildEncryptedPrivateKeyInfo(
                GostOids.PBES2, pbes2Params, encData);

        EncryptedPrivateKeyInfo epki =
                GostPkcs12Parser.parseEncryptedPrivateKeyInfo(epkiDer);
        assertEquals(GostOids.PBES2, epki.getEncryptionAlgorithmOid());
        assertArrayEquals(encData, epki.getEncryptedData());
        assertNotNull(epki.getEncryptionParams());
    }

    @Test
    @DisplayName("parsePbes2Params: с keyLength и без")
    void testParsePbes2Params() {
        byte[] ukm = new byte[16];
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] pbes2Params = buildPbes2Params(salt, 2000, ukm,
                GostOids.HMAC_STREEBOG_512, GostOids.KUZ_CTR_ACPKM_OMAC);

        Pbes2Params params = GostPkcs12Parser.parsePbes2Params(pbes2Params);
        assertArrayEquals(salt, params.getSalt());
        assertEquals(2000, params.getIterationCount());
        assertEquals(GostOids.HMAC_STREEBOG_512, params.getPrfOid());
        assertEquals(GostOids.KUZ_CTR_ACPKM_OMAC, params.getEncryptionSchemeOid());
        assertArrayEquals(ukm, params.getUkm());
    }

    @Test
    @DisplayName("parsePbes2Params: keyLength отсутствует -> prfOid корректен")
    void testParsePbes2ParamsNoKeyLength() {
        // PBKDF2-params: SEQUENCE { salt OCTET STRING, iterationCount INTEGER, prf AlgorithmIdentifier }
        byte[] salt = hex("01 02 03 04");
        byte[] prfAlgId = derSequence(encodeOid(GostOids.HMAC_STREEBOG_256));
        byte[] kdfParams = derSequence(derOctetString(salt), derInteger(500), prfAlgId);
        byte[] kdfAlgId = derSequence(encodeOid(GostOids.PBKDF2), kdfParams);

        byte[] encParams = derSequence(derOctetString(new byte[16]));
        byte[] encAlgId = derSequence(encodeOid(GostOids.KUZ_CTR_ACPKM), encParams);
        byte[] pbes2Params = derSequence(kdfAlgId, encAlgId);

        Pbes2Params params = GostPkcs12Parser.parsePbes2Params(pbes2Params);
        assertEquals(500, params.getIterationCount());
        assertArrayEquals(salt, params.getSalt());
        assertEquals(GostOids.HMAC_STREEBOG_256, params.getPrfOid());
        assertEquals(GostOids.KUZ_CTR_ACPKM, params.getEncryptionSchemeOid());
    }

    @Test
    @DisplayName("parseCertBag: корректный OID -> возвращает DER сертификата")
    void testParseCertBagValid() {
        byte[] certBag = buildCertBag(GostOids.PKCS9_X509_CERT, FAKE_CERT_DER);
        byte[] result = GostPkcs12Parser.parseCertBag(certBag);
        assertArrayEquals(FAKE_CERT_DER, result);
    }

    @Test
    @DisplayName("parseCertBag: неверный OID -> IllegalArgumentException")
    void testParseCertBagWrongOid() {
        byte[] certBag = buildCertBag("1.2.3.4", FAKE_CERT_DER);
        assertThrows(IllegalArgumentException.class,
                () -> GostPkcs12Parser.parseCertBag(certBag));
    }

    @Test
    @DisplayName("parsePfx: truncated data -> исключение")
    void testParsePfxTruncated() {
        byte[] pfx = buildFullPfx(derOctetString(new byte[1]), null);
        // Обрезаем в середине
        byte[] truncated = new byte[pfx.length / 2];
        System.arraycopy(pfx, 0, truncated, 0, truncated.length);
        assertThrows(Exception.class,
                () -> GostPkcs12Parser.parsePfx(truncated));
    }

    @Test
    @DisplayName("parsePfx: неверный тег на верхнем уровне -> IllegalArgumentException")
    void testParsePfxWrongTag() {
        // Вместо SEQUENCE (0x30) используем SET (0x31)
        byte[] badPfx = derTlv(0x31, derInteger(3));
        assertThrows(IllegalArgumentException.class,
                () -> GostPkcs12Parser.parsePfx(badPfx));
    }

    // ========================================================================
    // findLocalKeyId
    // ========================================================================

    @Test
    @DisplayName("findLocalKeyId: null -> null")
    void testFindLocalKeyIdNull() {
        assertNull(GostPkcs12Parser.findLocalKeyId(null));
    }

    @Test
    @DisplayName("findLocalKeyId: пустой список -> null")
    void testFindLocalKeyIdEmpty() {
        assertNull(GostPkcs12Parser.findLocalKeyId(List.of()));
    }

    @Test
    @DisplayName("findLocalKeyId: совпадающий ATTR_LOCAL_KEY_ID -> содержимое OCTET STRING")
    void testFindLocalKeyIdMatch() {
        byte[] keyId = new byte[]{0x01, 0x02, 0x03, 0x04};
        BagAttribute attr = new BagAttribute(
            GostOids.ATTR_LOCAL_KEY_ID,
            new byte[][]{derOctetString(keyId)});
        assertArrayEquals(keyId,
            GostPkcs12Parser.findLocalKeyId(List.of(attr)));
    }

    @Test
    @DisplayName("findLocalKeyId: повреждённый DER -> null (без исключения)")
    void testFindLocalKeyIdCorruptedDer() {
        BagAttribute attr = new BagAttribute(
            GostOids.ATTR_LOCAL_KEY_ID,
            new byte[][]{new byte[]{0x04, (byte) 0xFF, 0x01, 0x02}});
        assertNull(GostPkcs12Parser.findLocalKeyId(List.of(attr)));
    }

    @Test
    @DisplayName("findLocalKeyId: другой OID -> null")
    void testFindLocalKeyIdWrongOid() {
        BagAttribute attr = new BagAttribute("1.2.3.4",
            new byte[][]{derOctetString(new byte[]{0x01})});
        assertNull(GostPkcs12Parser.findLocalKeyId(List.of(attr)));
    }
}
