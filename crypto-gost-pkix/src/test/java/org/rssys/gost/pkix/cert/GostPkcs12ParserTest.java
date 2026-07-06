package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.pkix.cert.PkixCertTestHelper.hex;
import static org.rssys.gost.util.DerCodec.*;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.kdf.Pbkdf2Streebog;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostPkcs12Parser.*;

/**
 * Тесты разбора синтетического PFX-контейнера (RFC 7292).
 * <p>
 * DER-построение — через {@link org.rssys.gost.util.DerCodec}.
 */
@DisplayName("GostPkcs12Parser — разбор синтетического PFX")
class GostPkcs12ParserTest {

    private static final byte[] FAKE_CERT_DER =
            hex(
                    "30 82 01 01 02 01 01 30 0A 06 08 2A 85 03 07 01 02 01 01 30 0C 06 08 "
                            + "2A 85 03 07 01 02 01 02 04 00 30 0C 06 08 2A 85 03 07 01 02 01 03 04 "
                            + "00 02 01 00");

    private static byte[] ctx0(byte[] content) {
        return encodeTlv(0xA0, content);
    }

    /** DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING } */
    private static byte[] buildDigestInfo(String digestOid, byte[] digestValue) {
        return encodeSequence(encodeSequence(encodeOid(digestOid)), encodeOctetString(digestValue));
    }

    /** MacData ::= SEQUENCE { DigestInfo, OCTET STRING salt, INTEGER OPTIONAL } */
    private static byte[] buildMacData(
            byte[] salt, int iterations, String digestOid, byte[] digestValue) {
        byte[] macData =
                encodeSequence(
                        buildDigestInfo(digestOid, digestValue),
                        encodeOctetString(salt),
                        encodeInteger(iterations));
        return macData;
    }

    /** EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING } */
    private static byte[] buildEncryptedPrivateKeyInfo(
            String encAlgOid, byte[] encParams, byte[] encryptedData) {
        return encodeSequence(
                encodeSequence(encodeOid(encAlgOid), encParams), encodeOctetString(encryptedData));
    }

    /** PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme } */
    private static byte[] buildPbes2Params(
            byte[] salt, int iterationCount, byte[] ukm, String prfOid, String encOid) {
        byte[] prfAlgId = encodeSequence(encodeOid(prfOid));
        byte[] encParams = encodeSequence(encodeOctetString(ukm));
        byte[] encAlgId = encodeSequence(encodeOid(encOid), encParams);

        byte[] kdfAlgId =
                encodeSequence(
                        encodeOid(GostOids.PBKDF2),
                        encodeSequence(
                                encodeOctetString(salt), encodeInteger(iterationCount), prfAlgId));
        return encodeSequence(kdfAlgId, encAlgId);
    }

    /** CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING } */
    private static byte[] buildCertBag(String certOid, byte[] certDer) {
        return encodeSequence(encodeOid(certOid), ctx0(encodeOctetString(certDer)));
    }

    /** SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT, attributes SET OPTIONAL } */
    private static byte[] buildSafeBag(String bagId, byte[] bagValue) {
        return encodeSequence(encodeOid(bagId), ctx0(bagValue));
    }

    /** SafeBag с аттрибутами (SET of SEQUENCE). */
    private static byte[] buildSafeBagWithAttrs(String bagId, byte[] bagValue, byte[]... attrs) {
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
        all[2] = encodeSet(attrContent);
        return encodeSequence(all);
    }

    /** SafeContents ::= SEQUENCE OF SafeBag */
    private static byte[] buildSafeContents(byte[]... bags) {
        if (bags.length == 0) return encodeSequence();
        return encodeSequence(bags);
    }

    /** ContentInfo (pkcs7-data) ::= SEQUENCE { OID, [0] EXPLICIT OCTET STRING } */
    private static byte[] buildDataContentInfo(byte[] contentOctets) {
        return encodeSequence(
                encodeOid(GostOids.PKCS7_DATA), ctx0(encodeOctetString(contentOctets)));
    }

    /** AuthenticatedSafe ::= SEQUENCE OF ContentInfo */
    private static byte[] buildAuthSafe(byte[]... contentInfos) {
        return encodeSequence(contentInfos);
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
            return encodeSequence(encodeInteger(3), outerCi, macData);
        }
        return encodeSequence(encodeInteger(3), outerCi);
    }

    // ========================================================================
    // Тесты
    // ========================================================================

    @Test
    @DisplayName("parsePfx: версия, AuthSafe, MacData")
    void testParsePfx() {
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] digestVal = hex("AA BB CC DD");
        byte[] macData = buildMacData(salt, 100, GostOids.HMAC_STREEBOG_512, digestVal);

        byte[] pfx = buildFullPfx(encodeSequence(), macData);

        PfxData result = GostPkcs12Parser.parsePfx(pfx, 50);

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
        byte[] pfx = buildFullPfx(encodeSequence(), null);

        PfxData result = GostPkcs12Parser.parsePfx(pfx);
        assertEquals(3, result.getVersion());
        assertNull(result.getMacData());
    }

    @Test
    @DisplayName("parsePfx: неверная версия -> IllegalArgumentException")
    void testParsePfxWrongVersion() {
        byte[] pfx =
                encodeSequence(
                        encodeInteger(2),
                        encodeSequence(
                                encodeOid(GostOids.PKCS7_DATA),
                                ctx0(encodeOctetString(new byte[1]))));
        assertThrows(IllegalArgumentException.class, () -> GostPkcs12Parser.parsePfx(pfx));
    }

    @Test
    @DisplayName("parseMacData: без поля iterations -> default 1 ниже MIN_PBKDF2_ITERATIONS_PFX")
    void testParseMacDataNoIterations() {
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] digestVal = hex("11 22 33 44");
        // MacData без iterations: SEQUENCE { DigestInfo, OCTET STRING salt }
        byte[] macData =
                encodeSequence(
                        buildDigestInfo(GostOids.HMAC_STREEBOG_512, digestVal),
                        encodeOctetString(salt));

        byte[] pfx = buildFullPfx(encodeSequence(), macData);
        IllegalArgumentException ex =
                assertThrows(IllegalArgumentException.class, () -> GostPkcs12Parser.parsePfx(pfx));
        assertTrue(ex.getMessage().contains("MacData iterations too low"));
    }

    @Test
    @DisplayName("разбор SafeContents: pkcs8ShroudedKeyBag + certBag")
    void testParseSafeContents() {
        byte[] ukm = new byte[16];
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] encData = hex("AB CD EF");

        byte[] pbes2Params =
                buildPbes2Params(
                        salt, 1000, ukm, GostOids.HMAC_STREEBOG_512, GostOids.KUZ_CTR_ACPKM_OMAC);
        byte[] epki = buildEncryptedPrivateKeyInfo(GostOids.PBES2, pbes2Params, encData);

        byte[] keyBag = buildSafeBag(GostOids.BAG_PKCS8_SHROUDED_KEY, epki);
        byte[] certBag =
                buildSafeBag(
                        GostOids.BAG_CERT, buildCertBag(GostOids.PKCS9_X509_CERT, FAKE_CERT_DER));

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
        byte[] empty = encodeSequence(); // SEQUENCE {}
        List<SafeBagData> bags = GostPkcs12Parser.parseSafeContents(empty);
        assertTrue(bags.isEmpty());
    }

    @Test
    @DisplayName("разбор EncryptedPrivateKeyInfo: PBES2, OID, encryptedData")
    void testParseEncryptedPrivateKeyInfo() {
        byte[] ukm = new byte[16];
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] encData = hex("AB CD EF 01 02");
        byte[] pbes2Params =
                buildPbes2Params(
                        salt, 1000, ukm, GostOids.HMAC_STREEBOG_512, GostOids.KUZ_CTR_ACPKM_OMAC);
        byte[] epkiDer = buildEncryptedPrivateKeyInfo(GostOids.PBES2, pbes2Params, encData);

        EncryptedPrivateKeyInfo epki = GostPkcs12Parser.parseEncryptedPrivateKeyInfo(epkiDer);
        assertEquals(GostOids.PBES2, epki.getEncryptionAlgorithmOid());
        assertArrayEquals(encData, epki.getEncryptedData());
        assertNotNull(epki.getEncryptionParams());
    }

    @Test
    @DisplayName("parsePbes2Params: с keyLength и без")
    void testParsePbes2Params() {
        byte[] ukm = new byte[16];
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] pbes2Params =
                buildPbes2Params(
                        salt, 2000, ukm, GostOids.HMAC_STREEBOG_512, GostOids.KUZ_CTR_ACPKM_OMAC);

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
        // PBKDF2-params: SEQUENCE { salt OCTET STRING, iterationCount INTEGER, prf
        // AlgorithmIdentifier }
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] prfAlgId = encodeSequence(encodeOid(GostOids.HMAC_STREEBOG_256));
        byte[] kdfParams = encodeSequence(encodeOctetString(salt), encodeInteger(4096), prfAlgId);
        byte[] kdfAlgId = encodeSequence(encodeOid(GostOids.PBKDF2), kdfParams);

        byte[] encParams = encodeSequence(encodeOctetString(new byte[16]));
        byte[] encAlgId = encodeSequence(encodeOid(GostOids.KUZ_CTR_ACPKM), encParams);
        byte[] pbes2Params = encodeSequence(kdfAlgId, encAlgId);

        Pbes2Params params = GostPkcs12Parser.parsePbes2Params(pbes2Params);
        assertEquals(4096, params.getIterationCount());
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
        assertThrows(IllegalArgumentException.class, () -> GostPkcs12Parser.parseCertBag(certBag));
    }

    @Test
    @DisplayName("parsePfx: truncated data -> исключение")
    void testParsePfxTruncated() {
        byte[] pfx = buildFullPfx(encodeOctetString(new byte[1]), null);
        // Обрезаем в середине
        byte[] truncated = new byte[pfx.length / 2];
        System.arraycopy(pfx, 0, truncated, 0, truncated.length);
        assertThrows(Exception.class, () -> GostPkcs12Parser.parsePfx(truncated));
    }

    @Test
    @DisplayName("parsePfx: неверный тег на верхнем уровне -> IllegalArgumentException")
    void testParsePfxWrongTag() {
        // Вместо SEQUENCE (0x30) используем SET (0x31)
        byte[] badPfx = encodeTlv(0x31, encodeInteger(3));
        assertThrows(IllegalArgumentException.class, () -> GostPkcs12Parser.parsePfx(badPfx));
    }

    @Test
    @DisplayName(
            "parsePbes2Params: iterationCount превышает MAX_ITERATIONS -> IllegalArgumentException")
    void testParsePbes2ParamsIterationExceedsMax() {
        byte[] ukm = new byte[16];
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] pbes2Params =
                buildPbes2Params(
                        salt,
                        Pbkdf2Streebog.MAX_ITERATIONS + 1,
                        ukm,
                        GostOids.HMAC_STREEBOG_512,
                        GostOids.KUZ_CTR_ACPKM_OMAC);
        IllegalArgumentException ex =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> GostPkcs12Parser.parsePbes2Params(pbes2Params));
        assertTrue(ex.getMessage().contains("PBES2 iterationCount exceeds maximum"));
    }

    @Test
    @DisplayName("MacData iterations превышает MAX_ITERATIONS -> IllegalArgumentException")
    void testMacDataIterationsExceedsMax() {
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] digestVal = hex("11 22 33 44");
        byte[] macDataDer =
                buildMacData(
                        salt,
                        Pbkdf2Streebog.MAX_ITERATIONS + 1,
                        GostOids.HMAC_STREEBOG_512,
                        digestVal);
        byte[] pfx = buildFullPfx(encodeSequence(), macDataDer);
        IllegalArgumentException ex =
                assertThrows(IllegalArgumentException.class, () -> GostPkcs12Parser.parsePfx(pfx));
        assertTrue(ex.getMessage().contains("MacData iterations exceeds maximum"));
    }

    @Test
    @DisplayName(
            "MacData iterations больше Integer.MAX_VALUE, младшие 32 бита в допустимом диапазоне"
                    + " -> отвергается по BigInteger, без молчаливого усечения")
    void testMacDataIterationsBigIntegerTruncationRejected() {
        // 0x1_0000_03E8 усекается intValue() до 1000 (в диапазоне), но реальное значение огромно.
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] digestVal = hex("11 22 33 44");
        byte[] macDataDer =
                encodeSequence(
                        buildDigestInfo(GostOids.HMAC_STREEBOG_512, digestVal),
                        encodeOctetString(salt),
                        encodeInteger(new java.math.BigInteger("1000003E8", 16)));
        byte[] pfx = buildFullPfx(encodeSequence(), macDataDer);
        IllegalArgumentException ex =
                assertThrows(IllegalArgumentException.class, () -> GostPkcs12Parser.parsePfx(pfx));
        assertTrue(
                ex.getMessage().contains("MacData iterations exceeds maximum"),
                "должно отвергаться как превышение максимума, а не проходить как усечённое 1000: "
                        + ex.getMessage());
    }

    @Test
    @DisplayName(
            "parsePbes2Params iterationCount больше Integer.MAX_VALUE, младшие 32 бита в диапазоне"
                    + " -> отвергается по BigInteger, без молчаливого усечения")
    void testParsePbes2ParamsBigIntegerTruncationRejected() {
        byte[] ukm = new byte[16];
        byte[] salt = hex("01 02 03 04 05 06 07 08");
        byte[] prfAlgId = encodeSequence(encodeOid(GostOids.HMAC_STREEBOG_512));
        byte[] encParams = encodeSequence(encodeOctetString(ukm));
        byte[] encAlgId = encodeSequence(encodeOid(GostOids.KUZ_CTR_ACPKM_OMAC), encParams);
        byte[] kdfAlgId =
                encodeSequence(
                        encodeOid(GostOids.PBKDF2),
                        encodeSequence(
                                encodeOctetString(salt),
                                encodeInteger(new java.math.BigInteger("1000003E8", 16)),
                                prfAlgId));
        byte[] pbes2Params = encodeSequence(kdfAlgId, encAlgId);
        IllegalArgumentException ex =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> GostPkcs12Parser.parsePbes2Params(pbes2Params));
        assertTrue(
                ex.getMessage().contains("PBES2 iterationCount exceeds maximum"),
                "должно отвергаться как превышение максимума, а не проходить как усечённое 1000: "
                        + ex.getMessage());
    }

    // ========================================================================
    // findLocalKeyId
    // ========================================================================

    @Test
    @DisplayName("поиск локального идентификатора ключа: null -> null")
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
        byte[] keyId = new byte[] {0x01, 0x02, 0x03, 0x04};
        BagAttribute attr =
                new BagAttribute(
                        GostOids.ATTR_LOCAL_KEY_ID, new byte[][] {encodeOctetString(keyId)});
        assertArrayEquals(keyId, GostPkcs12Parser.findLocalKeyId(List.of(attr)));
    }

    @Test
    @DisplayName("findLocalKeyId: повреждённый DER -> null (без исключения)")
    void testFindLocalKeyIdCorruptedDer() {
        BagAttribute attr =
                new BagAttribute(
                        GostOids.ATTR_LOCAL_KEY_ID,
                        new byte[][] {new byte[] {0x04, (byte) 0xFF, 0x01, 0x02}});
        assertNull(GostPkcs12Parser.findLocalKeyId(List.of(attr)));
    }

    @Test
    @DisplayName("findLocalKeyId: другой OID -> null")
    void testFindLocalKeyIdWrongOid() {
        BagAttribute attr =
                new BagAttribute("1.2.3.4", new byte[][] {encodeOctetString(new byte[] {0x01})});
        assertNull(GostPkcs12Parser.findLocalKeyId(List.of(attr)));
    }
}
