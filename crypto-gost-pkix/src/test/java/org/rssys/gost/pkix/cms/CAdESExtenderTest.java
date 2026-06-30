package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.DerCodec;

@DisplayName("CAdESExtender: полный цикл CAdES-BES -> CAdES-T -> verify")
class CAdESExtenderTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static KeyPair signerKp;
    private static KeyPair tsaKp;
    private static GostCertificate signerCert;
    private static GostCertificate tsaCert;
    private static KeyPair signer2Kp;
    private static GostCertificate signer2Cert;

    @BeforeAll
    static void setUp() throws Exception {
        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerCert = CmsTestUtils.createSelfSignedCert(signerKp.getPrivate(), signerKp.getPublic());
        tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaCert = CmsTestUtils.createSelfSignedCert(tsaKp.getPrivate(), tsaKp.getPublic());
        signer2Kp = KeyGenerator.generateKeyPair(PARAMS);
        signer2Cert =
                CmsTestUtils.createSelfSignedCert(signer2Kp.getPrivate(), signer2Kp.getPublic());
    }

    // ========================================================================
    // Дыра 1: signingCertificateV2 — молчаливый пропуск
    // ========================================================================

    @Test
    @DisplayName("verify бросает PkixException при отсутствии signingCertificateV2")
    void verifyFailsWithoutSigningCertV2() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .build(); // withoutCAdES — нет signingCertificateV2

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdEST(cadesBes, signerCert),
                "CAdES без signingCertificateV2 должен быть отклонён");
    }

    // ========================================================================
    // Дыра 2: nonce — не сверяется в addTimestamp()
    // ========================================================================

    @Test
    @DisplayName("addTimestamp проходит при совпадении nonce")
    void addTimestampWithCorrectNonce() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("nonce ok".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        TspTransport matchNonceTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        byte[] token = buildTimeStampToken(sigHash, reqNonce);
                        return buildTspResponse(sigHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };

        byte[] cadesT =
                CAdESExtender.addTimestamp(cadesBes, "http://tsa", matchNonceTransport, tsaCert);
        assertNotNull(cadesT);
    }

    @Test
    @DisplayName("addTimestamp бросает при несовпадении nonce")
    void addTimestampFailsWithWrongNonce() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("wrong nonce".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        byte[] wrongNonceToken = buildTimeStampToken(sigHash, BigInteger.valueOf(99));
        byte[] wrongNonceResp = buildTspResponse(sigHash, wrongNonceToken, BigInteger.valueOf(99));
        TspTransport wrongNonceTransport = (req, url) -> wrongNonceResp;

        assertThrows(
                PkixException.class,
                () ->
                        CAdESExtender.addTimestamp(
                                cadesBes, "http://tsa", wrongNonceTransport, tsaCert),
                "Nonce не совпадает — должен быть отклонён");
    }

    // ========================================================================
    // Дыра 3: отсутствие метки / невалидная метка
    // ========================================================================

    @Test
    @DisplayName("verify бросает PkixException при отсутствии метки времени")
    void verifyFailsWithoutTimestamp() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("no timestamp".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdEST(cadesBes, signerCert),
                "CAdES без метки времени должен быть отклонён");
    }

    @Test
    @DisplayName("verify бросает если messageImprint метки не совпадает с подписью")
    void verifyFailsWithTimestampForWrongSignature() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("wrong imprint".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] wrongHash = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(wrongHash);
        byte[] wrongToken = buildTimeStampToken(wrongHash);
        byte[] cadesT = CAdESExtender.embedTimestamp(cadesBes, wrongToken);

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdEST(cadesT, signerCert, tsaCert),
                "messageImprint не совпадает с подписью — должен быть отклонён");
    }

    @Test
    @DisplayName("verify бросает если сертификат истёк до genTime метки")
    void verifyFailsWithExpiredCertAtGenTime() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("expired".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        Instant genTime2040 = ZonedDateTime.of(2040, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant();
        byte[] token =
                buildTimeStampTokenWithGenTime(
                        sigHash, BigInteger.valueOf(1), formatGenTime(genTime2040));
        byte[] cadesT = CAdESExtender.embedTimestamp(cadesBes, token);

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdEST(cadesT, signerCert, tsaCert),
                "Сертификат истёк до genTime — должен быть отклонён");
    }

    @Test
    @DisplayName("verify бросает если сертификат ещё не действовал на genTime метки")
    void verifyFailsWithCertNotYetValidAtGenTime() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("not yet".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        Instant genTime2020 = ZonedDateTime.of(2020, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toInstant();
        byte[] token =
                buildTimeStampTokenWithGenTime(
                        sigHash, BigInteger.valueOf(2), formatGenTime(genTime2020));
        byte[] cadesT = CAdESExtender.embedTimestamp(cadesBes, token);

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdEST(cadesT, signerCert, tsaCert),
                "Сертификат ещё не действовал на genTime — должен быть отклонён");
    }

    // ========================================================================
    // Happy-path
    // ========================================================================

    @Test
    @DisplayName("embedTimestamp: CAdES-BES -> CAdES-T round-trip")
    void embedTimestampRoundTrip() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("test data".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        assertNotNull(cadesBes);

        byte[] sigHash = extractAndHashSignature(cadesBes);
        byte[] timeStampToken = buildTimeStampToken(sigHash);
        byte[] cadesT = CAdESExtender.embedTimestamp(cadesBes, timeStampToken);
        assertNotNull(cadesT);
        assertTrue(cadesT.length > cadesBes.length, "CAdES-T должен быть больше CAdES-BES");
    }

    @Test
    @DisplayName("addTimestamp: полный цикл через mock-транспорт")
    void addTimestampFullCycle() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("full cycle test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        byte[] token = buildTimeStampToken(sigHash, reqNonce);
                        return buildTspResponse(sigHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };

        byte[] cadesT =
                CAdESExtender.addTimestamp(cadesBes, "http://test.tsa", mockTransport, tsaCert);
        assertNotNull(cadesT);
    }

    @Test
    @DisplayName("verify: валидный CAdES-T проходит верификацию")
    void verifyValidCAdEST() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("verify test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        byte[] token = buildTimeStampToken(sigHash, reqNonce);
                        return buildTspResponse(sigHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };

        byte[] cadesT =
                CAdESExtender.addTimestamp(
                        cadesBes, "http://test.tsa", mockTransport, tsaCert, signerCert);

        VerifiedCAdESData result = CAdESExtender.verifyCAdEST(cadesT, tsaCert, signerCert);
        assertNotNull(result);
        assertNotNull(result.signers().get(0).signerCertificate());
        assertNotNull(result.data());
        assertTrue(
                result.signers().get(0).timestamps().size() > 0,
                "Должна быть хотя бы одна метка времени");
    }

    @Test
    @DisplayName("embedTimestamp падает при null-входе")
    void embedTimestampNullThrows() {
        byte[] dummy = new byte[10];
        try {
            CAdESExtender.embedTimestamp(null, dummy);
            fail("Expected exception");
        } catch (NullPointerException | PkixException e) {
            // expected
        }
        try {
            CAdESExtender.embedTimestamp(dummy, null);
            fail("Expected exception");
        } catch (NullPointerException | PkixException e) {
            // expected
        }
    }

    // ========================================================================
    // Multi-signer CAdES-T (2+ подписанта)
    // ========================================================================

    @Test
    @DisplayName("multi-signer: embedTimestamps с двумя подписантами и верификация")
    void multiSignerEmbedTimestamps() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("multi-signer test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addSigner(signer2Kp.getPrivate(), signer2Cert)
                        .withCAdES()
                        .build();

        // Извлекаем хэши подписей в том же порядке SET, что использует embedTimestamps
        List<byte[]> sigHashes = extractAllSigHashes(cadesBes);
        assertEquals(2, sigHashes.size(), "Должно быть 2 подписи");

        byte[] token1 = buildTimeStampToken(sigHashes.get(0));
        byte[] token2 = buildTimeStampToken(sigHashes.get(1));

        byte[] cadesT = CAdESExtender.embedTimestamps(cadesBes, List.of(token1, token2));

        VerifiedCAdESData result =
                CAdESExtender.verifyCAdEST(cadesT, tsaCert, signerCert, signer2Cert);
        assertEquals(2, result.signers().size(), "Должно быть 2 подписанта");
        for (CAdESSignerResult sr : result.signers()) {
            assertTrue(
                    sr.timestamps().size() >= 1,
                    "Каждый подписант должен иметь хотя бы одну метку");
        }
    }

    @Test
    @DisplayName("multi-signer: addTimestamp через mock-транспорт с двумя подписантами")
    void multiSignerAddTimestamp() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("multi-addTimestamp".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addSigner(signer2Kp.getPrivate(), signer2Cert)
                        .withCAdES()
                        .build();

        // Извлекаем хэши подписей в порядке SET (в том же порядке addTimestamp делает запросы)
        List<byte[]> sigHashes = extractAllSigHashes(cadesBes);

        TspTransport mockTransport =
                (req, url) -> {
                    try {
                        BigInteger reqNonce = parseNonceFromRequest(req);
                        // Определяем, для какого подписанта запрос — сравниваем хэш из запроса
                        byte[] reqHash = extractMessageImprintFromRequest(req);
                        byte[] token = buildTimeStampToken(reqHash, reqNonce);
                        return buildTspResponse(reqHash, token, reqNonce);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };

        byte[] cadesT =
                CAdESExtender.addTimestamp(cadesBes, "http://test.tsa", mockTransport, tsaCert);

        VerifiedCAdESData result =
                CAdESExtender.verifyCAdEST(cadesT, tsaCert, signerCert, signer2Cert);
        assertEquals(2, result.signers().size(), "Должно быть 2 подписанта");
        for (CAdESSignerResult sr : result.signers()) {
            assertTrue(
                    sr.timestamps().size() >= 1,
                    "Каждый подписант должен иметь хотя бы одну метку");
        }
    }

    // ========================================================================
    // Double embed (регрессия: сортировка unsignedAttrs при повторном embed)
    // ========================================================================

    @Test
    @DisplayName("double-embed: повторный embedTimestamp не ломает сортировку unsignedAttrs")
    void doubleEmbedTimestampDoesNotBreakSorting() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("double embed".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        byte[] token1 = buildTimeStampToken(sigHash);
        byte[] token2 = buildTimeStampToken(sigHash);

        byte[] cadesT1 = CAdESExtender.embedTimestamp(cadesBes, token1);
        byte[] cadesT2 = CAdESExtender.embedTimestamp(cadesT1, token2);

        VerifiedCAdESData result = CAdESExtender.verifyCAdEST(cadesT2, tsaCert, signerCert);
        assertEquals(
                2,
                result.signers().get(0).timestamps().size(),
                "Должно быть 2 метки после двойного embed");
    }

    // ========================================================================
    // Count mismatch
    // ========================================================================

    @Test
    @DisplayName("embedTimestamps бросает PkixException при несовпадении количества токенов")
    void embedTimestampsThrowsOnCountMismatch() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("count mismatch".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        byte[] sigHash = extractAndHashSignature(cadesBes);
        byte[] token = buildTimeStampToken(sigHash);

        // Меньше токенов, чем подписантов
        assertThrows(
                PkixException.class,
                () -> CAdESExtender.embedTimestamps(cadesBes, List.of()),
                "Пустой список токенов должен вызывать PkixException");

        // Больше токенов, чем подписантов
        assertThrows(
                PkixException.class,
                () -> CAdESExtender.embedTimestamps(cadesBes, List.of(token, token)),
                "2 токена на 1 подписанта должны вызывать PkixException");
    }

    // ========================================================================
    // 0 SignerInfo
    // ========================================================================

    @Test
    @DisplayName("verifyCAdEST бросает PkixException при пустых signerInfos")
    void verifyCAdESTThrowsOnEmptySignerInfos() {
        byte[] emptySignedData = buildSignedDataWithNoSigners();

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdEST(emptySignedData, signerCert),
                "Пустые signerInfos должны вызывать PkixException в verifyCAdEST");
    }

    /** SignedData с версией, дайджестами, encapContentInfo, но без подписантов. */
    private static byte[] buildSignedDataWithNoSigners() {
        byte[] data = "test".getBytes();

        byte[] version = DerCodec.encodeInteger(CmsConstants.SIGNED_DATA_V1);
        byte[] digestAlgs =
                DerCodec.encodeSetOf(
                        new byte[][] {
                            DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.DIGEST_256))
                        });

        byte[] encapContent =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid(GostOids.PKCS7_DATA),
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeOctetString(data)));

        byte[] emptySignerInfos = DerCodec.encodeSetOf(new byte[0][]);

        byte[] signedData =
                DerCodec.encodeSequence(version, digestAlgs, encapContent, emptySignerInfos);

        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, signedData);
    }

    // ========================================================================
    // CAdES-BES verify
    // ========================================================================

    @Test
    @DisplayName("verifyCAdESBES: валидный CAdES-BES проходит верификацию")
    void verifyCAdESBESValid() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("bes verify".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();

        VerifiedCAdESData result = CAdESExtender.verifyCAdESBES(cadesBes, signerCert);
        assertNotNull(result);
        assertNotNull(result.signers().get(0).signerCertificate());
        assertTrue(
                result.signers().get(0).timestamps().isEmpty(),
                "CAdES-BES не должен иметь меток времени");
    }

    @Test
    @DisplayName("verifyCAdESBES бросает PkixException без signingCertificateV2")
    void verifyCAdESBESFailsWithoutScv2() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("bes no scv2".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .build(); // без withCAdES()

        assertThrows(
                PkixException.class,
                () -> CAdESExtender.verifyCAdESBES(cadesBes, signerCert),
                "CAdES-BES без signingCertificateV2 должен быть отклонён");
    }

    // ========================================================================
    // Дыра extractAllSignatures без проверки contentType
    // ========================================================================

    @Test
    @DisplayName("addTimestamp бросает PkixException при contentType != CMS_SIGNED_DATA")
    void addTimestampThrowsOnNonSignedData() throws Exception {
        // Строим EnvelopedData (не SignedData)
        byte[] envelopedData =
                CmsEnvelopedDataBuilder.create()
                        .data("enveloped".getBytes())
                        .addRecipient(signerCert)
                        .build();

        // Транспорт-заглушка: никогда не должен вызываться
        TspTransport stubTransport = (req, url) -> new byte[0];

        assertThrows(
                PkixException.class,
                () ->
                        CAdESExtender.addTimestamp(
                                envelopedData, "http://tsa", stubTransport, tsaCert),
                "Не-SignedData ContentInfo должен вызывать PkixException до transport.send");
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private byte[] extractAndHashSignature(byte[] signedDataDer) throws Exception {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);
        byte[][] siParts = DerCodec.parseSequenceContents(signerInfos[0], 0);
        byte[] sigOctet = null;
        for (int i = siParts.length - 1; i >= 0; i--) {
            if ((siParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                sigOctet = siParts[i];
                break;
            }
        }
        byte[] sig = DerCodec.parseOctetString(sigOctet, 0);
        int hlen = (sig.length == 64) ? 32 : 64;
        return hlen == 32
                ? org.rssys.gost.api.Digest.digest256(sig)
                : org.rssys.gost.api.Digest.digest512(sig);
    }

    private byte[] buildTimeStampToken(byte[] sigHash) throws Exception {
        return buildTimeStampToken(sigHash, BigInteger.valueOf(42));
    }

    private byte[] buildTimeStampToken(byte[] sigHash, BigInteger nonce) throws Exception {
        byte[] tstInfo = buildTstInfo(sigHash, nonce);
        return CmsSignedDataBuilder.create()
                .data(tstInfo)
                .contentType(GostOids.TST_INFO)
                .addSigner(tsaKp.getPrivate(), tsaCert)
                .build();
    }

    private byte[] buildTimeStampTokenWithGenTime(byte[] sigHash, BigInteger nonce, String genTime)
            throws Exception {
        byte[] tstInfo = buildTstInfoWithGenTime(sigHash, nonce, genTime);
        return CmsSignedDataBuilder.create()
                .data(tstInfo)
                .contentType(GostOids.TST_INFO)
                .addSigner(tsaKp.getPrivate(), tsaCert)
                .build();
    }

    private byte[] buildTspResponse(byte[] sigHash, byte[] timeStampToken) {
        return buildTspResponse(sigHash, timeStampToken, BigInteger.valueOf(42));
    }

    private byte[] buildTspResponse(byte[] sigHash, byte[] timeStampToken, BigInteger nonce) {
        byte[] pkiStatus =
                DerCodec.encodeSequence(
                        DerCodec.encodeInteger(BigInteger.valueOf(GostOids.PKI_STATUS_GRANTED)));
        return DerCodec.encodeSequence(pkiStatus, timeStampToken);
    }

    private byte[] buildTstInfo(byte[] hash, BigInteger nonce) {
        DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        String genTime = fmt.format(Instant.now());
        return buildTstInfoWithGenTime(hash, nonce, genTime);
    }

    private byte[] buildTstInfoWithGenTime(byte[] hash, BigInteger nonce, String genTime) {
        byte[] version = DerCodec.encodeInteger(1);
        byte[] policy = DerCodec.encodeOid("1.3.6.1.4.1.4146.1.2.1");
        byte[] hashAlg = org.rssys.gost.pkix.cms.CmsAlgorithmIdentifier.encode(GostOids.DIGEST_256);
        byte[] hashedMsg = DerCodec.encodeOctetString(hash);
        byte[] messageImprint = DerCodec.encodeSequence(hashAlg, hashedMsg);
        byte[] serial = DerCodec.encodeInteger(BigInteger.ONE);
        byte[] genTimeDer = DerCodec.encodeGeneralizedTime(genTime);
        byte[] nonceDer = DerCodec.encodeInteger(nonce);

        return DerCodec.encodeSequence(
                version, policy, messageImprint, serial, genTimeDer, nonceDer);
    }

    private static BigInteger parseNonceFromRequest(byte[] tspReqDer) {
        try {
            byte[][] parts = DerCodec.parseSequenceContents(tspReqDer, 0);
            if (parts.length < 3) return BigInteger.ZERO;
            for (int i = 2; i < parts.length; i++) {
                if (parts[i].length > 0 && (parts[i][0] & 0xFF) == DerCodec.TAG_INTEGER) {
                    return DerCodec.parseInteger(parts[i], 0);
                }
            }
            return BigInteger.ZERO;
        } catch (Exception e) {
            return BigInteger.ZERO;
        }
    }

    /**
     * Извлекает messageImprint hash из TSP-запроса (TimeStampReq DER).
     * Используется в multi-signer mock-транспорте для определения, какому подписанту отвечать.
     */
    private static byte[] extractMessageImprintFromRequest(byte[] tspReqDer) {
        byte[][] parts = DerCodec.parseSequenceContents(tspReqDer, 0);
        // TimeStampReq: SEQUENCE { version, messageImprint, ... }
        if (parts.length < 2) return null;
        // messageImprint: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
        byte[][] miParts = DerCodec.parseSequenceContents(parts[1], 0);
        if (miParts.length < 2) return null;
        return DerCodec.parseOctetString(miParts[1], 0);
    }

    /**
     * Извлекает хэши подписей всех подписантов в порядке SET OF SignerInfo.
     * Порядок совпадает с тем, который используют {@code embedTimestamps} и {@code addTimestamp}.
     */
    private List<byte[]> extractAllSigHashes(byte[] signedDataDer) throws Exception {
        CmsContentInfo ci = CmsContentInfo.decode(signedDataDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        byte[] signerInfosField = sdParts[sdParts.length - 1];
        byte[][] signerInfos = DerCodec.parseSetContents(signerInfosField, 0);

        List<byte[]> hashes = new ArrayList<>();
        for (byte[] si : signerInfos) {
            byte[][] siParts = DerCodec.parseSequenceContents(si, 0);
            byte[] sigOctet = null;
            for (int i = siParts.length - 1; i >= 0; i--) {
                if (siParts[i].length > 0 && (siParts[i][0] & 0xFF) == DerCodec.TAG_OCTET_STRING) {
                    sigOctet = siParts[i];
                    break;
                }
            }
            if (sigOctet == null) continue;
            byte[] sig = DerCodec.parseOctetString(sigOctet, 0);
            int hlen = (sig.length == 64) ? 32 : 64;
            byte[] hash =
                    hlen == 32
                            ? org.rssys.gost.api.Digest.digest256(sig)
                            : org.rssys.gost.api.Digest.digest512(sig);
            hashes.add(hash);
        }
        return hashes;
    }

    private static String formatGenTime(Instant instant) {
        DateTimeFormatter fmt =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        return fmt.format(instant);
    }
}
