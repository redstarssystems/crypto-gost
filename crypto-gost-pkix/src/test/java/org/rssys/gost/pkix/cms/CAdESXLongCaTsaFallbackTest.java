package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspResponseBuilder;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * X Long с TSA, выпущенным УЦ (форма КриптоПро): сертификат TSA и корень лежат только
 * во вложенном certificate-values сигнатурного штампа, поле certificates токена пусто.
 * Также проверяет слияние сертификатов токенов ({@code mergeCertificates}).
 */
@DisplayName(
        "CAdES-X Long: TSA из УЦ, fallback на вложенный certificate-values, слияние сертификатов")
class CAdESXLongCaTsaFallbackTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String TSA_POLICY = "1.2.3.4.5";

    private static KeyPair rootKp;
    private static GostCertificate root;
    private static KeyPair tsaKp;
    private static GostCertificate tsaCert;
    private static KeyPair signerKp;
    private static GostCertificate signerCert;

    @BeforeAll
    static void setUp() throws Exception {
        rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = CmsTestUtils.buildDn("Fallback Root");
        root =
                GostCertificateBuilder.create(PARAMS, rootDn)
                        .issuerDn(rootDn)
                        .publicKey(rootKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .basicConstraints(true, null)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .sign(rootKp.getPrivate());
        tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaCert = timeStampingCert(tsaKp, "Fallback TSA");
        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerCert =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Fallback Signer"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(signerKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(rootKp.getPrivate());
    }

    private static GostCertificate timeStampingCert(KeyPair kp, String name) throws Exception {
        return GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn(name))
                .issuerDn(root.getSubjectDnBytes())
                .publicKey(kp.getPublic())
                .randomSerial()
                .notBeforeNow()
                .validForDays(365)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(true, GostOids.EXT_TIME_STAMPING)
                .sign(rootKp.getPrivate());
    }

    private static byte[] tspResponse(byte[] request, KeyPair kp, GostCertificate cert, long serial)
            throws Exception {
        return TspResponseBuilder.create(request)
                .signer(kp.getPrivate(), cert)
                .policyOid(TSA_POLICY)
                .serialNumber(BigInteger.valueOf(serial))
                .accuracy(1)
                .withCAdES()
                .buildGranted();
    }

    private static byte[] timeStampToken(KeyPair kp, GostCertificate cert, boolean certReq)
            throws Exception {
        byte[] request =
                TspRequestBuilder.create()
                        .messageImprint(new byte[32], GostOids.DIGEST_256)
                        .certReq(certReq)
                        .build();
        return TspResponse.fromDer(tspResponse(request, kp, cert, 1)).timeStampTokenDer();
    }

    private static byte[] cachedXLong;

    /** Один X Long на класс: сборка содержит паузы между штампами и CRL. */
    private static byte[] xlong() throws Exception {
        if (cachedXLong == null) {
            cachedXLong = buildXLong(tsaKp, tsaCert);
        }
        return cachedXLong;
    }

    /** X Long, где TSA выпущен УЦ: вложения строятся до корня, certificates токена пуст. */
    private static byte[] buildXLong(KeyPair usedTsaKp, GostCertificate usedTsaCert)
            throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("ca tsa".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        long[] serial = {1};
        TspTransport transport =
                (req, url) -> {
                    try {
                        // escTimeStamp обязан быть позже signature-time-stamp
                        Thread.sleep(1100);
                        return tspResponse(req, usedTsaKp, usedTsaCert, serial[0]++);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };
        byte[] cadesT = CAdESExtender.addTimestamp(cadesBes, "local://tsa", transport, root);
        // CRL выпускается после штампа подписи: доказательство обязано быть свежее штампа
        Thread.sleep(1100);
        GostCrl crl =
                new GostCrl(
                        GostCrlBuilder.create(root.getSubjectDnBytes())
                                .thisUpdateNow()
                                .nextUpdateDays(30)
                                .withCrlNumber(1)
                                .sign(rootKp.getPrivate()));
        return CAdESExtender.embedXLongType1(
                cadesT,
                List.of(signerCert, root),
                Arrays.asList(crl, null),
                Arrays.asList((GostOcspResponse) null, null),
                "local://tsa",
                transport,
                root);
    }

    private static int countCerts(byte[] certsField) {
        if (certsField == null) {
            return 0;
        }
        int[] lenInfo = DerCodec.decodeLength(certsField, 1);
        int pos = 1 + lenInfo[1];
        int count = 0;
        while (pos < certsField.length) {
            int[] certLen = DerCodec.decodeLength(certsField, pos + 1);
            pos += 1 + certLen[1] + certLen[0];
            count++;
        }
        return count;
    }

    private static byte[] signatureTimestampToken(byte[] cadesDer) throws Exception {
        byte[] body = CmsContentInfo.decode(cadesDer).content();
        SignedDataParts sd = SignedDataParts.parse(body);
        byte[][] siParts =
                DerCodec.parseSequenceContents(
                        DerCodec.parseSetContents(sd.signerInfosField(), 0)[0], 0);
        for (byte[] part : siParts) {
            if (part.length > 0 && (part[0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                int[] len = DerCodec.decodeLength(part, 1);
                byte[] content = Arrays.copyOfRange(part, 1 + len[1], part.length);
                int pos = 0;
                while (pos < content.length) {
                    int[] attrLen = DerCodec.decodeLength(content, pos + 1);
                    int total = 1 + attrLen[1] + attrLen[0];
                    CmsAttribute attr =
                            CmsAttribute.decode(Arrays.copyOfRange(content, pos, pos + total));
                    if (GostOids.SIGNATURE_TIME_STAMP.equals(attr.attrType())) {
                        return attr.attrValues()[0];
                    }
                    pos += total;
                }
            }
        }
        throw new AssertionError("signature-time-stamp not found");
    }

    // ========================================================================
    // fallback верификатора
    // ========================================================================

    @Test
    @DisplayName(
            "TSA из УЦ: certificates токена пуст, сертификаты TSA и корня во вложенном certificate-values")
    void tokenHasEmptyCertificatesAndNestedValues() throws Exception {
        byte[] xlong = xlong();

        byte[] token = signatureTimestampToken(xlong);
        byte[] tokenSd = CmsContentInfo.decode(token).content();
        SignedDataParts sd = SignedDataParts.parse(tokenSd);
        assertEquals(0, countCerts(sd.certs()), "в токене нет сертификатов, как у КриптоПро");

        List<GostCertificate> candidates = CAdESVerifier.extractTokenCertificateCandidates(token);
        assertEquals(2, candidates.size(), "кандидаты: сертификат TSA и корень из значений");
        // Токен не пересобирается: исходные байты остаются прежними
        assertEquals(0, countCerts(SignedDataParts.parse(tokenSd).certs()));
    }

    @Test
    @DisplayName(
            "TSA из УЦ: верификатор находит TSA во вложенном certificate-values и принимает X Long")
    void verifierAcceptsTokenWithNestedCertificates() throws Exception {
        byte[] xlong = xlong();

        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(xlong, TrustAnchors.ofCertificates(root));

        assertEquals(1, result.signers().size());
    }

    @Test
    @DisplayName("TSA вне доверенной цепочки отклоняется, даже если лежит во вложенных значениях")
    void verifierRejectsTsaFromUntrustedRoot() throws Exception {
        byte[] xlong = xlong();
        KeyPair foreignKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate foreignRoot =
                CmsTestUtils.createSelfSignedCertWithDn(
                        foreignKp.getPrivate(),
                        foreignKp.getPublic(),
                        BigInteger.valueOf(77),
                        "Foreign Root");

        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyXLong(xlong, TrustAnchors.ofCertificates(foreignRoot)));
    }

    @Test
    @DisplayName("Токен без вложенного certificate-values даёт только свои сертификаты")
    void tokenWithoutNestedValuesGivesOwnCertificatesOnly() throws Exception {
        byte[] token = timeStampToken(tsaKp, tsaCert, true);

        List<GostCertificate> candidates = CAdESVerifier.extractTokenCertificateCandidates(token);

        assertEquals(1, candidates.size(), "только сертификат из поля certificates токена");
        assertArrayEquals(tsaCert.getEncoded(), candidates.get(0).getEncoded());
    }

    // ========================================================================
    // mergeCertificates
    // ========================================================================

    @Test
    @DisplayName("mergeCertificates: одинаковые сертификаты из нескольких токенов схлопываются")
    void mergeDeduplicatesByDer() throws Exception {
        byte[] token = timeStampToken(tsaKp, tsaCert, true);

        byte[] merged = CAdESExtender.mergeCertificates(null, List.of(token, token));

        assertEquals(1, countCerts(merged), "дубликат по DER не добавляется");
    }

    @Test
    @DisplayName("mergeCertificates: токен без поля certificates штатен")
    void mergeAcceptsTokenWithoutCertificates() throws Exception {
        byte[] full = timeStampToken(tsaKp, tsaCert, true);
        SignedDataParts sd = SignedDataParts.parse(CmsContentInfo.decode(full).content());
        // как у КриптоПро: поле certificates в токене отсутствует
        byte[] token =
                CmsContentInfo.encode(
                        GostOids.CMS_SIGNED_DATA, sd.rebuild(null, sd.signerInfosField()));

        assertNull(CAdESExtender.mergeCertificates(null, List.of(token)));
    }

    @Test
    @DisplayName("mergeCertificates: превышение MAX_EMBEDDED_CERTS отклоняется")
    void mergeRejectsTooManyCertificates() throws Exception {
        List<byte[]> tokens = new ArrayList<>();
        for (int i = 0; i <= CmsConstants.MAX_EMBEDDED_CERTS; i++) {
            KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
            tokens.add(timeStampToken(kp, timeStampingCert(kp, "TSA " + i), true));
        }

        PkixException ex =
                assertThrows(
                        PkixException.class, () -> CAdESExtender.mergeCertificates(null, tokens));
        assertTrue(ex.getMessage().contains("Too many certificates"));
    }

    @Test
    @DisplayName("mergeCertificates: нечитаемый токен приводит к PkixException")
    void mergeRejectsMalformedToken() {
        assertThrows(
                PkixException.class,
                () -> CAdESExtender.mergeCertificates(null, List.of(new byte[] {1, 2, 3})));
    }
}
