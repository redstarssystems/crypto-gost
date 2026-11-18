package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
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
import org.rssys.gost.pkix.tsp.TspResponseBuilder;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * X Long, где TSA выпущен промежуточным УЦ, а в escTimeStamp остался только сертификат
 * TSA: промежуточный УЦ виден лишь во вложенном certificate-values соседнего
 * signature-time-stamp. Так выглядит файл КриптоПро.
 */
@DisplayName("CAdES-X Long: промежуточный УЦ TSA только в соседнем токене")
class CAdESXLongTsaIntermediateFromOtherTokenTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static KeyPair rootKp;
    private static GostCertificate root;
    private static GostCertificate tsaInt;
    private static KeyPair tsaKp;
    private static GostCertificate tsaCert;

    /** Реальная форма: tsaInt только во вложенном certificate-values signature-токена. */
    private static byte[] xlongRealForm;

    /** Та же форма, но у signature-токена удалён вложенный certificate-values. */
    private static byte[] xlongWithoutNestedValues;

    @BeforeAll
    static void setUp() throws Exception {
        rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = CmsTestUtils.buildDn("Inter Root");
        root =
                GostCertificateBuilder.create(PARAMS, rootDn)
                        .issuerDn(rootDn)
                        .publicKey(rootKp.getPublic())
                        .serial(BigInteger.ONE)
                        .notBeforeNow()
                        .validForDays(365)
                        .basicConstraints(true, null)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .sign(rootKp.getPrivate());
        KeyPair intKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaInt =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Inter TSA CA"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(intKp.getPublic())
                        .serial(BigInteger.TWO)
                        .notBeforeNow()
                        .validForDays(365)
                        .basicConstraints(true, null)
                        .keyUsage(
                                GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                                GostCertificateBuilder.KeyUsage.CRL_SIGN)
                        .sign(rootKp.getPrivate());
        tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaCert =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Inter TSA"))
                        .issuerDn(tsaInt.getSubjectDnBytes())
                        .publicKey(tsaKp.getPublic())
                        .serial(BigInteger.valueOf(3))
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage(true, GostOids.EXT_TIME_STAMPING)
                        .sign(intKp.getPrivate());

        KeyPair signerKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate signerCert =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Inter Signer"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(signerKp.getPublic())
                        .serial(BigInteger.valueOf(4))
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(rootKp.getPrivate());

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("inter tsa".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .withCAdES()
                        .build();
        long[] serial = {1};
        TspTransport transport =
                (req, url) -> {
                    try {
                        // escTimeStamp обязан быть позже signature-time-stamp
                        Thread.sleep(1100);
                        return TspResponseBuilder.create(req)
                                .signer(tsaKp.getPrivate(), tsaCert)
                                .policyOid("1.2.3.4.5")
                                .serialNumber(BigInteger.valueOf(serial[0]++))
                                .accuracy(1)
                                .withCAdES()
                                .addChainCert(tsaInt)
                                .buildGranted();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };
        byte[] cadesT = CAdESExtender.addTimestamp(cadesBes, "local://tsa", transport, root);
        Thread.sleep(1100);
        GostCrl crl =
                new GostCrl(
                        GostCrlBuilder.create(root.getSubjectDnBytes())
                                .thisUpdateNow()
                                .nextUpdateDays(30)
                                .withCrlNumber(1)
                                .sign(rootKp.getPrivate()));
        byte[] xlong =
                CAdESExtender.embedXLongType1(
                        cadesT,
                        List.of(signerCert, root),
                        Arrays.asList(crl, null),
                        Arrays.asList((GostOcspResponse) null, null),
                        "local://tsa",
                        transport,
                        root);
        xlongRealForm = toRealCryptoProForm(xlong);
        xlongWithoutNestedValues = withoutSignatureTokenNestedValues(xlongRealForm);
    }

    /**
     * Приводит X Long к форме КриптоПро: в escTimeStamp остаётся только сертификат TSA,
     * а внешнее поле certificates не содержит промежуточного УЦ TSA. Эти поля не покрыты
     * подписью и не входят в хеш escTimeStamp, поэтому подписи остаются верными.
     */
    private static byte[] toRealCryptoProForm(byte[] xlong) throws Exception {
        SignedDataParts sd = SignedDataParts.parse(CmsContentInfo.decode(xlong).content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] oldToken = null;
        for (byte[] attrDer : unsignedAttrs(signerInfos[0])) {
            CmsAttribute attr = CmsAttribute.decode(attrDer);
            if (GostOids.ESC_TIME_STAMP.equals(attr.attrType())) {
                oldToken = attr.attrValues()[0];
            }
        }
        SignedDataParts tokenSd = SignedDataParts.parse(CmsContentInfo.decode(oldToken).content());
        byte[] newToken =
                CmsContentInfo.encode(
                        GostOids.CMS_SIGNED_DATA,
                        tokenSd.rebuild(
                                DerCodec.encodeContextConstructed(0, tsaCert.getEncoded()),
                                tokenSd.signerInfosField()));
        byte[] newSignerInfo =
                CAdESExtender.replaceUnsignedAttrsDer(
                        signerInfos[0],
                        new String[] {GostOids.ESC_TIME_STAMP},
                        new byte[][] {
                            CmsAttribute.encode(GostOids.ESC_TIME_STAMP, new byte[][] {newToken})
                        });
        return CmsContentInfo.encode(
                GostOids.CMS_SIGNED_DATA,
                sd.rebuild(
                        outerCertificatesWithout(sd.certs(), tsaInt),
                        DerCodec.encodeSetOf(new byte[][] {newSignerInfo})));
    }

    /** Пересобирает поле certificates без указанного сертификата (по DER). */
    private static byte[] outerCertificatesWithout(byte[] certsField, GostCertificate excluded) {
        if (certsField == null) {
            return null;
        }
        int[] lenInfo = DerCodec.decodeLength(certsField, 1);
        int pos = 1 + lenInfo[1];
        List<byte[]> kept = new java.util.ArrayList<>();
        while (pos < certsField.length) {
            int[] certLen = DerCodec.decodeLength(certsField, pos + 1);
            int total = 1 + certLen[1] + certLen[0];
            byte[] cert = Arrays.copyOfRange(certsField, pos, pos + total);
            if (!Arrays.equals(cert, excluded.getEncoded())) {
                kept.add(cert);
            }
            pos += total;
        }
        return DerCodec.encodeContextConstructed(0, DerCodec.concat(kept.toArray(new byte[0][])));
    }

    /** Удаляет вложенный certificate-values из signature-time-stamp токена. */
    private static byte[] withoutSignatureTokenNestedValues(byte[] xlong) throws Exception {
        SignedDataParts sd = SignedDataParts.parse(CmsContentInfo.decode(xlong).content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] oldToken = attributeValue(signerInfos[0], GostOids.SIGNATURE_TIME_STAMP);
        SignedDataParts tokenSd = SignedDataParts.parse(CmsContentInfo.decode(oldToken).content());
        byte[][] tokenSignerInfos = DerCodec.parseSetContents(tokenSd.signerInfosField(), 0);
        byte[] strippedTokenSignerInfo =
                CAdESExtender.replaceUnsignedAttrsDer(
                        tokenSignerInfos[0],
                        new String[] {GostOids.CERTIFICATE_VALUES},
                        new byte[][] {null});
        byte[] newToken =
                CmsContentInfo.encode(
                        GostOids.CMS_SIGNED_DATA,
                        tokenSd.rebuild(
                                tokenSd.certs(),
                                DerCodec.encodeSetOf(new byte[][] {strippedTokenSignerInfo})));
        byte[] newSignerInfo =
                CAdESExtender.replaceUnsignedAttrsDer(
                        signerInfos[0],
                        new String[] {GostOids.SIGNATURE_TIME_STAMP},
                        new byte[][] {
                            CmsAttribute.encode(
                                    GostOids.SIGNATURE_TIME_STAMP, new byte[][] {newToken})
                        });
        return CmsContentInfo.encode(
                GostOids.CMS_SIGNED_DATA,
                sd.rebuild(sd.certs(), DerCodec.encodeSetOf(new byte[][] {newSignerInfo})));
    }

    private static byte[] attributeValue(byte[] signerInfoDer, String oid) throws Exception {
        for (byte[] attrDer : unsignedAttrs(signerInfoDer)) {
            CmsAttribute attr = CmsAttribute.decode(attrDer);
            if (oid.equals(attr.attrType())) {
                return attr.attrValues()[0];
            }
        }
        throw new AssertionError("атрибут не найден: " + oid);
    }

    private static List<byte[]> unsignedAttrs(byte[] signerInfoDer) throws Exception {
        byte[][] parts = DerCodec.parseSequenceContents(signerInfoDer, 0);
        List<byte[]> result = new java.util.ArrayList<>();
        for (byte[] part : parts) {
            if (!DerCodec.isContextTag(part, 1)) {
                continue;
            }
            int[] len = DerCodec.decodeLength(part, 1);
            byte[] content = Arrays.copyOfRange(part, 1 + len[1], part.length);
            int pos = 0;
            while (pos < content.length) {
                int[] attrLen = DerCodec.decodeLength(content, pos + 1);
                int total = 1 + attrLen[1] + attrLen[0];
                result.add(Arrays.copyOfRange(content, pos, pos + total));
                pos += total;
            }
        }
        return result;
    }

    @Test
    @DisplayName("Форма КриптоПро: tsaInt только во вложенном certificate-values signature-токена")
    void fixtureHasRealCryptoProForm() throws Exception {
        SignedDataParts sd = SignedDataParts.parse(CmsContentInfo.decode(xlongRealForm).content());
        byte[][] signerInfos = DerCodec.parseSetContents(sd.signerInfosField(), 0);
        byte[] signatureToken = attributeValue(signerInfos[0], GostOids.SIGNATURE_TIME_STAMP);
        byte[] escToken = attributeValue(signerInfos[0], GostOids.ESC_TIME_STAMP);

        assertFalse(
                containsDer(outerCertificates(sd.certs()), tsaInt),
                "во внешнем certificates промежуточного УЦ TSA быть не должно");
        assertNull(
                SignedDataParts.parse(CmsContentInfo.decode(signatureToken).content()).certs(),
                "у signature-токена своё поле certificates пусто, как у КриптоПро");
        assertTrue(
                containsDer(
                        CAdESVerifier.extractTokenCertificateCandidates(signatureToken), tsaInt),
                "tsaInt есть во вложенном certificate-values signature-токена");
        List<GostCertificate> escCandidates =
                CAdESVerifier.extractTokenCertificateCandidates(escToken);
        assertEquals(1, escCandidates.size(), "в токене escTimeStamp только сертификат TSA");
        assertArrayEquals(tsaCert.getEncoded(), escCandidates.get(0).getEncoded());
    }

    @Test
    @DisplayName("Промежуточный УЦ берётся из соседнего токена: X Long принимается")
    void intermediateTakenFromSiblingToken() throws Exception {
        assertDoesNotThrow(
                () -> CAdESVerifier.verifyXLong(xlongRealForm, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("Без вложенного certificate-values signature-токена цепочка TSA не строится")
    void withoutNestedValuesChainIsNotBuilt() {
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CAdESVerifier.verifyXLong(
                                        xlongWithoutNestedValues,
                                        TrustAnchors.ofCertificates(root)));
        assertTrue(
                ex.getMessage().contains("issuer not found in certificates pool or trusted roots"),
                "ожидался отказ построения цепочки, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Чужой корень: промежуточный УЦ из токена доверия не создаёт")
    void foreignRootRejected() throws Exception {
        KeyPair foreignKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate foreignRoot =
                CmsTestUtils.createSelfSignedCertWithDn(
                        foreignKp.getPrivate(),
                        foreignKp.getPublic(),
                        BigInteger.valueOf(77),
                        "Inter Foreign Root");

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                xlongRealForm, TrustAnchors.ofCertificates(foreignRoot)));
    }

    private static List<GostCertificate> outerCertificates(byte[] certsField) {
        List<GostCertificate> result = new java.util.ArrayList<>();
        if (certsField == null) {
            return result;
        }
        int[] lenInfo = DerCodec.decodeLength(certsField, 1);
        int pos = 1 + lenInfo[1];
        while (pos < certsField.length) {
            int[] certLen = DerCodec.decodeLength(certsField, pos + 1);
            int total = 1 + certLen[1] + certLen[0];
            result.add(new GostCertificate(Arrays.copyOfRange(certsField, pos, pos + total)));
            pos += total;
        }
        return result;
    }

    private static boolean containsDer(List<GostCertificate> certs, GostCertificate cert) {
        for (GostCertificate candidate : certs) {
            if (Arrays.equals(candidate.getEncoded(), cert.getEncoded())) {
                return true;
            }
        }
        return false;
    }
}
