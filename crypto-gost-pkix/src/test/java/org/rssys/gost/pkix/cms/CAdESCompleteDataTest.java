package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CAdESCompleteData: кодирование/декодирование CAdES-C структур, полный roundtrip")
class CAdESCompleteDataTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static KeyPair caKp;
    private static GostCertificate caCert;
    private static KeyPair signerKp;
    private static GostCertificate signerCert;
    private static GostCrl crl;

    @BeforeAll
    static void setUp() throws Exception {
        caKp = KeyGenerator.generateKeyPair(PARAMS);
        caCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        caKp.getPrivate(), caKp.getPublic(), BigInteger.valueOf(1), "CA");

        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] signerDnDer = CmsTestUtils.buildDn("Signer");
        signerCert =
                GostCertificateBuilder.create(PARAMS, signerDnDer)
                        .issuerDn(caCert.getSubjectDnBytes())
                        .publicKey(signerKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .sign(caKp.getPrivate());

        byte[] crlDer =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .addRevoked(
                                BigInteger.valueOf(99), GostSignatureHelper.nowGeneralizedTime())
                        .sign(caKp.getPrivate());
        crl = new GostCrl(crlDer);
    }

    @Test
    @DisplayName("encode/decode OtherHash roundtrip")
    void otherHashRoundtrip() throws Exception {
        byte[] hash = Digest.digest256("test".getBytes());
        byte[] der = CAdESCompleteData.encodeOtherHashStreebog(hash, GostOids.DIGEST_256);
        CAdESCompleteData.OtherHash decoded = CAdESCompleteData.decodeOtherHash(der);
        assertEquals(GostOids.DIGEST_256, decoded.hashOid());
        assertTrue(Arrays.equals(hash, decoded.hashValue()));
    }

    @Test
    @DisplayName("Регресс: OtherHashAlgAndValue.hashAlgorithm несёт NULL-параметры")
    void otherHashAlgorithmHasNullParams() throws Exception {
        // OtherHashAlgAndValue (CAdES-C complete-refs, точки certificateRefs/
        // revocationRefs) — тот же AlgorithmIdentifier с GOST-digest-OID, что и
        // остальные digest-поля CMS; по Р 1323565.1.025 §4 параметры = NULL.
        // Ассерт фиксирует форму {OID, NULL} и защищает от молчаливого возврата
        // к кодированию без параметров при будущем рефакторинге (внешнего
        // эталона для CAdES-C нет — только собственный регресс).
        byte[] hash = Digest.digest256("null-param".getBytes());
        byte[] der = CAdESCompleteData.encodeOtherHashStreebog(hash, GostOids.DIGEST_256);

        // der = [1] IMPLICIT OtherHashAlgAndValue; снимаем контекстную обёртку [1]
        int[] len = DerCodec.decodeLength(der, 1);
        int seqOffset = 1 + len[1];
        byte[][] algAndValue = DerCodec.parseSequenceContents(der, seqOffset);
        byte[][] hashAlgId = DerCodec.parseSequenceContents(algAndValue[0], 0);

        assertEquals(2, hashAlgId.length, "hashAlgorithm должен нести OID и параметры");
        assertEquals(
                DerCodec.TAG_NULL,
                hashAlgId[1][0] & 0xFF,
                "параметры hashAlgorithm должны быть NULL");
    }

    @Test
    @DisplayName("decode OtherHash sha1Hash [0] rejected for GOST")
    void otherHashSha1Rejected() {
        byte[] fakeSha1 = new byte[] {0x30, 0x06, 0x06, 0x01, 0x00, 0x04, 0x01, 0x00};
        byte[] der = new byte[1 + 1 + fakeSha1.length];
        der[0] = (byte) 0xA0;
        der[1] = (byte) fakeSha1.length;
        System.arraycopy(fakeSha1, 0, der, 2, fakeSha1.length);
        assertThrows(PkixException.class, () -> CAdESCompleteData.decodeOtherHash(der));
    }

    @Test
    @DisplayName("decode OtherHash с неизвестным CHOICE-тегом")
    void otherHashUnknownTag() {
        byte[] der = new byte[] {(byte) 0xA3, 0x00};
        assertThrows(PkixException.class, () -> CAdESCompleteData.decodeOtherHash(der));
    }

    @Test
    @DisplayName("encode/decode OtherCertID roundtrip")
    void otherCertIdRoundtrip() throws Exception {
        byte[] der = CAdESCompleteData.encodeOtherCertID(caCert, GostOids.DIGEST_256);
        CAdESCompleteData.OtherCertID decoded = CAdESCompleteData.decodeOtherCertID(der);
        assertEquals(GostOids.DIGEST_256, decoded.otherCertHash().hashOid());
        assertNotNull(decoded.issuerSerial());
        assertEquals(caCert.getSerialNumberBigInt(), decoded.issuerSerial().serial());
    }

    @Test
    @DisplayName("encode/decode CrlOcspRef roundtrip (CRL-only)")
    void crlOcspRefRoundtrip() throws Exception {
        byte[] validatedDer = CAdESCompleteData.encodeCrlValidatedID(crl, GostOids.DIGEST_256);
        byte[] crlOcspRefDer = CAdESCompleteData.encodeCrlOcspRef(List.of(validatedDer), List.of());
        CAdESCompleteData.CrlOcspRef decoded = CAdESCompleteData.decodeCrlOcspRef(crlOcspRefDer);
        assertEquals(1, decoded.crlList().size());
        assertTrue(decoded.ocspList().isEmpty());
    }

    @Test
    @DisplayName("decodeCrlOcspRef: fail-closed при дублирующемся теге [0] crlids")
    void crlOcspRefDuplicateTag0Rejected() throws Exception {
        // Крафченный CrlOcspRef с двумя [0]: malformed DER, должен быть отклонён,
        // а не молча перезатёрт вторым вхождением.
        byte[] validatedDer = CAdESCompleteData.encodeCrlValidatedID(crl, GostOids.DIGEST_256);
        byte[] crlsSeqOf = DerCodec.encodeSequence(validatedDer);
        byte[] crlListId = DerCodec.encodeSequence(crlsSeqOf);
        byte[] tag0 = DerCodec.encodeContextConstructed(0, crlListId);
        byte[] malformed = DerCodec.encodeSequence(tag0, tag0);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> CAdESCompleteData.decodeCrlOcspRef(malformed),
                        "дублирующийся тег [0] должен приводить к PkixException");
        assertTrue(
                ex.getMessage().contains("duplicate [0]"),
                "сообщение должно указывать на дубль тега [0], получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("decodeCrlOcspRef: fail-closed при пустой, но дважды присутствующей [0]")
    void crlOcspRefEmptyDuplicateTag0Rejected() throws Exception {
        // Легитимно пустой внутренний SEQUENCE OF даёт пустой список — проверка через
        // флаг crlSeen (а не isEmpty) обязана поймать даже этот крайний случай.
        byte[] emptySeqOf = DerCodec.encodeSequence();
        byte[] crlListId = DerCodec.encodeSequence(emptySeqOf);
        byte[] tag0 = DerCodec.encodeContextConstructed(0, crlListId);
        byte[] malformed = DerCodec.encodeSequence(tag0, tag0);

        assertThrows(
                PkixException.class,
                () -> CAdESCompleteData.decodeCrlOcspRef(malformed),
                "дубль пустого [0] тоже должен отклоняться (флаг, а не проверка пустоты)");
    }

    @Test
    @DisplayName("encode/decode CompleteCertificateRefs roundtrip")
    void completeCertificateRefsRoundtrip() throws Exception {
        byte[] der1 = CAdESCompleteData.encodeOtherCertID(caCert, GostOids.DIGEST_256);
        byte[] refsDer = CAdESCompleteData.encodeCompleteCertificateRefs(List.of(der1));
        List<CAdESCompleteData.OtherCertID> refs =
                CAdESCompleteData.decodeCompleteCertificateRefs(refsDer);
        assertEquals(1, refs.size());
    }

    @Test
    @DisplayName("Полный roundtrip CAdES-C: BES -> embedCompleteRefs -> verifyCAdESC")
    void fullCadesCRoundtrip() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("CAdES-C test data".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addCertificate(caCert)
                        .withCAdES()
                        .build();

        List<GostCertificate> chain = List.of(signerCert, caCert);
        List<GostCrl> crlsForChain = Arrays.asList(crl, null);
        List<GostOcspResponse> ocspForChain = Arrays.asList(null, null);

        byte[] cadesC =
                CAdESExtender.embedCompleteRefs(cadesBes, chain, crlsForChain, ocspForChain);
        assertNotNull(cadesC);

        VerifiedCAdESData result = CAdESExtender.verifyCAdESC(cadesC, caCert);
        assertNotNull(result);
        assertEquals(1, result.signers().size());
        assertNotNull(result.signers().get(0).completeCertRefs());
        assertNotNull(result.signers().get(0).completeRevocRefs());
    }

    @Test
    @DisplayName("CAdES-C через convenience CertRevocationData overload")
    void cadesCViaCertRevocationData() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("CRD test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addCertificate(caCert)
                        .withCAdES()
                        .build();

        List<GostCertificate> chain = List.of(signerCert, caCert);
        List<org.rssys.gost.pkix.cert.CertRevocationData> revData =
                Arrays.asList(
                        new org.rssys.gost.pkix.cert.CertRevocationData(null, crl.getEncoded()),
                        null);

        byte[] cadesC = CAdESExtender.embedCompleteRefs(cadesBes, chain, revData);
        assertNotNull(cadesC);
        assertDoesNotThrow(() -> CAdESExtender.verifyCAdESC(cadesC, caCert));
    }

    @Test
    @DisplayName("PkixException при отсутствии complete-certificate-references")
    void missingCertRefs() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("missing".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addCertificate(caCert)
                        .withCAdES()
                        .build();
        assertThrows(PkixException.class, () -> CAdESExtender.verifyCAdESC(cadesBes, caCert));
    }

    @Test
    @DisplayName("PkixException при отсутствии revocation-данных для элемента цепочки")
    void missingCrlRevocation() {
        List<GostCertificate> chain = Arrays.asList(signerCert, caCert);
        assertThrows(
                PkixException.class,
                () ->
                        CAdESCompleteData.buildCompleteRefsResult(
                                chain, Arrays.asList(null, null), Arrays.asList(null, null)));
    }

    // ========================================================================
    // Security-регрессионные тесты (реальные вызовы verifyCAdESC)
    // ========================================================================

    @Test
    @DisplayName("PkixException при unknown hashAlgorithm OID в OtherHash (fail-closed whitelist)")
    void unknownHashOidInOtherHash() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("oid test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addCertificate(caCert)
                        .withCAdES()
                        .build();

        String fakeOid = "1.2.643.7.1.1.2.9";
        byte[] caHash = Digest.digest256(caCert.getEncoded());
        byte[] fakeHashDer = CAdESCompleteData.encodeOtherHashStreebog(caHash, fakeOid);
        byte[] issuerSerialDer =
                CAdESCompleteData.encodeIssuerSerial(
                        caCert.getIssuerDnBytes(), caCert.getSerialNumberBigInt());
        byte[] fakeCertID = CAdESCompleteData.encodeOtherCertID(fakeHashDer, issuerSerialDer);
        byte[] fakeRefs = CAdESCompleteData.encodeCompleteCertificateRefs(List.of(fakeCertID));
        byte[] fakeAttr = CmsAttribute.encode(GostOids.COMPLETE_CERTIFICATE_REFS, fakeRefs);

        byte[] tampered = injectUnsignedAttrIntoBes(cadesBes, fakeAttr);
        assertThrows(PkixException.class, () -> CAdESExtender.verifyCAdESC(tampered, caCert));
    }

    @Test
    @DisplayName("PkixException при несовпадении certHash в CompleteCertificateRefs")
    void wrongCertHash() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("hash test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addCertificate(caCert)
                        .withCAdES()
                        .build();

        // Строим fake certRefs с битым certHash — не совпадёт с caCert в embedded certs
        byte[] caDer = caCert.getEncoded();
        byte[] goodHash = Digest.digest256(caDer);
        byte[] wrongHash = Arrays.copyOf(goodHash, goodHash.length);
        wrongHash[0] ^= 0xFF;

        byte[] fakeHashDer =
                CAdESCompleteData.encodeOtherHashStreebog(wrongHash, GostOids.DIGEST_256);
        byte[] issuerDer =
                CAdESCompleteData.encodeIssuerSerial(
                        caCert.getIssuerDnBytes(), caCert.getSerialNumberBigInt());
        byte[] fakeCertId = CAdESCompleteData.encodeOtherCertID(fakeHashDer, issuerDer);
        byte[] fakeRefs = CAdESCompleteData.encodeCompleteCertificateRefs(List.of(fakeCertId));
        byte[] fakeAttr = CmsAttribute.encode(GostOids.COMPLETE_CERTIFICATE_REFS, fakeRefs);

        byte[] tampered = injectUnsignedAttrIntoBes(cadesBes, fakeAttr);
        PkixException ex =
                assertThrows(
                        PkixException.class, () -> CAdESExtender.verifyCAdESC(tampered, caCert));
        assertTrue(
                ex.getMessage().contains("certHash") || ex.getMessage().contains("not matched"),
                "Причина падения — несовпадение certHash: " + ex.getMessage());
    }

    @Test
    @DisplayName("PkixException при несовпадении количества CrlOcspRef и OtherCertID + 1")
    void crlOcspRefCountMismatch() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("count test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addCertificate(caCert)
                        .withCAdES()
                        .build();

        // injectValidCertsInjects И certRefs (1 элемент — extractAndVerifyCertificateRefs пройдёт)
        // И revocRefs (0 элементов — count mismatch: 0 != 1 + 1)
        byte[] certRefsDer =
                CAdESCompleteData.encodeCompleteCertificateRefs(
                        List.of(CAdESCompleteData.encodeOtherCertID(caCert, GostOids.DIGEST_256)));
        byte[] certRefsAttr = CmsAttribute.encode(GostOids.COMPLETE_CERTIFICATE_REFS, certRefsDer);

        byte[] emptyRevocDer = DerCodec.encodeSequence();
        byte[] emptyRevocAttr =
                CmsAttribute.encode(GostOids.COMPLETE_REVOCATION_REFS, emptyRevocDer);

        byte[] tampered = injectUnsignedAttrsIntoBes(cadesBes, certRefsAttr, emptyRevocAttr);
        assertThrows(PkixException.class, () -> CAdESExtender.verifyCAdESC(tampered, caCert));
    }

    @Test
    @DisplayName("PkixException при дубликате OtherCertID в CompleteCertificateRefs")
    void duplicateOtherCertId() throws Exception {
        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("dup test".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addCertificate(caCert)
                        .withCAdES()
                        .build();

        byte[] der1 = CAdESCompleteData.encodeOtherCertID(caCert, GostOids.DIGEST_256);
        byte[] der2 = CAdESCompleteData.encodeOtherCertID(caCert, GostOids.DIGEST_256);
        byte[] dupRefs = CAdESCompleteData.encodeCompleteCertificateRefs(List.of(der1, der2));
        byte[] fakeAttr = CmsAttribute.encode(GostOids.COMPLETE_CERTIFICATE_REFS, dupRefs);

        byte[] tampered = injectUnsignedAttrIntoBes(cadesBes, fakeAttr);
        PkixException ex =
                assertThrows(
                        PkixException.class, () -> CAdESExtender.verifyCAdESC(tampered, caCert));
        assertTrue(
                ex.getMessage().contains("duplicate"),
                "Причина падения — дубликат OtherCertID: " + ex.getMessage());
    }

    @Test
    @DisplayName("Revoked-сертификат проходит verifyCAdESC")
    void revokedCertStillPassesCadesC() throws Exception {
        byte[] revokingCrlDer =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(2)
                        .addRevoked(
                                signerCert.getSerialNumberBigInt(),
                                GostSignatureHelper.nowGeneralizedTime())
                        .sign(caKp.getPrivate());
        GostCrl revokingCrl = new GostCrl(revokingCrlDer);

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("revoked passes".getBytes())
                        .addSigner(signerKp.getPrivate(), signerCert)
                        .addCertificate(caCert)
                        .withCAdES()
                        .build();

        List<GostCertificate> chain = List.of(signerCert, caCert);
        byte[] cadesC =
                CAdESExtender.embedCompleteRefs(
                        cadesBes,
                        chain,
                        Arrays.asList(revokingCrl, null),
                        Arrays.asList(null, null));
        assertDoesNotThrow(() -> CAdESExtender.verifyCAdESC(cadesC, caCert));
    }

    @Test
    @DisplayName("512-битные ключи — хэширование Стрибог-512 в CAdES-C")
    void verifyWith512BitKeys() throws Exception {
        ECParameters params512 = ECParameters.tc26a512();
        KeyPair kp512 = KeyGenerator.generateKeyPair(params512);
        GostCertificate cert512 =
                CmsTestUtils.createSelfSignedCertWithDn(
                        kp512.getPrivate(), kp512.getPublic(), BigInteger.valueOf(7), "512Signer");

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("512-bit CAdES-C".getBytes())
                        .addSigner(kp512.getPrivate(), cert512)
                        .withCAdES()
                        .build();

        byte[] crl512Der =
                GostCrlBuilder.create(cert512.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(kp512.getPrivate());
        GostCrl crl512 = new GostCrl(crl512Der);

        byte[] cadesC =
                CAdESExtender.embedCompleteRefs(
                        cadesBes,
                        List.of(cert512),
                        List.of(crl512),
                        Arrays.asList((GostOcspResponse) null));
        assertNotNull(cadesC);
        assertDoesNotThrow(() -> CAdESExtender.verifyCAdESC(cadesC, cert512));
    }

    @Test
    @DisplayName("Multi-signer 256+512: запрещено без явного digestAlgorithm")
    void mixedDigestMultiSigner() throws Exception {
        ECParameters params512 = ECParameters.tc26a512();
        KeyPair kp512 = KeyGenerator.generateKeyPair(params512);
        GostCertificate cert512 =
                CmsTestUtils.createSelfSignedCertWithDn(
                        kp512.getPrivate(), kp512.getPublic(), BigInteger.valueOf(8), "512M");

        // 256-битный signer первый, 512-битный второй — без явного digestAlgorithm
        assertThrows(
                IllegalStateException.class,
                () ->
                        CmsSignedDataBuilder.create()
                                .data("mixed".getBytes())
                                .addSigner(signerKp.getPrivate(), signerCert)
                                .addSigner(kp512.getPrivate(), cert512)
                                .withCAdES()
                                .build());
    }

    // ========================================================================
    // Помошники для инъекции атрибутов в SignedData
    // ========================================================================

    private byte[] injectUnsignedAttrIntoBes(byte[] cadesBesDer, byte[] attrDer) throws Exception {
        CmsContentInfo ci = CmsContentInfo.decode(cadesBesDer);
        byte[][] sdParts = DerCodec.parseSequenceContents(ci.content(), 0);
        int sdIdx = 0;
        byte[] version = sdParts[sdIdx++];
        byte[] digestAlgs = sdParts[sdIdx++];
        byte[] encap = sdParts[sdIdx++];
        byte[] certs = null;
        if (sdIdx < sdParts.length && DerCodec.isContextTag(sdParts[sdIdx], 0))
            certs = sdParts[sdIdx++];
        byte[] crls = null;
        if (sdIdx < sdParts.length && DerCodec.isContextTag(sdParts[sdIdx], 1))
            crls = sdParts[sdIdx++];

        byte[][] siParts = DerCodec.parseSetContents(sdParts[sdIdx], 0);
        List<byte[]> modified = new ArrayList<>();
        for (byte[] siDer : siParts) {
            byte[][] parts = DerCodec.parseSequenceContents(siDer, 0);
            int ui = -1;
            for (int i = 0; i < parts.length; i++) {
                if (parts[i].length > 0 && (parts[i][0] & 0xFF) == DerCodec.TAG_CTX_CONSTRUCTED_1) {
                    ui = i;
                    break;
                }
            }
            if (ui >= 0) {
                byte[] ef = parts[ui];
                int[] li = DerCodec.decodeLength(ef, 1);
                int co = 1 + li[1];
                byte[] ec = Arrays.copyOfRange(ef, co, ef.length);
                List<byte[]> attrs = new ArrayList<>();
                int p = 0;
                while (p < ec.length) {
                    int[] al = DerCodec.decodeLength(ec, p + 1);
                    int at = 1 + al[1] + al[0];
                    attrs.add(Arrays.copyOfRange(ec, p, p + at));
                    p += at;
                }
                attrs.add(attrDer);
                byte[][] sorted = attrs.toArray(new byte[0][]);
                DerCodec.sortDer(sorted);
                parts[ui] = DerCodec.encodeContextConstructed(1, DerCodec.concat(sorted));
            } else {
                parts = Arrays.copyOf(parts, parts.length + 1);
                parts[parts.length - 1] = DerCodec.encodeContextConstructed(1, attrDer);
            }
            modified.add(DerCodec.encodeSequence(parts));
        }

        byte[] newSi = DerCodec.encodeSetOf(modified.toArray(new byte[0][]));
        List<byte[]> sd = new ArrayList<>();
        sd.add(version);
        sd.add(digestAlgs);
        sd.add(encap);
        if (certs != null) sd.add(certs);
        if (crls != null) sd.add(crls);
        sd.add(newSi);
        return CmsContentInfo.encode(
                GostOids.CMS_SIGNED_DATA, DerCodec.encodeSequence(sd.toArray(new byte[0][])));
    }

    /** Встраивает несколько CmsAttribute'ов в unsignedAttrs CAdES-BES. */
    private byte[] injectUnsignedAttrsIntoBes(byte[] cadesBesDer, byte[]... attrDers)
            throws Exception {
        byte[] result = cadesBesDer;
        for (byte[] attr : attrDers) {
            result = injectUnsignedAttrIntoBes(result, attr);
        }
        return result;
    }
}
