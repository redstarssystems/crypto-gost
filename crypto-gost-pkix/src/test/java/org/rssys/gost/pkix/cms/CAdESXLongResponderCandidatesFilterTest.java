package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.signature.ECParameters;

/**
 * Отбор кандидатов в OCSP-ответчики из certificate-values: кандидатом становится
 * только сертификат с CAdES-C reference вне первичной цепочки и якорей.
 */
@DisplayName("CAdES-X Long: отбор кандидатов-ответчиков из certificate-values")
class CAdESXLongResponderCandidatesFilterTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static GostCertificate root;
    private static GostCertificate leaf;
    private static GostCertificate referenced;
    private static GostCertificate unreferenced;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPair rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = CmsTestUtils.buildDn("Filter Root");
        root =
                GostCertificateBuilder.create(PARAMS, rootDn)
                        .issuerDn(rootDn)
                        .publicKey(rootKp.getPublic())
                        .serial(BigInteger.ONE)
                        .notBeforeNow()
                        .validForDays(365)
                        .basicConstraints(true, null)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .sign(rootKp.getPrivate());
        leaf = issued(rootKp, "Filter Leaf", 2, GostOids.EXT_SERVER_AUTH);
        referenced = issued(rootKp, "Filter Responder", 3, GostOids.EXT_OCSP_SIGNING);
        unreferenced = issued(rootKp, "Filter Extra", 4, GostOids.EXT_OCSP_SIGNING);
    }

    private static GostCertificate issued(KeyPair issuerKp, String cn, long serial, String eku)
            throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        return GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn(cn))
                .issuerDn(root.getSubjectDnBytes())
                .publicKey(kp.getPublic())
                .serial(BigInteger.valueOf(serial))
                .notBeforeNow()
                .validForDays(30)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(true, eku)
                .sign(issuerKp.getPrivate());
    }

    private static CAdESCompleteData.OtherCertID ref(GostCertificate cert) throws Exception {
        String hashOid = GostSignatureHelper.keySizeToDigestOid(cert.getKeySize());
        return new CAdESCompleteData.OtherCertID(
                new CAdESCompleteData.OtherHash(
                        hashOid, GostSignatureHelper.digestByOid(hashOid, cert.getEncoded())),
                new CAdESCompleteData.IssuerSerial(
                        cert.getIssuerDnBytes(), cert.getSerialNumberBigInt()));
    }

    @Test
    @DisplayName("С C-ссылкой и вне цепочки - кандидат; без ссылки и из цепочки - нет")
    void onlyReferencedCertificatesOutsideChainBecomeCandidates() throws Exception {
        List<GostCertificate> certValues = List.of(leaf, referenced, unreferenced, root);
        List<CAdESCompleteData.OtherCertID> refs = List.of(ref(referenced), ref(root));

        List<GostCertificate> candidates =
                CAdESVerifier.selectOcspResponderCandidates(
                        certValues, refs, List.of(leaf, root), new GostCertificate[] {root});

        assertEquals(1, candidates.size(), "кандидат только сертификат с C-ссылкой вне цепочки");
        assertSame(referenced, candidates.get(0));
    }

    @Test
    @DisplayName("Дубликат в certificate-values не размножает кандидата")
    void duplicateIsCollapsed() throws Exception {
        List<GostCertificate> candidates =
                CAdESVerifier.selectOcspResponderCandidates(
                        List.of(referenced, referenced),
                        List.of(ref(referenced)),
                        List.of(leaf, root),
                        new GostCertificate[] {root});

        assertEquals(1, candidates.size());
    }
}
