package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
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
 * OtherCertID без issuerSerial (поле необязательно по RFC 5126 §5.7.3.3): сверка идёт
 * по хэшу сертификата, а не падает с NullPointerException.
 */
@DisplayName("CAdES-X Long: OtherCertID без issuerSerial сверяется по хэшу")
class CAdESXLongMissingIssuerSerialTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static GostCertificate certA;
    private static GostCertificate certB;

    @BeforeAll
    static void setUp() throws Exception {
        certA = selfSigned("Hash Only A", 1);
        certB = selfSigned("Hash Only B", 2);
    }

    private static GostCertificate selfSigned(String cn, long serial) throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] dn = CmsTestUtils.buildDn(cn);
        return GostCertificateBuilder.create(PARAMS, dn)
                .issuerDn(dn)
                .publicKey(kp.getPublic())
                .serial(BigInteger.valueOf(serial))
                .notBeforeNow()
                .validForDays(30)
                .basicConstraints(true, null)
                .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                .sign(kp.getPrivate());
    }

    private static CAdESCompleteData.OtherHash hashOf(GostCertificate cert) throws Exception {
        String hashOid = GostSignatureHelper.keySizeToDigestOid(cert.getKeySize());
        return new CAdESCompleteData.OtherHash(
                hashOid, GostSignatureHelper.digestByOid(hashOid, cert.getEncoded()));
    }

    private static CAdESCompleteData.OtherCertID hashOnlyRef(GostCertificate cert)
            throws Exception {
        return new CAdESCompleteData.OtherCertID(hashOf(cert), null);
    }

    private static CAdESCompleteData.OtherCertID fullRef(GostCertificate cert) throws Exception {
        return new CAdESCompleteData.OtherCertID(
                hashOf(cert),
                new CAdESCompleteData.IssuerSerial(
                        cert.getIssuerDnBytes(), cert.getSerialNumberBigInt()));
    }

    @Test
    @DisplayName("Ссылка без issuerSerial с верным хэшем покрывает сертификат (раньше NPE)")
    void hashOnlyRefWithValidHashMatches() throws Exception {
        CAdESCompleteData.OtherCertID ref = hashOnlyRef(certA);

        assertTrue(
                assertDoesNotThrow(() -> CAdESVerifier.matchesCertRef(certA, ref)),
                "ссылка без issuerSerial должна сопоставляться по хэшу");
    }

    @Test
    @DisplayName("Ссылка без issuerSerial с чужим хэшем не покрывает сертификат")
    void hashOnlyRefWithOtherHashDoesNotMatch() throws Exception {
        CAdESCompleteData.OtherCertID ref = hashOnlyRef(certB);

        assertFalse(
                CAdESVerifier.matchesCertRef(certA, ref),
                "хэш другого сертификата не должен совпасть");
    }

    @Test
    @DisplayName("Ссылка с issuerSerial по-прежнему сверяет издателя и серийный номер")
    void fullRefStillComparesIssuerAndSerial() throws Exception {
        CAdESCompleteData.OtherCertID okRef = fullRef(certA);
        CAdESCompleteData.OtherCertID wrongSerialRef =
                new CAdESCompleteData.OtherCertID(
                        hashOf(certA),
                        new CAdESCompleteData.IssuerSerial(
                                certA.getIssuerDnBytes(), BigInteger.valueOf(999)));

        assertTrue(CAdESVerifier.matchesCertRef(certA, okRef), "полная ссылка совпадает");
        assertFalse(
                CAdESVerifier.matchesCertRef(certA, wrongSerialRef),
                "при верном хэше, но чужом serial ссылка не совпадает");
    }

    @Test
    @DisplayName("Две ссылки без issuerSerial с одинаковым хэшем - дубликат")
    void hashOnlyRefsWithSameHashAreDuplicates() throws Exception {
        assertTrue(
                CAdESVerifier.isDuplicateCertRef(hashOnlyRef(certA), hashOnlyRef(certA)),
                "одинаковый хэш без issuerSerial - это одна и та же ссылка");
    }

    @Test
    @DisplayName("Ссылки на разные сертификаты не дубликаты, с issuerSerial и без него")
    void differentCertificatesAreNotDuplicates() throws Exception {
        assertFalse(CAdESVerifier.isDuplicateCertRef(hashOnlyRef(certA), hashOnlyRef(certB)));
        assertFalse(CAdESVerifier.isDuplicateCertRef(hashOnlyRef(certA), fullRef(certB)));
        assertFalse(CAdESVerifier.isDuplicateCertRef(fullRef(certA), fullRef(certB)));
    }

    @Test
    @DisplayName("Ссылки с одинаковыми issuer+serial и разными хэшами остаются дубликатами")
    void sameIssuerSerialDifferentHashIsStillDuplicate() throws Exception {
        CAdESCompleteData.OtherHash otherHash =
                new CAdESCompleteData.OtherHash(
                        GostOids.DIGEST_256, Arrays.copyOf(hashOf(certA).hashValue(), 32));
        otherHash.hashValue()[0] ^= 0x01;
        CAdESCompleteData.OtherCertID tampered =
                new CAdESCompleteData.OtherCertID(
                        otherHash,
                        new CAdESCompleteData.IssuerSerial(
                                certA.getIssuerDnBytes(), certA.getSerialNumberBigInt()));

        assertTrue(
                CAdESVerifier.isDuplicateCertRef(fullRef(certA), tampered),
                "прежнее правило по issuer+serial сохранено");
    }
}
