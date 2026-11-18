package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCertificateBuilder.KeyUsage;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * CMS: CRL издателя без права подписывать CRL (KeyUsage без {@code cRLSign}) не принимается ни
 * при обязательной, ни при необязательной проверке отзыва. Молчаливый пропуск такого CRL
 * превратил бы запрет в «данных нет».
 */
@DisplayName("CMS: право издателя CRL на подпись (KeyUsage cRLSign)")
class CmsCrlIssuerKeyUsageTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    /** Подписанный контейнер со встроенным CRL издателя с заданным KeyUsage. */
    private record Scenario(byte[] signed, GostCertificate ca) {}

    private static Scenario scenario(KeyUsage... caUsages) throws Exception {
        KeyPair caKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] caDn = CmsTestUtils.buildDn("CN=Key Usage CA");
        GostCertificate ca =
                GostCertificateBuilder.create(PARAMS, caDn)
                        .issuerDn(caDn)
                        .publicKey(caKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .basicConstraints(true, null)
                        .keyUsage(caUsages)
                        .sign(caKp.getPrivate());
        KeyPair leafKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate leaf =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("CN=Key Usage Leaf"))
                        .issuerDn(ca.getSubjectDnBytes())
                        .publicKey(leafKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(30)
                        .keyUsage(KeyUsage.DIGITAL_SIGNATURE)
                        .sign(caKp.getPrivate());
        byte[] crl =
                GostCrlBuilder.create(ca.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(7)
                        .sign(caKp.getPrivate());
        byte[] signed =
                CmsSignedDataBuilder.create()
                        .data("key usage".getBytes())
                        .addSigner(leafKp.getPrivate(), leaf)
                        .addCertificate(ca)
                        .addCrl(new org.rssys.gost.pkix.cert.GostCrl(crl))
                        .build();
        return new Scenario(signed, ca);
    }

    private static VerifyOptions options(GostCertificate ca, Revocation revocation) {
        return VerifyOptions.trusting(
                TrustAnchors.ofCertificates(ca), SignerSelection.ALL, revocation);
    }

    @Test
    @DisplayName("Издатель с cRLSign: встроенный CRL принимается")
    void issuerWithCrlSignIsAccepted() throws Exception {
        Scenario s = scenario(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN);
        assertDoesNotThrow(
                () ->
                        CmsSignedDataVerifier.verify(
                                s.signed(), options(s.ca(), Revocation.required(List.of()))));
    }

    @Test
    @DisplayName("Издатель с KeyUsage без cRLSign: MISSING_CRL_SIGN при любой политике отзыва")
    void issuerWithoutCrlSignIsRejected() throws Exception {
        Scenario s = scenario(KeyUsage.KEY_CERT_SIGN);
        for (Revocation revocation :
                List.of(Revocation.required(List.of()), Revocation.ifAvailable(List.of()))) {
            PkixException e =
                    assertThrows(
                            PkixException.class,
                            () ->
                                    CmsSignedDataVerifier.verify(
                                            s.signed(), options(s.ca(), revocation)),
                            "CRL издателя без cRLSign не должен молча пропускаться");
            assertEquals(PkixException.Reason.MISSING_CRL_SIGN, e.reason());
        }
    }
}
