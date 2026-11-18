package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

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
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.pkix.tsp.TspResponseBuilder;
import org.rssys.gost.pkix.tsp.TspTransport;
import org.rssys.gost.signature.ECParameters;

/**
 * В результате проверки X Long остаются только CRL/OCSP, прошедшие проверку валидатора.
 * CRL, привязанный ссылкой к самому якорю, подпись которого никто не проверял (у якоря
 * доказательств отзыва не проверяют), в публичный результат не попадает.
 */
@DisplayName("CAdES-X Long: revocationValues содержит только проверенные CRL/OCSP")
class CAdESXLongVerifiedRevocationValuesTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String TSA_POLICY = "1.2.3.4.5";

    private static KeyPair rootKp;
    private static GostCertificate root;
    private static KeyPair tsaKp;
    private static GostCertificate tsaCert;
    private static KeyPair signerKp;
    private static GostCertificate signerCert;

    private static GostCrl crlForSigner;
    private static GostCrl crlForAnchor;
    private static byte[] xlong;

    @BeforeAll
    static void setUp() throws Exception {
        rootKp = KeyGenerator.generateKeyPair(PARAMS);
        byte[] rootDn = CmsTestUtils.buildDn("Verified Revoc Root");
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
        tsaCert =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Verified Revoc TSA"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(tsaKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .extendedKeyUsage(true, GostOids.EXT_TIME_STAMPING)
                        .sign(rootKp.getPrivate());
        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerCert =
                GostCertificateBuilder.create(PARAMS, CmsTestUtils.buildDn("Verified Revoc Signer"))
                        .issuerDn(root.getSubjectDnBytes())
                        .publicKey(signerKp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(365)
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .sign(rootKp.getPrivate());

        byte[] cadesBes =
                CmsSignedDataBuilder.create()
                        .data("verified revocation values".getBytes())
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
                                .policyOid(TSA_POLICY)
                                .serialNumber(BigInteger.valueOf(serial[0]++))
                                .accuracy(1)
                                .withCAdES()
                                .buildGranted();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                };
        byte[] cadesT = CAdESExtender.addTimestamp(cadesBes, "local://tsa", transport, root);
        // CRL выпускаются после штампа подписи: доказательство обязано быть свежее штампа
        Thread.sleep(1100);
        crlForSigner = crl(1);
        crlForAnchor = crl(2);
        xlong =
                CAdESExtender.embedXLongType1(
                        cadesT,
                        List.of(signerCert, root),
                        Arrays.asList(crlForSigner, crlForAnchor),
                        Arrays.asList((GostOcspResponse) null, null),
                        "local://tsa",
                        transport,
                        root);
    }

    private static GostCrl crl(int number) throws Exception {
        return new GostCrl(
                GostCrlBuilder.create(root.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(number)
                        .sign(rootKp.getPrivate()));
    }

    @Test
    @DisplayName("CRL, привязанный к якорю, в результат не попадает; CRL подписанта остаётся")
    void anchorCrlIsNotReturned() throws Exception {
        VerifiedCAdESData result =
                CAdESVerifier.verifyXLong(xlong, TrustAnchors.ofCertificates(root));

        List<GostCrl> returned = result.signers().get(0).revocationValues().crls();
        assertEquals(1, returned.size(), "только CRL сертификата ниже якоря");
        assertArrayEquals(
                crlForSigner.getEncoded(),
                returned.get(0).getEncoded(),
                "вернулся CRL подписанта, а не якоря");
        assertEquals(
                2,
                result.signers().get(0).completeRevocRefs().size(),
                "ссылки C-уровня по-прежнему покрывают и якорь");
    }
}
