package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.util.DerCodec;

/**
 * Приложенный OCSP-ответ приходит от недоверенной стороны: мусор в его поле certs
 * должен приводить к {@link TlsException}, а не к непроверяемому исключению разбора.
 */
@DisplayName("TlsCertUtils.verifyOcspResponse: недоверенный OCSP-ответ с мусором в certs")
class TlsOcspUntrustedInputTest {

    private static PkixCertTestHelper.CertBundle issuer;
    private static PkixCertTestHelper.CertBundle foreign;

    @BeforeAll
    static void setUp() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        issuer = PkixCertTestHelper.createRootCA(params);
        foreign = PkixCertTestHelper.createRootCA(params);
    }

    /** Корректный по TLV элемент certs, не являющийся сертификатом. */
    private static byte[] garbageCert() {
        return DerCodec.encodeSequence(new byte[0]);
    }

    @Test
    @DisplayName("Ответ чужого подписанта с мусором в certs: TlsException (bad_certificate)")
    void foreignSignerWithGarbageCerts_tlsException() {
        byte[] ocsp =
                GostOcspResponseBuilder.create(issuer.cert.getSerialNumber())
                        .issuerDn(issuer.subjectDn)
                        // byKey: при byName построитель сам разбирает первый сертификат из certs
                        .withResponderByKey()
                        .withDelegatedCerts(garbageCert())
                        .sign(foreign.priv);
        GostCertificate subject = new GostCertificate(issuer.cert.getEncoded());
        subject.setOcspResponse(ocsp);

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () -> TlsCertUtils.verifyOcspResponse(subject, issuer.cert),
                        "Недоверенный ответ с мусором в certs должен давать TlsException");
        assertEquals(
                TlsConstants.ALERT_BAD_CERTIFICATE,
                ex.getAlertCode(),
                "Отказ по OCSP — alert bad_certificate");
    }

    @Test
    @DisplayName("Подпись ключом издателя: мусор в certs не мешает")
    void issuerSignatureWithGarbageCerts_accepted() {
        byte[] ocsp =
                GostOcspResponseBuilder.create(issuer.cert.getSerialNumber())
                        .issuerDn(issuer.subjectDn)
                        .withResponderByKey()
                        .withDelegatedCerts(garbageCert())
                        .sign(issuer.priv);
        GostCertificate subject = new GostCertificate(issuer.cert.getEncoded());
        subject.setOcspResponse(ocsp);

        assertDoesNotThrow(
                () -> TlsCertUtils.verifyOcspResponse(subject, issuer.cert),
                "Подпись издателя проверяется напрямую, certs не разбираются");
    }

    @Test
    @DisplayName(
            "Подпись издателя верна, byKey недопустимой длины: TlsException, не IllegalArgumentException")
    void unsupportedByKeyLength_tlsException() {
        byte[] base =
                GostOcspResponseBuilder.create(issuer.cert.getSerialNumber())
                        .issuerDn(issuer.subjectDn)
                        .withResponderByKey()
                        .sign(issuer.priv);
        // 21 байт: допустимо для разбора ответа (20..64), но не 20, 32 и не 64
        byte[] ocsp = PkixCertTestHelper.withResponderKeyHash(base, new byte[21], issuer.priv);
        GostCertificate subject = new GostCertificate(issuer.cert.getEncoded());
        subject.setOcspResponse(ocsp);

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () -> TlsCertUtils.verifyOcspResponse(subject, issuer.cert),
                        "Недопустимая длина byKey при верной подписи должна давать TlsException");
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }
}
