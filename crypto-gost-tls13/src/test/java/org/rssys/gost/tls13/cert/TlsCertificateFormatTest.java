package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostPkcs12Builder;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

@DisplayName("TlsCertificate — проверка форматов isPem, isPkcs12, pemToDer")
class TlsCertificateFormatTest {

    private static GostCertificate createTestCert() throws Exception {
        ECParameters params = ECParameters.cryptoProA();
        return TlsTestHelper.createCertWithKey(params).cert;
    }

    @Test
    @DisplayName("isPem: PEM-заголовок определяется верно")
    void testIsPemTrue() throws Exception {
        String pem = "-----BEGIN CERTIFICATE-----\nMIIB";
        assertTrue(GostCertificate.isPem(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    @DisplayName("isPem: DER возвращает false")
    void testIsPemDer() throws Exception {
        byte[] der = createTestCert().getEncoded();
        assertFalse(GostCertificate.isPem(der));
    }

    @Test
    @DisplayName("isPem: null и пустой массив возвращают false")
    void testIsPemEdge() {
        assertFalse(GostCertificate.isPem(null));
        assertFalse(GostCertificate.isPem(new byte[0]));
    }

    @Test
    @DisplayName("isPkcs12: PFX-структура определяется верно")
    void testIsPkcs12True() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        byte[] pfx =
                GostPkcs12Builder.create()
                        .key(bundle.priv)
                        .certificate(bundle.cert)
                        .password("test".toCharArray())
                        .iterations(100)
                        .build();
        assertTrue(GostCertificate.isPkcs12(pfx));
    }

    @Test
    @DisplayName("isPkcs12: DER-сертификат возвращает false")
    void testIsPkcs12Der() throws Exception {
        byte[] der = createTestCert().getEncoded();
        assertFalse(GostCertificate.isPkcs12(der));
    }

    @Test
    @DisplayName("isPkcs12: PEM возвращает false")
    void testIsPkcs12Pem() {
        String pem = "-----BEGIN CERTIFICATE-----\nMIIB";
        assertFalse(GostCertificate.isPkcs12(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    @DisplayName("isPkcs12: null и короткие данные возвращают false")
    void testIsPkcs12Edge() {
        assertFalse(GostCertificate.isPkcs12(null));
        assertFalse(GostCertificate.isPkcs12(new byte[5]));
    }

    @Test
    @DisplayName("pemToDer: roundtrip даёт валидный сертификат")
    void testPemToDer() throws Exception {
        GostCertificate cert = createTestCert();
        String pem = cert.toPem();
        byte[] der = GostCertificate.pemToDer(pem.getBytes(StandardCharsets.US_ASCII));
        GostCertificate fromDer = new GostCertificate(der);
        assertArrayEquals(
                cert.getEncoded(),
                fromDer.getEncoded(),
                "pemToDer -> new TlsCertificate должен восстановить исходный сертификат");
    }
}
