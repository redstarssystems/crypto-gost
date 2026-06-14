package org.rssys.gost.tls13.cert;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("TlsCertificate — isPem, isPkcs12, pemToDer")
class TlsCertificateFormatTest {

    private static TlsCertificate createTestCert() throws Exception {
        ECParameters params = ECParameters.cryptoProA();
        return TlsTestHelper.createCertWithKey(params).cert;
    }

    @Test
    @DisplayName("isPem: PEM-заголовок определяется верно")
    void testIsPemTrue() throws Exception {
        String pem = "-----BEGIN CERTIFICATE-----\nMIIB";
        assertTrue(TlsCertificate.isPem(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    @DisplayName("isPem: DER возвращает false")
    void testIsPemDer() throws Exception {
        byte[] der = createTestCert().getEncoded();
        assertFalse(TlsCertificate.isPem(der));
    }

    @Test
    @DisplayName("isPem: null и пустой массив возвращают false")
    void testIsPemEdge() {
        assertFalse(TlsCertificate.isPem(null));
        assertFalse(TlsCertificate.isPem(new byte[0]));
    }

    @Test
    @DisplayName("isPkcs12: PFX-структура определяется верно")
    void testIsPkcs12True() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        byte[] pfx = GostPkcs12Builder.newBuilder()
                .key(bundle.priv)
                .certificate(bundle.cert)
                .password("test".toCharArray())
                .iterations(100)
                .build();
        assertTrue(TlsCertificate.isPkcs12(pfx));
    }

    @Test
    @DisplayName("isPkcs12: DER-сертификат возвращает false")
    void testIsPkcs12Der() throws Exception {
        byte[] der = createTestCert().getEncoded();
        assertFalse(TlsCertificate.isPkcs12(der));
    }

    @Test
    @DisplayName("isPkcs12: PEM возвращает false")
    void testIsPkcs12Pem() {
        String pem = "-----BEGIN CERTIFICATE-----\nMIIB";
        assertFalse(TlsCertificate.isPkcs12(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    @DisplayName("isPkcs12: null и короткие данные возвращают false")
    void testIsPkcs12Edge() {
        assertFalse(TlsCertificate.isPkcs12(null));
        assertFalse(TlsCertificate.isPkcs12(new byte[5]));
    }

    @Test
    @DisplayName("pemToDer: roundtrip даёт валидный сертификат")
    void testPemToDer() throws Exception {
        TlsCertificate cert = createTestCert();
        String pem = cert.toPem();
        byte[] der = TlsCertificate.pemToDer(pem.getBytes(StandardCharsets.US_ASCII));
        TlsCertificate fromDer = new TlsCertificate(der);
        assertArrayEquals(cert.getCertData(), fromDer.getCertData(),
                "pemToDer → new TlsCertificate должен восстановить исходный сертификат");
    }
}
