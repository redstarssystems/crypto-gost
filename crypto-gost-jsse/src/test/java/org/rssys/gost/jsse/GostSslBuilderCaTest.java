package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

@DisplayName("GostSslBuilder.trustCaFromPem: загрузка доверенных CA")
class GostSslBuilderCaTest {

    @Test
    @DisplayName("Один CA в PEM — buildClientContext успешен")
    void testOneCa() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle rootCa = TlsTestHelper.createRootCA(params);
        String pem = rootCa.cert.toPem();

        GostSsl.builder()
                .trustCaFromPem(pem.getBytes(StandardCharsets.US_ASCII))
                .buildClientContext();
    }

    @Test
    @DisplayName("Два CA в одном PEM — buildClientContext успешен")
    void testTwoCas() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle ca1 = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle ca2 = TlsTestHelper.createRootCA(params);
        String pem = ca1.cert.toPem() + ca2.cert.toPem();

        GostSsl.builder()
                .trustCaFromPem(pem.getBytes(StandardCharsets.US_ASCII))
                .buildClientContext();
    }

    @Test
    @DisplayName("Пустой PEM бросает IllegalArgumentException")
    void testEmptyPem() {
        byte[] emptyPem = "".getBytes(StandardCharsets.US_ASCII);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostSsl.builder().trustCaFromPem(emptyPem),
                "Пустой PEM должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("Метод возвращает this для fluent API")
    void testReturnsThis() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle rootCa = TlsTestHelper.createRootCA(params);
        String pem = rootCa.cert.toPem();

        GostSslBuilder builder = GostSsl.builder();
        assertSame(
                builder,
                builder.trustCaFromPem(pem.getBytes(StandardCharsets.US_ASCII)),
                "trustCaFromPem должен возвращать this");
    }
}
