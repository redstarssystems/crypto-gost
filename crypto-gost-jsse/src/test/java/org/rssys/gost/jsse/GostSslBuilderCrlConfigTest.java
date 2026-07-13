package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

@DisplayName("GostSslBuilder: конфигурация лимитов CRL/OCSP")
class GostSslBuilderCrlConfigTest {

    private static byte[] rootCaPem() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle rootCa = TlsTestHelper.createRootCA(params);
        return rootCa.cert.toPem().getBytes(StandardCharsets.US_ASCII);
    }

    @Test
    @DisplayName("Fluent-методы CRL/OCSP возвращают this")
    void testFluentReturnsThis() {
        GostSslBuilder b = GostSsl.builder();
        assertSame(b, b.crlPolicy(CrlPolicy.IF_CDP_PRESENT), "crlPolicy должен вернуть this");
        assertSame(b, b.crlFetcher(null), "crlFetcher должен вернуть this");
        assertSame(b, b.maxCrlSize(1024), "maxCrlSize должен вернуть this");
        assertSame(b, b.maxRevokedEntries(10), "maxRevokedEntries должен вернуть this");
        assertSame(b, b.ocspFetcher(null), "ocspFetcher должен вернуть this");
        assertSame(b, b.maxOcspAgeMs(3600_000L), "maxOcspAgeMs должен вернуть this");
    }

    @Test
    @DisplayName("null в crlPolicy трактуется как DISABLED (не падает при сборке)")
    void testNullCrlPolicyDefaultsDisabled() throws Exception {
        SSLContext ctx =
                GostSsl.builder().trustCaFromPem(rootCaPem()).crlPolicy(null).buildClientContext();
        assertNotNull(ctx, "контекст должен собраться при crlPolicy(null)");
    }

    @Test
    @DisplayName("buildClientContext с полной CRL/OCSP-конфигурацией успешен")
    void testBuildWithFullCrlConfig() throws Exception {
        SSLContext ctx =
                GostSsl.builder()
                        .trustCaFromPem(rootCaPem())
                        .ocsp(false)
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .maxCrlSize(2 * 1024 * 1024)
                        .maxRevokedEntries(50_000)
                        .maxOcspAgeMs(6 * 3600_000L)
                        .buildClientContext();
        assertNotNull(ctx, "клиентский контекст должен собраться с полной CRL/OCSP-конфигурацией");
    }

    @Test
    @DisplayName("buildServerContext с CRL-конфигурацией успешен")
    void testBuildServerWithCrlConfig() throws Exception {
        SSLContext ctx =
                GostSsl.builder()
                        .trustCaFromPem(rootCaPem())
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .maxRevokedEntries(100)
                        .buildServerContext();
        assertNotNull(ctx, "серверный контекст должен собраться с CRL-конфигурацией");
    }
}
