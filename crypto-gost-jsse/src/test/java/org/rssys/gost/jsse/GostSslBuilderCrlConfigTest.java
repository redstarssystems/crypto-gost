package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.engine.EndpointIdentificationMode;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;

@DisplayName("GostSslBuilder: конфигурация лимитов CRL/OCSP")
class GostSslBuilderCrlConfigTest {

    private static byte[] rootCaPem() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        return rootCa.cert.toPem().getBytes(StandardCharsets.US_ASCII);
    }

    @Test
    @DisplayName("null в crlPolicy трактуется как DISABLED (не падает при сборке)")
    void testNullCrlPolicyDefaultsDisabled() throws Exception {
        SSLContext ctx =
                GostSsl.builder().trustCa(rootCaPem()).crlPolicy(null).buildClientContext();
        assertNotNull(ctx, "контекст должен собраться при crlPolicy(null)");
    }

    @Test
    @DisplayName(
            "buildClientContext оставляет режим проверки имени DEFAULT, withoutHostnameVerification даёт DISABLED")
    void testBuildClientContextKeepsDefaultEndpointIdentificationMode() throws Exception {
        SSLContext byDefault = GostSsl.builder().trustCa(rootCaPem()).buildClientContext();
        SSLContext optOut =
                GostSsl.builder()
                        .trustCa(rootCaPem())
                        .withoutHostnameVerification()
                        .buildClientContext();

        assertEquals(
                EndpointIdentificationMode.DEFAULT,
                ((GostSSLSessionContext) byDefault.getClientSessionContext())
                        .getEndpointIdentificationMode(),
                "строгий режим ставит только адаптер Netty, GostSslBuilder его не меняет");
        assertEquals(
                EndpointIdentificationMode.DISABLED,
                ((GostSSLSessionContext) optOut.getClientSessionContext())
                        .getEndpointIdentificationMode(),
                "явное отключение проверки задаёт режим DISABLED");
    }

    @Test
    @DisplayName("buildClientContext с полной CRL/OCSP-конфигурацией успешен")
    void testBuildWithFullCrlConfig() throws Exception {
        SSLContext ctx =
                GostSsl.builder()
                        .trustCa(rootCaPem())
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
                        .trustCa(rootCaPem())
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .maxRevokedEntries(100)
                        .buildServerContext();
        assertNotNull(ctx, "серверный контекст должен собраться с CRL-конфигурацией");
    }

    @Test
    @DisplayName("crlCacheMaxBytes: 0 допустим, отрицательное значение отвергается при сборке")
    void testCrlCacheMaxBytesValidation() throws Exception {
        assertNotNull(
                GostSsl.builder()
                        .trustCa(rootCaPem())
                        .ocsp(false)
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .crlCacheMaxBytes(0)
                        .buildClientContext(),
                "нулевой бюджет допустим");
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostSsl.builder()
                                .trustCa(rootCaPem())
                                .crlCacheMaxBytes(-1)
                                .buildClientContext(),
                "отрицательный бюджет должен отвергаться как ошибка конфигурации");
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostSsl.builder()
                                .trustCa(rootCaPem())
                                .crlCacheMaxBytes(-1)
                                .buildServerContext(),
                "то же для серверного контекста");
    }

    @Test
    @DisplayName("crlMaxAge: значение проверяется сразу, границы проверяет CrlCache")
    void testCrlMaxAgeValidation() {
        GostSslBuilder b = GostSsl.builder();
        assertDoesNotThrow(() -> b.crlMaxAge(java.time.Duration.ZERO));
        assertThrows(
                IllegalArgumentException.class,
                () -> b.crlMaxAge(java.time.Duration.ofSeconds(59)),
                "значение меньше минимальной границы должно отвергаться сразу");
    }
}
