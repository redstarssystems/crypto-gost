package org.rssys.gost.jsse;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;

@DisplayName("GostSslBuilder: согласованность настроек отзыва (OCSP, CRL)")
class GostSslBuilderOcspConfigTest {

    private static final OcspFetcher NOOP_FETCHER = (cert, issuer, uri) -> null;

    private static byte[] rootCaPem() throws Exception {
        PkixCertTestHelper.CertBundle rootCa =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        return rootCa.cert.toPem().getBytes(StandardCharsets.US_ASCII);
    }

    @Test
    @DisplayName("ocspFetcher без ocsp(true) -> IllegalStateException, а не молчаливый no-op")
    void fetcherWithoutOcspIsRejected() throws Exception {
        GostSslBuilder builder = GostSsl.builder().trustCa(rootCaPem()).ocspFetcher(NOOP_FETCHER);
        assertThrows(
                IllegalStateException.class,
                builder::buildClientContext,
                "fetcher без обязательного OCSP не должен молча игнорироваться");
        assertThrows(
                IllegalStateException.class,
                builder::buildServerContext,
                "серверная сборка должна отклонять ту же комбинацию");
    }

    @Test
    @DisplayName("trustAll + ocsp(true) или ocspFetcher -> IllegalStateException")
    void trustAllWithOcspIsRejected() {
        assertThrows(
                IllegalStateException.class,
                () -> GostSsl.builder().trustAll().ocsp(true).buildClientContext(),
                "trustAll не выполняет проверок отзыва, ocsp(true) молча не работал бы");
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostSsl.builder()
                                .trustAll()
                                .ocsp(true)
                                .ocspFetcher(NOOP_FETCHER)
                                .buildClientContext(),
                "trustAll с fetcher должен отклоняться");
    }

    @Test
    @DisplayName("ocspFetcher(null) без ocsp(true) допустим")
    void nullFetcherWithoutOcspIsAllowed() throws Exception {
        SSLContext ctx =
                GostSsl.builder().trustCa(rootCaPem()).ocspFetcher(null).buildClientContext();
        assertNotNull(ctx, "контекст должен собраться без fetcher");
    }

    @Test
    @DisplayName("ocsp(true) + ocspFetcher собирается: staple или fetch")
    void ocspWithFetcherBuilds() throws Exception {
        SSLContext ctx =
                GostSsl.builder()
                        .trustCa(rootCaPem())
                        .ocsp(true)
                        .ocspFetcher(NOOP_FETCHER)
                        .buildClientContext();
        assertNotNull(ctx, "контекст должен собраться с ocsp(true) и fetcher");
    }

    @Test
    @DisplayName("Выбор политики: fetcher включает STAPLING_OR_FETCH только при ocsp(true)")
    void policySelection() {
        assertEquals(
                OcspPolicy.IF_PRESENT,
                GostSslBuilder.selectOcspPolicy(false, null),
                "без ocsp(true) staple не обязателен");
        assertEquals(
                OcspPolicy.STAPLING_REQUIRED,
                GostSslBuilder.selectOcspPolicy(true, null),
                "ocsp(true) без fetcher требует staple");
        assertEquals(
                OcspPolicy.STAPLING_OR_FETCH,
                GostSslBuilder.selectOcspPolicy(true, NOOP_FETCHER),
                "ocsp(true) с fetcher разрешает запрос статуса по сети");
    }

    @Test
    @DisplayName("trustAll + CrlPolicy.REQUIRE или IF_CDP_PRESENT -> IllegalStateException")
    void trustAllWithCrlPolicyIsRejected() {
        for (CrlPolicy policy : new CrlPolicy[] {CrlPolicy.REQUIRE, CrlPolicy.IF_CDP_PRESENT}) {
            assertThrows(
                    IllegalStateException.class,
                    () -> GostSsl.builder().trustAll().crlPolicy(policy).buildClientContext(),
                    "trustAll не проверяет отзыв, политика CRL "
                            + policy
                            + " молча не работала бы");
        }
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostSsl.builder()
                                .trustAll()
                                .crlPolicy(CrlPolicy.REQUIRE)
                                .buildServerContext(),
                "серверная сборка должна отклонять ту же комбинацию");
    }

    @Test
    @DisplayName("trustAll вместе с crlFetcher: IllegalStateException")
    void trustAllWithCrlFetcherIsRejected() {
        CrlFetcher fetcher = uri -> null;
        assertThrows(
                IllegalStateException.class,
                () -> GostSsl.builder().trustAll().crlFetcher(fetcher).buildClientContext(),
                "fetcher CRL в trustAll никогда не вызывался бы");
    }

    @Test
    @DisplayName("trustAll с CrlPolicy.DISABLED и без fetcher допустим")
    void trustAllWithDisabledCrlIsAllowed() {
        SSLContext ctx =
                GostSsl.builder()
                        .trustAll()
                        .crlPolicy(CrlPolicy.DISABLED)
                        .crlFetcher(null)
                        .buildClientContext();
        assertNotNull(ctx, "контекст должен собраться без настроек CRL");
    }

    @Test
    @DisplayName("Без trustAll: CrlPolicy.REQUIRE с crlFetcher собирается")
    void crlRequireWithFetcherBuilds() throws Exception {
        CrlFetcher fetcher = uri -> null;
        SSLContext ctx =
                GostSsl.builder()
                        .trustCa(rootCaPem())
                        .crlPolicy(CrlPolicy.REQUIRE)
                        .crlFetcher(fetcher)
                        .buildClientContext();
        assertNotNull(ctx, "контекст должен собраться с CRL-политикой и якорями");
    }

    private static CrlFetcher fetcherWithLimit(int limit) {
        return new CrlFetcher() {
            @Override
            public byte[] fetch(String crlUri) {
                return null;
            }

            @Override
            public int maxResponseSize() {
                return limit;
            }
        };
    }

    @Test
    @DisplayName("Загрузчик CRL с пределом меньше maxCrlSize -> IllegalStateException при сборке")
    void crlFetcherSmallerThanMaxCrlSizeIsRejected() throws Exception {
        GostSslBuilder builder =
                GostSsl.builder()
                        .trustCa(rootCaPem())
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .crlFetcher(fetcherWithLimit(1000))
                        .maxCrlSize(2000);
        IllegalStateException e =
                assertThrows(
                        IllegalStateException.class,
                        builder::buildClientContext,
                        "Загрузчик оборвал бы большой CRL раньше разбора: ошибка конфигурации,"
                                + " а не GostSslException из buildContext");
        assertTrue(e.getMessage().contains("maxResponseSize"), e.getMessage());
    }

    @Test
    @DisplayName(
            "Серверный контекст с mTLS: загрузчик CRL с малым пределом -> IllegalStateException")
    void crlFetcherSmallerThanMaxCrlSizeIsRejectedForServer() throws Exception {
        GostSslBuilder builder =
                GostSsl.builder()
                        .trustCa(rootCaPem())
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .crlFetcher(fetcherWithLimit(1000))
                        .maxCrlSize(2000);
        IllegalStateException e =
                assertThrows(
                        IllegalStateException.class,
                        builder::buildServerContext,
                        "Проверка конфигурации общая для клиентского и серверного контекстов");
        assertTrue(e.getMessage().contains("maxResponseSize"), e.getMessage());
    }

    @Test
    @DisplayName("Загрузчик CRL с достаточным пределом и без переопределения принимается")
    void crlFetcherLimitAcceptedCases() throws Exception {
        byte[] ca = rootCaPem();
        assertNotNull(
                GostSsl.builder()
                        .trustCa(ca)
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .crlFetcher(fetcherWithLimit(2000))
                        .maxCrlSize(2000)
                        .buildClientContext());
        assertNotNull(
                GostSsl.builder()
                        .trustCa(ca)
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .crlFetcher(uri -> null)
                        .maxCrlSize(2000)
                        .buildClientContext(),
                "Лямбда не сообщает предел: не проверяется");
    }

    @Test
    @DisplayName("Загрузчик CRL без crlPolicy (по умолчанию DISABLED): IllegalStateException")
    void crlFetcherWithoutPolicyIsRejected() throws Exception {
        byte[] ca = rootCaPem();
        IllegalStateException failure =
                assertThrows(
                        IllegalStateException.class,
                        () ->
                                GostSsl.builder()
                                        .trustCa(ca)
                                        .crlFetcher(uri -> null)
                                        .buildClientContext(),
                        "загрузчик без политики не используется: отзыв по CRL не проверялся бы");
        assertTrue(failure.getMessage().contains("crlPolicy"), failure.getMessage());
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostSsl.builder()
                                .trustCa(ca)
                                .crlPolicy(CrlPolicy.DISABLED)
                                .crlFetcher(uri -> null)
                                .buildServerContext(),
                "то же для сервера и явного DISABLED");
    }
}
