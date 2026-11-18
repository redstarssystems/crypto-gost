package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidAlgorithmParameterException;
import java.util.List;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

@DisplayName("GostTrustManagerFactorySpi: init с параметрами менеджера доверия")
class GostTrustManagerParametersTest {

    private static GostCertificate caCert() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        return rootCa.cert;
    }

    @Test
    @DisplayName("init с GostTrustManagerParameters даёт сконфигурированный TrustManager")
    void testInitWithParameters() throws Exception {
        GostTrustManagerParameters p =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificate(caCert()))
                        .ocspPolicy(OcspPolicy.IF_PRESENT)
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .maxCrlSize(1024 * 1024)
                        .maxRevokedEntries(1000)
                        .maxOcspAgeMs(3600_000L)
                        .build();

        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        spi.engineInit(p);
        TrustManager[] tms = spi.engineGetTrustManagers();

        assertEquals(1, tms.length, "ожидается один TrustManager");
        assertInstanceOf(GostX509TrustManager.class, tms[0], "должен быть GostX509TrustManager");
    }

    @Test
    @DisplayName("init с чужим ManagerFactoryParameters бросает InvalidAlgorithmParameterException")
    void testInitWithWrongParametersType() {
        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        ManagerFactoryParameters alien = new ManagerFactoryParameters() {};
        assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> spi.engineInit(alien),
                "чужой тип параметров должен отвергаться");
    }

    @Test
    @DisplayName("Дефолты билдера параметров безопасны (CRL DISABLED, OCSP-age по умолчанию)")
    void testBuilderDefaults() throws Exception {
        GostTrustManagerParameters p =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificate(caCert()))
                        .build();
        assertEquals(CrlPolicy.DISABLED, p.getCrlPolicy(), "по умолчанию CRL выключен");
        assertEquals(OcspPolicy.IF_PRESENT, p.getOcspPolicy(), "по умолчанию OCSP IF_PRESENT");
        assertEquals(
                GostOids.MAX_OCSP_AGE_MS,
                p.getMaxOcspAgeMs(),
                "по умолчанию OCSP-age = GostOids.MAX_OCSP_AGE_MS");
    }

    @Test
    @DisplayName("cert-режим: якорь-сертификат доступен")
    void testCertModeAnchorsAvailable() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        GostTrustManagerParameters p =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificates(List.of(root.cert)))
                        .build();
        assertEquals(1, p.getTrustAnchors().certificates().size(), "один якорь-сертификат");
    }

    @Test
    @DisplayName("Билдер без якорей бросает IllegalArgumentException")
    void testBuilderWithoutCaKeysRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostTrustManagerParameters.builder().build(),
                "без якорей параметры не должны собираться");
    }

    private static org.rssys.gost.jsse.crl.CrlFetcher fetcherWithLimit(int limit) {
        return new org.rssys.gost.jsse.crl.CrlFetcher() {
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
    @DisplayName("build: загрузчик CRL с пределом меньше maxCrlSize -> IllegalArgumentException")
    void testBuildRejectsFetcherSmallerThanMaxCrlSize() throws Exception {
        GostTrustManagerParameters.Builder builder =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificate(caCert()))
                        .crlPolicy(CrlPolicy.IF_CDP_PRESENT)
                        .crlFetcher(fetcherWithLimit(1000))
                        .maxCrlSize(2000);

        assertThrows(
                IllegalArgumentException.class,
                builder::build,
                "Загрузчик оборвал бы большой CRL раньше разбора");
        builder.maxCrlSize(1000);
        assertNotNull(builder.build(), "Равный предел допустим");
    }

    @Test
    @DisplayName("build: загрузчик CRL при DISABLED -> IllegalArgumentException")
    void testBuildRejectsFetcherWhenCrlDisabled() throws Exception {
        GostTrustManagerParameters.Builder builder =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificate(caCert()))
                        .crlPolicy(CrlPolicy.DISABLED)
                        .crlFetcher(uri -> null);
        assertThrows(
                IllegalArgumentException.class,
                builder::build,
                "загрузчик без политики не используется: отзыв по CRL не проверялся бы");
    }

    @Test
    @DisplayName("Конструктор менеджера: загрузчик CRL при DISABLED -> IllegalArgumentException")
    void testTrustManagerRejectsFetcherWhenCrlDisabled() throws Exception {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.ofCertificate(caCert()),
                                OcspPolicy.IF_PRESENT,
                                null,
                                CrlPolicy.DISABLED,
                                uri -> null),
                "конструктор доступен и напрямую, мимо построителей");
    }

    @Test
    @DisplayName("Бюджет кэша CRL: по умолчанию 512 МиБ, задаётся билдером, 0 допустим")
    void testCrlCacheMaxBytes() throws Exception {
        GostTrustManagerParameters.Builder builder =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificate(caCert()));
        assertEquals(
                org.rssys.gost.jsse.crl.CrlCache.DEFAULT_MAX_BYTES,
                builder.build().getCrlCacheMaxBytes(),
                "по умолчанию бюджет равен константе кэша");
        assertEquals(
                123_456L,
                builder.crlCacheMaxBytes(123_456L).build().getCrlCacheMaxBytes(),
                "значение билдера доходит до параметров");
        assertEquals(
                0L,
                builder.crlCacheMaxBytes(0).build().getCrlCacheMaxBytes(),
                "0 отключает хранение CRL и допустим");
    }

    @Test
    @DisplayName("Отрицательный бюджет кэша CRL -> IllegalArgumentException при build")
    void testNegativeCrlCacheMaxBytesRejected() throws Exception {
        GostTrustManagerParameters.Builder builder =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificate(caCert()))
                        .crlCacheMaxBytes(-1);
        assertThrows(
                IllegalArgumentException.class,
                builder::build,
                "Отрицательный бюджет должен отвергаться при сборке параметров");
    }

    @Test
    @DisplayName(
            "Предельный возраст записи CRL: по умолчанию 6 часов, задаётся билдером, ноль допустим")
    void testCrlMaxAge() throws Exception {
        GostTrustManagerParameters.Builder builder =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificate(caCert()));
        assertEquals(
                java.time.Duration.ofHours(6),
                builder.build().getCrlMaxAge(),
                "по умолчанию 6 часов");
        assertEquals(
                java.time.Duration.ofHours(6),
                builder.crlMaxAge(java.time.Duration.ofHours(6)).build().getCrlMaxAge(),
                "значение билдера доходит до параметров");
        assertEquals(
                java.time.Duration.ZERO,
                builder.crlMaxAge(java.time.Duration.ZERO).build().getCrlMaxAge(),
                "ноль выключает перепроверку и допустим");
    }

    @Test
    @DisplayName("Предельный возраст записи CRL: значение вне границ отвергается сразу")
    void testInvalidCrlMaxAgeRejected() {
        GostTrustManagerParameters.Builder builder = GostTrustManagerParameters.builder();
        assertThrows(
                IllegalArgumentException.class,
                () -> builder.crlMaxAge(java.time.Duration.ofSeconds(59)),
                "границы проверяет CrlCache, билдер должен делегировать проверку");
    }
}
