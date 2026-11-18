package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.crl.CrlCache;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.ClientOcspPolicy;

/**
 * Предел возраста {@code thisUpdate} доходит до проверки приложенного OCSP-ответа через оба
 * публичных входа {@link GostX509TrustManager}: полную {@code fromTrustAnchors} и
 * {@link GostTrustManagerParameters} с {@link GostTrustManagerFactorySpi}.
 */
@DisplayName("GostX509TrustManager: предел возраста thisUpdate (fromTrustAnchors и параметры)")
class GostX509TrustManagerThisUpdateAgeTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final Duration TWO_HOURS = Duration.ofHours(2);

    /**
     * Запас до предела у первого ответа. thisUpdate кодируется с точностью до секунды (дробная
     * часть отбрасывается), поэтому реальный запас лежит в пределах от LIMIT_MARGIN_MS - 1 с до
     * LIMIT_MARGIN_MS; 3 с хватает, чтобы подпись и проверка цепочки на загруженной машине
     * успели до выхода ответа за предел.
     */
    private static final long LIMIT_MARGIN_MS = 3000;

    /** Дополнительное ожидание сверх запаса: ответ гарантированно выходит за предел. */
    private static final long WAIT_PAST_LIMIT_MS = 300;

    private static PkixCertTestHelper.CertBundle root;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
    }

    /** Цепочка клиента: лист с приложенным ответом (thisUpdate 5 ч назад, nextUpdate +30 сут). */
    private static List<GostCertificate> chainWithOldStaple() throws Exception {
        GostCertificate leaf =
                PkixCertTestHelper.createCertSignedBy(
                                PARAMS,
                                root.priv,
                                root.cert.getPublicKey(),
                                root.subjectDn,
                                "240501120000Z",
                                "21060101120000Z",
                                (String[]) null,
                                (String[]) null,
                                new byte[] {(byte) 0x80},
                                new String[] {GostOids.EXT_CLIENT_AUTH},
                                false,
                                null,
                                null)
                        .cert;
        leaf.setOcspResponse(
                GostOcspResponseBuilder.create(leaf.getSerialNumber())
                        .issuerDn(root.subjectDn)
                        .thisUpdate(Instant.now().minus(5, ChronoUnit.HOURS))
                        .nextUpdate(Instant.now().plus(30, ChronoUnit.DAYS))
                        .sign(root.priv));
        return List.of(leaf, root.cert);
    }

    private static GostX509TrustManager viaFromTrustAnchors(Duration limit) {
        return GostX509TrustManager.fromTrustAnchors(
                TrustAnchors.ofCertificate(root.cert),
                OcspPolicy.IF_PRESENT,
                null,
                CrlPolicy.DISABLED,
                null,
                GostCrl.DEFAULT_MAX_CRL_SIZE,
                GostCrl.DEFAULT_MAX_REVOKED_ENTRIES,
                CrlCache.DEFAULT_MAX_BYTES,
                CrlCache.DEFAULT_MAX_AGE,
                GostOids.MAX_OCSP_AGE_MS,
                limit);
    }

    private static GostX509TrustManager viaParameters(Duration limit) throws Exception {
        GostTrustManagerParameters params =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificate(root.cert))
                        .maxThisUpdateAge(limit)
                        .build();
        GostTrustManagerFactorySpi spi = new GostTrustManagerFactorySpi();
        spi.engineInit(params);
        TrustManager[] managers = spi.engineGetTrustManagers();
        return (GostX509TrustManager) managers[0];
    }

    /** Причина отказа - именно предел возраста, а не посторонний сбой проверки. */
    private static void assertRejectedByAgeLimit(Throwable failure) {
        StringBuilder messages = new StringBuilder();
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            messages.append(cause.getMessage()).append(" | ");
        }
        assertTrue(
                messages.toString().contains("older than allowed thisUpdate age"),
                "Ожидался отказ по пределу возраста, получено: " + messages);
    }

    @Test
    @DisplayName("fromTrustAnchors: без предела старый staple принимается, с пределом - отказ")
    void fromTrustAnchors_limitEnforced() throws Exception {
        List<GostCertificate> chain = chainWithOldStaple();

        assertDoesNotThrow(
                () ->
                        viaFromTrustAnchors(null)
                                .validateClientChain(chain, ClientOcspPolicy.REQUEST));
        CertificateException ex =
                assertThrows(
                        CertificateException.class,
                        () ->
                                viaFromTrustAnchors(TWO_HOURS)
                                        .validateClientChain(chain, ClientOcspPolicy.REQUEST),
                        "Предел из fromTrustAnchors должен действовать на присланный staple");
        assertRejectedByAgeLimit(ex);
    }

    @Test
    @DisplayName("Параметры и фабрика: предел доходит до TrustManager и до проверки")
    void parametersAndFactory_limitEnforced() throws Exception {
        List<GostCertificate> chain = chainWithOldStaple();

        assertDoesNotThrow(
                () -> viaParameters(null).validateClientChain(chain, ClientOcspPolicy.REQUEST));
        CertificateException ex =
                assertThrows(
                        CertificateException.class,
                        () ->
                                viaParameters(TWO_HOURS)
                                        .validateClientChain(chain, ClientOcspPolicy.REQUEST),
                        "Предел из GostTrustManagerParameters должен пройти через фабрику");
        assertRejectedByAgeLimit(ex);
    }

    @Test
    @DisplayName("Параметры: геттер, null сбрасывает предел, ноль и отрицательное отвергаются")
    void parameters_validation() throws Exception {
        GostTrustManagerParameters.Builder builder =
                GostTrustManagerParameters.builder()
                        .trustAnchors(TrustAnchors.ofCertificate(root.cert));

        assertNull(builder.build().getMaxThisUpdateAge(), "По умолчанию предел не задан");
        assertEquals(TWO_HOURS, builder.maxThisUpdateAge(TWO_HOURS).build().getMaxThisUpdateAge());
        assertNull(
                builder.maxThisUpdateAge(null).build().getMaxThisUpdateAge(),
                "null сбрасывает предел");
        assertThrows(IllegalArgumentException.class, () -> builder.maxThisUpdateAge(Duration.ZERO));
        assertThrows(
                IllegalArgumentException.class,
                () -> builder.maxThisUpdateAge(Duration.ofSeconds(-1)));
    }

    @Test
    @DisplayName("fromTrustAnchors: ноль и отрицательное значение отвергаются при создании")
    void fromTrustAnchors_rejectsNonPositiveAtCreation() {
        assertThrows(IllegalArgumentException.class, () -> viaFromTrustAnchors(Duration.ZERO));
        assertThrows(
                IllegalArgumentException.class, () -> viaFromTrustAnchors(Duration.ofSeconds(-5)));
    }

    @Test
    @DisplayName("Очень большой предел: проверка не обрывается переполнением")
    void hugeLimit_noOverflow() throws Exception {
        List<GostCertificate> chain = chainWithOldStaple();

        assertDoesNotThrow(
                () ->
                        viaFromTrustAnchors(Duration.ofSeconds(Long.MAX_VALUE))
                                .validateClientChain(chain, ClientOcspPolicy.REQUEST));
    }

    /** Лист с адресом OCSP в AIA: ответ запрашивается по сети, а не приходит приложенным. */
    private static byte[] leafWithAiaDer() throws Exception {
        byte[] aia = PkixCertTestHelper.buildAiaOcspExtension("http://localhost:1/ocsp");
        return PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null,
                        aia)
                .cert
                .getEncoded();
    }

    @Test
    @DisplayName("Кэш OCSP: запись не живёт дольше предела, затем ответ запрашивается заново")
    void cache_entryDoesNotOutliveLimit() throws Exception {
        Duration limit = TWO_HOURS;
        byte[] leafDer = leafWithAiaDer();
        AtomicInteger fetches = new AtomicInteger();
        // Первый ответ почти исчерпал предел, nextUpdate далёкий; следующие ответы свежие.
        // Без учёта предела в сроке записи кэш отдал бы первый ответ повторно, а проверка
        // его отвергла бы
        OcspFetcher fetcher =
                (certDer, issuerDer, uri) -> {
                    GostCertificate cert = new GostCertificate(certDer);
                    Instant thisUpdate =
                            fetches.incrementAndGet() == 1
                                    ? Instant.now().minus(limit).plusMillis(LIMIT_MARGIN_MS)
                                    : Instant.now();
                    return GostOcspResponseBuilder.create(cert.getSerialNumber())
                            .issuerDn(root.subjectDn)
                            .thisUpdate(thisUpdate)
                            .nextUpdate(Instant.now().plus(30, ChronoUnit.DAYS))
                            .sign(root.priv);
                };
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.STAPLING_OR_FETCH,
                        fetcher,
                        CrlPolicy.DISABLED,
                        null,
                        GostCrl.DEFAULT_MAX_CRL_SIZE,
                        GostCrl.DEFAULT_MAX_REVOKED_ENTRIES,
                        CrlCache.DEFAULT_MAX_BYTES,
                        CrlCache.DEFAULT_MAX_AGE,
                        GostOids.MAX_OCSP_AGE_MS,
                        limit);

        tm.validateChainWithOcsp(List.of(new GostCertificate(leafDer), root.cert), null, false);
        assertEquals(1, fetches.get(), "Первое соединение запрашивает ответ у службы");

        // Ждём, пока первый ответ выйдет за предел (запись кэша к этому моменту истекает)
        Thread.sleep(LIMIT_MARGIN_MS + WAIT_PAST_LIMIT_MS);

        assertDoesNotThrow(
                () ->
                        tm.validateChainWithOcsp(
                                List.of(new GostCertificate(leafDer), root.cert), null, false),
                "Устаревшая запись кэша не должна обрывать соединение: нужен новый запрос");
        assertEquals(2, fetches.get(), "После предела ответ запрашивается заново");
    }
}
