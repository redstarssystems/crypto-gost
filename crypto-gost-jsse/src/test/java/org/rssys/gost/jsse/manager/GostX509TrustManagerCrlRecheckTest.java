package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.Security;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.crl.CrlCache;
import org.rssys.gost.jsse.crl.CrlCacheTestSupport;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Перепроверка записи кэша CRL на уровне менеджера: она необязательна и не должна занимать
 * «первую загрузку, разрешённую всегда», которая нужна обязательным загрузкам цепочки.
 */
@DisplayName("GostX509TrustManager: перепроверка CRL не расходует первую загрузку бюджета")
class GostX509TrustManagerCrlRecheckTest {

    private static final String LEAF_CDP = "http://crl.example.com/int.crl";
    private static final String INTERMEDIATE_CDP = "http://crl.example.com/root.crl";
    private static final Duration MAX_AGE = Duration.ofHours(1);

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle intermediate;
    private static GostCertificate leaf;
    private static byte[] leafCrl;
    private static byte[] intermediateCrl;

    @BeforeAll
    static void setUpCerts() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        root = PkixCertTestHelper.createRootCA(params);
        intermediate =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        // keyCertSign | cRLSign: промежуточный УЦ сам выпускает CRL листа
                        new byte[] {(byte) 0x06},
                        null,
                        true,
                        0,
                        PkixCertTestHelper.buildCdpExtension(INTERMEDIATE_CDP));
        leaf =
                PkixCertTestHelper.createCertSignedBy(
                                params,
                                intermediate.priv,
                                intermediate.cert.getPublicKey(),
                                intermediate.subjectDn,
                                "240501120000Z",
                                "21060101120000Z",
                                new String[] {"gost.example.com"},
                                (String[]) null,
                                (byte[]) null,
                                (String[]) null,
                                false,
                                null,
                                PkixCertTestHelper.buildCdpExtension(LEAF_CDP))
                        .cert;
        // CRL листа действует долго; CRL промежуточного УЦ истекает в кэше раньше, чем будет
        // перепроверен лист: тогда обязательная загрузка нужна именно ему
        leafCrl =
                PkixCertTestHelper.buildCrl(
                        null,
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn,
                        "21060101120000Z",
                        false);
        String soon =
                ZonedDateTime.now(ZoneOffset.UTC)
                                .plusMinutes(90)
                                .format(DateTimeFormatter.ofPattern("yyMMddHHmmss"))
                        + "Z";
        intermediateCrl =
                PkixCertTestHelper.buildCrl(
                        null, root.priv, root.cert.getPublicKey(), root.subjectDn, soon, false);
    }

    private static void pause(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static GostX509TrustManager manager(CrlFetcher fetcher) {
        return GostX509TrustManager.fromTrustAnchors(
                TrustAnchors.ofCertificate(root.cert),
                OcspPolicy.IF_PRESENT,
                null,
                CrlPolicy.REQUIRE,
                fetcher);
    }

    private static void validate(GostX509TrustManager tm) throws Exception {
        tm.validateChainWithOcsp(List.of(leaf, intermediate.cert, root.cert), null, false);
    }

    @Test
    @DisplayName("Загрузчик перепроверки: без остатка бюджета - пропуск, первая загрузка цела")
    void recheckLoaderWiring() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        GostX509TrustManager tm =
                manager(
                        uri -> {
                            fetches.incrementAndGet();
                            return leafCrl.clone();
                        });

        GostX509TrustManager.RevocationBudget exhausted =
                new GostX509TrustManager.RevocationBudget(Duration.ofMillis(30));
        Thread.sleep(60);
        CrlCache.Loader skipped = tm.recheckLoader(LEAF_CDP, exhausted);
        assertThrows(CrlCache.LoadSkippedException.class, skipped::fetch, "бюджет исчерпан");
        assertEquals(0, fetches.get(), "сеть не тронута");
        assertTrue(exhausted.tryStart(), "первая загрузка по-прежнему разрешена");

        GostX509TrustManager.RevocationBudget fresh =
                new GostX509TrustManager.RevocationBudget(Duration.ofSeconds(30));
        assertDoesNotThrow(() -> tm.recheckLoader(LEAF_CDP, fresh).fetch());
        assertEquals(1, fetches.get(), "загрузка перепроверки выполнена");
        Thread.sleep(1);
        assertTrue(fresh.tryStart(), "перепроверка не взвела started");
    }

    @Test
    @DisplayName(
            "REQUIRE: перепроверка листового CRL не удалась, обязательная загрузка CRL УЦ выполнена")
    void failedRecheckDoesNotBlockMandatoryLoad() throws Exception {
        AtomicInteger leafFetches = new AtomicInteger();
        AtomicInteger intermediateFetches = new AtomicInteger();
        CrlFetcher fetcher =
                uri -> {
                    if (uri.equals(LEAF_CDP)) {
                        if (leafFetches.getAndIncrement() == 0) {
                            return leafCrl.clone();
                        }
                        // Перепроверка: долго и неудачно, дольше бюджета второй проверки
                        pause(150);
                        throw new IOException("CDP down");
                    }
                    intermediateFetches.incrementAndGet();
                    return intermediateCrl.clone();
                };
        AtomicLong clock = new AtomicLong(System.currentTimeMillis());
        GostX509TrustManager tm = manager(fetcher);
        tm.setCrlCacheForTest(
                CrlCacheTestSupport.withClock(CrlCache.DEFAULT_MAX_BYTES, MAX_AGE, clock::get));

        validate(tm);
        assertEquals(1, leafFetches.get());
        assertEquals(1, intermediateFetches.get());

        // Лист старше предела (нужна перепроверка), CRL промежуточного УЦ истёк в кэше
        clock.addAndGet(Duration.ofHours(2).toMillis());
        tm.setRevocationBudgetForTest(Duration.ofMillis(100));

        assertDoesNotThrow(
                () -> validate(tm),
                "перепроверка не должна лишать обязательную загрузку права на выполнение");

        assertEquals(2, leafFetches.get(), "перепроверка листового CRL выполнена и не удалась");
        assertEquals(2, intermediateFetches.get(), "CRL промежуточного УЦ загружен заново");
    }

    @Test
    @DisplayName(
            "Перепроверка листового CRL условная: валидатор первой загрузки, ответ 304, цепочка проходит")
    void conditionalRecheckUsesValidatorFromFirstLoad() throws Exception {
        String validator = "Sun, 08 Nov 2026 03:08:46 GMT";
        List<String> leafValidators = new java.util.concurrent.CopyOnWriteArrayList<>();
        AtomicInteger intermediateFetches = new AtomicInteger();
        CrlFetcher fetcher =
                new CrlFetcher() {
                    @Override
                    public byte[] fetch(String uri) {
                        return fetchConditional(uri, null).der();
                    }

                    @Override
                    public org.rssys.gost.jsse.crl.CrlFetchResult fetchConditional(
                            String uri, String lastModified) {
                        if (uri.equals(LEAF_CDP)) {
                            leafValidators.add(lastModified);
                            return lastModified == null
                                    ? org.rssys.gost.jsse.crl.CrlFetchResult.full(
                                            leafCrl.clone(), validator)
                                    : org.rssys.gost.jsse.crl.CrlFetchResult.notModified();
                        }
                        intermediateFetches.incrementAndGet();
                        return org.rssys.gost.jsse.crl.CrlFetchResult.full(intermediateCrl.clone());
                    }
                };
        AtomicLong clock = new AtomicLong(System.currentTimeMillis());
        GostX509TrustManager tm = manager(fetcher);
        tm.setCrlCacheForTest(
                CrlCacheTestSupport.withClock(CrlCache.DEFAULT_MAX_BYTES, MAX_AGE, clock::get));

        validate(tm);
        clock.addAndGet(Duration.ofHours(2).toMillis());
        validate(tm);

        assertEquals(
                java.util.Arrays.asList(null, validator),
                leafValidators,
                "первая загрузка безусловная, перепроверка с валидатором первой загрузки");
        assertEquals(2, intermediateFetches.get(), "CRL промежуточного УЦ загружен заново");
    }
}
