package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Ожидание чужой загрузки CRL ограничено остатком бюджета проверки: соединение, не дождавшееся
 * инициатора, считает адрес недоступным и дальше решает политика отзыва.
 */
@DisplayName("GostX509TrustManager: ожидание чужой загрузки CRL ограничено бюджетом")
class GostX509TrustManagerCrlWaitTest {

    private static final String CDP = "http://crl.example.com/root.crl";
    // Малый бюджет: ожидающий сдаётся быстро. Инициатор бюджетом не ограничен (первая загрузка)
    private static final Duration TINY_BUDGET = Duration.ofMillis(100);

    private static PkixCertTestHelper.CertBundle root;
    private static GostCertificate leaf;
    private static byte[] crlDer;

    private LogCapture log;

    @BeforeAll
    static void setUpCerts() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        root = PkixCertTestHelper.createRootCA(params);
        crlDer =
                PkixCertTestHelper.buildCrl(
                        null,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "21060101120000Z",
                        false);
        leaf =
                PkixCertTestHelper.createCertSignedBy(
                                params,
                                root.priv,
                                root.cert.getPublicKey(),
                                root.subjectDn,
                                "240501120000Z",
                                "21060101120000Z",
                                new String[] {"gost.example.com"},
                                (String[]) null,
                                (byte[]) null,
                                (String[]) null,
                                false,
                                null,
                                PkixCertTestHelper.buildCdpExtension(CDP))
                        .cert;
    }

    @BeforeEach
    void captureLogger() {
        log = LogCapture.start(LogCapture.JSSE);
    }

    @AfterEach
    void restoreLogger() {
        log.close();
    }

    /** Загрузчик, удерживающий инициатора, пока тест не отпустит его. */
    private static final class HeldFetcher implements CrlFetcher {
        final CountDownLatch inside = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final AtomicInteger calls = new AtomicInteger();

        @Override
        public byte[] fetch(String crlUri) {
            calls.incrementAndGet();
            inside.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return crlDer.clone();
        }
    }

    private GostX509TrustManager manager(CrlPolicy policy, HeldFetcher fetcher) {
        GostX509TrustManager tm =
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(root.cert),
                        OcspPolicy.IF_PRESENT,
                        null,
                        policy,
                        fetcher);
        tm.setRevocationBudgetForTest(TINY_BUDGET);
        return tm;
    }

    private void validate(GostX509TrustManager tm) throws Exception {
        tm.validateChainWithOcsp(List.of(leaf, root.cert), null, false);
    }

    @Test
    @DisplayName("REQUIRE: ожидающий не дождался инициатора - отказ; инициатор завершается успешно")
    void requireRejectsGaveUpWaiter() throws Exception {
        HeldFetcher fetcher = new HeldFetcher();
        GostX509TrustManager tm = manager(CrlPolicy.REQUIRE, fetcher);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<Void> leader =
                    pool.submit(
                            () -> {
                                validate(tm);
                                return null;
                            });
            assertTrue(fetcher.inside.await(10, TimeUnit.SECONDS), "инициатор в загрузке");

            assertThrows(CertificateException.class, () -> validate(tm), "fail-closed при REQUIRE");

            assertEquals(1, fetcher.calls.get(), "ожидающий не загружал сам");
            fetcher.release.countDown();
            assertDoesNotThrow(() -> leader.get(30, TimeUnit.SECONDS), "инициатор не пострадал");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("IF_CDP_PRESENT: ожидающий не дождался - проверка пропущена, зеркало недоступно")
    void ifCdpPresentSkipsForGaveUpWaiter() throws Exception {
        HeldFetcher fetcher = new HeldFetcher();
        GostX509TrustManager tm = manager(CrlPolicy.IF_CDP_PRESENT, fetcher);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<Void> leader =
                    pool.submit(
                            () -> {
                                validate(tm);
                                return null;
                            });
            assertTrue(fetcher.inside.await(10, TimeUnit.SECONDS), "инициатор в загрузке");

            assertDoesNotThrow(() -> validate(tm), "при IF_CDP_PRESENT проверка пропускается");

            List<String> lines = log.allMessages("GostX509TrustManager");
            assertTrue(
                    lines.stream()
                            .anyMatch(
                                    l ->
                                            l.contains("CRL mirror unavailable")
                                                    && l.contains("TIMEOUT")),
                    "сдача идёт общей веткой «зеркало недоступно»: " + lines);
            assertEquals(1, fetcher.calls.get(), "ожидающий не загружал сам");
            fetcher.release.countDown();
            assertDoesNotThrow(() -> leader.get(30, TimeUnit.SECONDS), "инициатор не пострадал");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("Остаток бюджета считается от создания, а не «полный до первой загрузки»")
    void remainingCountsFromCreation() throws Exception {
        GostX509TrustManager.RevocationBudget budget =
                new GostX509TrustManager.RevocationBudget(Duration.ofMillis(300));

        Thread.sleep(200);

        // tryStart ещё не вызывался: ожидание флаг не взводит, но окно бюджета уже тратится
        assertTrue(
                budget.remaining().toMillis() <= 150,
                "остаток должен уменьшаться без первой загрузки: " + budget.remaining());
        Thread.sleep(150);
        assertEquals(Duration.ZERO, budget.remaining(), "исчерпанный бюджет - нулевой остаток");
        assertTrue(budget.tryStart(), "первая загрузка разрешена и при исчерпанном бюджете");
        assertTrue(!budget.tryStart(), "вторая загрузка после исчерпания не разрешена");
    }

    @Test
    @DisplayName("Перепроверка не расходует первую загрузку: hasRemaining не взводит started")
    void recheckDoesNotConsumeFirstLoad() throws Exception {
        GostX509TrustManager.RevocationBudget budget =
                new GostX509TrustManager.RevocationBudget(Duration.ofMillis(50));
        Thread.sleep(80);

        assertTrue(!budget.hasRemaining(), "окно бюджета исчерпано, перепроверка не стартует");
        assertTrue(budget.tryStart(), "обязательная первая загрузка по-прежнему разрешена");
        assertTrue(!budget.tryStart(), "вторая после исчерпания - нет");
    }
}
