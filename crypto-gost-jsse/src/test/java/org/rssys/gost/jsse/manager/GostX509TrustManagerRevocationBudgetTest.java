package org.rssys.gost.jsse.manager;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.ocsp.OcspFetcher;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Предел адресов и общий бюджет времени на загрузки отзыва за одну проверку цепочки. Адреса OCSP и
 * CDP задаёт тот, кто выпустил сертификат, поэтому без этих границ рукопожатие удерживалось бы
 * медленными серверами столько, сколько он захочет.
 */
@DisplayName("GostX509TrustManager: предел адресов и бюджет загрузок отзыва")
class GostX509TrustManagerRevocationBudgetTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final Duration SLOW_FETCH = Duration.ofMillis(600);
    private static final Duration SHORT_BUDGET = Duration.ofMillis(500);

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle intermediate;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
        intermediate =
                signedBy(
                        root,
                        true,
                        new byte[] {(byte) 0x04},
                        aiaOcsp("http://ocsp.example.com/inter"),
                        PkixCertTestHelper.buildCdpExtension("http://crl.example.com/inter.crl"));
    }

    /** Склейка расширений: каждое уже закодировано как Extension. */
    private static byte[] concat(byte[]... parts) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.write(p);
        }
        return out.toByteArray();
    }

    private static PkixCertTestHelper.CertBundle signedBy(
            PkixCertTestHelper.CertBundle issuer, boolean ca, byte[] keyUsage, byte[]... extensions)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                ca ? null : new String[] {"gost.example.com"},
                null,
                keyUsage,
                null,
                ca,
                ca ? 0 : null,
                concat(extensions));
    }

    private static PkixCertTestHelper.CertBundle leaf(byte[]... extensions) throws Exception {
        return signedBy(intermediate, false, null, extensions);
    }

    // --- Минимальный DER для AIA с несколькими адресами OCSP ---

    private static byte[] der(int tag, byte[]... parts) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            body.write(p);
        }
        byte[] content = body.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (content.length < 128) {
            out.write(content.length);
        } else if (content.length < 256) {
            out.write(0x81);
            out.write(content.length);
        } else {
            out.write(0x82);
            out.write(content.length >>> 8);
            out.write(content.length);
        }
        out.write(content);
        return out.toByteArray();
    }

    /** Extension authorityInfoAccess с несколькими адресами OCSP. */
    private static byte[] aiaOcsp(String... uris) throws IOException {
        byte[] ocspOid = {0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01};
        byte[] aiaOid = {0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01};
        ByteArrayOutputStream descriptions = new ByteArrayOutputStream();
        for (String uri : uris) {
            descriptions.write(
                    der(0x30, ocspOid, der(0x86, uri.getBytes(StandardCharsets.US_ASCII))));
        }
        return der(0x30, aiaOid, der(0x04, der(0x30, descriptions.toByteArray())));
    }

    /**
     * Цепочка из свежих копий сертификатов: менеджер кладёт полученный OCSP-ответ прямо в объект
     * сертификата, и общий объект перенёс бы ответ из одного теста в другой.
     */
    private static List<GostCertificate> chain(PkixCertTestHelper.CertBundle leaf)
            throws Exception {
        return List.of(
                new GostCertificate(leaf.cert.getEncoded()),
                new GostCertificate(intermediate.cert.getEncoded()),
                new GostCertificate(root.cert.getEncoded()));
    }

    private static TrustAnchors anchors() {
        return TrustAnchors.ofCertificate(root.cert);
    }

    // --- Заглушки загрузчиков ---

    /** OCSP-загрузчик: считает обращения, ждёт заданное время и отвечает {@code null} или good. */
    private static final class FakeOcspFetcher implements OcspFetcher {
        final AtomicInteger calls = new AtomicInteger();
        private final Duration delay;
        private final boolean answer;

        FakeOcspFetcher(Duration delay, boolean answer) {
            this.delay = delay;
            this.answer = answer;
        }

        @Override
        public byte[] fetch(byte[] certDer, byte[] issuerDer, String ocspResponderUri) {
            calls.incrementAndGet();
            pause(delay);
            if (!answer) {
                return null;
            }
            try {
                GostCertificate cert = new GostCertificate(certDer);
                // Ответ подписывает издатель проверяемого сертификата
                boolean issuedByRoot = java.util.Arrays.equals(issuerDer, root.cert.getEncoded());
                PkixCertTestHelper.CertBundle signer = issuedByRoot ? root : intermediate;
                return GostOcspResponseBuilder.create(cert.getSerialNumber())
                        .issuerDn(signer.subjectDn)
                        .thisUpdate(Instant.now())
                        .noNextUpdate()
                        .sign(signer.priv);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static final class FakeCrlFetcher implements CrlFetcher {
        final AtomicInteger calls = new AtomicInteger();
        private final Duration delay;
        private final java.util.Map<String, byte[]> crlByUri;

        /** Все адреса недоступны. */
        FakeCrlFetcher(Duration delay) {
            this(delay, java.util.Map.of());
        }

        /** Адреса из карты отдают свой CRL, остальные недоступны. */
        FakeCrlFetcher(Duration delay, java.util.Map<String, byte[]> crlByUri) {
            this.delay = delay;
            this.crlByUri = crlByUri;
        }

        @Override
        public byte[] fetch(String crlUri) throws IOException {
            calls.incrementAndGet();
            pause(delay);
            byte[] crl = crlByUri.get(crlUri);
            if (crl == null) {
                throw new IOException("mirror unavailable");
            }
            return crl.clone();
        }
    }

    /** Пустой CRL издателя: сертификат не отозван. */
    private static byte[] emptyCrl(PkixCertTestHelper.CertBundle issuer) throws Exception {
        return PkixCertTestHelper.buildCrl(
                null,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "21060101120000Z",
                false);
    }

    private static void pause(Duration d) {
        try {
            Thread.sleep(d.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static GostX509TrustManager ocspManager(FakeOcspFetcher fetcher) {
        return GostX509TrustManager.fromTrustAnchors(
                anchors(), OcspPolicy.STAPLING_OR_FETCH, fetcher);
    }

    private static GostX509TrustManager crlManager(CrlFetcher fetcher) {
        return GostX509TrustManager.fromTrustAnchors(
                anchors(), OcspPolicy.IF_PRESENT, null, CrlPolicy.REQUIRE, fetcher);
    }

    // ========================================================================
    // Предел адресов
    // ========================================================================

    @Test
    @DisplayName("OCSP: из пяти адресов сертификата пробуются только первые три")
    void ocspAddressCap() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                leaf(
                        aiaOcsp(
                                "http://o1.example.com/",
                                "http://o2.example.com/",
                                "http://o3.example.com/",
                                "http://o4.example.com/",
                                "http://o5.example.com/"));
        FakeOcspFetcher fetcher = new FakeOcspFetcher(Duration.ZERO, false);
        List<GostCertificate> chain = chain(leaf);

        assertThrows(
                CertificateException.class,
                () -> ocspManager(fetcher).validateChainWithOcsp(chain, null, false),
                "без OCSP-ответа STAPLING_OR_FETCH отказывает");

        // Сам сертификат даёт 3 попытки, промежуточный CA со своим адресом - ещё одну
        assertEquals(
                GostX509TrustManager.MAX_REVOCATION_URIS_PER_KIND + 1,
                fetcher.calls.get(),
                "адреса сверх предела не пробуются");
    }

    @Test
    @DisplayName("CDP: из пяти адресов сертификата пробуются только первые три")
    void crlAddressCap() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                leaf(
                        PkixCertTestHelper.buildCdpExtension(
                                "http://c1.example.com/a.crl",
                                "http://c2.example.com/a.crl",
                                "http://c3.example.com/a.crl",
                                "http://c4.example.com/a.crl",
                                "http://c5.example.com/a.crl"));
        FakeCrlFetcher fetcher = new FakeCrlFetcher(Duration.ZERO);
        List<GostCertificate> chain = chain(leaf);

        assertThrows(
                CertificateException.class,
                () -> crlManager(fetcher).validateChainWithOcsp(chain, null, false),
                "REQUIRE без пригодного CRL отказывает");

        // При REQUIRE лист отклоняется после своих трёх адресов, до промежуточного CA дело не
        // доходит
        assertEquals(
                GostX509TrustManager.MAX_REVOCATION_URIS_PER_KIND,
                fetcher.calls.get(),
                "адреса сверх предела не пробуются");
    }

    // ========================================================================
    // Бюджет
    // ========================================================================

    @Test
    @DisplayName("OCSP: бюджет кончился на первом сертификате цепочки, для второго загрузки нет")
    void ocspBudgetCoversWholeChain() throws Exception {
        PkixCertTestHelper.CertBundle leaf = leaf(aiaOcsp("http://o1.example.com/"));
        FakeOcspFetcher fetcher = new FakeOcspFetcher(SLOW_FETCH, false);
        GostX509TrustManager tm = ocspManager(fetcher);
        tm.setRevocationBudgetForTest(SHORT_BUDGET);
        List<GostCertificate> chain = chain(leaf);

        long start = System.nanoTime();
        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, false),
                "неудачная загрузка при STAPLING_OR_FETCH - отказ (fail-closed)");
        long elapsed = (System.nanoTime() - start) / 1_000_000;

        assertEquals(1, fetcher.calls.get(), "после исчерпания бюджета новых загрузок нет");
        assertTrue(
                elapsed < SHORT_BUDGET.toMillis() + 2 * SLOW_FETCH.toMillis(),
                "время " + elapsed + " мс превышает бюджет плюс одну загрузку");
    }

    @Test
    @DisplayName("CRL: бюджет кончился на первом сертификате, для второго загрузки нет")
    void crlBudgetCoversWholeChain() throws Exception {
        PkixCertTestHelper.CertBundle leaf =
                leaf(PkixCertTestHelper.buildCdpExtension("http://c1.example.com/a.crl"));
        // Лист получает годный CRL (иначе при REQUIRE он отказал бы раньше, чем дело дойдёт до
        // промежуточного CA), а загрузка для промежуточного CA должна быть пропущена бюджетом
        FakeCrlFetcher fetcher =
                new FakeCrlFetcher(
                        SLOW_FETCH,
                        java.util.Map.of(
                                "http://c1.example.com/a.crl", emptyCrl(intermediate),
                                "http://crl.example.com/inter.crl", emptyCrl(root)));
        GostX509TrustManager tm = crlManager(fetcher);
        tm.setRevocationBudgetForTest(SHORT_BUDGET);
        List<GostCertificate> chain = chain(leaf);

        assertThrows(
                CertificateException.class,
                () -> tm.validateChainWithOcsp(chain, null, false),
                "при REQUIRE у промежуточного CA нет пригодного CRL: исчерпание бюджета - жёсткий отказ");

        assertEquals(1, fetcher.calls.get(), "после исчерпания бюджета новых загрузок нет");
    }

    @Test
    @DisplayName("Первая загрузка разрешена всегда, даже при нулевом бюджете")
    void firstFetchAlwaysAllowed() throws Exception {
        PkixCertTestHelper.CertBundle leaf = leaf(aiaOcsp("http://o1.example.com/"));
        FakeOcspFetcher fetcher = new FakeOcspFetcher(Duration.ZERO, true);
        GostX509TrustManager tm = ocspManager(fetcher);
        tm.setRevocationBudgetForTest(Duration.ZERO);

        // OCSP-ответ обязателен листу: его первая загрузка разрешена, проверка проходит.
        // Для промежуточного CA загрузка была бы второй, при нулевом бюджете её нет
        assertDoesNotThrow(
                () -> tm.validateChainWithOcsp(chain(leaf), null, false),
                "первая загрузка не должна блокироваться бюджетом");

        assertEquals(1, fetcher.calls.get(), "ровно одна загрузка на весь вызов");
    }

    @Test
    @DisplayName(
            "Попадание в кэш OCSP бюджет не расходует: кэшированный сертификат проходит и при исчерпанном бюджете")
    void cacheHitDoesNotConsumeBudget() throws Exception {
        PkixCertTestHelper.CertBundle leaf1 = leaf(aiaOcsp("http://o1.example.com/"));
        PkixCertTestHelper.CertBundle leaf2 = leaf(aiaOcsp("http://o2.example.com/"));
        FakeOcspFetcher fetcher = new FakeOcspFetcher(Duration.ZERO, true);
        GostX509TrustManager tm = ocspManager(fetcher);

        // Первый вызов с обычным бюджетом: в кэш попадают лист 1 и промежуточный CA
        assertDoesNotThrow(() -> tm.validateChainWithOcsp(chain(leaf1), null, false));
        assertEquals(2, fetcher.calls.get(), "лист 1 и промежуточный CA загружены");

        // Второй: лист 2 не в кэше (разрешённая первая загрузка), промежуточный CA - из кэша.
        // Бюджет исчерпан сразу после первой загрузки, но кэш его не требует
        tm.setRevocationBudgetForTest(Duration.ZERO);
        assertDoesNotThrow(
                () -> tm.validateChainWithOcsp(chain(leaf2), null, false),
                "кэшированный сертификат не должен отказывать из-за исчерпанного бюджета");
        assertEquals(3, fetcher.calls.get(), "загружен только лист 2");
    }

    @Test
    @DisplayName("Бюджет создаётся на вызов: исчерпание в одной проверке не влияет на следующую")
    void budgetIsPerCall() throws Exception {
        PkixCertTestHelper.CertBundle leaf = leaf(aiaOcsp("http://o1.example.com/"));
        FakeOcspFetcher fetcher = new FakeOcspFetcher(Duration.ZERO, false);
        GostX509TrustManager tm = ocspManager(fetcher);
        tm.setRevocationBudgetForTest(Duration.ZERO);
        List<GostCertificate> chain = chain(leaf);

        assertThrows(
                CertificateException.class, () -> tm.validateChainWithOcsp(chain, null, false));
        assertThrows(
                CertificateException.class, () -> tm.validateChainWithOcsp(chain, null, false));

        assertEquals(
                2, fetcher.calls.get(), "в каждом вызове своя первая загрузка, бюджет не копится");
    }
}
