package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.jsse.crl.CrlCache.CrlKey;
import org.rssys.gost.jsse.crl.CrlCache.Loaded;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.CrlLimits;
import org.rssys.gost.pkix.cert.CrlVerifier;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.VerifiedCrl;
import org.rssys.gost.pkix.util.Deadline;
import org.rssys.gost.pkix.util.DeadlineExceededException;
import org.rssys.gost.signature.ECParameters;

/**
 * Модульные тесты {@link CrlCache}: проверенные CRL, единственная загрузка, бюджет памяти,
 * вытеснение и защита от отката.
 */
@DisplayName("CrlCache: кэш проверенных CRL")
class CrlCacheTest {

    private static final String URI = "http://crl.example.com/root.crl";
    private static final Duration NO_LIMIT = Deadline.MAX_FETCH_TIMEOUT;
    private static final String ISSUER_HASH = "aa";
    private static final long FUTURE_DAYS = 30;

    private static KeyPair issuer;
    private static GostCertificate issuerCert;

    @BeforeAll
    static void setUp() {
        issuer = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        issuerCert =
                GostCertificateBuilder.create(ECParameters.tc26a256(), "CN=CRL Test Issuer,C=RU")
                        .publicKey(issuer.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(3650)
                        .basicConstraints(true, null)
                        .sign(issuer.getPrivate());
    }

    private static CrlKey key(String uri) {
        return new CrlKey(uri, ISSUER_HASH);
    }

    /** CRL издателя теста; серийные номера 1..revoked отозваны. */
    private static byte[] crl(Integer number, Instant nextUpdate, int revoked) {
        GostCrlBuilder builder =
                GostCrlBuilder.create("CN=Cache Root,C=RU")
                        .thisUpdate(Instant.now().minus(Duration.ofDays(2)));
        if (number != null) {
            builder = builder.withCrlNumber(number);
        }
        if (nextUpdate != null) {
            builder = builder.nextUpdate(nextUpdate);
        }
        for (int i = 1; i <= revoked; i++) {
            builder = builder.addRevoked(BigInteger.valueOf(i), "20260101000000Z");
        }
        return builder.sign(issuer.getPrivate());
    }

    private static byte[] crl(int number) {
        return crl(number, Instant.now().plus(Duration.ofDays(FUTURE_DAYS)), 1);
    }

    private static VerifiedCrl authenticate(byte[] der) throws PkixException {
        return CrlVerifier.authenticate(
                der,
                issuerCert,
                new CrlLimits(GostCrl.DEFAULT_MAX_CRL_SIZE, GostCrl.DEFAULT_MAX_REVOKED_ENTRIES));
    }

    private static void pause(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted in test", e);
        }
    }

    private static void awaitLatch(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted in test", e);
        }
    }

    /** Сбой потока-инициатора, имитируемый внутри загрузчика. */
    @FunctionalInterface
    private interface LeaderFailure {
        void fail() throws IOException;
    }

    /** Загрузчик, считающий вызовы. */
    private static final class CountingLoader implements CrlCache.Loader {
        final AtomicInteger calls = new AtomicInteger();
        final byte[] der;

        CountingLoader(byte[] der) {
            this.der = der;
        }

        @Override
        public byte[] fetch() {
            calls.incrementAndGet();
            return der;
        }
    }

    // ------------------------------------------------------------------------
    // Базовое поведение
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Первый get загружает и проверяет, второй берёт из кэша без загрузки")
    void secondGetComesFromCache() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        CountingLoader loader = new CountingLoader(crl(1));

        Loaded first = cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);
        Loaded second = cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);

        assertFalse(first.fromCache(), "первый вызов загружает CRL");
        assertTrue(second.fromCache(), "второй вызов берёт готовый объект из кэша");
        assertSame(first.crl(), second.crl(), "объект проверки общий");
        assertEquals(1, loader.calls.get(), "загрузка выполняется один раз");
        assertEquals(BigInteger.ONE, cache.lastKnownCrlNumber(key(URI)), "номер запомнен");
    }

    @Test
    @DisplayName("Null-аргументы -> NullPointerException; отрицательный бюджет -> IAE")
    void argumentValidation() {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        assertThrows(
                NullPointerException.class,
                () -> cache.get(null, () -> null, null, d -> null, NO_LIMIT));
        assertThrows(
                NullPointerException.class,
                () -> cache.get(key(URI), null, null, d -> null, NO_LIMIT));
        assertThrows(
                NullPointerException.class,
                () -> cache.get(key(URI), () -> null, null, null, NO_LIMIT));
        assertThrows(NullPointerException.class, () -> cache.lastKnownCrlNumber(null));
        assertThrows(IllegalArgumentException.class, () -> new CrlCache(-1, Duration.ZERO));
    }

    @Test
    @DisplayName("Разные адреса и разные издатели не делят запись")
    void differentKeysAreIndependent() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        CountingLoader loader = new CountingLoader(crl(1));

        cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);
        cache.get(
                key("http://crl.example.com/other.crl"),
                loader,
                null,
                CrlCacheTest::authenticate,
                NO_LIMIT);
        cache.get(new CrlKey(URI, "bb"), loader, null, CrlCacheTest::authenticate, NO_LIMIT);

        assertEquals(3, loader.calls.get(), "каждый ключ загружается отдельно");
        assertEquals(3, cache.size(), "три записи");
    }

    @Test
    @DisplayName("Загрузчик вернул null -> IOException, запись не создаётся")
    void nullDataIsIoException() {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        assertThrows(
                IOException.class,
                () -> cache.get(key(URI), () -> null, null, CrlCacheTest::authenticate, NO_LIMIT),
                "отсутствие данных равно недоступному адресу");
        assertEquals(0, cache.size(), "ничего не кэшируется");
    }

    @Test
    @DisplayName("Ошибка не кэшируется: следующий запрос грузит заново и успешен")
    void failureIsNotCached() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        AtomicInteger calls = new AtomicInteger();
        byte[] der = crl(1);
        CrlCache.Loader flaky =
                () -> {
                    if (calls.incrementAndGet() == 1) {
                        throw new IOException("network down");
                    }
                    return der;
                };

        assertThrows(
                IOException.class,
                () -> cache.get(key(URI), flaky, null, CrlCacheTest::authenticate, NO_LIMIT));
        Loaded second = cache.get(key(URI), flaky, null, CrlCacheTest::authenticate, NO_LIMIT);

        assertNotNull(second.crl(), "повторный запрос после ошибки успешен");
        assertEquals(2, calls.get(), "после ошибки CRL загружается снова");
    }

    @Test
    @DisplayName("CRL с неверной подписью не попадает в кэш и не запоминает номер")
    void crlWithForeignSignatureIsNotCached() {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        KeyPair other = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        byte[] foreignSigned =
                GostCrlBuilder.create("CN=Cache Root,C=RU")
                        .thisUpdate(Instant.now().minus(Duration.ofDays(2)))
                        .nextUpdate(Instant.now().plus(Duration.ofDays(FUTURE_DAYS)))
                        .withCrlNumber(999)
                        .sign(other.getPrivate());

        assertThrows(
                PkixException.class,
                () ->
                        cache.get(
                                key(URI),
                                new CountingLoader(foreignSigned),
                                null,
                                CrlCacheTest::authenticate,
                                NO_LIMIT));

        assertEquals(0, cache.size(), "CRL с чужой подписью не кэшируется");
        assertNull(
                cache.lastKnownCrlNumber(key(URI)),
                "номер из CRL с чужой подписью не запоминается");
    }

    @Test
    @DisplayName("CRL без nextUpdate отвергается проверкой, не кэшируется и не запоминает номер")
    void crlWithoutNextUpdateIsNotCached() {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        byte[] withoutNextUpdate =
                GostCrlBuilder.create("CN=Cache Root,C=RU")
                        .thisUpdate(Instant.now().minus(Duration.ofDays(2)))
                        .withoutNextUpdate()
                        .withCrlNumber(7)
                        .sign(issuer.getPrivate());

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                cache.get(
                                        key(URI),
                                        new CountingLoader(withoutNextUpdate),
                                        null,
                                        CrlCacheTest::authenticate,
                                        NO_LIMIT),
                        "CRL без nextUpdate должен быть отвергнут проверкой");

        assertEquals(
                PkixException.Reason.NEXT_UPDATE_MISSING,
                e.reason(),
                "причина отказа должна быть NEXT_UPDATE_MISSING");
        assertEquals(0, cache.size(), "CRL без nextUpdate не кэшируется");
        assertNull(cache.lastKnownCrlNumber(key(URI)), "его номер не запоминается");
    }

    @Test
    @DisplayName("invalidate удаляет запись с этим объектом; следующий get загружает заново")
    void invalidateRemovesEntry() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        CountingLoader loader = new CountingLoader(crl(1));
        Loaded first = cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);

        cache.invalidate(key(URI), first.crl());
        cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);

        assertEquals(2, loader.calls.get(), "после invalidate CRL загружается заново");
    }

    // ------------------------------------------------------------------------
    // Срок записи и защита от отката
    // ------------------------------------------------------------------------

    @Test
    @DisplayName(
            "Запись истекает после nextUpdate + допуск часов; номер для защиты от отката остаётся")
    void entryExpiresButCrlNumberSurvives() throws Exception {
        AtomicLong clock = new AtomicLong(System.currentTimeMillis());
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO, clock::get);
        CountingLoader loader = new CountingLoader(crl(7));
        cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);

        clock.addAndGet(Duration.ofDays(FUTURE_DAYS + 1).toMillis());
        assertEquals(BigInteger.valueOf(7), cache.lastKnownCrlNumber(key(URI)), "номер жив");
        Loaded reloaded = cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);

        assertFalse(reloaded.fromCache(), "просроченная запись не отдаётся");
        assertEquals(2, loader.calls.get(), "после истечения CRL загружается заново");
    }

    @Test
    @DisplayName("Откат cRLNumber ниже запомненного отвергается для всех")
    void rollbackIsRejected() throws Exception {
        AtomicLong clock = new AtomicLong(System.currentTimeMillis());
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO, clock::get);
        cache.get(
                key(URI), new CountingLoader(crl(10)), null, CrlCacheTest::authenticate, NO_LIMIT);
        clock.addAndGet(Duration.ofDays(FUTURE_DAYS + 1).toMillis());

        PkixException e =
                assertThrows(
                        PkixException.class,
                        () ->
                                cache.get(
                                        key(URI),
                                        new CountingLoader(crl(3)),
                                        null,
                                        CrlCacheTest::authenticate,
                                        NO_LIMIT),
                        "CRL с номером ниже 10 должен отвергаться как откат");
        assertTrue(e.getMessage().contains("downgrade"), "причина - откат номера");
        assertEquals(BigInteger.TEN, cache.lastKnownCrlNumber(key(URI)), "baseline не снижен");
    }

    @Test
    @DisplayName("CRL без cRLNumber при существующем baseline отвергается")
    void crlWithoutNumberRejectedWhenBaselineExists() throws Exception {
        AtomicLong clock = new AtomicLong(System.currentTimeMillis());
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO, clock::get);
        cache.get(
                key(URI), new CountingLoader(crl(10)), null, CrlCacheTest::authenticate, NO_LIMIT);
        clock.addAndGet(Duration.ofDays(FUTURE_DAYS + 1).toMillis());

        byte[] noNumber = crl(null, Instant.now().plus(Duration.ofDays(FUTURE_DAYS)), 1);
        assertThrows(
                PkixException.class,
                () ->
                        cache.get(
                                key(URI),
                                new CountingLoader(noNumber),
                                null,
                                CrlCacheTest::authenticate,
                                NO_LIMIT),
                "CRL без номера при известном baseline - возможный откат");
    }

    @Test
    @DisplayName("Номер запоминается только вверх")
    void crlNumberOnlyGrows() throws Exception {
        AtomicLong clock = new AtomicLong(System.currentTimeMillis());
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO, clock::get);
        cache.get(key(URI), new CountingLoader(crl(5)), null, CrlCacheTest::authenticate, NO_LIMIT);
        clock.addAndGet(Duration.ofDays(FUTURE_DAYS + 1).toMillis());
        cache.get(key(URI), new CountingLoader(crl(9)), null, CrlCacheTest::authenticate, NO_LIMIT);

        assertEquals(BigInteger.valueOf(9), cache.lastKnownCrlNumber(key(URI)), "номер вырос");
    }

    // ------------------------------------------------------------------------
    // Бюджет памяти
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Оценка удержания растёт с длиной DER и числом отозванных записей")
    void estimateGrowsWithEntries() throws Exception {
        byte[] small = crl(1, Instant.now().plus(Duration.ofDays(FUTURE_DAYS)), 1);
        byte[] big = crl(1, Instant.now().plus(Duration.ofDays(FUTURE_DAYS)), 11);
        VerifiedCrl vSmall = authenticate(small);
        VerifiedCrl vBig = authenticate(big);

        assertTrue(vSmall.getEstimatedBytes() > small.length, "оценка больше длины DER");
        assertTrue(
                vBig.getEstimatedBytes() - vSmall.getEstimatedBytes() > 10 * 200L,
                "каждая дополнительная запись добавляет оценку удержания");
    }

    @Test
    @DisplayName("Разобранный объект не влезает в бюджет, DER влезает -> хранится сырой DER")
    void rawDerKeptWhenParsedDoesNotFit() throws Exception {
        byte[] der = crl(1);
        long parsedEstimate = authenticate(der).getEstimatedBytes();
        CrlCache cache = new CrlCache(parsedEstimate - 1, Duration.ZERO);
        CountingLoader loader = new CountingLoader(der);

        Loaded first = cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);
        Loaded second = cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);

        assertEquals(1, loader.calls.get(), "сырой DER сохраняет главное: сеть один раз");
        assertFalse(first.fromCache(), "первый вызов загружает");
        assertFalse(second.fromCache(), "из сырой записи проверка повторяется");
        assertEquals(1, cache.size(), "одна сырая запись");
        assertEquals(der.length, cache.usedBytes(), "сырая запись входит в бюджет длиной DER");
    }

    @Test
    @DisplayName("DER не влезает в бюджет -> CRL не кэшируется, загрузка при каждом вызове")
    void notCachedWhenDerExceedsBudget() throws Exception {
        byte[] der = crl(1);
        CrlCache cache = new CrlCache(der.length - 1, Duration.ZERO);
        CountingLoader loader = new CountingLoader(der);

        cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);
        cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);

        assertEquals(2, loader.calls.get(), "последовательные соединения грузят заново");
        assertEquals(0, cache.size(), "кэш пуст");
        assertEquals(
                BigInteger.ONE,
                cache.lastKnownCrlNumber(key(URI)),
                "baseline сохраняется и без кэша");
    }

    @Test
    @DisplayName("Бюджет 0: записей нет, baseline и откат работают")
    void zeroBudgetKeepsRollbackProtection() throws Exception {
        CrlCache cache = new CrlCache(0, Duration.ZERO);
        cache.get(
                key(URI), new CountingLoader(crl(10)), null, CrlCacheTest::authenticate, NO_LIMIT);

        assertEquals(0, cache.size(), "при бюджете 0 записей нет");
        assertEquals(BigInteger.TEN, cache.lastKnownCrlNumber(key(URI)), "baseline запомнен");
        assertThrows(
                PkixException.class,
                () ->
                        cache.get(
                                key(URI),
                                new CountingLoader(crl(2)),
                                null,
                                CrlCacheTest::authenticate,
                                NO_LIMIT),
                "откат отвергается и при нулевом бюджете");
    }

    @Test
    @DisplayName("Вытесняется запись, ближайшая к истечению; новая не вытесняется")
    void evictsNearestToExpiryNotTheNewOne() throws Exception {
        byte[] soon = crl(1, Instant.now().plus(Duration.ofDays(1)), 1);
        byte[] later = crl(1, Instant.now().plus(Duration.ofDays(5)), 1);
        byte[] newest = crl(1, Instant.now().plus(Duration.ofDays(2)), 1);
        long one =
                Math.max(
                        authenticate(soon).getEstimatedBytes(),
                        Math.max(
                                authenticate(later).getEstimatedBytes(),
                                authenticate(newest).getEstimatedBytes()));
        CrlCache cache = new CrlCache(one * 2, Duration.ZERO);

        cache.get(
                key("http://a/"),
                new CountingLoader(soon),
                null,
                CrlCacheTest::authenticate,
                NO_LIMIT);
        cache.get(
                key("http://b/"),
                new CountingLoader(later),
                null,
                CrlCacheTest::authenticate,
                NO_LIMIT);
        cache.get(
                key("http://c/"),
                new CountingLoader(newest),
                null,
                CrlCacheTest::authenticate,
                NO_LIMIT);

        List<CrlKey> keys = cache.keys();
        assertEquals(2, keys.size(), "в бюджет помещаются две записи");
        assertFalse(keys.contains(key("http://a/")), "вытеснена ближайшая к истечению");
        assertTrue(keys.contains(key("http://c/")), "только что добавленная запись осталась");
        assertTrue(keys.contains(key("http://b/")), "запись с дальним сроком осталась");
    }

    @Test
    @DisplayName("Вытеснение не теряет baseline cRLNumber")
    void evictionKeepsCrlNumber() throws Exception {
        byte[] first = crl(1, Instant.now().plus(Duration.ofDays(1)), 1);
        byte[] second = crl(1, Instant.now().plus(Duration.ofDays(2)), 1);
        long one =
                Math.max(
                        authenticate(first).getEstimatedBytes(),
                        authenticate(second).getEstimatedBytes());
        CrlCache cache = new CrlCache(one, Duration.ZERO);
        cache.get(
                key("http://a/"),
                new CountingLoader(crl(42)),
                null,
                CrlCacheTest::authenticate,
                NO_LIMIT);
        cache.get(
                key("http://b/"),
                new CountingLoader(second),
                null,
                CrlCacheTest::authenticate,
                NO_LIMIT);

        assertFalse(cache.keys().contains(key("http://a/")), "первая запись вытеснена");
        assertEquals(
                BigInteger.valueOf(42),
                cache.lastKnownCrlNumber(key("http://a/")),
                "baseline вытесненной записи сохранён");
    }

    @Test
    @DisplayName(
            "Более новый CRL после вытеснения заменяет старый; кэш не отдаёт номер ниже базового")
    void newerCrlAfterEvictionReplacesOlder() throws Exception {
        byte[] first = crl(10);
        byte[] second = crl(11);
        long one =
                Math.max(
                        authenticate(first).getEstimatedBytes(),
                        authenticate(second).getEstimatedBytes());
        CrlCache cache = new CrlCache(one, Duration.ZERO);
        Loaded old =
                cache.get(
                        key("http://a/"),
                        new CountingLoader(first),
                        null,
                        CrlCacheTest::authenticate,
                        NO_LIMIT);
        // Другая запись вытесняет первую из-за бюджета
        cache.get(
                key("http://b/"),
                new CountingLoader(crl(1)),
                null,
                CrlCacheTest::authenticate,
                NO_LIMIT);
        assertFalse(cache.keys().contains(key("http://a/")), "первая запись вытеснена");

        Loaded newer =
                cache.get(
                        key("http://a/"),
                        new CountingLoader(second),
                        null,
                        CrlCacheTest::authenticate,
                        NO_LIMIT);

        assertEquals(
                BigInteger.valueOf(11), newer.crl().getCrlNumber(), "загружен более новый CRL");
        assertEquals(
                BigInteger.valueOf(11),
                cache.lastKnownCrlNumber(key("http://a/")),
                "baseline вырос");
        assertEquals(
                BigInteger.valueOf(10),
                old.crl().getCrlNumber(),
                "ранее выданный объект остаётся неизменным и пригодным для начатой проверки");
        Loaded again =
                cache.get(
                        key("http://a/"),
                        new CountingLoader(first),
                        null,
                        CrlCacheTest::authenticate,
                        NO_LIMIT);
        assertSame(newer.crl(), again.crl(), "из кэша выдаётся только новый объект, не старый");
    }

    @Test
    @DisplayName("Число записей ограничено; число запомненных номеров ограничено")
    void entryAndBaselineCountsAreBounded() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        VerifiedCrl shared = authenticate(crl(1));
        for (int i = 0; i < CrlCache.MAX_LAST_KNOWN + 5; i++) {
            cache.get(key("http://host/" + i), () -> new byte[] {1}, null, der -> shared, NO_LIMIT);
        }

        assertTrue(cache.size() <= CrlCache.MAX_ENTRIES, "записей не больше предела");
        int known = 0;
        for (int i = 0; i < CrlCache.MAX_LAST_KNOWN + 5; i++) {
            if (cache.lastKnownCrlNumber(key("http://host/" + i)) != null) {
                known++;
            }
        }
        assertTrue(known <= CrlCache.MAX_LAST_KNOWN, "запомненных номеров не больше предела");
    }

    // ------------------------------------------------------------------------
    // Единственная загрузка
    // ------------------------------------------------------------------------

    private static <T> List<Future<T>> startAll(
            ExecutorService pool, int count, CountDownLatch go, Callable<T> task) {
        List<Future<T>> futures = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            futures.add(
                    pool.submit(
                            () -> {
                                go.await();
                                return task.call();
                            }));
        }
        return futures;
    }

    @Test
    @DisplayName("N потоков на один адрес -> загрузка выполняется один раз")
    void singleFlightLoadsOnce() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        byte[] der = crl(1);
        AtomicInteger calls = new AtomicInteger();
        int threads = 16;
        CountDownLatch go = new CountDownLatch(1);
        CrlCache.Loader slow =
                () -> {
                    calls.incrementAndGet();
                    pause(200);
                    return der;
                };
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<Loaded>> futures =
                    startAll(
                            pool,
                            threads,
                            go,
                            () ->
                                    cache.get(
                                            key(URI),
                                            slow,
                                            null,
                                            CrlCacheTest::authenticate,
                                            NO_LIMIT));
            go.countDown();
            VerifiedCrl first = futures.get(0).get(30, TimeUnit.SECONDS).crl();
            for (Future<Loaded> f : futures) {
                assertSame(first, f.get(30, TimeUnit.SECONDS).crl(), "все получили один объект");
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, calls.get(), "CRL загружен один раз");
    }

    private void assertOutcomeReachesAllWaiters(
            CrlCache.Loader failing,
            Class<? extends Exception> expected,
            CrlCache.Authenticator auth)
            throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        int threads = 8;
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger arrived = new AtomicInteger();
        CrlCache.Loader gated =
                () -> {
                    // Ждём, пока остальные потоки встанут в ожидание результата инициатора
                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                    while (arrived.get() < threads && System.nanoTime() < deadline) {
                        pause(10);
                    }
                    pause(100);
                    return failing.fetch();
                };
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<Loaded>> futures =
                    startAll(
                            pool,
                            threads,
                            go,
                            () -> {
                                arrived.incrementAndGet();
                                return cache.get(key(URI), gated, null, auth, NO_LIMIT);
                            });
            go.countDown();
            for (Future<Loaded> f : futures) {
                ExecutionException e =
                        assertThrows(
                                ExecutionException.class,
                                () -> f.get(30, TimeUnit.SECONDS),
                                "каждый поток должен получить исход CRL");
                assertEquals(
                        expected,
                        e.getCause().getClass(),
                        "исключение без обёртки: " + e.getCause());
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(0, cache.size(), "ошибка не кэшируется");
    }

    @Test
    @DisplayName("Исход CRL: CrlSizeLimitException доходит до всех ожидающих без обёртки")
    void sizeLimitReachesWaiters() throws Exception {
        assertOutcomeReachesAllWaiters(
                () -> {
                    throw new CrlSizeLimitException("too big", 10, 20);
                },
                CrlSizeLimitException.class,
                CrlCacheTest::authenticate);
    }

    @Test
    @DisplayName("Исход CRL: IOException доходит до всех ожидающих без обёртки")
    void ioExceptionReachesWaiters() throws Exception {
        assertOutcomeReachesAllWaiters(
                () -> {
                    throw new IOException("network down");
                },
                IOException.class,
                CrlCacheTest::authenticate);
    }

    @Test
    @DisplayName("Исход CRL: PkixException (подпись) доходит до всех ожидающих без обёртки")
    void pkixExceptionReachesWaiters() throws Exception {
        KeyPair other = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        byte[] foreignSigned =
                GostCrlBuilder.create("CN=Cache Root,C=RU")
                        .thisUpdate(Instant.now().minus(Duration.ofDays(2)))
                        .nextUpdate(Instant.now().plus(Duration.ofDays(FUTURE_DAYS)))
                        .withCrlNumber(1)
                        .sign(other.getPrivate());
        assertOutcomeReachesAllWaiters(
                () -> foreignSigned, PkixException.class, CrlCacheTest::authenticate);
    }

    /**
     * Лидер упал по причине потока, а не CRL: ожидающие не получают его исключение, повторяют, и
     * ровно один из них выполняет новую загрузку.
     */
    private void assertWaitersRetryAfterLeaderFailure(
            LeaderFailure leaderFailure, Class<? extends Throwable> leaderExpected)
            throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        byte[] der = crl(1);
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch leaderInside = new CountDownLatch(1);
        int waiters = 6;
        AtomicInteger waiting = new AtomicInteger();
        CrlCache.Loader loader =
                () -> {
                    if (calls.incrementAndGet() == 1) {
                        leaderInside.countDown();
                        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
                        while (waiting.get() < waiters && System.nanoTime() < deadline) {
                            pause(10);
                        }
                        pause(150);
                        leaderFailure.fail();
                        throw new AssertionError("сбой лидера не сработал");
                    }
                    return der;
                };
        ExecutorService pool = Executors.newFixedThreadPool(waiters + 1);
        try {
            Future<Throwable> leader =
                    pool.submit(
                            () -> {
                                try {
                                    cache.get(
                                            key(URI),
                                            loader,
                                            null,
                                            CrlCacheTest::authenticate,
                                            NO_LIMIT);
                                    return null;
                                } catch (Throwable t) {
                                    return t;
                                }
                            });
            assertTrue(leaderInside.await(10, TimeUnit.SECONDS), "лидер вошёл в загрузку");
            List<Future<Loaded>> followers = new ArrayList<>();
            for (int i = 0; i < waiters; i++) {
                followers.add(
                        pool.submit(
                                () -> {
                                    waiting.incrementAndGet();
                                    return cache.get(
                                            key(URI),
                                            loader,
                                            null,
                                            CrlCacheTest::authenticate,
                                            NO_LIMIT);
                                }));
            }
            Throwable leaderResult = leader.get(30, TimeUnit.SECONDS);
            assertNotNull(leaderResult, "лидер получает собственный отказ");
            assertEquals(leaderExpected, leaderResult.getClass(), "тип отказа лидера");
            for (Future<Loaded> f : followers) {
                assertNotNull(
                        f.get(30, TimeUnit.SECONDS).crl(),
                        "ожидающие не наследуют сбой лидера и проверяются по новой загрузке");
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(2, calls.get(), "после сбоя лидера выполнена ровно одна новая загрузка");
    }

    @Test
    @DisplayName("Лидер прерван: ожидающие не получают его исключение и грузят CRL заново")
    void interruptedLeaderDoesNotPoisonWaiters() throws Exception {
        assertWaitersRetryAfterLeaderFailure(
                () -> {
                    // Загрузчики библиотеки восстанавливают флаг и бросают IOException
                    Thread.currentThread().interrupt();
                    throw new IOException("CRL fetch interrupted");
                },
                IOException.class);
    }

    @Test
    @DisplayName(
            "Лидер пропустил загрузку (исчерпан бюджет): ожидающие не получают его ошибку и грузят заново")
    void skippedLoadDoesNotPoisonWaiters() throws Exception {
        assertWaitersRetryAfterLeaderFailure(
                () -> {
                    throw new CrlCache.LoadSkippedException("Revocation fetch budget is exhausted");
                },
                CrlCache.LoadSkippedException.class);
    }

    @Test
    @DisplayName("Лидер упал неожиданным RuntimeException: ожидающие повторяют загрузку")
    void failedLeaderDoesNotPoisonWaiters() throws Exception {
        assertWaitersRetryAfterLeaderFailure(
                () -> {
                    throw new IllegalStateException("unexpected");
                },
                IllegalStateException.class);
    }

    @Test
    @DisplayName("Лидер упал с Error: ожидающие повторяют загрузку")
    void leaderErrorDoesNotPoisonWaiters() throws Exception {
        assertWaitersRetryAfterLeaderFailure(
                () -> {
                    throw new StackOverflowError("simulated");
                },
                StackOverflowError.class);
    }

    @Test
    @DisplayName("Прерванный ожидающий получает IOException, флаг прерывания сохранён")
    void interruptedWaiterGetsIoException() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        byte[] der = crl(1);
        CountDownLatch leaderInside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CrlCache.Loader blocking =
                () -> {
                    leaderInside.countDown();
                    awaitLatch(release);
                    return der;
                };
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Loaded> leader =
                    pool.submit(
                            () ->
                                    cache.get(
                                            key(URI),
                                            blocking,
                                            null,
                                            CrlCacheTest::authenticate,
                                            NO_LIMIT));
            assertTrue(leaderInside.await(10, TimeUnit.SECONDS), "лидер в загрузке");
            Future<Boolean> waiter =
                    pool.submit(
                            () -> {
                                Thread.currentThread().interrupt();
                                try {
                                    cache.get(
                                            key(URI),
                                            blocking,
                                            null,
                                            CrlCacheTest::authenticate,
                                            NO_LIMIT);
                                    return false;
                                } catch (IOException e) {
                                    return Thread.currentThread().isInterrupted();
                                }
                            });
            assertTrue(waiter.get(10, TimeUnit.SECONDS), "флаг прерывания должен сохраниться");
            release.countDown();
            assertNotNull(leader.get(10, TimeUnit.SECONDS).crl(), "лидер завершил загрузку");
        } finally {
            pool.shutdownNow();
        }
    }

    // ------------------------------------------------------------------------
    // Срок ожидания чужой загрузки
    // ------------------------------------------------------------------------

    /** Загрузчик, удерживающий инициатора, пока тест не отпустит его. */
    private static final class HeldLoader implements CrlCache.Loader {
        final CountDownLatch inside = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final AtomicInteger calls = new AtomicInteger();
        final byte[] der;

        HeldLoader(byte[] der) {
            this.der = der;
        }

        @Override
        public byte[] fetch() {
            calls.incrementAndGet();
            inside.countDown();
            awaitLatch(release);
            return der;
        }
    }

    private static CrlCache.Loader mustNotLoad() {
        return () -> {
            throw new AssertionError("ожидающий не должен загружать сам");
        };
    }

    @Test
    @DisplayName(
            "Ожидающий сдаётся по сроку, пока инициатор грузит; инициатор и терпеливый ожидающий получают CRL")
    void waiterGivesUpWithoutHarmingLeader() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        HeldLoader held = new HeldLoader(crl(1));
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Loaded> leader =
                    pool.submit(
                            () ->
                                    cache.get(
                                            key(URI),
                                            held,
                                            null,
                                            CrlCacheTest::authenticate,
                                            NO_LIMIT));
            assertTrue(held.inside.await(10, TimeUnit.SECONDS), "инициатор в загрузке");
            Future<Loaded> patient =
                    pool.submit(
                            () ->
                                    cache.get(
                                            key(URI),
                                            mustNotLoad(),
                                            null,
                                            CrlCacheTest::authenticate,
                                            NO_LIMIT));
            pause(100);
            long start = System.nanoTime();

            DeadlineExceededException e =
                    assertThrows(
                            DeadlineExceededException.class,
                            () ->
                                    cache.get(
                                            key(URI),
                                            mustNotLoad(),
                                            null,
                                            CrlCacheTest::authenticate,
                                            Duration.ofMillis(100)));

            long elapsedMillis = (System.nanoTime() - start) / 1_000_000;
            assertTrue(elapsedMillis < 2_000, "сдача в пределах срока: " + elapsedMillis);
            assertTrue(e.getMessage().contains("crl.example.com/root.crl"), e.getMessage());
            held.release.countDown();
            VerifiedCrl led = leader.get(30, TimeUnit.SECONDS).crl();
            Loaded patientResult = patient.get(30, TimeUnit.SECONDS);
            assertSame(led, patientResult.crl(), "терпеливый ожидающий получил CRL инициатора");
            // Получен из общей загрузки, а не из кэша: сдача соседа её не испортила
            assertFalse(patientResult.fromCache(), "результат пришёл от инициатора");
            assertEquals(1, held.calls.get(), "загрузка одна, сдача её не отменила и не повторила");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("Срок 0: ожидающий сдаётся сразу, а без инициатора поток грузит сам")
    void zeroWaitDoesNotWaitButStillLoads() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        HeldLoader held = new HeldLoader(crl(1));
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Loaded own =
                    cache.get(
                            key("http://a/"),
                            new CountingLoader(crl(1)),
                            null,
                            CrlCacheTest::authenticate,
                            Duration.ZERO);
            assertFalse(own.fromCache(), "первая загрузка разрешена и при нулевом сроке");

            Future<Loaded> leader =
                    pool.submit(
                            () ->
                                    cache.get(
                                            key(URI),
                                            held,
                                            null,
                                            CrlCacheTest::authenticate,
                                            NO_LIMIT));
            assertTrue(held.inside.await(10, TimeUnit.SECONDS), "инициатор в загрузке");
            assertThrows(
                    DeadlineExceededException.class,
                    () ->
                            cache.get(
                                    key(URI),
                                    mustNotLoad(),
                                    null,
                                    CrlCacheTest::authenticate,
                                    Duration.ZERO),
                    "ожидающий с нулевым сроком не ждёт");
            held.release.countDown();
            leader.get(30, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("Попадание в кэш отдаётся при любом сроке, включая 0")
    void cacheHitIgnoresWait() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        CountingLoader loader = new CountingLoader(crl(1));
        cache.get(key(URI), loader, null, CrlCacheTest::authenticate, NO_LIMIT);

        Loaded hit = cache.get(key(URI), loader, null, CrlCacheTest::authenticate, Duration.ZERO);

        assertTrue(hit.fromCache());
        assertEquals(1, loader.calls.get());
    }

    @Test
    @DisplayName("Срок null, отрицательный и больше предела отвергаются; 0 и предел допустимы")
    void maxWaitValidation() throws Exception {
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        CountingLoader loader = new CountingLoader(crl(1));

        for (Duration bad :
                new Duration[] {
                    null,
                    Duration.ofNanos(-1),
                    Duration.ofSeconds(-1),
                    Deadline.MAX_FETCH_TIMEOUT.plusNanos(1)
                }) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> cache.get(key(URI), loader, null, CrlCacheTest::authenticate, bad),
                    "срок " + bad);
        }
        assertEquals(0, loader.calls.get(), "неверный срок отвергается до загрузки");
        cache.get(key(URI), loader, null, CrlCacheTest::authenticate, Deadline.MAX_FETCH_TIMEOUT);
        cache.get(key(URI), loader, null, CrlCacheTest::authenticate, Duration.ZERO);
    }

    @Test
    @DisplayName("lastKnownCrlNumber не публичный: менеджеру номер не нужен")
    void lastKnownCrlNumberIsNotPublic() throws Exception {
        java.lang.reflect.Method method =
                CrlCache.class.getDeclaredMethod("lastKnownCrlNumber", CrlKey.class);

        assertFalse(
                java.lang.reflect.Modifier.isPublic(method.getModifiers()),
                "метод должен быть пакетным");
    }

    // ------------------------------------------------------------------------
    // Предупреждения раз на ключ
    // ------------------------------------------------------------------------

    private static final String NOT_CACHED = "not cached";
    private static final String RAW_KEPT = "raw DER is kept";
    private static final String GAVE_UP = "Gave up waiting";

    /** Перехват предупреждений CrlCache; закрывается в {@link #restoreLogger()}. */
    private Warnings capture() {
        log = LogCapture.start(LogCapture.JSSE);
        return new Warnings(log);
    }

    private LogCapture log;

    @org.junit.jupiter.api.AfterEach
    void restoreLogger() {
        if (log != null) {
            log.close();
            log = null;
        }
    }

    /** Предупреждения (WARNING) логгера CrlCache. */
    private record Warnings(LogCapture log) {
        long count(String fragment) {
            return log.messages(Level.WARNING, "CrlCache").stream()
                    .filter(w -> w.contains(fragment))
                    .count();
        }
    }

    @Test
    @DisplayName("«Не кэшируется»: одно предупреждение на ключ, другой ключ - ещё одно")
    void notCachedWarnedOncePerKey() throws Exception {
        Warnings sink = capture();
        byte[] der = crl(1);
        CrlCache cache = new CrlCache(der.length - 1, Duration.ZERO);

        for (int i = 0; i < 3; i++) {
            cache.get(
                    key(URI), new CountingLoader(der), null, CrlCacheTest::authenticate, NO_LIMIT);
        }
        assertEquals(1, sink.count(NOT_CACHED), "три соединения - одно предупреждение");
        cache.get(
                key("http://other/"),
                new CountingLoader(der),
                null,
                CrlCacheTest::authenticate,
                NO_LIMIT);

        assertEquals(2, sink.count(NOT_CACHED), "другой ключ - своё предупреждение");
        assertEquals(2, cache.warnedKeysCount(CrlCache.Warning.NOT_CACHED));
    }

    @Test
    @DisplayName("«Сырой DER»: одно предупреждение на ключ при нескольких загрузках")
    void rawKeptWarnedOncePerKey() throws Exception {
        Warnings sink = capture();
        byte[] der = crl(1);
        AtomicLong clock = new AtomicLong(System.currentTimeMillis());
        CrlCache cache =
                new CrlCache(authenticate(der).getEstimatedBytes() - 1, Duration.ZERO, clock::get);

        cache.get(key(URI), new CountingLoader(der), null, CrlCacheTest::authenticate, NO_LIMIT);
        // Запись истекает, следующий вызов загружает снова
        clock.addAndGet(Duration.ofDays(FUTURE_DAYS + 1).toMillis());
        cache.get(key(URI), new CountingLoader(crl(2)), null, CrlCacheTest::authenticate, NO_LIMIT);

        assertEquals(1, sink.count(RAW_KEPT), "две загрузки - одно предупреждение");
    }

    @Test
    @DisplayName("«Сырой DER» и «не кэшируется» одного ключа не подавляют друг друга")
    void warningKindsAreIndependent() throws Exception {
        Warnings sink = capture();
        byte[] small = crl(1, Instant.now().plus(Duration.ofDays(FUTURE_DAYS)), 1);
        byte[] big = crl(2, Instant.now().plus(Duration.ofDays(FUTURE_DAYS)), 400);
        AtomicLong clock = new AtomicLong(System.currentTimeMillis());
        // Бюджет: мал для разобранного маленького CRL, но не для его DER; большой DER не влезает
        CrlCache cache = new CrlCache(small.length + 1, Duration.ZERO, clock::get);
        assertTrue(authenticate(small).getEstimatedBytes() > small.length + 1);
        assertTrue(big.length > small.length + 1);

        cache.get(key(URI), new CountingLoader(small), null, CrlCacheTest::authenticate, NO_LIMIT);
        clock.addAndGet(Duration.ofDays(FUTURE_DAYS + 1).toMillis());
        cache.get(key(URI), new CountingLoader(big), null, CrlCacheTest::authenticate, NO_LIMIT);

        assertEquals(1, sink.count(RAW_KEPT));
        assertEquals(1, sink.count(NOT_CACHED), "второе состояние ключа тоже предупреждено");
    }

    @Test
    @DisplayName("Сдача ожидающего: одно предупреждение на ключ")
    void gaveUpWarnedOncePerKey() throws Exception {
        Warnings sink = capture();
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);
        HeldLoader held = new HeldLoader(crl(1));
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<Loaded> leader =
                    pool.submit(
                            () ->
                                    cache.get(
                                            key(URI),
                                            held,
                                            null,
                                            CrlCacheTest::authenticate,
                                            NO_LIMIT));
            assertTrue(held.inside.await(10, TimeUnit.SECONDS));
            for (int i = 0; i < 3; i++) {
                assertThrows(
                        DeadlineExceededException.class,
                        () ->
                                cache.get(
                                        key(URI),
                                        mustNotLoad(),
                                        null,
                                        CrlCacheTest::authenticate,
                                        Duration.ofMillis(20)));
            }
            held.release.countDown();
            leader.get(30, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }

        assertEquals(1, sink.count(GAVE_UP), "три сдачи - одно предупреждение");
    }

    @Test
    @DisplayName("Сдача - событие: после успешной загрузки следующая сдача снова предупреждает")
    void gaveUpWarningResetsAfterSuccessfulLoad() throws Exception {
        Warnings sink = capture();
        CrlCache cache = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO);

        // Инициатор успешно загружает CRL уже после сдачи ожидающего
        Loaded first = giveUpOnce(cache, new HeldLoader(crl(1)));
        assertEquals(1, sink.count(GAVE_UP), "первая серия - одна запись");
        // Запись убирается, чтобы следующий инициатор снова грузил; наборы предупреждений не
        // трогаются
        cache.invalidate(key(URI), first.crl());
        giveUpOnce(cache, new HeldLoader(crl(2)));

        assertEquals(2, sink.count(GAVE_UP), "вторая серия после успешной загрузки - снова запись");
    }

    /** Одна сдача: инициатор держит загрузку, ожидающий сдаётся, инициатор завершается успешно. */
    private Loaded giveUpOnce(CrlCache cache, HeldLoader held) throws Exception {
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<Loaded> leader =
                    pool.submit(
                            () ->
                                    cache.get(
                                            key(URI),
                                            held,
                                            null,
                                            CrlCacheTest::authenticate,
                                            NO_LIMIT));
            assertTrue(held.inside.await(10, TimeUnit.SECONDS));
            assertThrows(
                    DeadlineExceededException.class,
                    () ->
                            cache.get(
                                    key(URI),
                                    mustNotLoad(),
                                    null,
                                    CrlCacheTest::authenticate,
                                    Duration.ofMillis(20)));
            held.release.countDown();
            return leader.get(30, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("Переполнение набора: набор не растёт, предупреждение пишется каждый раз")
    void warnedSetIsBounded() throws Exception {
        Warnings sink = capture();
        byte[] der = crl(1);
        CrlCache cache = new CrlCache(der.length - 1, Duration.ZERO);
        int keys = CrlCache.MAX_WARNED_KEYS + 5;

        for (int i = 0; i < keys; i++) {
            cache.get(
                    key("http://host" + i + "/c.crl"),
                    new CountingLoader(der),
                    null,
                    CrlCacheTest::authenticate,
                    NO_LIMIT);
        }
        // Повтор по ключу сверх предела пишется снова: он не запомнен
        cache.get(
                key("http://host" + (keys - 1) + "/c.crl"),
                new CountingLoader(der),
                null,
                CrlCacheTest::authenticate,
                NO_LIMIT);

        assertEquals(CrlCache.MAX_WARNED_KEYS, cache.warnedKeysCount(CrlCache.Warning.NOT_CACHED));
        assertEquals(keys + 1, sink.count(NOT_CACHED), "сверх предела - предупреждение каждый раз");
    }

    @Test
    @DisplayName("clear() сбрасывает наборы предупреждений")
    void clearResetsWarnings() throws Exception {
        Warnings sink = capture();
        byte[] der = crl(1);
        CrlCache cache = new CrlCache(der.length - 1, Duration.ZERO);
        cache.get(key(URI), new CountingLoader(der), null, CrlCacheTest::authenticate, NO_LIMIT);

        cache.clear();
        cache.get(key(URI), new CountingLoader(der), null, CrlCacheTest::authenticate, NO_LIMIT);

        assertEquals(2, sink.count(NOT_CACHED), "после clear() предупреждение выдаётся снова");
    }
}
