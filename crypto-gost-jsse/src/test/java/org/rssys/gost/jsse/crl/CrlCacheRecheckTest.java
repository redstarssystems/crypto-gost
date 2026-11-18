package org.rssys.gost.jsse.crl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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
import org.rssys.gost.signature.ECParameters;

/**
 * Перепроверка записей {@link CrlCache} раньше {@code nextUpdate} по предельному возрасту: границы
 * возраста, исходы по {@code cRLNumber}, неудача и пауза, одна перепроверка на ключ, резерв.
 */
@DisplayName("CrlCache: перепроверка записи по предельному возрасту")
class CrlCacheRecheckTest {

    private static final String URI = "http://crl.example.com/root.crl";
    private static final Duration MAX_AGE = Duration.ofHours(1);
    private static final long HOUR_MS = MAX_AGE.toMillis();
    private static final long PAUSE_MS = Duration.ofMinutes(5).toMillis();
    private static final Duration NO_LIMIT = Deadline.MAX_FETCH_TIMEOUT;

    private static KeyPair issuer;
    private static GostCertificate issuerCert;

    private final AtomicLong clock = new AtomicLong(System.currentTimeMillis());
    private LogCapture log;

    @BeforeAll
    static void setUpKeys() {
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

    @BeforeEach
    void captureLogger() {
        log = LogCapture.start(LogCapture.JSSE);
    }

    @AfterEach
    void restoreLogger() {
        log.close();
    }

    /** Число записей уровня JUL, в тексте которых есть фрагмент. */
    private long count(Level level, String fragment) {
        return log.messages(level, "CrlCache").stream().filter(l -> l.contains(fragment)).count();
    }

    private static CrlKey key() {
        return new CrlKey(URI, "aa");
    }

    private static byte[] crl(Integer number, Instant nextUpdate, int revoked) {
        GostCrlBuilder builder =
                GostCrlBuilder.create("CN=Cache Root,C=RU")
                        .thisUpdate(Instant.now().minus(Duration.ofDays(2)));
        if (number != null) {
            builder = builder.withCrlNumber(number);
        }
        builder = builder.nextUpdate(nextUpdate);
        for (int i = 1; i <= revoked; i++) {
            builder = builder.addRevoked(BigInteger.valueOf(i), "20260101000000Z");
        }
        return builder.sign(issuer.getPrivate());
    }

    private static byte[] crl(int number) {
        return crl(number, Instant.now().plus(Duration.ofDays(30)), 1);
    }

    private static VerifiedCrl authenticate(byte[] der) throws PkixException {
        return CrlVerifier.authenticate(
                der,
                issuerCert,
                new CrlLimits(GostCrl.DEFAULT_MAX_CRL_SIZE, GostCrl.DEFAULT_MAX_REVOKED_ENTRIES));
    }

    /** Загрузчик с очередью ответов; исключение в очереди бросается. */
    private static final class ScriptedLoader implements CrlCache.Loader {
        final AtomicInteger calls = new AtomicInteger();
        private final List<Object> script = new ArrayList<>();
        private Runnable beforeReturn = () -> {};

        ScriptedLoader then(Object... results) {
            script.addAll(List.of(results));
            return this;
        }

        ScriptedLoader before(Runnable action) {
            this.beforeReturn = action;
            return this;
        }

        @Override
        public byte[] fetch() throws IOException {
            int call = calls.getAndIncrement();
            beforeReturn.run();
            Object next = script.get(Math.min(call, script.size() - 1));
            if (next instanceof IOException e) {
                throw e;
            }
            return (byte[]) next;
        }
    }

    private CrlCache cache(long maxBytes) {
        return new CrlCache(maxBytes, MAX_AGE, clock::get);
    }

    private Loaded get(CrlCache cache, CrlCache.Loader loader, CrlCache.Loader recheck)
            throws Exception {
        return cache.get(key(), loader, recheck, CrlCacheRecheckTest::authenticate, NO_LIMIT);
    }

    /** Кэш с одной загруженной записью (номер 1), возраст ноль. */
    private CrlCache primed(ScriptedLoader mandatory) throws Exception {
        CrlCache cache = cache(CrlCache.DEFAULT_MAX_BYTES);
        get(cache, mandatory, null);
        return cache;
    }

    // ------------------------------------------------------------------------
    // Границы возраста
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Возраст на 1 мс меньше предела - перепроверки нет; ровно предел - есть")
    void ageBoundary() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1));
        ScriptedLoader recheck = new ScriptedLoader().then((Object) crl(1));
        CrlCache cache = primed(mandatory);

        clock.addAndGet(HOUR_MS - 1);
        get(cache, mandatory, recheck);
        assertEquals(0, recheck.calls.get(), "младше предела");

        clock.addAndGet(1);
        get(cache, mandatory, recheck);
        assertEquals(1, recheck.calls.get(), "ровно предел");
    }

    @Test
    @DisplayName("Перепроверка выключена (ноль) или recheckLoader отсутствует - не запускается")
    void disabledRecheck() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1));
        ScriptedLoader recheck = new ScriptedLoader().then((Object) crl(2));
        CrlCache off = new CrlCache(CrlCache.DEFAULT_MAX_BYTES, Duration.ZERO, clock::get);
        get(off, mandatory, null);
        CrlCache noLoader = primed(mandatory);
        clock.addAndGet(HOUR_MS * 10);

        get(off, mandatory, recheck);
        get(noLoader, mandatory, null);

        assertEquals(0, recheck.calls.get());
    }

    @Test
    @DisplayName("Часы ушли назад: отрицательный возраст не запускает перепроверку")
    void clockGoingBackwards() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1));
        ScriptedLoader recheck = new ScriptedLoader().then((Object) crl(2));
        CrlCache cache = primed(mandatory);

        clock.addAndGet(-HOUR_MS * 3);
        get(cache, mandatory, recheck);

        assertEquals(0, recheck.calls.get());
    }

    @Test
    @DisplayName("nextUpdate раньше предела: запись истекает раньше, перепроверки нет")
    void expiryBeatsRecheck() throws Exception {
        ScriptedLoader mandatory =
                new ScriptedLoader()
                        .then(crl(1, Instant.now().plus(Duration.ofMinutes(10)), 1), crl(2));
        ScriptedLoader recheck = new ScriptedLoader().then((Object) crl(3));
        CrlCache cache = primed(mandatory);

        clock.addAndGet(HOUR_MS);
        Loaded loaded = get(cache, mandatory, recheck);

        assertEquals(0, recheck.calls.get(), "истёкшая запись перепроверкой не обновляется");
        assertEquals(2, mandatory.calls.get(), "обычная обязательная загрузка");
        assertFalse(loaded.fromCache());
    }

    @Test
    @DisplayName("Границы crlMaxAge: ноль, 1 минута и 30 суток допустимы; null и вне границ нет")
    void maxAgeValidation() {
        assertDoesNotThrow(() -> CrlCache.requireValidMaxAge(Duration.ZERO));
        assertDoesNotThrow(() -> CrlCache.requireValidMaxAge(Duration.ofMinutes(1)));
        assertDoesNotThrow(() -> CrlCache.requireValidMaxAge(Duration.ofDays(30)));
        for (Duration bad :
                new Duration[] {
                    null,
                    Duration.ofSeconds(59),
                    Duration.ofMillis(-1),
                    Duration.ofDays(30).plusMillis(1)
                }) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> CrlCache.requireValidMaxAge(bad),
                    "значение " + bad);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new CrlCache(CrlCache.DEFAULT_MAX_BYTES, bad),
                    "конструктор " + bad);
        }
    }

    // ------------------------------------------------------------------------
    // Исходы
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Больший номер: запись заменена, возраст сброшен, соединение получает новый CRL")
    void higherNumberReplaces() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1));
        ScriptedLoader recheck = new ScriptedLoader().then((Object) crl(2));
        CrlCache cache = primed(mandatory);
        clock.addAndGet(HOUR_MS);

        Loaded fresh = get(cache, mandatory, recheck);

        assertFalse(fresh.fromCache(), "свежая загрузка");
        assertEquals(BigInteger.TWO, fresh.crl().getCrlNumber());
        assertEquals(BigInteger.TWO, cache.lastKnownCrlNumber(key()));
        Loaded again = get(cache, mandatory, recheck);
        assertTrue(again.fromCache());
        assertSame(fresh.crl(), again.crl(), "новая запись в кэше");
        assertEquals(1, recheck.calls.get(), "возраст сброшен, повторной перепроверки нет");
        assertEquals(1, mandatory.calls.get(), "обязательная загрузка одна");
    }

    @Test
    @DisplayName("Тот же номер с прежним nextUpdate: запись прежняя, возраст сброшен")
    void sameNumberKeepsEntry() throws Exception {
        Instant nextUpdate = Instant.now().plus(Duration.ofDays(30));
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1, nextUpdate, 1));
        ScriptedLoader recheck = new ScriptedLoader().then((Object) crl(1, nextUpdate, 1));
        CrlCache cache = primed(mandatory);
        VerifiedCrl original = get(cache, mandatory, null).crl();
        clock.addAndGet(HOUR_MS);

        Loaded loaded = get(cache, mandatory, recheck);

        assertTrue(loaded.fromCache());
        assertSame(original, loaded.crl(), "запись не заменена");
        clock.addAndGet(HOUR_MS - 1);
        get(cache, mandatory, recheck);
        assertEquals(1, recheck.calls.get(), "возраст сброшен");
    }

    @Test
    @DisplayName("Тот же номер, но nextUpdate позже: запись заменена новым объектом")
    void sameNumberWithLaterNextUpdateReplaces() throws Exception {
        ScriptedLoader mandatory =
                new ScriptedLoader()
                        .then((Object) crl(1, Instant.now().plus(Duration.ofDays(10)), 1));
        ScriptedLoader recheck =
                new ScriptedLoader()
                        .then((Object) crl(1, Instant.now().plus(Duration.ofDays(20)), 1));
        CrlCache cache = primed(mandatory);
        VerifiedCrl original = get(cache, mandatory, null).crl();
        clock.addAndGet(HOUR_MS);

        Loaded loaded = get(cache, mandatory, recheck);

        assertTrue(loaded.fromCache());
        assertNotSame(original, get(cache, mandatory, recheck).crl(), "запись продлена");
    }

    @Test
    @DisplayName(
            "Меньший номер: запись и lastKnown прежние, ERROR, пауза; рукопожатие не отвергается")
    void lowerNumberIsRollback() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(5));
        ScriptedLoader recheck = new ScriptedLoader().then((Object) crl(3));
        CrlCache cache = primed(mandatory);
        VerifiedCrl original = get(cache, mandatory, null).crl();
        clock.addAndGet(HOUR_MS);

        Loaded loaded = get(cache, mandatory, recheck);

        assertTrue(loaded.fromCache());
        assertSame(original, loaded.crl());
        assertEquals(BigInteger.valueOf(5), cache.lastKnownCrlNumber(key()));
        assertEquals(1, count(Level.WARNING, "rollback suspected"), "откат - WARNING");
        get(cache, mandatory, recheck);
        assertEquals(1, recheck.calls.get(), "пауза: сервер не опрашивается");
        clock.addAndGet(PAUSE_MS);
        get(cache, mandatory, recheck);
        assertEquals(2, recheck.calls.get(), "после паузы - снова");
    }

    @Test
    @DisplayName("CRL без номера при известном номере: так же, как откат")
    void missingNumberIsRollback() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(5));
        ScriptedLoader recheck =
                new ScriptedLoader()
                        .then((Object) crl(null, Instant.now().plus(Duration.ofDays(30)), 1));
        CrlCache cache = primed(mandatory);
        clock.addAndGet(HOUR_MS);

        Loaded loaded = get(cache, mandatory, recheck);

        assertTrue(loaded.fromCache());
        assertEquals(1, count(Level.WARNING, "rollback suspected"));
    }

    @Test
    @DisplayName("Устаревший результат: обязательная загрузка успела положить более новый номер")
    void staleRecheckResultIsDiscardedQuietly() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1));
        CrlCache cache = primed(mandatory);
        // Пока перепроверка качает номер 2, обязательная загрузка успела записать номер 3
        ScriptedLoader recheck =
                new ScriptedLoader()
                        .then((Object) crl(2))
                        .before(() -> cache.rememberCrlNumber(key(), BigInteger.valueOf(3)));
        clock.addAndGet(HOUR_MS);

        Loaded loaded = get(cache, mandatory, recheck);

        assertTrue(loaded.fromCache(), "перепроверка отброшена");
        assertEquals(0, count(Level.WARNING, "rollback suspected"), "ложной тревоги нет");
        get(cache, mandatory, recheck);
        assertEquals(2, recheck.calls.get(), "и паузы нет");
    }

    // ------------------------------------------------------------------------
    // Неудача
    // ------------------------------------------------------------------------

    @Test
    @DisplayName(
            "Неудача: резерв с fromCache=true, возраст не сброшен, пауза, предупреждение раз на серию")
    void failureKeepsEntryAndPauses() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1));
        IOException down = new IOException("down");
        ScriptedLoader recheck = new ScriptedLoader().then((Object) down);
        CrlCache cache = primed(mandatory);
        VerifiedCrl original = get(cache, mandatory, null).crl();
        clock.addAndGet(HOUR_MS);

        Loaded loaded = get(cache, mandatory, recheck);
        assertTrue(loaded.fromCache());
        assertSame(original, loaded.crl());
        get(cache, mandatory, recheck);
        assertEquals(1, recheck.calls.get(), "пауза: следующее соединение на сервер не идёт");

        clock.addAndGet(PAUSE_MS);
        get(cache, mandatory, recheck);
        assertEquals(2, recheck.calls.get(), "после паузы повтор: возраст не сброшен");
        assertEquals(1, count(Level.WARNING, "recheck"), "предупреждение раз на серию");
        assertEquals(1, mandatory.calls.get(), "обязательная загрузка не повторялась");
    }

    @Test
    @DisplayName(
            "Успех после серии неудач сбрасывает предупреждение: следующая серия пишется снова")
    void successResetsFailureWarning() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1));
        IOException down = new IOException("down");
        ScriptedLoader recheck = new ScriptedLoader().then(down, crl(2), down);
        CrlCache cache = primed(mandatory);
        clock.addAndGet(HOUR_MS);
        get(cache, mandatory, recheck);
        clock.addAndGet(PAUSE_MS);
        get(cache, mandatory, recheck);
        clock.addAndGet(HOUR_MS);
        get(cache, mandatory, recheck);

        assertEquals(2, count(Level.WARNING, "recheck"), "две серии - две записи");
    }

    @Test
    @DisplayName("Пропуск бюджетом: без паузы и без предупреждения")
    void loadSkippedHasNoPause() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1));
        CrlCache.LoadSkippedException skipped = new CrlCache.LoadSkippedException("budget");
        ScriptedLoader recheck = new ScriptedLoader().then((Object) skipped);
        CrlCache cache = primed(mandatory);
        clock.addAndGet(HOUR_MS);

        get(cache, mandatory, recheck);
        get(cache, mandatory, recheck);

        assertEquals(2, recheck.calls.get(), "паузы нет");
        assertEquals(0, count(Level.WARNING, "recheck"));
    }

    @Test
    @DisplayName("Неверная подпись нового CRL: запись не заменяется")
    void crlWithForeignSignatureDoesNotReplace() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1));
        byte[] foreignSigned = crl(9);
        foreignSigned[foreignSigned.length - 1] ^= 0x01;
        ScriptedLoader recheck = new ScriptedLoader().then((Object) foreignSigned);
        CrlCache cache = primed(mandatory);
        VerifiedCrl original = get(cache, mandatory, null).crl();
        clock.addAndGet(HOUR_MS);

        Loaded loaded = get(cache, mandatory, recheck);

        assertSame(original, loaded.crl());
        assertEquals(
                BigInteger.ONE,
                cache.lastKnownCrlNumber(key()),
                "номер из искажённого CRL не запомнен");
    }

    @Test
    @DisplayName("Резерв истёк, пока шла перепроверка: используется обязательная загрузка")
    void reserveExpiredDuringRecheck() throws Exception {
        ScriptedLoader mandatory =
                new ScriptedLoader()
                        .then(crl(1, Instant.now().plus(Duration.ofMinutes(90)), 1), crl(2));
        ScriptedLoader recheck =
                new ScriptedLoader()
                        .then((Object) new IOException("down"))
                        .before(() -> clock.addAndGet(Duration.ofMinutes(40).toMillis()));
        CrlCache cache = primed(mandatory);
        clock.addAndGet(HOUR_MS + 1);

        Loaded loaded = get(cache, mandatory, recheck);

        assertFalse(loaded.fromCache(), "истёкший резерв не возвращается");
        assertEquals(BigInteger.TWO, loaded.crl().getCrlNumber());
        assertEquals(2, mandatory.calls.get(), "обязательная загрузка выполнена");
    }

    // ------------------------------------------------------------------------
    // Параллельность
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Одна перепроверка на ключ: остальные берут запись без ожидания")
    void singleRecheckPerKey() throws Exception {
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) crl(1));
        CrlCache cache = primed(mandatory);
        VerifiedCrl original = get(cache, mandatory, null).crl();
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ScriptedLoader recheck =
                new ScriptedLoader()
                        .then((Object) crl(2))
                        .before(
                                () -> {
                                    inside.countDown();
                                    try {
                                        release.await();
                                    } catch (InterruptedException e) {
                                        Thread.currentThread().interrupt();
                                    }
                                });
        clock.addAndGet(HOUR_MS);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Loaded> first = pool.submit(() -> get(cache, mandatory, recheck));
            assertTrue(inside.await(10, TimeUnit.SECONDS), "перепроверка идёт");

            Future<Loaded> second = pool.submit(() -> get(cache, mandatory, recheck));
            Loaded other = second.get(5, TimeUnit.SECONDS);

            assertTrue(other.fromCache(), "второе соединение не ждёт");
            assertSame(original, other.crl());
            release.countDown();
            assertEquals(BigInteger.TWO, first.get(30, TimeUnit.SECONDS).crl().getCrlNumber());
            assertEquals(1, recheck.calls.get(), "одна загрузка на ключ");
        } finally {
            pool.shutdownNow();
        }
    }

    // ------------------------------------------------------------------------
    // Бюджет памяти и сырая запись
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("CRL на 60 % бюджета остаётся разобранной записью после перепроверки")
    void replacementDoesNotDoubleCountBudget() throws Exception {
        byte[] first = crl(1);
        long estimate = authenticate(first).getEstimatedBytes();
        CrlCache cache = cache(estimate * 10 / 6);
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) first);
        ScriptedLoader recheck = new ScriptedLoader().then((Object) crl(2));
        get(cache, mandatory, null);
        clock.addAndGet(HOUR_MS);

        Loaded fresh = get(cache, mandatory, recheck);

        assertEquals(BigInteger.TWO, fresh.crl().getCrlNumber());
        assertTrue(get(cache, mandatory, recheck).fromCache(), "разобранная запись, а не сырая");
        assertEquals(1, cache.size());
    }

    @Test
    @DisplayName(
            "Новый CRL не помещается в бюджет: прежняя запись удаляется, перепроверки на каждом соединении нет")
    void unfitReplacementRemovesOldEntry() throws Exception {
        byte[] small = crl(1);
        byte[] big = crl(2, Instant.now().plus(Duration.ofDays(30)), 400);
        long budget = authenticate(small).getEstimatedBytes() + 10;
        assertTrue(big.length > budget, "тест рассчитан на CRL больше бюджета");
        CrlCache cache = cache(budget);
        ScriptedLoader mandatory = new ScriptedLoader().then(small, big);
        ScriptedLoader recheck = new ScriptedLoader().then((Object) big);
        get(cache, mandatory, null);
        clock.addAndGet(HOUR_MS);

        Loaded fresh = get(cache, mandatory, recheck);
        assertEquals(BigInteger.TWO, fresh.crl().getCrlNumber(), "новый CRL получен");
        assertEquals(0, cache.size(), "прежняя запись удалена");

        get(cache, mandatory, recheck);
        assertEquals(1, recheck.calls.get(), "записи нет - перепроверять нечего");
        assertEquals(2, mandatory.calls.get(), "дальше обязательная загрузка");
    }

    @Test
    @DisplayName(
            "Сырая запись: перепроверка грузит заново и заменяет; при неудаче сырая запись остаётся")
    void rawEntryIsRechecked() throws Exception {
        byte[] first = crl(1);
        long parsed = authenticate(first).getEstimatedBytes();
        CrlCache cache = cache(parsed - 1);
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) first);
        ScriptedLoader failing = new ScriptedLoader().then((Object) new IOException("down"));
        get(cache, mandatory, null);
        assertEquals(1, cache.size(), "хранится сырая запись");
        clock.addAndGet(HOUR_MS);

        get(cache, mandatory, failing);
        assertEquals(1, failing.calls.get(), "сырая запись перепроверяется сетевой загрузкой");
        assertEquals(1, cache.size(), "неудача сырую запись не удаляет");
        assertEquals(1, mandatory.calls.get());

        clock.addAndGet(PAUSE_MS);
        ScriptedLoader good = new ScriptedLoader().then((Object) crl(2));
        Loaded fresh = get(cache, mandatory, good);
        assertEquals(BigInteger.TWO, fresh.crl().getCrlNumber());
        assertEquals(BigInteger.TWO, cache.lastKnownCrlNumber(key()));
    }

    @Test
    @DisplayName("Ответ перепроверки не мутирует чужие данные: загрузчик возвращает свой массив")
    void loaderArrayIsNotShared() throws Exception {
        byte[] first = crl(1);
        byte[] copy = first.clone();
        ScriptedLoader mandatory = new ScriptedLoader().then((Object) first);
        CrlCache cache = primed(mandatory);
        clock.addAndGet(HOUR_MS);
        get(cache, mandatory, new ScriptedLoader().then((Object) crl(2)));

        assertArrayEquals(copy, first);
        assertNull(cache.lastKnownCrlNumber(new CrlKey(URI, "other")));
    }

    // ------------------------------------------------------------------------
    // Условный запрос (If-Modified-Since)
    // ------------------------------------------------------------------------

    private static final String LM1 = "Sun, 08 Nov 2026 03:08:46 GMT";
    private static final String LM2 = "Sun, 08 Nov 2026 03:13:54 GMT";

    /** Загрузчик, умеющий условный запрос: запоминает валидаторы, отдаёт заготовленные ответы. */
    private static final class ConditionalLoader implements CrlCache.Loader {
        final List<String> validators = new ArrayList<>();
        private final List<CrlFetchResult> script = new ArrayList<>();
        private Runnable beforeReturn = () -> {};

        ConditionalLoader then(CrlFetchResult... results) {
            script.addAll(List.of(results));
            return this;
        }

        ConditionalLoader before(Runnable action) {
            this.beforeReturn = action;
            return this;
        }

        @Override
        public byte[] fetch() throws IOException {
            return fetchConditional(null).der();
        }

        @Override
        public CrlFetchResult fetchConditional(String validator) {
            int call = validators.size();
            validators.add(validator);
            beforeReturn.run();
            return script.get(Math.min(call, script.size() - 1));
        }
    }

    /** Кэш с одной записью (номер 1), загруженной обязательным загрузчиком с валидатором LM1. */
    private CrlCache primedConditional(ConditionalLoader mandatory) throws Exception {
        CrlCache cache = cache(CrlCache.DEFAULT_MAX_BYTES);
        get(cache, mandatory, null);
        return cache;
    }

    @Test
    @DisplayName(
            "Обязательная загрузка безусловная, но валидатор ответа попадает в запись и уходит при перепроверке")
    void mandatoryLoadCapturesValidator() throws Exception {
        ConditionalLoader mandatory =
                new ConditionalLoader().then(CrlFetchResult.full(crl(1), LM1));
        ConditionalLoader recheck = new ConditionalLoader().then(CrlFetchResult.notModified());
        CrlCache cache = primedConditional(mandatory);
        clock.addAndGet(HOUR_MS);

        get(cache, mandatory, recheck);

        assertEquals(java.util.Arrays.asList((String) null), mandatory.validators, "безусловная");
        assertEquals(List.of(LM1), recheck.validators, "перепроверка условная");
    }

    @Test
    @DisplayName(
            "304: запись прежняя, возраст сброшен, срок не продлён, пауза и предупреждения сняты")
    void notModifiedResetsAgeOnly() throws Exception {
        ConditionalLoader mandatory =
                new ConditionalLoader().then(CrlFetchResult.full(crl(1), LM1));
        ConditionalLoader recheck = new ConditionalLoader().then(CrlFetchResult.notModified());
        CrlCache cache = primedConditional(mandatory);
        VerifiedCrl original = get(cache, mandatory, null).crl();
        clock.addAndGet(HOUR_MS);

        Loaded loaded = get(cache, mandatory, recheck);

        assertTrue(loaded.fromCache());
        assertSame(original, loaded.crl(), "тело не загружалось, запись та же");
        clock.addAndGet(HOUR_MS - 1);
        get(cache, mandatory, recheck);
        assertEquals(1, recheck.validators.size(), "возраст сброшен");
        clock.addAndGet(1);
        get(cache, mandatory, recheck);
        assertEquals(List.of(LM1, LM1), recheck.validators, "валидатор прежний, 304 его не менял");
    }

    @Test
    @DisplayName("304 валидатор не меняет: он остаётся прежним при любом числе ответов 304")
    void notModifiedKeepsValidator() throws Exception {
        ConditionalLoader mandatory =
                new ConditionalLoader().then(CrlFetchResult.full(crl(1), LM1));
        ConditionalLoader recheck = new ConditionalLoader().then(CrlFetchResult.notModified());
        CrlCache cache = primedConditional(mandatory);

        for (int i = 0; i < 3; i++) {
            clock.addAndGet(HOUR_MS);
            get(cache, mandatory, recheck);
        }

        assertEquals(List.of(LM1, LM1, LM1), recheck.validators, "304 валидатор не двигает");
    }

    @Test
    @DisplayName(
            "Ответ 200 не ограничивается правилом 304: его Last-Modified - новая точка отсчёта")
    void fullResponseValidatorIsTakenAsIs() throws Exception {
        ConditionalLoader mandatory =
                new ConditionalLoader().then(CrlFetchResult.full(crl(1), LM2));
        ConditionalLoader recheck =
                new ConditionalLoader()
                        .then(CrlFetchResult.full(crl(2), LM1), CrlFetchResult.notModified());
        CrlCache cache = primedConditional(mandatory);

        clock.addAndGet(HOUR_MS);
        get(cache, mandatory, recheck);
        clock.addAndGet(HOUR_MS);
        get(cache, mandatory, recheck);

        assertEquals(List.of(LM2, LM1), recheck.validators, "новое содержимое - его дата");
    }

    @Test
    @DisplayName(
            "Ответ 200 без Last-Modified очищает валидатор: следующая перепроверка безусловная")
    void fullResponseWithoutLastModifiedClearsValidator() throws Exception {
        ConditionalLoader mandatory =
                new ConditionalLoader().then(CrlFetchResult.full(crl(1), LM1));
        ConditionalLoader recheck =
                new ConditionalLoader()
                        .then(CrlFetchResult.full(crl(2)), CrlFetchResult.notModified());
        CrlCache cache = primedConditional(mandatory);
        clock.addAndGet(HOUR_MS);
        get(cache, mandatory, recheck);
        clock.addAndGet(HOUR_MS);

        get(cache, mandatory, recheck);

        assertEquals(
                java.util.Arrays.asList(LM1, null),
                recheck.validators,
                "после 200 без LM валидатора нет");
    }

    @Test
    @DisplayName("«Тот же номер» с ответом 200 без Last-Modified тоже очищает валидатор")
    void sameNumberWithoutLastModifiedClearsValidator() throws Exception {
        Instant nextUpdate = Instant.now().plus(Duration.ofDays(30));
        ConditionalLoader mandatory =
                new ConditionalLoader().then(CrlFetchResult.full(crl(1, nextUpdate, 1), LM1));
        ConditionalLoader recheck =
                new ConditionalLoader()
                        .then(
                                CrlFetchResult.full(crl(1, nextUpdate, 1)),
                                CrlFetchResult.notModified());
        CrlCache cache = primedConditional(mandatory);
        clock.addAndGet(HOUR_MS);
        get(cache, mandatory, recheck);
        clock.addAndGet(HOUR_MS);

        get(cache, mandatory, recheck);

        assertEquals(java.util.Arrays.asList(LM1, null), recheck.validators);
    }

    @Test
    @DisplayName("200 вместо 304 с новым Last-Modified: новая запись и новый валидатор")
    void fullResponseReplacesValidator() throws Exception {
        ConditionalLoader mandatory =
                new ConditionalLoader().then(CrlFetchResult.full(crl(1), LM1));
        ConditionalLoader recheck =
                new ConditionalLoader()
                        .then(CrlFetchResult.full(crl(2), LM2), CrlFetchResult.notModified());
        CrlCache cache = primedConditional(mandatory);
        clock.addAndGet(HOUR_MS);
        Loaded fresh = get(cache, mandatory, recheck);
        clock.addAndGet(HOUR_MS);

        get(cache, mandatory, recheck);

        assertEquals(BigInteger.TWO, fresh.crl().getCrlNumber());
        assertEquals(List.of(LM1, LM2), recheck.validators);
    }

    @Test
    @DisplayName("304, пришедший после истечения записи, не принимается: запись не продлевается")
    void notModifiedForExpiredEntryIsIgnored() throws Exception {
        ConditionalLoader mandatory =
                new ConditionalLoader()
                        .then(
                                CrlFetchResult.full(
                                        crl(1, Instant.now().plus(Duration.ofMinutes(90)), 1), LM1),
                                CrlFetchResult.full(crl(2), LM2));
        ConditionalLoader recheck =
                new ConditionalLoader()
                        .then(CrlFetchResult.notModified())
                        .before(() -> clock.addAndGet(Duration.ofMinutes(40).toMillis()));
        CrlCache cache = primedConditional(mandatory);
        clock.addAndGet(HOUR_MS + 1);

        Loaded loaded = get(cache, mandatory, recheck);

        assertFalse(loaded.fromCache(), "истёкшую запись 304 не оживляет");
        assertEquals(BigInteger.TWO, loaded.crl().getCrlNumber(), "обязательная загрузка");
        assertEquals(2, mandatory.validators.size());
    }

    @Test
    @DisplayName(
            "304 на безусловный запрос (валидатора нет): неудача перепроверки, запись остаётся")
    void unconditionalNotModifiedIsFailure() throws Exception {
        ConditionalLoader mandatory = new ConditionalLoader().then(CrlFetchResult.full(crl(1)));
        ConditionalLoader recheck = new ConditionalLoader().then(CrlFetchResult.notModified());
        CrlCache cache = primedConditional(mandatory);
        VerifiedCrl original = get(cache, mandatory, null).crl();
        clock.addAndGet(HOUR_MS);

        Loaded loaded = get(cache, mandatory, recheck);
        get(cache, mandatory, recheck);

        assertSame(original, loaded.crl());
        assertEquals(1, recheck.validators.size(), "неудача поставила паузу");
        assertEquals(1, count(Level.WARNING, "recheck"));
        assertEquals(
                java.util.Arrays.asList((String) null),
                recheck.validators,
                "запрос был безусловным");
    }

    @Test
    @DisplayName("Сырая запись сохраняет валидатор и перепроверяется условно")
    void rawEntryKeepsValidator() throws Exception {
        byte[] first = crl(1);
        long parsed = authenticate(first).getEstimatedBytes();
        CrlCache cache = cache(parsed - 1);
        ConditionalLoader mandatory = new ConditionalLoader().then(CrlFetchResult.full(first, LM1));
        ConditionalLoader recheck = new ConditionalLoader().then(CrlFetchResult.notModified());
        get(cache, mandatory, null);
        assertEquals(1, cache.size(), "хранится сырая запись");
        clock.addAndGet(HOUR_MS);

        get(cache, mandatory, recheck);

        assertEquals(List.of(LM1), recheck.validators);
    }

    @Test
    @DisplayName("CRL, не помещающийся в бюджет, не кэшируется: записи и условного запроса нет")
    void notCachedCrlHasNoValidator() throws Exception {
        byte[] der = crl(1);
        CrlCache cache = cache(der.length - 1);
        ConditionalLoader mandatory = new ConditionalLoader().then(CrlFetchResult.full(der, LM1));
        ConditionalLoader recheck = new ConditionalLoader().then(CrlFetchResult.notModified());
        get(cache, mandatory, recheck);
        clock.addAndGet(HOUR_MS);

        get(cache, mandatory, recheck);

        assertEquals(0, recheck.validators.size(), "перепроверять нечего");
        assertEquals(2, mandatory.validators.size(), "обязательные загрузки безусловные");
    }

    /** Два узла за одним адресом: файл на A датирован LM1, на B - LM2 > LM1; оба включают свою дату в 304. */
    private static final class TwoNodes implements CrlCache.Loader {
        final AtomicInteger fullResponses = new AtomicInteger();
        private final AtomicInteger calls = new AtomicInteger();
        private final byte[] crl;

        TwoNodes(byte[] crl) {
            this.crl = crl;
        }

        @Override
        public byte[] fetch() {
            return fetchConditional(null).der();
        }

        @Override
        public CrlFetchResult fetchConditional(String validator) {
            // Запросы чередуются: первым отвечает B, затем A, и так далее
            String mtime = calls.getAndIncrement() % 2 == 0 ? LM2 : LM1;
            if (validator != null && !isAfter(mtime, validator)) {
                return CrlFetchResult.notModified();
            }
            fullResponses.incrementAndGet();
            return CrlFetchResult.full(crl, mtime);
        }

        private static boolean isAfter(String a, String b) {
            java.time.format.DateTimeFormatter f =
                    java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME;
            return java.time.ZonedDateTime.parse(a, f).isAfter(java.time.ZonedDateTime.parse(b, f));
        }
    }

    @Test
    @DisplayName(
            "Два узла с датами D1 < D2 чередуются: после первого ответа 200 от D2 все ответы 304")
    void twoNodesConvergeToNewestDate() throws Exception {
        byte[] crl = crl(1, Instant.now().plus(Duration.ofDays(30)), 1);
        TwoNodes nodes = new TwoNodes(crl);
        // Первая (обязательная) загрузка пришла от узла A с датой LM1
        CrlCache cache = cache(CrlCache.DEFAULT_MAX_BYTES);
        get(cache, new ConditionalLoader().then(CrlFetchResult.full(crl, LM1)), null);

        for (int i = 0; i < 8; i++) {
            clock.addAndGet(HOUR_MS);
            get(cache, nodes, nodes);
        }

        assertEquals(
                1,
                nodes.fullResponses.get(),
                "одна полная загрузка (узел B с более новой датой), дальше только 304");
    }
}
