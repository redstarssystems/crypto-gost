package org.rssys.gost.jsse.crl;

import java.io.IOException;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.VerifiedCrl;
import org.rssys.gost.pkix.util.Deadline;
import org.rssys.gost.pkix.util.DeadlineExceededException;
import org.rssys.gost.pkix.util.FetchFailure;
import org.rssys.gost.util.GostLogger;
import org.rssys.gost.util.GostLogger.Level;
import org.rssys.gost.util.SafeText;

/**
 * Кэш проверенных CRL с единственной загрузкой и защитой от отката (RFC 5280 §5.2.3).
 *
 * <p>Дорогая часть проверки CRL (хэш, подпись ГОСТ, строгий разбор записей) не зависит от
 * проверяемого сертификата, поэтому кэш хранит результат этой части - {@link VerifiedCrl}, а
 * сертификат проверяется по нему на каждом соединении ({@link VerifiedCrl#verifyFor}).</p>
 *
 * <h2>Ключ и записи</h2>
 * <p>Ключ - адрес CRL и хэш сертификата издателя: один адрес у двух издателей не смешивается.
 * Запись бывает двух видов. Разобранная ({@link VerifiedCrl}) снимает с соединения хэш и разбор.
 * Сырая (DER) хранится, когда разобранный объект не помещается в бюджет: она сохраняет главное
 * свойство кэша - CRL берётся по сети один раз до {@code nextUpdate}, но проверка выполняется
 * заново. Сырой DER наружу не выдаётся. Срок жизни записи - {@code nextUpdate} плюс допуск часов
 * ({@link GostOids#CLOCK_SKEW_MS}). CRL без {@code nextUpdate} проверка не принимает, поэтому в
 * кэш он не попадает.</p>
 *
 * <h2>Бюджет памяти</h2>
 * <p>Бюджет общий для обоих видов записей: у разобранной считается
 * {@link VerifiedCrl#getEstimatedBytes()} (около шести байт кучи на байт DER), у сырой - длина
 * DER. Это верхняя граница, а не занятая память. Значение 0 запрещает хранить любые записи;
 * единственная загрузка и защита от отката при этом остаются, но каждое последовательное
 * соединение загружает CRL заново. При переполнении вытесняется запись, ближайшая к истечению;
 * только что добавленная не вытесняется, если сама не больше бюджета.</p>
 *
 * <h2>Единственная загрузка</h2>
 * <p>Если CRL нет в кэше, загружает его один поток (инициатор), остальные ждут его результата и
 * проверяют по нему свои сертификаты. Ожидание ограничено сроком {@code maxWait} вызова
 * {@link #get} (менеджер доверия передаёт остаток бюджета проверки): ожидающий, не дождавшийся
 * результата, получает {@link DeadlineExceededException}. Это не отменяет и не портит загрузку
 * инициатора: инициатор и остальные ожидающие получают результат как обычно. Срок ограничивает
 * только ожидание. Попадание в кэш срок игнорирует, а поток, не нашедший инициатора, становится
 * им сам и грузит без ограничения срока (первая загрузка разрешена всегда). Поэтому
 * {@link CrlFetcher} по-прежнему обязан ограничивать время загрузки, а проверка подписи
 * инициатора срока не имеет: ожидающий может сдаться, пока инициатор её выполняет. Исход самого
 * CRL (слишком большой, сетевая ошибка, неверная подпись) получают все; исход потока-инициатора
 * (прерывание, сбой) получает только он, а ожидающие повторяют попытку. Ошибка не кэшируется.
 * О сдаче ожидающего кэш пишет в журнал одно предупреждение на серию сдач по ключу: после
 * успешной загрузки по этому ключу следующая сдача снова пишется.</p>
 *
 * <h2>Перепроверка раньше nextUpdate</h2>
 * <p>Запись живёт до {@code nextUpdate} плюс допуск часов, но если УЦ выпустил новый CRL раньше,
 * он не виден. Поэтому запись, загруженная давнее предельного возраста ({@code maxAge}, по
 * умолчанию {@link #DEFAULT_MAX_AGE}), но ещё не истёкшая, перепроверяется: одно соединение
 * (поставившее отметку на ключ) грузит CRL заново, остальные не ждут и берут действующую запись.
 * Возраст считается от последней успешной загрузки на часах кэша. Больший {@code cRLNumber}
 * заменяет запись; тот же номер только сбрасывает возраст; меньший номер или отсутствие номера
 * при известном - признак отката, запись остаётся, пишется ERROR. Неудача (сеть, срок, подпись,
 * пропуск бюджета) оставляет прежнюю подлинную запись до {@code nextUpdate}, возраст не
 * сбрасывает, а следующая попытка по ключу не раньше паузы {@code min(maxAge, 5 минут)}.
 * Это сознательное ослабление свежести ради доступности: под {@code REQUIRE} отзыв, опубликованный
 * после загрузки, не виден до {@code nextUpdate}, пока сервер недоступен. Задержка видимости нового
 * CRL равна предельному возрасту плюс интервал выпуска CRL у УЦ, а не самому возрасту. Пока идёт
 * перепроверка, в куче лежат старая и новая записи (пик равен сумме двух разобранных записей и в
 * бюджет не входит): бюджет должен вмещать две самые большие разобранные записи. Загрузка
 * перепроверки не ограничена сроком ожидания {@code maxWait}, её ограничивает только срок
 * загрузчика: одно соединение раз в предельный возраст на ключ может занять до потолка проверки
 * плюс срок загрузчика. Перепроверка защищает от устаревшего кэша, а не от подмены ответа на канале.</p>
 *
 * <h2>Защита от отката</h2>
 * <p>Последний известный {@code cRLNumber} хранится по ключу отдельно от записей и переживает
 * истечение и вытеснение. Обновляется до попытки положить CRL в кэш, поэтому не зависит от
 * бюджета.</p>
 *
 * <p>Кэш принадлежит одному менеджеру доверия: несколько {@code SSLContext} держат по отдельной
 * копии.</p>
 */
public final class CrlCache {

    private static final GostLogger LOG = GostLogger.getLogger("org.rssys.gost.jsse.crl.CrlCache");

    /**
     * Предельный возраст записи по умолчанию, 6 часов. Это интервал перепроверки, а не срок, в
     * течение которого отозванный сертификат может приниматься: задержка равна предельному
     * возрасту плюс интервал, с которым УЦ выпускает новый CRL. Значение небольшое, потому что
     * условный запрос ({@code If-Modified-Since}) делает перепроверку неизменившегося CRL дешёвой;
     * если CDP не отдаёт {@code Last-Modified} (или отвечает перенаправлением) и CRL большой,
     * каждая перепроверка - полная загрузка, и значение стоит увеличить.
     */
    public static final Duration DEFAULT_MAX_AGE = Duration.ofHours(6);

    /** Бюджет кэша по умолчанию, 512 МиБ: один CRL ФНС (оценка около 233 МиБ) помещается дважды. */
    public static final long DEFAULT_MAX_BYTES = 512L * 1024 * 1024;

    /**
     * Срок записи после nextUpdate - тот же допуск часов, с которым {@code GostCrl.isExpired()}
     * отвергает CRL: запись не должна жить дольше окна, которое примет проверка.
     */
    private static final long GRACE_MS = GostOids.CLOCK_SKEW_MS;

    /** Максимальное количество записей (защита от аномального числа адресов) */
    static final int MAX_ENTRIES = 100;

    /** Максимальное число ключей с запомненным номером (защита от неограниченного роста) */
    static final int MAX_LAST_KNOWN = 1000;

    /**
     * Предел числа ключей в каждом наборе уже выданных предупреждений. Отдельная константа от
     * {@link #MAX_LAST_KNOWN}: это другой смысл (подавление повторов журнала, а не база защиты от
     * отката). При переполнении набор не растёт, а предупреждение пишется каждый раз.
     */
    static final int MAX_WARNED_KEYS = 1000;

    /** Наименьший допустимый предельный возраст записи: чаще перепроверять CDP не имеет смысла. */
    static final Duration MIN_MAX_AGE = Duration.ofMinutes(1);

    /** Наибольший допустимый предельный возраст записи. */
    static final Duration MAX_MAX_AGE = Duration.ofDays(30);

    /**
     * Наибольшая пауза после неудачной перепроверки. Без паузы каждое следующее соединение шло бы
     * на недоступный сервер: отметка {@code rechecking} объединяет только одновременные попытки.
     */
    static final long MAX_RECHECK_PAUSE_MS = Duration.ofMinutes(5).toMillis();

    /**
     * Предел числа ключей с паузой (защита от неограниченного роста). При переполнении пауза для
     * нового ключа не запоминается, и его постоянно неудачная перепроверка идёт на каждом
     * соединении: тысяча одновременно недоступных адресов на один менеджер - исключительная
     * ситуация.
     */
    static final int MAX_PAUSED_KEYS = 1000;

    /** Предупреждения, которые пишутся не чаще одного раза на ключ. */
    enum Warning {
        /** Разобранный CRL не помещается в бюджет: хранится сырой DER. */
        RAW_KEPT,
        /** CRL не помещается в бюджет вовсе: грузится заново на каждом соединении. */
        NOT_CACHED,
        /** Ожидающий не дождался чужой загрузки этого CRL. */
        WAIT_GAVE_UP,
        /** Перепроверка не удалась, используется прежняя запись. Событие: сбрасывается успехом. */
        RECHECK_FAILED
    }

    private final long maxBytes;
    private final long maxAgeMs;
    private final LongSupplier clock;
    private final ConcurrentHashMap<CrlKey, Entry> cache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<CrlKey, CompletableFuture<VerifiedCrl>> inflight =
            new ConcurrentHashMap<>();
    private final ConcurrentHashMap<CrlKey, BigInteger> lastKnown = new ConcurrentHashMap<>();
    // Ключи, по которым сейчас идёт перепроверка: перепроверяет тот, у кого add вернул true
    private final Set<CrlKey> rechecking = ConcurrentHashMap.newKeySet();
    // До какого момента (по часам кэша) перепроверка ключа после неудачи не повторяется
    private final ConcurrentHashMap<CrlKey, Long> retryAt = new ConcurrentHashMap<>();
    // Наборы ключей, по которым предупреждение уже выдано. Карта по перечислению заполняется в
    // конструкторе и дальше не меняется, наборы потокобезопасны сами по себе
    private final EnumMap<Warning, Set<CrlKey>> warned = new EnumMap<>(Warning.class);
    // Замок только вокруг изменения набора записей: сумма бюджета считается по содержимому карты
    private final ReentrantLock storeLock = new ReentrantLock();

    /** Ключ кэша: адрес CRL и хэш сертификата издателя (шестнадцатеричный). */
    public record CrlKey(String uri, String issuerCertHash) {
        /** Проверяет, что обе части ключа заданы. */
        public CrlKey {
            Objects.requireNonNull(uri);
            Objects.requireNonNull(issuerCertHash);
        }
    }

    /**
     * Результат {@link #get}.
     *
     * @param crl       проверенный CRL
     * @param fromCache {@code true}, если объект взят из кэша; {@code false}, если загружен в этом
     *                  вызове или получен от потока-инициатора
     */
    public record Loaded(VerifiedCrl crl, boolean fromCache) {}

    /** Загрузка DER CRL; {@code null} означает «данных нет». */
    @FunctionalInterface
    public interface Loader {
        byte[] fetch() throws IOException;

        /**
         * Условная загрузка. Кэш вызывает именно этот метод: при обязательной загрузке с
         * {@code validator == null}, при перепроверке - с {@code Last-Modified}, сохранённым вместе
         * с записью. Реализация по умолчанию - полная загрузка через {@link #fetch()} без валидатора:
         * лямбды и загрузчики, не умеющие условный запрос, работают как раньше.
         *
         * @param validator {@code Last-Modified} прошлой загрузки или {@code null}
         * @return ответ с телом, «не изменился» (только если {@code validator != null}) либо без данных
         */
        default CrlFetchResult fetchConditional(String validator) throws IOException {
            return CrlFetchResult.full(fetch());
        }
    }

    /** Проверка подписи и разбор DER (дорогая часть, не зависит от сертификата). */
    @FunctionalInterface
    public interface Authenticator {
        VerifiedCrl authenticate(byte[] crlDer) throws PkixException;
    }

    private record Entry(
            VerifiedCrl parsed,
            byte[] rawDer,
            long expiresAt,
            long bytes,
            long loadedAt,
            String validator) {
        boolean isExpired(long now) {
            return now > expiresAt;
        }

        /** Та же запись с новым возрастом и валидатором ({@code null} очищает валидатор). */
        Entry withAge(long newLoadedAt, String newValidator) {
            return new Entry(parsed, rawDer, expiresAt, bytes, newLoadedAt, newValidator);
        }
    }

    /**
     * @param maxBytes бюджет кэша в байтах оценки удержания; 0 - не хранить записи
     * @param maxAge   предельный возраст записи с последней успешной загрузки: запись старше
     *                 перепроверяется раньше {@code nextUpdate}. {@link Duration#ZERO} выключает
     *                 перепроверку, иначе от 1 минуты до 30 суток
     * @throws IllegalArgumentException если {@code maxBytes} отрицательный, а {@code maxAge}
     *                                  {@code null} или вне допустимых границ
     */
    public CrlCache(long maxBytes, Duration maxAge) {
        this(maxBytes, maxAge, System::currentTimeMillis);
    }

    /** Для тестов: подмена часов, чтобы проверять истечение записей без ожидания. */
    CrlCache(long maxBytes, Duration maxAge, LongSupplier clock) {
        this.maxBytes = requireValidMaxBytes(maxBytes);
        requireValidMaxAge(maxAge);
        this.maxAgeMs = maxAge.toMillis();
        this.clock = Objects.requireNonNull(clock);
        for (Warning kind : Warning.values()) {
            warned.put(kind, ConcurrentHashMap.newKeySet());
        }
    }

    /**
     * Проверяет бюджет кэша: не отрицательный; 0 запрещает хранить CRL между соединениями.
     *
     * @return {@code maxBytes}
     * @throws IllegalArgumentException если значение отрицательное
     */
    public static long requireValidMaxBytes(long maxBytes) {
        if (maxBytes < 0) {
            throw new IllegalArgumentException(
                    "crlCacheMaxBytes must not be negative: " + maxBytes);
        }
        return maxBytes;
    }

    /**
     * Проверяет предельный возраст записи: {@link Duration#ZERO} (перепроверка выключена) или от
     * {@link #MIN_MAX_AGE} до {@link #MAX_MAX_AGE}.
     *
     * @throws IllegalArgumentException если значение {@code null} или вне границ
     */
    public static Duration requireValidMaxAge(Duration maxAge) {
        if (maxAge == null
                || maxAge.isNegative()
                || (!maxAge.isZero()
                        && (maxAge.compareTo(MIN_MAX_AGE) < 0
                                || maxAge.compareTo(MAX_MAX_AGE) > 0))) {
            throw new IllegalArgumentException(
                    "crlMaxAge must be zero (disabled) or between "
                            + MIN_MAX_AGE
                            + " and "
                            + MAX_MAX_AGE
                            + ": "
                            + maxAge);
        }
        return maxAge;
    }

    /**
     * Возвращает проверенный CRL: из кэша либо загрузив и проверив его (один поток на ключ).
     *
     * <p>Дорогая проверка выполняется до применения к сертификату и от него не зависит.
     * Откат {@code cRLNumber} относительно запомненного номера отвергает CRL для всех.</p>
     *
     * <p><b>Срок {@code maxWait}</b> - общий предел ожидания чужой загрузки на весь вызов, а не на
     * одну попытку. Он не ограничивает остальное: попадание в кэш возвращается при любом сроке (и
     * при {@link Duration#ZERO}), а поток, не нашедший инициатора, грузит и проверяет сам. Если
     * инициатор есть, а срок вышел, бросается {@link DeadlineExceededException}; загрузка
     * инициатора при этом не отменяется и не портится. Результат, уже готовый к моменту проверки
     * срока, отдаётся и при нулевом остатке.</p>
     *
     * <p><b>Перепроверка.</b> Если запись старше предельного возраста ({@code maxAge} кэша), но
     * ещё не истекла, один из потоков (тот, кто поставил отметку) грузит CRL заново через
     * {@code recheckLoader}, остальные сразу берут действующую запись и не ждут. Перепроверка
     * необязательна: при любой неудаче (сеть, срок, размер, подпись, пропуск бюджета) запись
     * остаётся до {@code nextUpdate}, возраст не сбрасывается, а следующая попытка по ключу не
     * раньше паузы. Загрузка перепроверки не ограничена {@code maxWait} (её ограничивает срок
     * загрузчика). Новый CRL с меньшим {@code cRLNumber}, чем у записи, и CRL без номера при
     * известном номере не заменяют запись и записываются в журнал как ERROR: это признак отката,
     * но соединение не отвергается, у него есть более новая подлинная запись.</p>
     *
     * @param key           ключ
     * @param loader        получение DER (например, по сети) для обязательной загрузки
     * @param recheckLoader получение DER для перепроверки или {@code null}: перепроверка для
     *                      этого вызова отключена. Отдельный загрузчик нужен, чтобы необязательная
     *                      перепроверка не расходовала «первую загрузку» бюджета вызывающего
     * @param authenticator проверка подписи и разбор
     * @param maxWait       предел ожидания чужой загрузки, от нуля до
     *                      {@link Deadline#MAX_FETCH_TIMEOUT}
     * @return проверенный CRL и признак того, что он взят из кэша
     * @throws IllegalArgumentException   если {@code maxWait} равен {@code null}, отрицателен или
     *                                    больше {@link Deadline#MAX_FETCH_TIMEOUT}
     * @throws DeadlineExceededException  если срок вышел, пока ждали чужую загрузку
     * @throws IOException                при сетевой ошибке, отсутствии данных, превышении размера
     *                                    ({@link CrlSizeLimitException}) или прерывании ожидания
     * @throws PkixException              если CRL не прошёл проверку или его номер ниже запомненного
     */
    public Loaded get(
            CrlKey key,
            Loader loader,
            Loader recheckLoader,
            Authenticator authenticator,
            Duration maxWait)
            throws IOException, PkixException {
        Objects.requireNonNull(key);
        Objects.requireNonNull(loader);
        Objects.requireNonNull(authenticator);
        requireValidMaxWait(maxWait);
        // Один конечный момент на весь вызов: каждая ветка ожидания берёт остаток
        long waitEndNanos = System.nanoTime() + maxWait.toNanos();
        for (; ; ) {
            long now = clock.getAsLong();
            removeExpired(now);
            Entry cached = cache.get(key);
            if (recheckLoader != null && isRecheckDue(key, cached, now)) {
                Loaded fresh = recheck(key, cached, recheckLoader, authenticator);
                if (fresh != null) {
                    return fresh;
                }
                // Перепроверка не заменила запись (неудача, «новостей нет», чужая): состояние
                // читается заново, резерв проверяется на срок в момент возврата
                now = clock.getAsLong();
                removeExpired(now);
                cached = cache.get(key);
            }
            if (cached != null && cached.parsed() != null && !cached.isExpired(now)) {
                return new Loaded(cached.parsed(), true);
            }
            CompletableFuture<VerifiedCrl> mine = new CompletableFuture<>();
            CompletableFuture<VerifiedCrl> other = inflight.putIfAbsent(key, mine);
            if (other == null) {
                Loaded led = lead(key, mine, loader, authenticator);
                if (led != null) {
                    return led;
                }
                continue;
            }
            VerifiedCrl awaited = await(key, other, waitEndNanos);
            if (awaited != null) {
                return new Loaded(awaited, false);
            }
            // Инициатор не дошёл до результата по своей причине: пробуем снова
        }
    }

    /** Нужна ли перепроверка: возраст дошёл до предела, запись не истекла, паузы нет. */
    private boolean isRecheckDue(CrlKey key, Entry cached, long now) {
        if (maxAgeMs == 0 || cached == null || cached.isExpired(now)) {
            return false;
        }
        // Часы ушли назад: отрицательный возраст не может достичь предела
        if (now - cached.loadedAt() < maxAgeMs) {
            return false;
        }
        Long until = retryAt.get(key);
        if (until != null) {
            if (now < until) {
                return false;
            }
            retryAt.remove(key, until);
        }
        return true;
    }

    /**
     * Перепроверка записи. Возвращает новый CRL, если он принят и заменил запись, иначе
     * {@code null}: вызывающий идёт дальше по обычной логике и использует прежнюю запись.
     */
    private Loaded recheck(
            CrlKey key, Entry cached, Loader recheckLoader, Authenticator authenticator) {
        // Тот, кто не поставил отметку, не перепроверяет: запись уже проверяет другой поток
        if (!rechecking.add(key)) {
            return null;
        }
        try {
            BigInteger startNumber = lastKnown.get(key);
            String sentValidator = cached.validator();
            byte[] der;
            VerifiedCrl verified;
            CrlFetchResult result;
            try {
                result = recheckLoader.fetchConditional(sentValidator);
                if (result.isNotModified()) {
                    acceptNotModified(key, cached, sentValidator);
                    return null;
                }
                der = result.der();
                if (der == null) {
                    recheckFailed(
                            key, result.failure() != null ? result.failure().name() : "no data");
                    return null;
                }
                verified = authenticator.authenticate(der);
            } catch (LoadSkippedException e) {
                // Бюджет вызывающего, а не адрес: ни паузы, ни предупреждения
                return null;
            } catch (IOException | PkixException | RuntimeException e) {
                recheckFailed(key, e.getClass().getSimpleName());
                return null;
            }
            // Ответ 200 - новое содержимое, его дата и есть точка отсчёта; без допустимого
            // Last-Modified валидатор очищается: он относился к прежнему телу
            String newValidator = result.lastModified();
            BigInteger number = verified.getCrlNumber();
            // Откат относительно записи, с которой перепроверка начиналась: подмена или ошибка
            // публикации
            if (startNumber != null && (number == null || number.compareTo(startNumber) < 0)) {
                LOG.log(
                        Level.WARNING,
                        "CRL recheck for {0} returned cRLNumber {1} below the known {2}:"
                                + " rollback suspected, the cached CRL is kept",
                        SafeText.uri(key.uri()),
                        number,
                        startNumber);
                pauseRecheck(key);
                return null;
            }
            // Пока перепроверка качала CRL, обязательная загрузка могла положить более новый:
            // результат устарел, это не откат, и тревогу поднимать не нужно
            BigInteger current = lastKnown.get(key);
            if (current != null && number != null && number.compareTo(current) < 0) {
                return null;
            }
            boolean sameNumber = number != null && number.equals(startNumber);
            if (sameNumber) {
                refreshSameNumber(key, cached, verified, der, newValidator);
                recheckSucceeded(key);
                return null;
            }
            rememberCrlNumber(key, number);
            if (!store(key, verified, der, newValidator)) {
                // Свежий CRL не помещается в бюджет: прежняя запись удаляется, чтобы не
                // перепроверять его на каждом соединении; дальше CRL грузится обязательной
                // загрузкой, как при любом «не кэшируется»
                cache.remove(key, cached);
            }
            recheckSucceeded(key);
            return new Loaded(verified, false);
        } finally {
            rechecking.remove(key);
        }
    }

    /**
     * Ответ 304 на условный запрос перепроверки: CRL не изменился. Успешная перепроверка: возраст
     * сбрасывается, срок записи не меняется, валидатор остаётся прежним (дата из ответа 304 не
     * читается: более ранняя откатила бы валидатор, а более поздняя противоречит RFC 9110 и
     * увела бы его вперёд без тела). 304 принимается только на наш условный запрос и только для
     * записи, которая жива к моменту ответа: ответ не подписан, и истёкшую запись он не продлевает.
     */
    private void acceptNotModified(CrlKey key, Entry cached, String sentValidator) {
        if (sentValidator == null) {
            // 304 на безусловный запрос - аномалия сервера или загрузчика
            recheckFailed(key, "unexpected 304");
            return;
        }
        long now = clock.getAsLong();
        if (cached.isExpired(now)) {
            return;
        }
        cache.replace(key, cached, cached.withAge(now, sentValidator));
        recheckSucceeded(key);
    }

    /**
     * «Новостей нет»: возраст записи сбрасывается; запись заменяется новым объектом, только если
     * у него {@code nextUpdate} позже (продлевает жизнь), иначе остаётся прежняя. Валидатор
     * берётся из нового ответа (без {@code Last-Modified} он очищается).
     */
    private void refreshSameNumber(
            CrlKey key, Entry cached, VerifiedCrl verified, byte[] der, String validator) {
        if (expiryOf(verified) > cached.expiresAt() && store(key, verified, der, validator)) {
            return;
        }
        cache.replace(key, cached, cached.withAge(clock.getAsLong(), validator));
    }

    private void recheckSucceeded(CrlKey key) {
        retryAt.remove(key);
        warned.get(Warning.RECHECK_FAILED).remove(key);
    }

    private void recheckFailed(CrlKey key, String reason) {
        warnOnce(
                Warning.RECHECK_FAILED,
                key,
                "CRL recheck for {0} failed ({1}): the cached CRL is used until nextUpdate",
                reason);
        pauseRecheck(key);
    }

    /** Откладывает следующую попытку перепроверки по ключу. */
    private void pauseRecheck(CrlKey key) {
        if (retryAt.size() >= MAX_PAUSED_KEYS && !retryAt.containsKey(key)) {
            // Переполнение: пауза не запоминается, перепроверка ключа возможна снова
            return;
        }
        retryAt.put(key, clock.getAsLong() + Math.min(maxAgeMs, MAX_RECHECK_PAUSE_MS));
    }

    private static void requireValidMaxWait(Duration maxWait) {
        if (maxWait == null
                || maxWait.isNegative()
                || maxWait.compareTo(Deadline.MAX_FETCH_TIMEOUT) > 0) {
            throw new IllegalArgumentException(
                    "maxWait must be between zero and "
                            + Deadline.MAX_FETCH_TIMEOUT
                            + ": "
                            + maxWait);
        }
    }

    /**
     * <b>Внутренний тип механизма бюджета загрузок, не публичный API; может измениться без
     * предупреждения.</b> Загрузка не начата по причине вызывающего потока (например, исчерпан его бюджет на
     * загрузки), а не из-за адреса. Загрузчик бросает её, чтобы поток-инициатор отказался от
     * загрузки: ожидающие потоки других соединений ошибку не получают и повторяют загрузку сами.
     */
    public static final class LoadSkippedException extends IOException {

        private static final long serialVersionUID = 1L;

        /**
         * Создаёт исключение пропущенной загрузки.
         *
         * @param message причина пропуска
         */
        public LoadSkippedException(String message) {
            super(message);
        }
    }

    /**
     * Загрузчик не дал данных CRL. Причина (если загрузчик её сообщил) это перечисление, не
     * текст: менеджер доверия пишет её в журнал вместе с адресом, не читая сообщение.
     */
    public static final class NoDataException extends IOException {

        private static final long serialVersionUID = 1L;

        private final FetchFailure failure;

        NoDataException(String uri, FetchFailure failure) {
            super("No CRL data from " + SafeText.uri(uri));
            this.failure = failure;
        }

        /** Причина отказа загрузки или {@code null}, если загрузчик её не сообщил. */
        public FetchFailure failure() {
            return failure;
        }
    }

    /**
     * Последний известный {@code cRLNumber} по ключу или {@code null}. Переживает истечение и
     * вытеснение записи. Менеджеру номер не нужен: откат проверяет сам {@link #get} при загрузке.
     */
    BigInteger lastKnownCrlNumber(CrlKey key) {
        Objects.requireNonNull(key);
        return lastKnown.get(key);
    }

    /**
     * Удаляет запись, если в ней лежит именно этот объект (например, когда срок объекта истёк
     * между выдачей и использованием). Запомненный номер не трогается.
     */
    public void invalidate(CrlKey key, VerifiedCrl crl) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(crl);
        cache.entrySet().removeIf(e -> e.getKey().equals(key) && e.getValue().parsed() == crl);
    }

    /**
     * Работа потока-инициатора. Возвращает {@code null}, если нужно начать цикл заново (сырая
     * запись оказалась просроченной в узком окне между проверкой срока кэша и срока CRL).
     */
    private Loaded lead(
            CrlKey key,
            CompletableFuture<VerifiedCrl> mine,
            Loader loader,
            Authenticator authenticator)
            throws IOException, PkixException {
        try {
            Entry raw = cache.get(key);
            boolean fromRaw =
                    raw != null && raw.rawDer() != null && !raw.isExpired(clock.getAsLong());
            byte[] der;
            String validator = null;
            if (fromRaw) {
                der = raw.rawDer();
            } else {
                // Обязательная загрузка всегда безусловная, но захватывает Last-Modified ответа:
                // так уже первая перепроверка записи может быть условной
                CrlFetchResult fetched = loader.fetchConditional(null);
                if (fetched.isNotModified()) {
                    throw new IOException(
                            "Unexpected 'not modified' for an unconditional load of "
                                    + SafeText.uri(key.uri()));
                }
                der = fetched.der();
                validator = fetched.lastModified();
                if (der == null) {
                    throw new NoDataException(key.uri(), fetched.failure());
                }
            }
            VerifiedCrl verified;
            try {
                verified = authenticator.authenticate(der);
            } catch (PkixException e) {
                if (fromRaw && e.reason() == PkixException.Reason.EXPIRED) {
                    cache.remove(key, raw);
                    return null;
                }
                throw e;
            }
            requireNotRollback(key, verified);
            rememberCrlNumber(key, verified.getCrlNumber());
            if (!fromRaw) {
                store(key, verified, der, validator);
            }
            mine.complete(verified);
            // Сдача ожидающего - событие, а не свойство CRL: после успешной загрузки следующая
            // серия сдач снова заслуживает записи (при IF_CDP_PRESENT каждая значит пропущенную
            // проверку отзыва). Наборы «сырой DER» и «не кэшируется» не сбрасываются: успешная
            // загрузка не делает слишком большой CRL меньше
            warned.get(Warning.WAIT_GAVE_UP).remove(key);
            return new Loaded(verified, false);
        } catch (IOException e) {
            // Прерывание и пропуск загрузки принадлежат потоку-инициатору, а не CRL: ожидающим их
            // передавать нельзя, иначе одно соединение портило бы проверку других
            if (Thread.currentThread().isInterrupted() || e instanceof LoadSkippedException) {
                mine.complete(null);
            } else {
                mine.completeExceptionally(e);
            }
            throw e;
        } catch (PkixException e) {
            mine.completeExceptionally(e);
            throw e;
        } finally {
            // Запись из карты ожидающих убирается после помещения в кэш: пришедший в этот момент
            // поток найдёт запись, а не начнёт вторую загрузку. Незавершённый результат (сбой
            // потока: Error, неожиданное исключение) означает «повторить» для ожидающих.
            inflight.remove(key, mine);
            if (!mine.isDone()) {
                mine.complete(null);
            }
        }
    }

    /**
     * Ожидание результата инициатора; {@code null} - инициатор не дошёл до результата. Срок
     * ожидания не записывается в общую будущую загрузку: сдача принадлежит только ожидающему.
     */
    private VerifiedCrl await(CrlKey key, CompletableFuture<VerifiedCrl> future, long waitEndNanos)
            throws IOException, PkixException {
        try {
            // get с нулевым остатком отдаёт уже готовый результат: инициатор, закончивший в
            // последний момент, не превращается в ложный отказ
            return future.get(Math.max(0L, waitEndNanos - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            warnOnce(
                    Warning.WAIT_GAVE_UP,
                    key,
                    "Gave up waiting for a concurrent CRL load of {0}: wait limit exceeded");
            throw new DeadlineExceededException(
                    "Timed out waiting for another connection's CRL load of "
                            + SafeText.uri(key.uri()),
                    e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("CRL wait interrupted", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException io) {
                throw io;
            }
            if (cause instanceof PkixException px) {
                throw px;
            }
            return null;
        }
    }

    /**
     * Пишет предупреждение не чаще одного раза на ключ. При переполнении набора ключ не
     * запоминается и предупреждение пишется каждый раз: громко, но ничего не прячет (тысяча разных
     * адресов на один менеджер - исключительная ситуация). Из-за гонки размер набора может
     * превысить предел на число потоков.
     */
    private void warnOnce(Warning kind, CrlKey key, String message, Object... params) {
        Set<CrlKey> seen = warned.get(kind);
        if (seen.contains(key)) {
            return;
        }
        if (seen.size() < MAX_WARNED_KEYS) {
            if (!seen.add(key)) {
                return;
            }
        }
        Object[] all = new Object[params.length + 1];
        all[0] = SafeText.uri(key.uri());
        System.arraycopy(params, 0, all, 1, params.length);
        LOG.log(Level.WARNING, message, all);
    }

    /** Для тестов: число ключей, по которым предупреждение уже выдано. */
    int warnedKeysCount(Warning kind) {
        return warned.get(kind).size();
    }

    private void requireNotRollback(CrlKey key, VerifiedCrl verified) throws PkixException {
        BigInteger known = lastKnown.get(key);
        if (known == null) {
            return;
        }
        BigInteger actual = verified.getCrlNumber();
        if (actual == null) {
            throw new PkixException(
                    "CRL: no cRLNumber extension, but a previous cRLNumber is known");
        }
        if (actual.compareTo(known) < 0) {
            throw new PkixException(
                    "CRL: cRLNumber downgrade — got " + actual + ", min expected " + known);
        }
    }

    /**
     * Запоминает номер только вверх, до попытки положить CRL в кэш. Пакетная видимость: тест
     * вытеснения базовой линии не должен загружать тысячи CRL.
     */
    void rememberCrlNumber(CrlKey key, BigInteger number) {
        if (number == null) {
            return;
        }
        lastKnown.merge(key, number, (old, fresh) -> fresh.compareTo(old) > 0 ? fresh : old);
        if (lastKnown.size() > MAX_LAST_KNOWN) {
            for (CrlKey candidate : lastKnown.keySet()) {
                if (!candidate.equals(key) && lastKnown.remove(candidate) != null) {
                    LOG.log(
                            Level.WARNING,
                            "CRL rollback baseline evicted for {0} - protection reset for this CDP",
                            SafeText.uri(candidate.uri()));
                    break;
                }
            }
        }
    }

    private void removeExpired(long now) {
        cache.entrySet().removeIf(e -> e.getValue().isExpired(now));
    }

    /** @return {@code true}, если запись положена в кэш; {@code false} - CRL не кэшируется */
    private boolean store(CrlKey key, VerifiedCrl verified, byte[] der, String validator) {
        if (maxBytes == 0) {
            return false;
        }
        long expiresAt = expiryOf(verified);
        Entry chosen;
        if (verified.getEstimatedBytes() <= maxBytes) {
            chosen =
                    new Entry(
                            verified,
                            null,
                            expiresAt,
                            verified.getEstimatedBytes(),
                            clock.getAsLong(),
                            validator);
        } else if (der.length <= maxBytes) {
            warnOnce(
                    Warning.RAW_KEPT,
                    key,
                    "Parsed CRL for {0} (about {1} bytes of heap) exceeds crlCacheMaxBytes {2}:"
                            + " raw DER is kept, parse and signature check repeat per connection",
                    verified.getEstimatedBytes(),
                    maxBytes);
            chosen = new Entry(null, der, expiresAt, der.length, clock.getAsLong(), validator);
        } else {
            warnOnce(
                    Warning.NOT_CACHED,
                    key,
                    "CRL for {0} ({1} bytes) exceeds crlCacheMaxBytes {2}: not cached, it is"
                            + " fetched again on every connection",
                    der.length,
                    maxBytes);
            return false;
        }
        storeLock.lock();
        try {
            cache.remove(key);
            evictToFit(chosen.bytes());
            cache.put(key, chosen);
        } finally {
            storeLock.unlock();
        }
        LOG.log(
                Level.DEBUG,
                "CRL cached for {0} ({1}), expires at {2}",
                SafeText.uri(key.uri()),
                chosen.parsed() != null ? "parsed" : "raw",
                Instant.ofEpochMilli(chosen.expiresAt()));
        return true;
    }

    /** Освобождает место для новой записи: вытесняет записи, ближайшие к истечению. */
    private void evictToFit(long newBytes) {
        for (; ; ) {
            long used = 0;
            Map.Entry<CrlKey, Entry> victim = null;
            for (Map.Entry<CrlKey, Entry> e : cache.entrySet()) {
                used += e.getValue().bytes();
                if (victim == null || e.getValue().expiresAt() < victim.getValue().expiresAt()) {
                    victim = e;
                }
            }
            boolean fits = used + newBytes <= maxBytes && cache.size() < MAX_ENTRIES;
            if (fits || victim == null) {
                return;
            }
            cache.remove(victim.getKey(), victim.getValue());
            LOG.log(
                    Level.DEBUG,
                    "CRL cache evicted entry for {0} to fit the budget",
                    SafeText.uri(victim.getKey().uri()));
        }
    }

    private long expiryOf(VerifiedCrl verified) {
        Instant nextUpdate = verified.getNextUpdate();
        // Проверка CRL без nextUpdate не принимает, поэтому в кэш такой объект попасть не может;
        // ошибка здесь означает нарушение этого инварианта, а не штатный случай
        if (nextUpdate == null) {
            throw new IllegalStateException("Verified CRL without nextUpdate must not be cached");
        }
        return nextUpdate.toEpochMilli() + GRACE_MS;
    }

    /** Для тестов: число записей. */
    int size() {
        return cache.size();
    }

    /** Для тестов: сумма оценок удержания записей. */
    long usedBytes() {
        long used = 0;
        for (Entry e : cache.values()) {
            used += e.bytes();
        }
        return used;
    }

    /** Для тестов: ключи записей. */
    List<CrlKey> keys() {
        return new ArrayList<>(cache.keySet());
    }

    /** Удаляет все записи и запомненные номера (для тестов). */
    void clear() {
        cache.clear();
        lastKnown.clear();
        retryAt.clear();
        warned.values().forEach(Set::clear);
    }
}
