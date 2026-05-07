package org.rssys.gost.tls13.psk;

import org.rssys.gost.tls13.TlsUtils;

import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Хранилище PSK для session resumption (RFC 8446 §2.2).
 *
 * <p>Используйте один экземпляр на один сервер. Смешивание тикетов
 * от разных серверов — неопределённое поведение: разные серверы
 * могут иметь несовместимые ротации ключей, идентификаторы
 * или политики безопасности.</p>
 *
 * <p>0-RTT и external PSK не поддерживаются.</p>
 *
 * <p>Хранилище использует {@code maxSize} (soft cap). При превышении
 * лимита случайная запись вытесняется. Выберите значение под ваш
 * профиль нагрузки.</p>
 *
 * <p>Выбор {@code maxSize}:</p>
 * <ul>
 *   <li><b>Клиент:</b> достаточно 10-100. Клиент хранит 1-5 PSK на
 *       каждый сервер. 100 — запас на десятки серверов.</li>
 *   <li><b>Сервер:</b> PSK живёт от handshake до истечения
 *       {@code ticket_lifetime} секунд. В хранилище одновременно живут
 *       все PSK, выданные за последние {@code ticket_lifetime} секунд.
 *       <br><b>Формула:</b>
 *       {@code maxSize = handshakeRate × ticketLifetime × nstPerHandshake × 1.5}
 *       <br>где {@code handshakeRate} — количество новых TLS handshake'ов
 *       в секунду (не RPS запросов! один keep-alive канал = один handshake,
 *       даже при сотнях запросов). {@code ticketLifetime} — время жизни
 *       PSK-тикета в секундах. {@code nstPerHandshake} — число
 *       NewSessionTicket на handshake (типично 1-2). Коэффициент 1.5 —
 *       запас на пики.
 *       <br><b>Пример:</b> 10 новых handshake/сек, lifetime = 3600 сек,
 *       1 NST на handshake: {@code 10 × 3600 × 1 × 1.5 = 54 000}.
 *       <br>Каждая запись ~300-350 байт → 54 000 записей ≈ 18 МБ.</li>
 *   <li><b>Мониторинг:</b> используйте {@link #size()} для наблюдения
 *       и корректировки.</li>
 * </ul>
 */
public final class PskStore {

    /**
     * Запись PSK-тикета.
     */
    public static final class PskEntry {
        private final byte[] ticket;
        private final long ticketLifetime;
        private final long ticketAgeAdd;
        private final byte[] ticketNonce;
        // volatile: destroyPsk() может быть вызван из computeIfPresent в одном потоке,
        // в то время как другой поток читает psk через getPsk(). Без volatile запись
        // null в destroyPsk() может не стать видимой читающему потоку.
        private volatile byte[] psk;
        private final long issueTime;

        /**
         * @param ticket         opaque ticket (будет скопирован)
         * @param ticketLifetime время жизни в секундах
         * @param ticketAgeAdd   obfuscated ticket age (uint32)
         * @param ticketNonce    nonce для диверсификации PSK (будет скопирован)
         * @param psk            Pre-Shared Key (будет скопирован, может быть null)
         * @param issueTime      время сохранения в миллисекундах (System.currentTimeMillis)
         */
        PskEntry(byte[] ticket, long ticketLifetime, long ticketAgeAdd,
                 byte[] ticketNonce, byte[] psk, long issueTime) {
            this.ticket = ticket.clone();
            this.ticketLifetime = ticketLifetime;
            this.ticketAgeAdd = ticketAgeAdd;
            this.ticketNonce = ticketNonce.clone();
            this.psk = psk != null ? psk.clone() : null;
            this.issueTime = issueTime;
        }

        public byte[] getTicket() {
            return ticket.clone();
        }

        public long getTicketLifetime() {
            return ticketLifetime;
        }

        public long getTicketAgeAdd() {
            return ticketAgeAdd;
        }

        public byte[] getTicketNonce() {
            return ticketNonce.clone();
        }

        public byte[] getPsk() {
            return psk != null ? psk.clone() : null;
        }

        public long getIssueTime() {
            return issueTime;
        }

        /**
         * Проверяет, истёк ли срок действия PSK-тикета.
         *
         * @param now текущее время в миллисекундах
         * @return true если тикет просрочен
         */
        public boolean isExpired(long now) {
            return (now - issueTime) > ticketLifetime * 1000L;
        }

        /**
         * Затирает PSK при вытеснении записи.
         *
         * Почему не вызывается автоматически в finalize: PSK — ключевой материал,
         * его время жизни в heap должно быть минимальным. При evict мы зануляем
         * ключ немедленно, не дожидаясь GC.
         *
         * Best-effort: склонированные через getPsk() копии в вызывающем коде
         * не затрагиваются.
         */
        void destroyPsk() {
            byte[] k = psk;
            if (k != null) {
                TlsUtils.wipeArray(k);
                psk = null;
            }
        }
    }

    // Хранилище: ConcurrentHashMap, потому что PskStore предназначен для
    // многопоточного доступа (один экземпляр на сервер, много handshake'ов).
    private final ConcurrentMap<ByteArrayKey, PskEntry> store = new ConcurrentHashMap<>();
    private final int maxSize;
    // Счётчик для периодической очистки просроченных записей.
    // AtomicInteger: add() вызывается конкурентно, обычный int дал бы race condition.
    private final AtomicInteger addCounter = new AtomicInteger(0);

    // ========================================================================
    // Конструкторы
    // ========================================================================

    /**
     * Создаёт хранилище с мягким лимитом {@code maxSize} на количество записей.
     *
     * При превышении лимита одна случайная запись вытесняется перед вставкой новой.
     * Почему soft cap, а не жёсткий: ConcurrentHashMap не поддерживает атомарную
     * проверку размера при вставке — между store.size() и put() всегда есть окно
     * для race condition. Гарантировать жёсткий лимит без блокировки всего store
     * невозможно. Soft cap — осознанный tradeoff: при конкурентных вставках размер
     * может кратковременно превышать maxSize, но среднее значение не уйдёт далеко.
     *
     * Вытесняется случайная запись, а не самая старая: ConcurrentHashMap не хранит
     * порядок вставки, а поддержание ConcurrentSkipListMap параллельно с CHM —
     * избыточный overhead. Для PSK вытеснение любой записи безопасно: клиент
     * выполнит полный handshake вместо resumption.
     *
     * Просроченные записи удаляются не при каждой вставке, а раз в ~1024 вставок.
     * Почему: evictExpired() — O(n). На хранилище с миллионами записей делать его
     * на каждый add() неприемлемо. Периодичность ~1024 амортизирует стоимость
     * до O(1) на вставку.
     *
     * Для высоконагруженных серверов рекомендуется дополнительно вызывать
     * {@link #evictExpired()} по внешнему расписанию (ScheduledExecutorService).
     *
     * @param maxSize максимальное количество PSK-тикетов (должно быть &ge; 1)
     */
    public PskStore(int maxSize) {
        if (maxSize < 1) {
            throw new IllegalArgumentException("maxSize must be at least 1");
        }
        this.maxSize = maxSize;
    }

    /**
     * Сохраняет PSK-тикет с PSK.
     *
     * Если {@code maxSize} достигнут — вытесняет одну случайную запись.
     * Раз в ~1024 вставок удаляет все просроченные записи ({@link #evictExpired()}).
     *
     * @throws IllegalArgumentException если ticket пуст или длиннее 65535 байт
     */
    public void add(byte[] ticket, long ticketLifetime, long ticketAgeAdd,
                    byte[] ticketNonce, byte[] psk) {
        if (ticket == null || ticket.length < 1 || ticket.length > 65535) {
            throw new IllegalArgumentException(
                    "ticket length must be 1..65535, got " + (ticket == null ? "null" : ticket.length));
        }

        // Soft cap: если превысили maxSize — вытесняем случайную запись.
        // TOCTOU race между size() и put() осознанно не закрывается:
        // жёсткий лимит без блокировки всего store невозможен (см. конструктор).
        // findAny() на entrySet ConcurrentHashMap — weakly consistent,
        // при конкурентной модификации может вернуть пустой Optional.
        // В этом случае просто пропускаем evict — следующий add() повторит попытку.
        if (store.size() >= maxSize) {
            store.keySet().stream().findAny().ifPresent(key ->
                    store.computeIfPresent(key, (k, entry) -> {
                        entry.destroyPsk();
                        return null;
                    })
            );
        }

        // Периодическая очистка просроченных записей.
        // Почему не на каждом add(): evictExpired() — O(n).
        // На 86M записей это катастрофа. Раз в ~1024 вставок — O(1) амортизированно.
        // Почему 1024: степень двойки для дешёвой битовой маски вместо деления.
        // AtomicInteger: add() конкурентный, нужна атомарность инкремента.
        if ((addCounter.incrementAndGet() & 0x3FF) == 0) {
            evictExpired();
        }

        store.put(new ByteArrayKey(ticket),
                new PskEntry(ticket, ticketLifetime, ticketAgeAdd,
                        ticketNonce, psk, System.currentTimeMillis()));
    }

    /**
     * Извлекает PSK-тикет по бинарному тикету.
     * Просроченные тикеты атомарно удаляются.
     *
     * <p><b>Внимание:</b> вызов {@code get()} + {@link #remove(byte[])} не является
     * атомарным — между ними может быть произвольная задержка (например, binder verify).
     * При конкурентном доступе несколько потоков могут получить один и тот же тикет,
     * если remove() не успел выполниться. Это не угроза безопасности (все соединения
     * криптографически валидны), но single-use гарантия смягчается до best-effort.
     * Для строгого single-use используйте {@link ConcurrentMap#computeIfPresent computeIfPresent}.</p>
     *
     * @param ticket бинарный PSK-тикет (идентификатор записи)
     * @return запись или null если не найдена
     */
    public PskEntry get(byte[] ticket) {
        ByteArrayKey key = new ByteArrayKey(ticket);
        return store.compute(key, (k, entry) -> {
            if (entry == null) return null;
            if (entry.isExpired(System.currentTimeMillis())) return null;
            return entry;
        });
    }

    /** Удаляет все просроченные PSK-тикеты. */
    public void evictExpired() {
        long now = System.currentTimeMillis();
        store.values().removeIf(e -> e.isExpired(now));
    }

    /**
     * @return первый неистёкший PSK-тикет или null
     */
    public PskEntry getAnyEntry() {
        evictExpired();
        long now = System.currentTimeMillis();
        for (PskEntry entry : store.values()) {
            if (!entry.isExpired(now)) {
                return entry;
            }
        }
        return null;
    }

    /** Удаляет тикет (single-use: RFC 8446 §8.1). */
    public void remove(byte[] ticket) {
        store.remove(new ByteArrayKey(ticket));
    }

    /** @return количество сохранённых тикетов */
    public int size() {
        return store.size();
    }

    /** Ключ для HashMap на основе byte[]. */
    private static final class ByteArrayKey {
        private final byte[] data;
        private final int hash;

        ByteArrayKey(byte[] data) {
            this.data = data;
            this.hash = Arrays.hashCode(data);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof ByteArrayKey)) return false;
            return Arrays.equals(data, ((ByteArrayKey) o).data);
        }

        @Override
        public int hashCode() {
            return hash;
        }
    }
}
