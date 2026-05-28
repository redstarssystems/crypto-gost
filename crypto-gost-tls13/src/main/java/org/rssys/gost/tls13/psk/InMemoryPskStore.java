package org.rssys.gost.tls13.psk;

import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In-memory реализация {@link PskStore} для session resumption (RFC 8446 §2.2).
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
public final class InMemoryPskStore implements PskStore {

    private final ConcurrentMap<ByteArrayKey, PskEntry> store = new ConcurrentHashMap<>();
    private final int maxSize;
    private final AtomicInteger addCounter = new AtomicInteger(0);

    /**
     * @param maxSize максимальное количество PSK-тикетов (должно быть &ge; 1)
     */
    public InMemoryPskStore(int maxSize) {
        if (maxSize < 1) {
            throw new IllegalArgumentException("maxSize must be at least 1");
        }
        this.maxSize = maxSize;
    }

    @Override
    public void onTicketReceived(PskEntry entry) {
        byte[] ticket = entry.getTicket();
        if (ticket == null || ticket.length < 1 || ticket.length > 65535) {
            throw new IllegalArgumentException(
                    "ticket length must be 1..65535, got " + (ticket == null ? "null" : ticket.length));
        }

        // Soft cap: если превысили maxSize — вытесняем случайную запись.
        if (store.size() >= maxSize) {
            store.keySet().stream().findAny().ifPresent(key ->
                    store.computeIfPresent(key, (k, e) -> {
                        e.destroy();
                        return null;
                    })
            );
        }

        // Периодическая очистка просроченных записей (раз в ~1024 вставок).
        // WHY: evictExpired на каждой вставке — O(n) на горячем пути handshake,
        // где n растёт до maxSize. Периодический вызов снижает overhead до O(n/1024).
        if ((addCounter.incrementAndGet() & 0x3FF) == 0) {
            evictExpired();
        }

        store.put(new ByteArrayKey(ticket), entry);
    }

    @Override
    public PskEntry get(byte[] ticket) {
        ByteArrayKey key = new ByteArrayKey(ticket);
        // Атомарное удаление — гарантирует single-use (RFC 8446 §8.1).
        // ConcurrentHashMap.remove() блокирует сегмент, возвращает запись
        // и гарантирует что никакой другой поток не получит тот же тикет.
        // Если тикет expired — возвращаем null, запись уже удалена.
        PskEntry entry = store.remove(key);
        if (entry == null) return null;
        if (entry.isExpired(System.currentTimeMillis())) {
            entry.destroy();
            return null;
        }
        return entry;
    }

    @Override
    public PskEntry peek(byte[] ticket) {
        ByteArrayKey key = new ByteArrayKey(ticket);
        PskEntry entry = store.get(key);
        if (entry == null) return null;
        if (entry.isExpired(System.currentTimeMillis())) {
            return null;
        }
        return entry;
    }

    @Override
    public void evictExpired() {
        long now = System.currentTimeMillis();
        store.values().removeIf(e -> {
            if (e.isExpired(now)) {
                e.destroy();
                return true;
            }
            return false;
        });
    }

    @Override
    public PskEntry getForResumption() {
        // Принудительная очистка просроченных — контракт требует
        // «MUST не возвращать expired», без неё expired entry мог бы
        // висеть в store до следующей периодической чистки в onTicketReceived.
        evictExpired();
        long now = System.currentTimeMillis();
        PskEntry best = null;
        long maxIssueTime = Long.MIN_VALUE;
        for (PskEntry entry : store.values()) {
            long issueTime = entry.getIssueTime();
            if (!entry.isExpired(now) && issueTime > maxIssueTime) {
                maxIssueTime = issueTime;
                best = entry;
            }
        }
        return best;
    }

    @Override
    public void clear() {
        store.values().forEach(e -> e.destroy());
        store.clear();
    }

    @Override
    public void remove(byte[] ticket) {
        store.remove(new ByteArrayKey(ticket));
    }

    @Override
    public int size() {
        return store.size();
    }

    private static final class ByteArrayKey {
        private final byte[] data;
        private final int hash;

        ByteArrayKey(byte[] data) {
            // data не клонируется: все входы в store (onTicketReceived, get, remove)
            // получают массив либо из PskEntry.getTicket() (который уже клонирует),
            // либо от вызывающего кода (InMemoryPskStore.get(byte[])), где caller
            // не владеет ключом после return — массив больше не используется.
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
