package org.rssys.gost.tls13.psk;

/**
 * Хранилище PSK для session resumption (RFC 8446 §2.2).
 *
 * <p>Разделение ответственности:
 * <ul>
 *   <li><b>Read API</b> — для пользовательского кода (get, getForResumption, remove, size, evictExpired)</li>
 *   <li><b>TLS callback</b> — {@link #onTicketReceived(PskEntry)} вызывается стеком, не пользователем</li>
 * </ul>
 *
 * <p>0-RTT и external PSK не поддерживаются.
 *
 * <p>Используйте один экземпляр на один сервер. Смешивание тикетов
 * от разных серверов — неопределённое поведение: разные серверы
 * могут иметь несовместимые ротации ключей, идентификаторы
 * или политики безопасности.
 */
public interface PskStore {

    // ========================================================================
    // Read API — для пользовательского кода
    // ========================================================================

    /** @return запись по идентификатору тикета, или null если нет/expired */
    PskEntry get(byte[] ticket);

    /** @return валидный кандидат для resumption attempt, или null если нет.
     *          MUST не возвращать expired (expiry check per-call). */
    PskEntry getForResumption();

    /** Удаляет тикет (single-use: RFC 8446 §8.1). */
    void remove(byte[] ticket);

    /** @return запись по идентификатору тикета без удаления, или null если нет/expired */
    PskEntry peek(byte[] ticket);

    /** @return количество сохранённых тикетов */
    int size();

    /** Удаляет все просроченные PSK-тикеты. */
    void evictExpired();

    /** Удаляет все PSK-тикеты (с зачисткой ключевого материала).
     *  <p>Используется в JMH-бенчмарках для сброса состояния между итерациями. */
    void clear();

    // ========================================================================
    // TLS callback — вызывается стеком, не пользователем
    // ========================================================================

    /** Вызывается TLS-стеком при получении NewSessionTicket от пира.
     *  Не вызывать напрямую из пользовательского кода.
     *  Implementation может бросить RuntimeException при ошибке backend;
     *  TLS-стек логирует и продолжает handshake. */
    void onTicketReceived(PskEntry entry);
}
