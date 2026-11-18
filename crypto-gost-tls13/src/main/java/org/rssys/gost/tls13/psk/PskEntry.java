package org.rssys.gost.tls13.psk;

import java.util.concurrent.locks.ReentrantLock;
import org.rssys.gost.tls13.TlsUtils;

/**
 * Запись PSK-тикета для session resumption (RFC 8446 §2.2).
 * <p>
 * Создаётся TLS-стеком при обработке NewSessionTicket, передаётся
 * в {@link PskStore#onTicketReceived(PskEntry)}. Пользователь получает
 * готовые записи через {@link PskStore#getForResumption(PskBinding)} / {@link PskStore#get(byte[])}.
 *
 * <p>Привязка ({@link #getBinding()}) — доверенное значение: его ставит вызывающий код
 * (TLS-стек), а инвариант «тикет предъявляется только своему серверу» держит сам стек
 * сверкой привязки, а не хранилище.</p>
 */
public final class PskEntry {

    /**
     * Значение {@code validUntil} для записи, не ограниченной сроком сертификата сервера.
     * Библиотека сама такие записи не создаёт, значением по умолчанию эта константа не является:
     * она нужна пользовательским хранилищам и тестам.
     */
    public static final long NO_CERTIFICATE_BOUND = Long.MAX_VALUE;

    private final byte[] ticket;
    private final long ticketLifetime;
    private final long ticketAgeAdd;
    private final byte[] ticketNonce;
    private byte[] psk;
    private final long issueTime;
    private final PskBinding binding;
    private final long validUntil;
    private final ReentrantLock pskLock = new ReentrantLock();

    /**
     * @param ticket          тикет (1..65535 байт, или null для проверки)
     * @param ticketLifetime  время жизни в секундах (с момента выдачи)
     * @param ticketAgeAdd    обфускация возраста (RFC 8446 §4.6.1)
     * @param ticketNonce     одноразовый номер для диверсификации PSK
     * @param psk             Pre-Shared Key (выводится из resumption_master_secret)
     * @param issueTime       момент выписки тикета (System.currentTimeMillis())
     *                        — для {@link #isExpired(long)} на стороне клиента
     * @param binding         привязка к серверу и модели доверия (не null);
     *                        {@link PskBinding#forServer(String)} для серверных записей
     * @param validUntil      граница доверия в миллисекундах эпохи: наименьший {@code notAfter}
     *                        среди сертификатов сервера, по которым этот тикет получен.
     *                        Запись просрочена строго после этого момента
     *                        ({@link #NO_CERTIFICATE_BOUND} - без границы)
     *
     * <p>Все массивы клонируются — запись принимает владение данными.
     * Вызывающий код может затереть оригиналы.
     */
    public PskEntry(
            byte[] ticket,
            long ticketLifetime,
            long ticketAgeAdd,
            byte[] ticketNonce,
            byte[] psk,
            long issueTime,
            PskBinding binding,
            long validUntil) {
        if (binding == null) {
            throw new IllegalArgumentException("binding must not be null");
        }
        this.binding = binding;
        this.validUntil = validUntil;
        this.ticket = ticket != null ? ticket.clone() : null;
        this.ticketLifetime = ticketLifetime;
        this.ticketAgeAdd = ticketAgeAdd;
        this.ticketNonce = ticketNonce != null ? ticketNonce.clone() : null;
        this.psk = psk != null ? psk.clone() : null;
        this.issueTime = issueTime;
    }

    public byte[] getTicket() {
        return ticket != null ? ticket.clone() : null;
    }

    public long getTicketLifetime() {
        return ticketLifetime;
    }

    public long getTicketAgeAdd() {
        return ticketAgeAdd;
    }

    public byte[] getTicketNonce() {
        return ticketNonce != null ? ticketNonce.clone() : null;
    }

    /**
     * Возвращает копию PSK.
     * <p>
     * Защищено {@link #pskLock} от конкурентного {@link #destroy()}:
     * clone и wipeArray не могут пересечься на одном массиве.
     */
    public byte[] getPsk() {
        pskLock.lock();
        try {
            return psk != null ? psk.clone() : null;
        } finally {
            pskLock.unlock();
        }
    }

    public long getIssueTime() {
        return issueTime;
    }

    /** @return привязка тикета к серверу и модели доверия (не null) */
    public PskBinding getBinding() {
        return binding;
    }

    /**
     * @return граница доверия в миллисекундах эпохи: тикет не должен пережить сертификаты, по
     *         которым сервер был принят ({@link #NO_CERTIFICATE_BOUND} - без границы)
     */
    public long getValidUntil() {
        return validUntil;
    }

    /**
     * Проверяет, что тикет просрочен по сроку жизни или по сроку сертификата сервера.
     *
     * <p>Сертификат действует по {@code notAfter} включительно (RFC 5280 §4.1.2.5), поэтому
     * запись просрочена только при {@code now > validUntil}. Допуск на расхождение часов нулевой:
     * {@code CLOCK_SKEW_MS} в проверке цепочки нужен на момент проверки, а тикет продолжает уже
     * оказанное доверие и не должен переживать {@code notAfter}. Так тикет строже валидатора на
     * величину допуска.</p>
     *
     * @return true если тикет просрочен (относительно {@code now} в миллисекундах)
     */
    public boolean isExpired(long now) {
        return (now - issueTime) > ticketLifetime * 1000L || now > validUntil;
    }

    /**
     * Затирает PSK при вытеснении записи.
     * <p>
     * Защищено {@link #pskLock}: если конкурентный {@link #getPsk()} держит
     * лок, destroy ждёт завершения clone и только потом затирает массив —
     * нулевой PSK не утекает в вызывающий код. Если destroy взял лок первым,
     * getPsk видит psk == null и возвращает null — вызывающий код пропускает
     * PSK и выполняет полный handshake.
     */
    public void destroy() {
        pskLock.lock();
        try {
            byte[] k = psk;
            psk = null;
            if (k != null) {
                TlsUtils.wipeArray(k);
            }
        } finally {
            pskLock.unlock();
        }
    }
}
