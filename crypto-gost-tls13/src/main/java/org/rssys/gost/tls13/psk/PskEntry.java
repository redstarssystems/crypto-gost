package org.rssys.gost.tls13.psk;

import java.util.concurrent.locks.ReentrantLock;
import org.rssys.gost.tls13.TlsUtils;

/**
 * Запись PSK-тикета для session resumption (RFC 8446 §2.2).
 * <p>
 * Создаётся TLS-стеком при обработке NewSessionTicket, передаётся
 * в {@link PskStore#onTicketReceived(PskEntry)}. Пользователь получает
 * готовые записи через {@link PskStore#getForResumption()} / {@link PskStore#get(byte[])}.
 */
public final class PskEntry {
    private final byte[] ticket;
    private final long ticketLifetime;
    private final long ticketAgeAdd;
    private final byte[] ticketNonce;
    private byte[] psk;
    private final long issueTime;
    private final ReentrantLock pskLock = new ReentrantLock();

    /**
     * @param ticket          тикет (1..65535 байт, или null для проверки)
     * @param ticketLifetime  время жизни в секундах (с момента выдачи)
     * @param ticketAgeAdd    обфускация возраста (RFC 8446 §4.6.1)
     * @param ticketNonce     одноразовый номер для диверсификации PSK
     * @param psk             Pre-Shared Key (выводится из resumption_master_secret)
     * @param issueTime       момент выписки тикета (System.currentTimeMillis())
     *                        — для {@link #isExpired(long)} на стороне клиента
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
            long issueTime) {
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

    /** @return true если тикет просрочен (относительно {@code now} в миллисекундах). */
    public boolean isExpired(long now) {
        return (now - issueTime) > ticketLifetime * 1000L;
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
