package org.rssys.gost.tls13.psk;

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
    private volatile byte[] psk;
    private final long issueTime;

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

    public byte[] getPsk() {
        return psk != null ? psk.clone() : null;
    }

    public long getIssueTime() {
        return issueTime;
    }

    /** @return true если тикет просрочен (относительно {@code now} в миллисекундах). */
    public boolean isExpired(long now) {
        return (now - issueTime) > ticketLifetime * 1000L;
    }

    /** Затирает PSK при вытеснении записи. */
    public void destroy() {
        byte[] k = psk;
        if (k != null) {
            TlsUtils.wipeArray(k);
            psk = null;
        }
    }
}
