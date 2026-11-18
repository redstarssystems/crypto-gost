package org.rssys.gost.tls13.psk;

import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsUtils;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.util.GostLogger;

/**
 * Выдача и приём тикетов возобновления (RFC 8446 §4.6.1): вывод PSK, запись в {@link PskStore},
 * затирание ключевого материала.
 *
 * <p><b>Внутренний помощник стека, не часть API для приложений.</b> Класс публичный только потому,
 * что его вызывают слои {@code TlsSession} и jsse из разных модулей; приложениям следует работать
 * через {@code TlsSession.setPskStore} и хранилище, а не вызывать его напрямую. Сигнатуры могут
 * меняться без предупреждения.</p>
 *
 * <p>Общая часть для сервера (выдаёт тикет) и клиента (сохраняет полученный) в {@code TlsSession}
 * и в jsse. Отправка сообщения {@code NewSessionTicket}, проверки конкретной стороны (привязка,
 * срок, границы доверия) и политика срока остаются у вызывающего: они зависят от слоя.</p>
 *
 * <p>Сбой хранилища ({@link RuntimeException} из {@link PskStore#onTicketReceived}) не
 * пробрасывается: контракт хранилища велит стеку логировать и продолжать рукопожатие. В журнал
 * попадает только имя класса исключения, без ключевого материала.</p>
 */
public final class TlsTicketHelper {

    private static final GostLogger LOG =
            GostLogger.getLogger("org.rssys.gost.tls13.psk.TlsTicketHelper");

    private TlsTicketHelper() {}

    /**
     * Выданный сервером тикет: данные для сообщения {@code NewSessionTicket}. Запись в хранилище
     * уже сделана, вызывающему остаётся собрать и отправить сообщение, затем вызвать
     * {@link #wipe()}.
     */
    public static final class IssuedTicket {
        private final byte[] ticket;
        private final byte[] ticketNonce;
        private final long ticketAgeAdd;
        private final long lifetimeSeconds;

        private IssuedTicket(
                byte[] ticket, byte[] ticketNonce, long ticketAgeAdd, long lifetimeSeconds) {
            this.ticket = ticket;
            this.ticketNonce = ticketNonce;
            this.ticketAgeAdd = ticketAgeAdd;
            this.lifetimeSeconds = lifetimeSeconds;
        }

        /** @return identity тикета; массив принадлежит объекту и затирается в {@link #wipe()} */
        public byte[] ticket() {
            return ticket;
        }

        /** @return ticket_nonce; массив принадлежит объекту и затирается в {@link #wipe()} */
        public byte[] ticketNonce() {
            return ticketNonce;
        }

        /** @return ticket_age_add (uint32) */
        public long ticketAgeAdd() {
            return ticketAgeAdd;
        }

        /** @return ticket_lifetime в секундах */
        public long lifetimeSeconds() {
            return lifetimeSeconds;
        }

        /** Затирает identity и nonce после отправки сообщения; запись хранилища держит копии. */
        public void wipe() {
            TlsUtils.wipeArray(ticket);
            TlsUtils.wipeArray(ticketNonce);
        }
    }

    /**
     * Выдаёт тикет: генерирует identity и ticket_age_add, выводит PSK, сохраняет запись в
     * хранилище. Порядок «сохранить, затем отправить» принципиален: тикет, которого сервер не
     * знает, клиенту бесполезен, а быстрое повторное подключение не должно обогнать запись.
     *
     * <p>ticket_nonce - 8-байтовый big-endian счётчик по номеру тикета в соединении: RFC 8446
     * §4.6.1 требует уникальности nonce в пределах соединения, счётчик гарантирует её
     * детерминированно, случайное значение только вероятностно.</p>
     *
     * @param store            хранилище PSK сервера
     * @param rms              Resumption Master Secret (копия вызывающего, здесь не затирается)
     * @param ticketIndex      номер тикета в соединении, с нуля
     * @param hashLen          длина хэша набора шифров
     * @param lifetimeSeconds  срок тикета, секунды, больше нуля
     * @param issueTimeMillis  момент выдачи, миллисекунды эпохи
     * @param binding          привязка записи (для сервера {@link PskBinding#forServer})
     * @param validUntil       граница доверия собственной цепочки, миллисекунды эпохи
     * @return выданный тикет или {@code null}, если PSK не вывелся либо хранилище отказало
     *     (тикет в этом случае не выдаётся, причина в журнале)
     */
    public static IssuedTicket issue(
            PskStore store,
            byte[] rms,
            int ticketIndex,
            int hashLen,
            long lifetimeSeconds,
            long issueTimeMillis,
            PskBinding binding,
            long validUntil) {
        byte[] ticket = new byte[TlsConstants.RANDOM_LENGTH];
        byte[] ticketNonce = encodeTicketNonce(ticketIndex);
        byte[] psk = null;
        boolean stored = false;
        try {
            CryptoRandom.INSTANCE.nextBytes(ticket);
            long ticketAgeAdd = CryptoRandom.INSTANCE.nextInt() & 0xFFFFFFFFL;
            psk = TlsPskHelper.derivePsk(rms, ticketNonce, hashLen);
            if (psk == null) {
                LOG.log(GostLogger.Level.WARNING, "PSK derivation failed, ticket not issued");
                return null;
            }
            stored =
                    save(
                            store,
                            new PskEntry(
                                    ticket,
                                    lifetimeSeconds,
                                    ticketAgeAdd,
                                    ticketNonce,
                                    psk,
                                    issueTimeMillis,
                                    binding,
                                    validUntil),
                            "ticket not issued");
            if (!stored) {
                return null;
            }
            return new IssuedTicket(ticket, ticketNonce, ticketAgeAdd, lifetimeSeconds);
        } finally {
            // PskEntry хранит собственные копии; массивы вызывающему отдаются только при успехе
            if (psk != null) TlsUtils.wipeArray(psk);
            if (!stored) {
                TlsUtils.wipeArray(ticket);
                TlsUtils.wipeArray(ticketNonce);
            }
        }
    }

    /**
     * Сохраняет полученный от сервера тикет: выводит PSK из Resumption Master Secret и ticket_nonce
     * и записывает его в хранилище. Массивы {@code ticket} и {@code ticketNonce} и
     * {@code rms} здесь не затираются: ими владеет вызывающий.
     *
     * @param store            хранилище PSK клиента
     * @param rms              Resumption Master Secret (копия вызывающего)
     * @param ticket           identity тикета
     * @param ticketNonce      ticket_nonce из сообщения
     * @param ticketAgeAdd     ticket_age_add (uint32)
     * @param lifetimeSeconds  срок хранения, секунды (уже ограниченный границей доверия), больше нуля
     * @param receivedMillis   момент получения, миллисекунды эпохи
     * @param binding          привязка к серверу и модели доверия
     * @param validUntil       граница доверия, миллисекунды эпохи
     * @param hashLen          длина хэша набора шифров
     * @return {@code true}, если запись сохранена; {@code false}, если PSK не вывелся либо
     *     хранилище отказало (причина в журнале), и тогда запоминать тикет нельзя
     */
    public static boolean storeReceived(
            PskStore store,
            byte[] rms,
            byte[] ticket,
            byte[] ticketNonce,
            long ticketAgeAdd,
            long lifetimeSeconds,
            long receivedMillis,
            PskBinding binding,
            long validUntil,
            int hashLen) {
        byte[] psk = TlsPskHelper.derivePsk(rms, ticketNonce, hashLen);
        if (psk == null) {
            LOG.log(GostLogger.Level.WARNING, "PSK derivation failed, ticket not saved");
            return false;
        }
        try {
            return save(
                    store,
                    new PskEntry(
                            ticket,
                            lifetimeSeconds,
                            ticketAgeAdd,
                            ticketNonce,
                            psk,
                            receivedMillis,
                            binding,
                            validUntil),
                    "ticket not saved");
        } finally {
            // PskEntry получил копию
            TlsUtils.wipeArray(psk);
        }
    }

    private static boolean save(PskStore store, PskEntry entry, String consequence) {
        try {
            store.onTicketReceived(entry);
            return true;
        } catch (RuntimeException e) {
            // Контракт PskStore.onTicketReceived: стек логирует и продолжает рукопожатие.
            // Только метаданные исключения, без ключевого материала (no-debug)
            LOG.log(
                    GostLogger.Level.WARNING,
                    "PskStore.onTicketReceived failed, "
                            + consequence
                            + ": "
                            + e.getClass().getName());
            return false;
        }
    }

    /** 8-байтовый big-endian счётчик: номер тикета в соединении. */
    private static byte[] encodeTicketNonce(int ticketIndex) {
        byte[] nonce = new byte[TlsConstants.TICKET_NONCE_LENGTH];
        nonce[7] = (byte) (ticketIndex & 0xFF);
        nonce[6] = (byte) ((ticketIndex >>> 8) & 0xFF);
        nonce[5] = (byte) ((ticketIndex >>> 16) & 0xFF);
        nonce[4] = (byte) ((ticketIndex >>> 24) & 0xFF);
        return nonce;
    }
}
