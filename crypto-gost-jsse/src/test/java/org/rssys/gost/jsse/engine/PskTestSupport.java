package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskEntry;

/** Общие хелперы тестов возобновления по PSK. */
final class PskTestSupport {

    /** Порт в ключе привязки тикетов к узлу; в сеть не уходит. */
    static final int BINDING_PORT = 443;

    private PskTestSupport() {}

    /**
     * Делает запись «старше» на {@code ageMs}: {@code issueTime} неизменяем, поэтому запись
     * заменяется такой же, выпущенной раньше. Спать в тесте не нужно.
     */
    static void age(GostSSLSessionContext ctx, byte[] ticket, long ageMs) {
        InMemoryPskStore store = ctx.getPskStore();
        PskEntry entry = store.peek(ticket);
        assertNotNull(entry, "запись для старения должна существовать");
        store.remove(ticket);
        store.onTicketReceived(
                new PskEntry(
                        entry.getTicket(),
                        entry.getTicketLifetime(),
                        entry.getTicketAgeAdd(),
                        entry.getTicketNonce(),
                        entry.getPsk(),
                        entry.getIssueTime() - ageMs,
                        entry.getBinding(),
                        PskEntry.NO_CERTIFICATE_BOUND));
    }
}
