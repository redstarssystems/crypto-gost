package org.rssys.gost.tls13.psk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.util.CryptoRandom;

/**
 * Общая часть выдачи и приёма тикетов: вывод PSK, запись в хранилище, затирание, поведение при
 * сбое хранилища.
 */
@DisplayName("TlsTicketHelper: выдача и приём тикетов возобновления")
class TlsTicketHelperTest {

    private static final int HASH_LEN = 32;
    private static final long LIFETIME = 3600;
    private static final long VALID_UNTIL = Long.MAX_VALUE / 2;
    private static final PskBinding BINDING = PskBinding.forServer("host.example.com");

    /** Хранилище, отвергающее каждую запись, как недоступный внешний backend. */
    private static final class FailingStore implements PskStore {
        final AtomicInteger attempts = new AtomicInteger();

        @Override
        public void onTicketReceived(PskEntry entry) {
            attempts.incrementAndGet();
            throw new IllegalStateException("backend недоступен");
        }

        @Override
        public PskEntry get(byte[] ticket) {
            return null;
        }

        @Override
        public PskEntry getForResumption(PskBinding binding) {
            return null;
        }

        @Override
        public void remove(byte[] ticket) {}

        @Override
        public PskEntry peek(byte[] ticket) {
            return null;
        }

        @Override
        public int size() {
            return 0;
        }

        @Override
        public void evictExpired() {}

        @Override
        public void clear() {}
    }

    private static byte[] newRms() {
        byte[] rms = new byte[HASH_LEN];
        CryptoRandom.INSTANCE.nextBytes(rms);
        return rms;
    }

    private static TlsTicketHelper.IssuedTicket issue(
            PskStore store, byte[] rms, int index, long now) {
        return TlsTicketHelper.issue(
                store, rms, index, HASH_LEN, LIFETIME, now, BINDING, VALID_UNTIL);
    }

    @Test
    @DisplayName(
            "issue: запись в хранилище совпадает с выданным тикетом, PSK выведен из RMS и nonce")
    void issueStoresEntryMatchingIssuedTicket() {
        InMemoryPskStore store = new InMemoryPskStore(10);
        byte[] rms = newRms();
        long now = System.currentTimeMillis();

        TlsTicketHelper.IssuedTicket issued = issue(store, rms, 0, now);

        assertNotNull(issued);
        assertEquals(1, store.size());
        PskEntry entry = store.peek(issued.ticket());
        assertNotNull(entry, "тикет найден в хранилище по identity");
        assertArrayEquals(issued.ticketNonce(), entry.getTicketNonce());
        assertArrayEquals(
                TlsPskHelper.derivePsk(rms, issued.ticketNonce(), HASH_LEN),
                entry.getPsk(),
                "PSK выведен из RMS и ticket_nonce");
        assertEquals(issued.ticketAgeAdd(), entry.getTicketAgeAdd());
        assertEquals(LIFETIME, issued.lifetimeSeconds());
        assertEquals(LIFETIME, entry.getTicketLifetime());
        assertEquals(now, entry.getIssueTime());
        assertEquals(BINDING, entry.getBinding());
        assertEquals(TlsConstants.RANDOM_LENGTH, issued.ticket().length);
        assertTrue(issued.ticketAgeAdd() >= 0 && issued.ticketAgeAdd() <= 0xFFFFFFFFL);
    }

    @Test
    @DisplayName("issue: ticket_nonce - 8-байтовый big-endian счётчик, уникальный по номеру тикета")
    void issueNonceIsBigEndianCounter() {
        InMemoryPskStore store = new InMemoryPskStore(10);
        byte[] rms = newRms();

        byte[] nonce0 = issue(store, rms, 0, 1).ticketNonce();
        byte[] nonce1 = issue(store, rms, 1, 1).ticketNonce();
        byte[] nonce258 = issue(store, rms, 258, 1).ticketNonce();

        assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 0, 0, 0}, nonce0);
        assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 0, 0, 1}, nonce1);
        assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 0, 1, 2}, nonce258);
    }

    @Test
    @DisplayName("issue: два тикета с одним RMS получают разные identity и разные PSK")
    void issueTicketsDiffer() {
        InMemoryPskStore store = new InMemoryPskStore(10);
        byte[] rms = newRms();

        long now = System.currentTimeMillis();
        TlsTicketHelper.IssuedTicket first = issue(store, rms, 0, now);
        TlsTicketHelper.IssuedTicket second = issue(store, rms, 1, now);

        assertFalse(java.util.Arrays.equals(first.ticket(), second.ticket()));
        assertNotEquals(
                java.util.Arrays.toString(store.peek(first.ticket()).getPsk()),
                java.util.Arrays.toString(store.peek(second.ticket()).getPsk()));
    }

    @Test
    @DisplayName("issue: RMS вызывающего не затирается, wipe() затирает identity и nonce")
    void issueKeepsRmsAndWipeClearsTicketArrays() {
        InMemoryPskStore store = new InMemoryPskStore(10);
        byte[] rms = newRms();
        byte[] rmsCopy = rms.clone();

        TlsTicketHelper.IssuedTicket issued = issue(store, rms, 1, 1);
        issued.wipe();

        assertArrayEquals(rmsCopy, rms, "RMS принадлежит вызывающему");
        assertArrayEquals(new byte[TlsConstants.RANDOM_LENGTH], issued.ticket());
        assertArrayEquals(new byte[TlsConstants.TICKET_NONCE_LENGTH], issued.ticketNonce());
        assertEquals(1, store.size(), "запись хранилища держит собственные копии");
    }

    @Test
    @DisplayName("issue: сбой хранилища даёт null, исключение не пробрасывается")
    void issueReturnsNullWhenStoreFails() {
        FailingStore store = new FailingStore();

        TlsTicketHelper.IssuedTicket issued = issue(store, newRms(), 0, 1);

        assertNull(issued, "тикет без записи в хранилище не выдаётся");
        assertEquals(1, store.attempts.get());
    }

    @Test
    @DisplayName("storeReceived: сохраняет полученный тикет с PSK из RMS и nonce")
    void storeReceivedSavesEntry() {
        InMemoryPskStore store = new InMemoryPskStore(10);
        byte[] rms = newRms();
        byte[] rmsCopy = rms.clone();
        byte[] ticket = {1, 2, 3, 4};
        byte[] nonce = {9, 8, 7};
        long now = System.currentTimeMillis();

        boolean saved =
                TlsTicketHelper.storeReceived(
                        store,
                        rms,
                        ticket,
                        nonce,
                        77,
                        LIFETIME,
                        now,
                        BINDING,
                        VALID_UNTIL,
                        HASH_LEN);

        assertTrue(saved);
        PskEntry entry = store.peek(ticket);
        assertNotNull(entry);
        assertArrayEquals(TlsPskHelper.derivePsk(rms, nonce, HASH_LEN), entry.getPsk());
        assertEquals(77, entry.getTicketAgeAdd());
        assertEquals(now, entry.getIssueTime());
        assertArrayEquals(rmsCopy, rms, "RMS принадлежит вызывающему");
        assertArrayEquals(new byte[] {1, 2, 3, 4}, ticket, "массивы вызывающего не затираются");
        assertArrayEquals(new byte[] {9, 8, 7}, nonce, "массивы вызывающего не затираются");
    }

    @Test
    @DisplayName("storeReceived: сбой хранилища даёт false, исключение не пробрасывается")
    void storeReceivedReturnsFalseWhenStoreFails() {
        FailingStore store = new FailingStore();

        boolean saved =
                TlsTicketHelper.storeReceived(
                        store,
                        newRms(),
                        new byte[] {1},
                        new byte[] {2},
                        0,
                        LIFETIME,
                        1,
                        BINDING,
                        VALID_UNTIL,
                        HASH_LEN);

        assertFalse(saved, "тикет не сохранён, запоминать его нельзя");
        assertEquals(1, store.attempts.get());
    }
}
