package org.rssys.gost.tls13.psk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PskEntry: граница по сроку сертификата сервера")
class PskEntryValidUntilTest {

    private static final long ISSUE_TIME = 1_000_000L;
    private static final long LIFETIME_SECONDS = 3600L;
    private static final PskBinding BINDING = PskBinding.forServer("a.example");

    private static PskEntry entry(long validUntil) {
        return entry(new byte[] {1, 2, 3, 4}, validUntil);
    }

    private static PskEntry entry(byte[] ticket, long validUntil) {
        return new PskEntry(
                ticket,
                LIFETIME_SECONDS,
                7L,
                new byte[] {9},
                new byte[32],
                ISSUE_TIME,
                BINDING,
                validUntil);
    }

    @Test
    @DisplayName("Граница раньше срока тикета: запись просрочена после границы, а не после срока")
    void boundaryEarlierThanLifetimeExpiresEntry() {
        long validUntil = ISSUE_TIME + 10_000L;
        PskEntry e = entry(validUntil);
        assertEquals(validUntil, e.getValidUntil(), "геттер должен вернуть границу как есть");
        assertFalse(e.isExpired(validUntil - 1), "до границы запись действует");
        assertTrue(e.isExpired(validUntil + 1), "после границы запись просрочена");
    }

    @Test
    @DisplayName(
            "Ровно на границе запись не просрочена: notAfter включён в срок (RFC 5280 §4.1.2.5)")
    void exactlyOnBoundaryIsNotExpired() {
        long validUntil = ISSUE_TIME + 10_000L;
        assertFalse(
                entry(validUntil).isExpired(validUntil),
                "в момент notAfter сертификат ещё действует, тикет тоже");
    }

    @Test
    @DisplayName("Граница позже срока тикета: срок тикета по-прежнему ограничивает запись")
    void lifetimeStillLimitsWhenBoundaryIsLater() {
        PskEntry e = entry(ISSUE_TIME + 2 * LIFETIME_SECONDS * 1000L);
        assertFalse(e.isExpired(ISSUE_TIME + LIFETIME_SECONDS * 1000L), "срок ещё не вышел");
        assertTrue(
                e.isExpired(ISSUE_TIME + LIFETIME_SECONDS * 1000L + 1),
                "после срока тикета запись просрочена независимо от границы");
    }

    @Test
    @DisplayName("NO_CERTIFICATE_BOUND поведения срока не меняет")
    void noCertificateBoundKeepsLifetimeSemantics() {
        PskEntry e = entry(PskEntry.NO_CERTIFICATE_BOUND);
        assertEquals(Long.MAX_VALUE, e.getValidUntil(), "константа равна Long.MAX_VALUE");
        assertFalse(e.isExpired(ISSUE_TIME + LIFETIME_SECONDS * 1000L), "срок ещё не вышел");
        assertTrue(e.isExpired(ISSUE_TIME + LIFETIME_SECONDS * 1000L + 1), "срок тикета вышел");
    }

    @Test
    @DisplayName("InMemoryPskStore не отдаёт запись за границей ни одним из методов выдачи")
    void storeHidesEntriesPastBoundary() {
        InMemoryPskStore store = new InMemoryPskStore(10);
        long now = System.currentTimeMillis();
        byte[] expiredTicket = {1, 1, 1, 1};
        byte[] liveTicket = {2, 2, 2, 2};
        // issueTime = 1_000_000 далеко в прошлом относительно срока: границу ставим в прошлое,
        // срок тикета делаем большим, чтобы просрочка была вызвана только границей
        PskEntry past = longLived(expiredTicket, now - 1_000L, now);
        PskEntry future = longLived(liveTicket, now + 3_600_000L, now);
        store.onTicketReceived(past);
        store.onTicketReceived(future);

        assertNull(store.peek(expiredTicket), "peek не должен отдавать запись за границей");
        assertNotNull(store.peek(liveTicket), "peek отдаёт запись до границы");
        assertNull(store.get(expiredTicket), "get не должен отдавать запись за границей");
        PskEntry resumed = store.getForResumption(BINDING);
        assertNotNull(resumed, "getForResumption должен вернуть действующую запись");
        assertEquals(
                future.getValidUntil(),
                resumed.getValidUntil(),
                "getForResumption не должен вернуть запись за границей");
    }

    private static PskEntry longLived(byte[] ticket, long validUntil, long issueTime) {
        return new PskEntry(
                ticket, 86_400L, 7L, new byte[] {9}, new byte[32], issueTime, BINDING, validUntil);
    }
}
