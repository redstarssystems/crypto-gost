package org.rssys.gost.tls13.psk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.util.CryptoRandom;

/** Хранилище тикетов в памяти: добавление, получение, удаление, границы тикета, конкуренция. */
@DisplayName("InMemoryPskStore: хранение тикетов возобновления")
class InMemoryPskStoreTest {

    @Test
    @DisplayName("InMemoryPskStore: добавление -> получение -> удаление")
    void testPskStoreAddGetRemove() {
        PskStore store = new InMemoryPskStore(100);
        byte[] ticket = new byte[] {0x01, 0x02, 0x03, 0x04};
        byte[] nonce = new byte[] {0x0A, 0x0B};

        store.onTicketReceived(
                new PskEntry(
                        ticket,
                        3600,
                        99,
                        nonce,
                        null,
                        System.currentTimeMillis(),
                        PskBinding.forServer(null),
                        PskEntry.NO_CERTIFICATE_BOUND));
        assertEquals(1, store.size());

        PskEntry entry = store.get(ticket);
        assertNotNull(entry);
        assertEquals(3600, entry.getTicketLifetime());
        assertEquals(99, entry.getTicketAgeAdd());
        assertArrayEquals(nonce, entry.getTicketNonce());
        assertArrayEquals(ticket, entry.getTicket());

        store.remove(ticket);
        assertNull(store.get(ticket));
        assertEquals(0, store.size());
    }

    @Test
    @DisplayName("InMemoryPskStore: add с пустым тикетом -> IllegalArgumentException")
    void testPskStoreAddEmptyTicket() {
        PskStore store = new InMemoryPskStore(100);
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        store.onTicketReceived(
                                new PskEntry(
                                        new byte[0],
                                        3600,
                                        0,
                                        new byte[] {0x01},
                                        new byte[8],
                                        System.currentTimeMillis(),
                                        PskBinding.forServer(null),
                                        PskEntry.NO_CERTIFICATE_BOUND)));
    }

    @Test
    @DisplayName("InMemoryPskStore: add с null тикетом -> IllegalArgumentException")
    void testPskStoreAddNullTicket() {
        PskStore store = new InMemoryPskStore(100);
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        store.onTicketReceived(
                                new PskEntry(
                                        null,
                                        3600,
                                        0,
                                        new byte[] {0x01},
                                        new byte[8],
                                        System.currentTimeMillis(),
                                        PskBinding.forServer(null),
                                        PskEntry.NO_CERTIFICATE_BOUND)));
    }

    @Test
    @DisplayName("InMemoryPskStore: 8 потоков, без исключений, после remove -> null")
    void testPskStoreConcurrent() throws Exception {
        PskStore store = new InMemoryPskStore(100);
        byte[] ticket = new byte[] {0x01, 0x02, 0x03, 0x04};
        store.onTicketReceived(
                new PskEntry(
                        ticket,
                        3600,
                        CryptoRandom.INSTANCE.nextInt() & 0xFFFFFFFFL,
                        new byte[] {0x05},
                        new byte[8],
                        System.currentTimeMillis(),
                        PskBinding.forServer(null),
                        PskEntry.NO_CERTIFICATE_BOUND));

        int threadCount = 8;
        AtomicInteger successCount = new AtomicInteger();
        Thread[] threads = new Thread[threadCount];
        CountDownLatch latch = new CountDownLatch(1);

        for (int i = 0; i < threadCount; i++) {
            threads[i] =
                    new Thread(
                            () -> {
                                try {
                                    latch.await();
                                } catch (InterruptedException e) {
                                    return;
                                }
                                PskEntry entry = store.get(ticket);
                                if (entry != null) {
                                    store.remove(ticket);
                                    successCount.incrementAndGet();
                                }
                            });
            threads[i].start();
        }

        latch.countDown();
        for (Thread t : threads) t.join(5000);

        assertTrue(successCount.get() >= 1, "хотя бы один поток должен получить запись");
        assertNull(store.get(ticket));
    }

    @Test
    @DisplayName("InMemoryPskStore: getForResumption после expiry -> null (без evictExpired)")
    void testPskStoreGetForResumptionExpired() throws Exception {
        InMemoryPskStore store = new InMemoryPskStore(100);
        byte[] ticket = new byte[] {0x01, 0x02, 0x03, 0x04};
        byte[] nonce = new byte[] {0x0A, 0x0B};
        byte[] psk = new byte[32];

        // Тикет с lifetime = 0 (фактически истёк сразу)
        store.onTicketReceived(
                new PskEntry(
                        ticket,
                        0,
                        99,
                        nonce,
                        psk,
                        System.currentTimeMillis() - 1000,
                        PskBinding.forServer(null),
                        PskEntry.NO_CERTIFICATE_BOUND));

        // getForResumption должен вернуть null — тикет expired per-call
        assertNull(
                store.getForResumption(PskBinding.forServer(null)),
                "просроченный тикет не должен возвращаться getForResumption");
        assertNull(store.get(ticket), "просроченный тикет не должен возвращаться get");
        // size() может остаться равным 1: вытеснение просроченных записей здесь не вызывалось
    }
}
