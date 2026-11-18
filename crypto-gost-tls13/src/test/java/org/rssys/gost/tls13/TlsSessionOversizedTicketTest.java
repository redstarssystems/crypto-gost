package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.EOFException;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import org.rssys.gost.util.CryptoRandom;

/**
 * Слишком длинные тикеты на разных путях клиента. Какой тест какой путь покрывает:
 * <ul>
 *   <li>приём {@code NewSessionTicket} в {@code TlsSession} - тесты {@code newSessionTicket*}:
 *       сервер присылает тикет, который не предъявить, клиент его не сохраняет;</li>
 *   <li>сборка ClientHello - {@code oversizedTicketGivesFullHandshakeAndIsRemoved}: тикет прошёл
 *       грубую проверку, но с другими расширениями не поместился, клиент идёт полным рукопожатием
 *       и убирает тикет из кэша;</li>
 *   <li>сохранение в {@code GostSSLSessionContext} и {@code setPsk} - в тестах jsse и
 *       {@code TlsHandshakeEnginePskSelectionTest}.</li>
 * </ul>
 */
@DisplayName("TlsSession: тикет, не поместившийся в ClientHello")
class TlsSessionOversizedTicketTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final String HOST = "gost.example.com";
    private static final int TIMEOUT_SECONDS = 15;

    private final PkixCertTestHelper.CertBundle server =
            PkixCertTestHelper.createCertWithKey(
                    ECParameters.tc26a256(),
                    "20240501120000Z",
                    "21060101120000Z",
                    new String[] {HOST});

    @Test
    @DisplayName("Тикет в 65492 байта: полное рукопожатие без исключения, тикет удалён из кэша")
    void oversizedTicketGivesFullHandshakeAndIsRemoved() throws Exception {
        RecordingStore clientStore = new RecordingStore();
        // Привязку клиента берём у настоящей записи: сначала обычное соединение
        obtainRealTicket(clientStore);
        PskBinding binding = clientStore.lastBinding;
        byte[] hugeTicket =
                new byte[TlsPskHelper.maxIdentityLength(TlsConstants.STREEBOG_256_HASH_LEN)];
        hugeTicket[0] = 1;
        clientStore.clear();
        clientStore.onTicketReceived(
                new PskEntry(
                        hugeTicket,
                        3600,
                        0,
                        new byte[8],
                        new byte[32],
                        System.currentTimeMillis(),
                        binding,
                        PskEntry.NO_CERTIFICATE_BOUND));
        assertNotNull(clientStore.peek(hugeTicket), "предусловие: тикет в кэше");

        var pair = InMemoryTlsTransport.newPair();
        TlsSession serverSession = serverSession(pair, new InMemoryPskStore(100));
        TlsSession clientSession = clientSession(pair, clientStore);
        try {
            handshake(clientSession, serverSession);

            assertFalse(clientSession.wasResumed(), "возобновления нет: PSK не предъявлялся");
            assertNull(
                    clientStore.peek(hugeTicket), "тикет, который не поместился, удалён из кэша");
        } finally {
            serverSession.close();
            clientSession.close();
        }
    }

    /**
     * Отправляет клиенту NewSessionTicket с тикетом заданной длины, разбитый на записи, и затем
     * запись данных. Сообщение длиннее одной записи собирается на стороне чтения из нескольких.
     */
    private static PskStore receiveTicketOfLength(int ticketLength) throws Exception {
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(iv);
        TlsTrafficKeys keys = new TlsTrafficKeys(key, iv);
        TlsRecord writer = new TlsRecord(keys.getKey(), keys.getIv(), SUITE.getTagLen(), SUITE);
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        PskStore store = new InMemoryPskStore(100);
        TlsSession client = TlsSession.createForTest(transport, SUITE, keys, keys);
        client.setPskStore(store);

        byte[] ticket = new byte[ticketLength];
        CryptoRandom.INSTANCE.nextBytes(ticket);
        byte[] framed =
                new TlsHandshakeMessage(
                                TlsConstants.HT_NEW_SESSION_TICKET,
                                TlsMessageBuilder.buildNewSessionTicket(
                                        7200, 12345, new byte[8], ticket))
                        .encode();
        int chunk = 16_000;
        int records = 0;
        for (int offset = 0; offset < framed.length; offset += chunk) {
            transport.inject(
                    writer.protect(
                            TlsConstants.CT_HANDSHAKE,
                            framed,
                            offset,
                            Math.min(chunk, framed.length - offset)));
            records++;
        }
        assertTrue(records > 1, "предусловие: сообщение разбито на несколько записей");
        transport.inject(writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {0x41}));

        // Соединение остаётся живым: после тикета читается обычная запись данных
        assertArrayEquals(new byte[] {0x41}, client.read(), "соединение продолжает работать");
        return store;
    }

    @Test
    @DisplayName("NewSessionTicket с тикетом длиннее предела, в нескольких записях: не сохраняется")
    void newSessionTicketTooLongIsNotSaved() throws Exception {
        int limit = TlsPskHelper.maxIdentityLength(TlsConstants.STREEBOG_256_HASH_LEN);

        PskStore store = receiveTicketOfLength(limit + 1);

        assertEquals(0, store.size(), "тикет, который не предъявить, не сохраняется");
    }

    @Test
    @DisplayName("NewSessionTicket с тикетом предельной длины, в нескольких записях: сохраняется")
    void newSessionTicketOfMaximalLengthIsSaved() throws Exception {
        int limit = TlsPskHelper.maxIdentityLength(TlsConstants.STREEBOG_256_HASH_LEN);

        PskStore store = receiveTicketOfLength(limit);

        assertEquals(1, store.size(), "граница включительная: тикет в limit байт сохраняется");
    }

    /** Хранилище, запоминающее привязку последней полученной записи. */
    private static final class RecordingStore implements PskStore {
        private final InMemoryPskStore delegate = new InMemoryPskStore(100);
        private PskBinding lastBinding;

        @Override
        public void onTicketReceived(PskEntry entry) {
            lastBinding = entry.getBinding();
            delegate.onTicketReceived(entry);
        }

        @Override
        public PskEntry get(byte[] ticket) {
            return delegate.get(ticket);
        }

        @Override
        public PskEntry getForResumption(PskBinding binding) {
            return delegate.getForResumption(binding);
        }

        @Override
        public void remove(byte[] ticket) {
            delegate.remove(ticket);
        }

        @Override
        public PskEntry peek(byte[] ticket) {
            return delegate.peek(ticket);
        }

        @Override
        public int size() {
            return delegate.size();
        }

        @Override
        public void evictExpired() {
            delegate.evictExpired();
        }

        @Override
        public void clear() {
            delegate.clear();
        }
    }

    /** Обычное соединение: клиент получает настоящий тикет, из него берём привязку. */
    private void obtainRealTicket(RecordingStore clientStore) throws Exception {
        var pair = InMemoryTlsTransport.newPair();
        TlsSession serverSession = serverSession(pair, new InMemoryPskStore(100));
        TlsSession clientSession = clientSession(pair, clientStore);
        try {
            handshake(clientSession, serverSession);
            // NewSessionTicket клиент обрабатывает в read(): закрываем сервер и дочитываем
            serverSession.close();
            assertThrows(EOFException.class, clientSession::read);
        } finally {
            serverSession.close();
            clientSession.close();
        }
        assertEquals(1, clientStore.size(), "предусловие: клиент получил тикет");
    }

    private TlsSession serverSession(InMemoryTlsTransport.Pair pair, PskStore store) {
        TlsSession session =
                TlsSession.createServer(
                        new TlsServerConfig(
                                SUITE, Collections.singletonList(server.cert), server.priv),
                        pair.getServerTransport());
        session.setPskStore(store);
        return session;
    }

    private TlsSession clientSession(InMemoryTlsTransport.Pair pair, PskStore store) {
        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(server.cert))
                                .withServerHostname(HOST),
                        pair.getClientTransport());
        session.setPskStore(store);
        return session;
    }

    private static void handshake(TlsSession client, TlsSession server) throws Exception {
        ExecutorService exec = Executors.newFixedThreadPool(2);
        try {
            Future<Void> clientDone =
                    exec.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            Future<Void> serverDone =
                    exec.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            clientDone.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            serverDone.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } finally {
            exec.shutdownNow();
        }
    }
}
