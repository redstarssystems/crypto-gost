package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Сервер выдаёт тикеты возобновления только тогда, когда может их принять: при заданном хранилище
 * PSK и только после успешной записи в него.
 *
 * <p>Клиент получает тикет при чтении после рукопожатия, поэтому проверки делаются после
 * {@code read()}: проверка клиентского хранилища сразу после рукопожатия прошла бы и тогда, когда
 * тикет отправлен.
 */
@DisplayName("TlsSession: выдача тикетов зависит от хранилища PSK сервера")
class TlsSessionTicketIssuanceTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final String HOST = "gost.example.com";
    private static final int TICKETS = 3;
    private static final byte[] MESSAGE = "после тикетов".getBytes(StandardCharsets.UTF_8);

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle leaf;

    @BeforeAll
    static void setUp() throws Exception {
        root = PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {HOST},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
    }

    /** Хранилище, которое отвергает каждую запись, как недоступный внешний backend. */
    private static final class FailingStore implements PskStore {
        private final InMemoryPskStore delegate = new InMemoryPskStore(100);
        final AtomicInteger attempts = new AtomicInteger();

        @Override
        public void onTicketReceived(PskEntry entry) {
            attempts.incrementAndGet();
            throw new IllegalStateException("backend недоступен");
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

    /**
     * Проводит рукопожатие, пишет данные с сервера и читает их клиентом: к этому моменту клиент
     * разобрал все отправленные тикеты. Хранилище сервера задаётся только если оно не null.
     */
    private static void handshakeAndRead(PskStore serverStore, PskStore clientStore)
            throws Exception {
        var transports = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(SUITE, Collections.singletonList(leaf.cert), leaf.priv)
                                .withTicketsToSend(TICKETS),
                        transports.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname(HOST),
                        transports.getClientTransport());
        if (serverStore != null) {
            server.setPskStore(serverStore);
        }
        client.setPskStore(clientStore);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Void> clientHandshake =
                    executor.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            Future<Void> serverHandshake =
                    executor.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            clientHandshake.get(15, TimeUnit.SECONDS);
            serverHandshake.get(15, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
        server.write(MESSAGE);
        assertArrayEquals(MESSAGE, client.read(), "данные после рукопожатия доходят до клиента");
        server.close();
        client.close();
    }

    @Test
    @DisplayName("сервер без хранилища: тикеты не выдаются, клиентское хранилище пусто")
    void serverWithoutStoreIssuesNoTickets() throws Exception {
        InMemoryPskStore clientStore = new InMemoryPskStore(TICKETS);

        handshakeAndRead(null, clientStore);

        assertEquals(
                0,
                clientStore.size(),
                "сервер без хранилища не может принять тикет, выдавать его нельзя");
    }

    @Test
    @DisplayName("сервер с хранилищем: выдаёт запрошенное число тикетов, и они сохранены у обоих")
    void serverWithStoreIssuesRequestedTickets() throws Exception {
        InMemoryPskStore serverStore = new InMemoryPskStore(TICKETS);
        InMemoryPskStore clientStore = new InMemoryPskStore(TICKETS);

        handshakeAndRead(serverStore, clientStore);

        assertEquals(TICKETS, serverStore.size(), "сервер сохранил все выданные тикеты");
        assertEquals(TICKETS, clientStore.size(), "клиент получил все выданные тикеты");
    }

    @Test
    @DisplayName("хранилище сервера отказало: рукопожатие проходит, тикета нет, повторов нет")
    void failingServerStoreIssuesNoTicketAndKeepsHandshake() throws Exception {
        FailingStore serverStore = new FailingStore();
        InMemoryPskStore clientStore = new InMemoryPskStore(TICKETS);

        handshakeAndRead(serverStore, clientStore);

        assertEquals(
                0,
                clientStore.size(),
                "тикет, которого сервер не смог сохранить, клиенту не отдаётся");
        assertEquals(
                1,
                serverStore.attempts.get(),
                "после первого сбоя остальные тикеты соединения не выдаются");
    }
}
