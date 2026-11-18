package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.EOFException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.AnchorExpiryPolicy;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.PkixCertTestHelper.CertBundle;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

@DisplayName("PSK: тикет не переживает сертификат сервера")
class TlsSessionPskCertBoundTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final String HOST = "bound.example";
    private static final String NOT_BEFORE = "20240501120000Z";
    private static final String FAR_FUTURE = "21060101120000Z";
    private static final byte[] KU_DIGITAL_SIGNATURE = {(byte) 0x80};
    private static final byte[] KU_KEY_CERT_SIGN = {(byte) 0x04};
    private static final String[] EKU_SERVER_AUTH = {GostOids.EXT_SERVER_AUTH};
    private static final DateTimeFormatter ASN1_TIME =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final long TWO_HOURS_SECONDS = Duration.ofHours(2).toSeconds();

    private static String inFuture(Duration delta) {
        return ASN1_TIME.format(Instant.now().plus(delta));
    }

    // ========================================================================
    // Выдача и сохранение тикета
    // ========================================================================

    @Test
    @DisplayName("Полное рукопожатие: граница клиента и сервера равна notAfter сертификата сервера")
    void boundaryEqualsLeafNotAfter() throws Exception {
        CertBundle leaf = selfSigned(inFuture(Duration.ofHours(2)));
        Fixture f = Fixture.single(leaf);

        f.connect();

        PskEntry client = f.clientStore.last();
        PskEntry server = f.serverStore.last();
        assertNotNull(client, "клиент должен сохранить тикет");
        assertNotNull(server, "сервер должен сохранить запись о тикете");
        long notAfter = leaf.cert.getNotAfter().toEpochMilli();
        assertEquals(notAfter, client.getValidUntil(), "граница клиента");
        assertEquals(notAfter, server.getValidUntil(), "граница сервера");
    }

    @Test
    @DisplayName("ticket_lifetime ограничен остатком до notAfter с округлением вниз")
    void ticketLifetimeIsClampedToRemainingCertificateLifetime() throws Exception {
        CertBundle leaf = selfSigned(inFuture(Duration.ofHours(2)));
        Fixture f = Fixture.single(leaf);
        long before = System.currentTimeMillis();

        f.connect();

        long maxRemaining = Math.floorDiv(leaf.cert.getNotAfter().toEpochMilli() - before, 1000L);
        for (PskEntry entry : List.of(f.clientStore.last(), f.serverStore.last())) {
            assertTrue(
                    entry.getTicketLifetime() <= maxRemaining,
                    "срок тикета не должен превышать остаток срока сертификата");
            assertTrue(
                    entry.getTicketLifetime() > TWO_HOURS_SECONDS - 60,
                    "срок тикета не должен быть занижен сверх округления");
        }
    }

    @Test
    @DisplayName("Сертификат сервера истёк в пределах допуска часов: сервер не выдаёт тикет")
    void serverDoesNotIssueTicketPastItsOwnCertificate() throws Exception {
        // Валидатор клиента допускает просрочку до CLOCK_SKEW_MS, поэтому соединение состоится,
        // а вот тикет сервер выдавать не должен: его сертификат уже не действует
        CertBundle leaf = selfSigned(inFuture(Duration.ofSeconds(-60)));
        Fixture f = Fixture.single(leaf);

        f.connect();

        assertEquals(0, f.serverStore.size(), "сервер не должен хранить запись о тикете");
        assertEquals(0, f.clientStore.size(), "клиент не должен получать тикет");
    }

    @Test
    @DisplayName("Промежуточный CA истекает раньше leaf: граница равна notAfter промежуточного")
    void intermediateDefinesBoundary() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle intermediate = ca(root, NOT_BEFORE, inFuture(Duration.ofHours(3)));
        CertBundle leaf = leaf(intermediate, FAR_FUTURE);
        Fixture f =
                new Fixture(
                        List.of(leaf.cert, intermediate.cert),
                        leaf.priv,
                        TrustAnchors.ofCertificate(root.cert));

        f.connect();

        long expected = intermediate.cert.getNotAfter().toEpochMilli();
        assertEquals(expected, f.clientStore.last().getValidUntil(), "граница клиента");
        assertEquals(expected, f.serverStore.last().getValidUntil(), "граница сервера");
    }

    @Test
    @DisplayName("Клиент считает границу по проверенной цепочке: якорь при REJECT входит в границу")
    void clientBoundaryIncludesAnchorUnderReject() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle shortAnchor = ca(root, NOT_BEFORE, inFuture(Duration.ofHours(2)));
        CertBundle leaf = leaf(shortAnchor, FAR_FUTURE);
        // Сервер якорь не присылает, поэтому его собственная граница позднее клиентской
        Fixture f =
                new Fixture(
                        List.of(leaf.cert),
                        leaf.priv,
                        TrustAnchors.ofCertificate(shortAnchor.cert)
                                .withExpiryPolicy(AnchorExpiryPolicy.REJECT));

        f.connect();

        PskEntry client = f.clientStore.last();
        assertEquals(
                shortAnchor.cert.getNotAfter().toEpochMilli(),
                client.getValidUntil(),
                "граница клиента должна определяться якорем");
        assertTrue(
                client.getTicketLifetime() <= TWO_HOURS_SECONDS,
                "срок тикета клиента ограничен границей, а не 24 часами сервера");
        assertEquals(
                leaf.cert.getNotAfter().toEpochMilli(),
                f.serverStore.last().getValidUntil(),
                "серверная граница определяется присланной цепочкой");
    }

    @Test
    @DisplayName("Режим без аутентификации сервера: граница по leaf, возобновление сохраняется")
    void noServerAuthModeUsesLeafBoundary() throws Exception {
        CertBundle leaf = selfSigned(inFuture(Duration.ofHours(2)));
        Fixture f = Fixture.single(leaf);

        f.connectNoServerAuth();
        boolean resumed = f.connectNoServerAuth();

        assertEquals(
                leaf.cert.getNotAfter().toEpochMilli(),
                f.clientStore.last().getValidUntil(),
                "граница должна равняться notAfter leaf");
        assertTrue(resumed, "возобновление в этом режиме должно работать");
    }

    // ========================================================================
    // Возобновление
    // ========================================================================

    @Test
    @DisplayName("Новый тикет возобновлённой сессии наследует границу, а не получает новую")
    void resumedSessionInheritsBoundary() throws Exception {
        CertBundle root = PkixCertTestHelper.createRootCA(PARAMS);
        CertBundle shortAnchor = ca(root, NOT_BEFORE, inFuture(Duration.ofHours(2)));
        CertBundle leaf = leaf(shortAnchor, FAR_FUTURE);
        // Граница клиента (якорь, 2 часа) заведомо раньше серверной (leaf, 2106 год): если бы
        // клиент брал границу не из прежней записи, значения различались бы
        Fixture f =
                new Fixture(
                        List.of(leaf.cert),
                        leaf.priv,
                        TrustAnchors.ofCertificate(shortAnchor.cert)
                                .withExpiryPolicy(AnchorExpiryPolicy.REJECT));
        f.connect();
        long firstBoundary = f.clientStore.last().getValidUntil();

        boolean resumed = f.connect();

        assertTrue(resumed, "второе соединение должно возобновиться");
        assertEquals(2, f.clientStore.receivedCount(), "возобновлённая сессия выдаёт новый тикет");
        assertEquals(
                firstBoundary,
                f.clientStore.last().getValidUntil(),
                "граница возобновлённого тикета должна совпасть с прежней");
    }

    @Test
    @DisplayName("Клиент не предъявляет запись за границей, даже если хранилище её отдало")
    void clientDoesNotOfferEntryPastBoundary() throws Exception {
        CertBundle leaf = selfSigned(FAR_FUTURE);
        Fixture f = Fixture.single(leaf);
        f.connect();
        PskEntry valid = f.clientStore.last();
        PskEntry stale =
                new PskEntry(
                        valid.getTicket(),
                        valid.getTicketLifetime(),
                        valid.getTicketAgeAdd(),
                        valid.getTicketNonce(),
                        valid.getPsk(),
                        valid.getIssueTime(),
                        valid.getBinding(),
                        System.currentTimeMillis() - 1_000L);
        f.clientStore.forced = stale;

        assertFalse(f.connect(), "запись за границей не должна приводить к возобновлению");
    }

    @Test
    @DisplayName("Сервер не принимает собственный тикет после границы своего сертификата")
    void serverRejectsOwnTicketPastBoundary() throws Exception {
        CertBundle leaf = selfSigned(FAR_FUTURE);
        Fixture f = Fixture.single(leaf);
        f.connect();
        PskEntry issued = f.serverStore.last();
        PskEntry stale =
                new PskEntry(
                        issued.getTicket(),
                        issued.getTicketLifetime(),
                        issued.getTicketAgeAdd(),
                        issued.getTicketNonce(),
                        issued.getPsk(),
                        issued.getIssueTime(),
                        issued.getBinding(),
                        System.currentTimeMillis() - 1_000L);
        // Клиент тикет предъявит (его запись действует), а запись сервера уже за границей
        f.serverStore = new RecordingStore();
        f.serverStore.onTicketReceived(stale);

        assertFalse(f.connect(), "сервер должен перейти к полному рукопожатию");
    }

    // ========================================================================
    // Вспомогательные средства
    // ========================================================================

    private static CertBundle selfSigned(String notAfter) {
        return PkixCertTestHelper.createCertWithKey(
                PARAMS, NOT_BEFORE, notAfter, new String[] {HOST});
    }

    private static CertBundle ca(CertBundle issuer, String notBefore, String notAfter)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                notBefore,
                notAfter,
                null,
                null,
                KU_KEY_CERT_SIGN,
                null,
                true,
                null);
    }

    private static CertBundle leaf(CertBundle issuer, String notAfter) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                PARAMS,
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                NOT_BEFORE,
                notAfter,
                new String[] {HOST},
                null,
                KU_DIGITAL_SIGNATURE,
                EKU_SERVER_AUTH,
                false,
                null);
    }

    /** Хранилище, запоминающее принятые записи; может отдать заданную запись принудительно. */
    private static final class RecordingStore implements PskStore {
        private final InMemoryPskStore delegate = new InMemoryPskStore(100);
        private final List<PskEntry> received = new CopyOnWriteArrayList<>();
        volatile PskEntry forced;

        PskEntry last() {
            return received.isEmpty() ? null : received.get(received.size() - 1);
        }

        int receivedCount() {
            return received.size();
        }

        @Override
        public PskEntry get(byte[] ticket) {
            return delegate.get(ticket);
        }

        @Override
        public PskEntry getForResumption(PskBinding binding) {
            return forced != null ? forced : delegate.getForResumption(binding);
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

        @Override
        public void onTicketReceived(PskEntry entry) {
            received.add(entry);
            delegate.onTicketReceived(entry);
        }
    }

    private static final class Fixture {
        final List<org.rssys.gost.pkix.cert.GostCertificate> serverChain;
        final PrivateKeyParameters serverKey;
        final TrustAnchors anchors;
        RecordingStore serverStore = new RecordingStore();
        final RecordingStore clientStore = new RecordingStore();

        Fixture(
                List<org.rssys.gost.pkix.cert.GostCertificate> serverChain,
                PrivateKeyParameters serverKey,
                TrustAnchors anchors) {
            this.serverChain = serverChain;
            this.serverKey = serverKey;
            this.anchors = anchors;
        }

        static Fixture single(CertBundle bundle) {
            return new Fixture(
                    List.of(bundle.cert), bundle.priv, TrustAnchors.ofCertificate(bundle.cert));
        }

        boolean connect() throws Exception {
            return run(
                    tp ->
                            TlsSession.createClient(
                                    new TlsClientConfig(SUITE, anchors).withServerHostname(HOST),
                                    tp));
        }

        boolean connectNoServerAuth() throws Exception {
            return run(tp -> TlsSession.createClientWithoutServerAuth(tp, SUITE, null, null));
        }

        /** Одно соединение; возвращает true, если клиент возобновился по PSK. */
        private boolean run(
                java.util.function.Function<InMemoryTlsTransport, TlsSession> clientFactory)
                throws Exception {
            var pair = InMemoryTlsTransport.newPair();
            TlsSession serverSession =
                    TlsSession.createServer(
                            new TlsServerConfig(SUITE, serverChain, serverKey),
                            pair.getServerTransport());
            TlsSession clientSession = clientFactory.apply(pair.getClientTransport());
            serverSession.setPskStore(serverStore);
            clientSession.setPskStore(clientStore);
            ExecutorService exec = Executors.newFixedThreadPool(2);
            try {
                Future<Void> cf =
                        exec.submit(
                                () -> {
                                    clientSession.handshakeAsClient();
                                    return null;
                                });
                Future<Void> sf =
                        exec.submit(
                                () -> {
                                    serverSession.handshakeAsServer();
                                    return null;
                                });
                cf.get(15, TimeUnit.SECONDS);
                sf.get(15, TimeUnit.SECONDS);
                boolean resumed = clientSession.wasResumed();
                // NewSessionTicket клиент обрабатывает в read(): закрываем сервер и дочитываем.
                serverSession.close();
                assertThrows(EOFException.class, clientSession::read);
                return resumed;
            } finally {
                exec.shutdownNow();
                serverSession.close();
                clientSession.close();
            }
        }
    }
}
