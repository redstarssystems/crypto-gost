package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.EOFException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.pkix.cert.AnchorExpiryPolicy;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

@DisplayName("PSK: привязка тикета к серверу и модели доверия")
class TlsSessionPskBindingTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final String HOST_A = "a.example";
    private static final String HOST_B = "b.example";

    // ========================================================================
    // Сквозные сценарии
    // ========================================================================

    @Test
    @DisplayName("Штатное возобновление: тот же сервер и та же модель доверия -> PSK принят")
    void resumesForSameServer() throws Exception {
        Fixture f = new Fixture();
        assertFalse(f.connect(f.client(HOST_A)), "первое соединение должно быть полным");
        assertTrue(f.connect(f.client(HOST_A)), "второе соединение должно возобновиться по PSK");
    }

    @Test
    @DisplayName("Тикет, полученный от A, не предлагается при подключении к B")
    void ticketOfOneServerIsNotOfferedToAnother() throws Exception {
        Fixture f = new Fixture();
        f.connect(f.client(HOST_A));
        assertFalse(
                f.connect(f.client(HOST_B)),
                "при другом имени сервера должно быть полное рукопожатие");
    }

    @Test
    @DisplayName("Смена набора якорей инвалидирует тикет")
    void anchorsChangeInvalidatesTicket() throws Exception {
        Fixture f = new Fixture();
        f.connect(f.client(HOST_A));
        TrustAnchors widened = TrustAnchors.ofCertificates(f.server.cert, f.other.cert);
        assertFalse(
                f.connect(f.client(HOST_A, widened)),
                "при другом наборе якорей тикет не должен предлагаться");
    }

    @Test
    @DisplayName("Смена политики срока якоря инвалидирует тикет")
    void expiryPolicyChangeInvalidatesTicket() throws Exception {
        Fixture f = new Fixture();
        f.connect(f.client(HOST_A));
        TrustAnchors strict = f.anchors().withExpiryPolicy(AnchorExpiryPolicy.REJECT);
        assertFalse(
                f.connect(f.client(HOST_A, strict)),
                "при другой политике срока якоря тикет не должен предлагаться");
    }

    @Test
    @DisplayName("Режим без сверки имени: тот же SNI возобновляется, другой SNI нет")
    void hostnameOptOutBindsSni() throws Exception {
        Fixture f = new Fixture();
        f.connect(f.clientOptOut(HOST_A));
        assertTrue(f.connect(f.clientOptOut(HOST_A)), "тот же SNI должен возобновиться");
        assertFalse(f.connect(f.clientOptOut(HOST_B)), "другой SNI не должен возобновляться");
    }

    @Test
    @DisplayName("Тикеты режимов «цепочка и имя» и «без сверки имени» не пересекаются")
    void nameVerificationModesDoNotMix() throws Exception {
        Fixture strictFirst = new Fixture();
        strictFirst.connect(strictFirst.client(HOST_A));
        assertFalse(
                strictFirst.connect(strictFirst.clientOptOut(HOST_A)),
                "тикет режима со сверкой имени не подходит режиму без сверки");

        Fixture optOutFirst = new Fixture();
        optOutFirst.connect(optOutFirst.clientOptOut(HOST_A));
        assertFalse(
                optOutFirst.connect(optOutFirst.client(HOST_A)),
                "тикет режима без сверки имени не подходит режиму со сверкой");
    }

    @Test
    @DisplayName("Режим без аутентификации сервера не пересекается с проверяемыми режимами")
    void noServerAuthModeDoesNotMix() throws Exception {
        Fixture f = new Fixture();
        f.connect(f.clientNoServerAuth());
        assertTrue(f.connect(f.clientNoServerAuth()), "тот же режим должен возобновляться");
        assertFalse(
                f.connect(f.client(HOST_A)),
                "тикет режима без аутентификации не подходит проверяемому режиму");
    }

    @Test
    @DisplayName("Хранилище вернуло запись с чужой привязкой: стек её игнорирует")
    void engineIgnoresEntryWithForeignBinding() throws Exception {
        Fixture f = new Fixture();
        // Хранилище, которое игнорирует привязку и всегда отдаёт последнюю принятую запись.
        ForeignBindingStore dishonest = new ForeignBindingStore();
        f.clientStore = dishonest;
        f.connect(f.client(HOST_A));
        assertNotNull(dishonest.lastEntry(), "тикет для A должен быть сохранён");
        assertFalse(
                f.connect(f.client(HOST_B)),
                "запись, привязанная к A, не должна использоваться при подключении к B");
    }

    // ========================================================================
    // Фабрика привязки
    // ========================================================================

    @Test
    @DisplayName("Режим со сверкой имени и пустое имя: PSK не предлагается")
    void blankNameWithVerificationYieldsNoBinding() throws Exception {
        TrustAnchors anchors = TrustAnchors.ofCertificate(new Fixture().server.cert);
        assertNull(forClient(null, true, false, anchors, false, false));
        assertNull(forClient("   ", true, false, anchors, false, false));
    }

    @Test
    @DisplayName("Пустое имя в режимах без сверки имени допустимо и даёт null-имя в привязке")
    void blankNameWithoutVerificationIsAllowed() throws Exception {
        TrustAnchors anchors = TrustAnchors.ofCertificate(new Fixture().server.cert);
        PskBinding optOut = forClient("  ", true, true, anchors, false, false);
        assertNotNull(optOut);
        assertNull(optOut.serverName());
        PskBinding noAuth = forClient(null, false, false, null, false, false);
        assertNotNull(noAuth);
        assertNull(noAuth.serverName());
    }

    @Test
    @DisplayName("PskBinding сам нормализует имя: привязка из другого кода совпадает с вычисленной")
    void bindingNormalizesServerNameItself() {
        assertEquals(new PskBinding("A.Example", "id"), new PskBinding("a.example", "id"));
        assertEquals("a.example", new PskBinding("A.Example", "id").serverName());
    }

    @Test
    @DisplayName("Имя сервера приводится к нижнему регистру")
    void serverNameIsCaseInsensitive() throws Exception {
        TrustAnchors anchors = TrustAnchors.ofCertificate(new Fixture().server.cert);
        assertEquals(
                forClient("A.Example", true, false, anchors, false, false),
                forClient("a.example", true, false, anchors, false, false));
    }

    @Test
    @DisplayName("Любая настройка проверки сервера меняет идентификатор модели доверия")
    void everyVerificationKnobChangesVerificationId() throws Exception {
        TrustAnchors anchors = TrustAnchors.ofCertificate(new Fixture().server.cert);
        String base = forClient(HOST_A, true, false, anchors, false, false).verificationId();

        assertNotEquals(
                base,
                forClient(HOST_A, true, false, anchors, true, false).verificationId(),
                "requireOcspStapling должен входить в привязку");
        assertNotEquals(
                base,
                forClient(HOST_A, true, false, anchors, false, true).verificationId(),
                "interopAcceptGostBaseSigScheme должен входить в привязку");
        assertNotEquals(
                base,
                forClient(HOST_A, true, true, anchors, false, false).verificationId(),
                "отключение сверки имени должно входить в привязку");
        assertNotEquals(
                base,
                forClient(HOST_A, false, false, null, false, false).verificationId(),
                "отсутствие аутентификации сервера должно входить в привязку");
        assertNotEquals(
                base,
                PskBindingFactory.forClient(
                                HOST_A,
                                true,
                                false,
                                anchors,
                                false,
                                false,
                                Digest.Algorithm.STREEBOG_512)
                        .verificationId(),
                "алгоритм хэша KDF должен входить в привязку (подмена алгоритма, а не длины)");
        assertFalse(base.isEmpty(), "клиентский идентификатор не должен быть пустым");
    }

    // ========================================================================
    // Хранилище
    // ========================================================================

    @Test
    @DisplayName("InMemoryPskStore: фильтр по привязке, серверная запись клиенту не возвращается")
    void inMemoryStoreFiltersByBinding() {
        InMemoryPskStore store = new InMemoryPskStore(10);
        PskBinding a = new PskBinding(HOST_A, "id-1");
        PskBinding b = new PskBinding(HOST_B, "id-1");
        long now = System.currentTimeMillis();
        store.onTicketReceived(entry(1, now - 2000, a));
        store.onTicketReceived(entry(2, now - 1000, a));
        store.onTicketReceived(entry(3, now, PskBinding.forServer(null)));

        PskEntry found = store.getForResumption(a);
        assertNotNull(found, "запись с равной привязкой должна находиться");
        assertEquals(now - 1000, found.getIssueTime(), "должна выбираться самая свежая запись");
        assertNull(store.getForResumption(b), "запись другого сервера возвращаться не должна");
        assertNull(
                store.getForResumption(new PskBinding(HOST_A, "id-2")),
                "запись другой модели доверия возвращаться не должна");
        assertEquals(
                PskBinding.forServer(null),
                store.getForResumption(PskBinding.forServer(null)).getBinding(),
                "серверная запись ищется только запросом с серверной привязкой, а не клиентской");
        assertThrows(IllegalArgumentException.class, () -> store.getForResumption(null));
    }

    @Test
    @DisplayName("Серверный поиск по байтам тикета привязку не использует")
    void serverLookupByTicketBytesIgnoresBinding() {
        InMemoryPskStore store = new InMemoryPskStore(10);
        store.onTicketReceived(entry(7, System.currentTimeMillis(), PskBinding.forServer(null)));
        byte[] ticket = new byte[] {7};
        assertNotNull(store.peek(ticket), "peek по байтам должен находить запись");
        assertNotNull(store.get(ticket), "get по байтам должен находить запись");
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static PskBinding forClient(
            String hostname,
            boolean verifyChain,
            boolean hostnameVerificationDisabled,
            TrustAnchors anchors,
            boolean requireOcsp,
            boolean interop) {
        return PskBindingFactory.forClient(
                hostname,
                verifyChain,
                hostnameVerificationDisabled,
                anchors,
                requireOcsp,
                interop,
                SUITE.getKdfHashAlgorithm());
    }

    private static PskEntry entry(int ticketByte, long issueTime, PskBinding binding) {
        return new PskEntry(
                new byte[] {(byte) ticketByte},
                3600,
                0,
                new byte[] {1},
                new byte[32],
                issueTime,
                binding,
                PskEntry.NO_CERTIFICATE_BOUND);
    }

    /** Хранилище, нарушающее контракт: отдаёт последнюю принятую запись при любой привязке. */
    private static final class ForeignBindingStore implements PskStore {
        private final InMemoryPskStore delegate = new InMemoryPskStore(10);
        private final List<PskEntry> received = new CopyOnWriteArrayList<>();

        PskEntry lastEntry() {
            return received.isEmpty() ? null : received.get(received.size() - 1);
        }

        @Override
        public PskEntry get(byte[] ticket) {
            return delegate.get(ticket);
        }

        @Override
        public PskEntry getForResumption(PskBinding binding) {
            return lastEntry();
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

    /** Сервер с сертификатом на два имени, раздельные хранилища клиента и сервера. */
    private static final class Fixture {
        final PkixCertTestHelper.CertBundle server =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(),
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {HOST_A, HOST_B});
        final PkixCertTestHelper.CertBundle other =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(),
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"other.example"});
        final PskStore serverStore = new InMemoryPskStore(100);
        PskStore clientStore = new InMemoryPskStore(100);

        TrustAnchors anchors() {
            return TrustAnchors.ofCertificate(server.cert);
        }

        Function<InMemoryTlsTransport, TlsSession> client(String host) {
            return client(host, anchors());
        }

        Function<InMemoryTlsTransport, TlsSession> client(String host, TrustAnchors anchors) {
            return tp ->
                    TlsSession.createClient(
                            new TlsClientConfig(SUITE, anchors).withServerHostname(host), tp);
        }

        Function<InMemoryTlsTransport, TlsSession> clientOptOut(String host) {
            return tp ->
                    TlsSession.createClient(
                            new TlsClientConfig(SUITE, anchors())
                                    .withServerHostname(host)
                                    .withoutHostnameVerification(),
                            tp);
        }

        Function<InMemoryTlsTransport, TlsSession> clientNoServerAuth() {
            return tp -> TlsSession.createClientWithoutServerAuth(tp, SUITE, null, null);
        }

        /** Одно соединение; возвращает true, если клиент возобновился по PSK. */
        boolean connect(Function<InMemoryTlsTransport, TlsSession> clientFactory) throws Exception {
            var pair = InMemoryTlsTransport.newPair();
            TlsSession serverSession =
                    TlsSession.createServer(
                            pair.getServerTransport(), SUITE, server.cert, server.priv);
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
