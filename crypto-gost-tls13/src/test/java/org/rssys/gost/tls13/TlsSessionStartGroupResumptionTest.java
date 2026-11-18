package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Стартовая группа клиента ({@link TlsClientConfig#withSelectedNamedGroup(int)}) и итог
 * {@link TlsSession#wasResumed()}: возобновление идёт и через HelloRetryRequest, и без него.
 */
@DisplayName("TlsSession: стартовая группа клиента, возобновление и wasResumed()")
class TlsSessionStartGroupResumptionTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final String HOST = "gost.example.com";
    // Сервер предпочитает GC256A, клиент по умолчанию начинает с GC256B
    private static final int SERVER_GROUP = TlsConstants.GRP_GC256A;
    private static final int TIMEOUT_SECONDS = 15;

    /** Итог одного соединения. */
    private record Outcome(boolean resumed, int clientHellos) {}

    private final PkixCertTestHelper.CertBundle server =
            PkixCertTestHelper.createCertWithKey(
                    ECParameters.tc26a256(),
                    "20240501120000Z",
                    "21060101120000Z",
                    new String[] {HOST});
    private final PskStore serverStore = new InMemoryPskStore(100);
    private final PskStore clientStore = new InMemoryPskStore(100);

    @Test
    @DisplayName("withSelectedNamedGroup: неизвестная группа отвергается сразу")
    void unknownGroupIsRejectedEarly() {
        TlsClientConfig config =
                new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(server.cert));
        assertThrows(
                IllegalArgumentException.class,
                () -> config.withSelectedNamedGroup(0xFFFF),
                "неподдерживаемая группа должна отвергаться при настройке");
    }

    @Test
    @DisplayName("Группа клиента по умолчанию (GC256B) против GC256A: HRR, возобновление работает")
    void resumesThroughHrrWithDefaultGroup() throws Exception {
        Outcome first = connect(0);
        assertFalse(first.resumed(), "первое соединение полное");
        assertEquals(2, first.clientHellos(), "первое соединение шло через HRR");

        Outcome second = connect(0);
        assertTrue(second.resumed(), "второе соединение возобновляется через HRR");
        assertEquals(2, second.clientHellos(), "второе соединение шло через HRR");
    }

    @Test
    @DisplayName("Группа клиента совпадает с группой сервера: HRR нет, возобновление работает")
    void resumesWithoutHrrWhenGroupMatches() throws Exception {
        Outcome first = connect(SERVER_GROUP);
        assertFalse(first.resumed(), "первое соединение полное");
        assertEquals(1, first.clientHellos(), "без HRR один ClientHello");

        Outcome second = connect(SERVER_GROUP);
        assertTrue(second.resumed(), "второе соединение возобновляется");
        assertEquals(1, second.clientHellos(), "без HRR один ClientHello");
    }

    @Test
    @DisplayName(
            "wasResumed(): до рукопожатия исключение, после завершения и close() значение стабильно")
    void wasResumedIsStableAfterClose() throws Exception {
        connect(SERVER_GROUP);

        var pair = InMemoryTlsTransport.newPair();
        TlsSession serverSession = serverSession(pair);
        TlsSession clientSession = clientSession(pair, SERVER_GROUP);
        assertThrows(
                IllegalStateException.class,
                clientSession::wasResumed,
                "клиент: итог неизвестен до рукопожатия");
        assertThrows(
                IllegalStateException.class,
                serverSession::wasResumed,
                "сервер: итог неизвестен до рукопожатия");

        handshake(clientSession, serverSession);
        assertTrue(clientSession.wasResumed(), "клиент: возобновление");
        assertTrue(serverSession.wasResumed(), "сервер: возобновление");

        serverSession.close();
        clientSession.close();
        assertTrue(clientSession.wasResumed(), "клиент: значение переживает close()");
        assertTrue(serverSession.wasResumed(), "сервер: значение переживает close()");
    }

    private Outcome connect(int clientStartGroup) throws Exception {
        var pair = InMemoryTlsTransport.newPair();
        TlsSession serverSession = serverSession(pair);
        TlsSession clientSession = clientSession(pair, clientStartGroup);
        try {
            handshake(clientSession, serverSession);
            boolean resumed = clientSession.wasResumed();
            assertEquals(resumed, serverSession.wasResumed(), "обе стороны согласны об итоге");
            // NewSessionTicket клиент обрабатывает в read(): закрываем сервер и дочитываем
            serverSession.close();
            assertThrows(EOFException.class, clientSession::read);
            return new Outcome(resumed, clientTransport.sentPlainHandshakeRecords());
        } finally {
            serverSession.close();
            clientSession.close();
        }
    }

    private HandshakeRecordCountingTransport clientTransport;

    private TlsSession serverSession(InMemoryTlsTransport.Pair pair) {
        TlsSession session =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        SUITE, Collections.singletonList(server.cert), server.priv)
                                .withSelectedNamedGroup(SERVER_GROUP),
                        pair.getServerTransport());
        session.setPskStore(serverStore);
        return session;
    }

    private TlsSession clientSession(InMemoryTlsTransport.Pair pair, int startGroup) {
        clientTransport = new HandshakeRecordCountingTransport(pair.getClientTransport());
        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(server.cert))
                                .withServerHostname(HOST)
                                .withSelectedNamedGroup(startGroup),
                        clientTransport);
        session.setPskStore(clientStore);
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
