package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.concurrent.ExecutionException;
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
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Явный отказ от сверки имени узла ({@code withoutHostnameVerification}) отключает только сверку
 * с сертификатом: SNI по-прежнему передаётся серверу.
 */
class TlsSessionHostnameOptOutTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    @Test
    @DisplayName(
            "withoutHostnameVerification при заданном имени: чужой сертификат принят, SNI передан")
    void optOutAcceptsMismatchAndKeepsSni() throws Exception {
        HandshakeResult result = handshake("server.com", "evil.com", true);
        assertNull(result.clientFailure, "рукопожатие с opt-out должно пройти");
        assertEquals("evil.com", result.requestedServerName, "SNI должен сохраниться");
    }

    @Test
    @DisplayName("Без opt-out чужое имя отвергается")
    void withoutOptOutMismatchRejected() throws Exception {
        HandshakeResult result = handshake("server.com", "evil.com", false);
        assertNotNull(result.clientFailure, "несовпадение имени должно отвергаться");
        assertInstanceOf(
                TlsException.class,
                result.clientFailure,
                "ожидалась TlsException: " + result.clientFailure);
    }

    @Test
    @DisplayName("Opt-out без имени: рукопожатие проходит, SNI не передаётся")
    void optOutWithoutHostnameWorks() throws Exception {
        HandshakeResult result = handshake("server.com", null, true);
        assertNull(result.clientFailure, "рукопожатие должно пройти");
        assertNull(result.requestedServerName, "без имени SNI не передаётся");
    }

    @Test
    @DisplayName("Без имени и без opt-out createClient отказывает")
    void missingHostnameWithoutOptOutThrows() throws Exception {
        PkixCertTestHelper.CertBundle bundle = bundle("server.com");
        var tp = InMemoryTlsTransport.newPair();
        TlsClientConfig config =
                new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(bundle.cert));
        assertThrows(
                IllegalArgumentException.class,
                () -> TlsSession.createClient(config, tp.getClientTransport()),
                "имя узла обязательно, если проверка не отключена явно");
    }

    @Test
    @DisplayName("Leaf-only: opt-out отключает сверку имени, без него чужое имя отвергается")
    void leafOnlyHonorsOptOut() throws Exception {
        PkixCertTestHelper.CertBundle bundle = bundle("server.com");
        for (boolean optOut : new boolean[] {true, false}) {
            var tp = InMemoryTlsTransport.newPair();
            TlsClientConfig config =
                    new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(bundle.cert))
                            .withServerHostname("evil.com");
            if (optOut) {
                config.withoutHostnameVerification();
            }
            try (TlsSession client = TlsSession.createClient(config, tp.getClientTransport())) {
                if (optOut) {
                    assertDoesNotThrow(
                            () -> client.checkServerCertificateLeafOnly(List.of(bundle.cert)),
                            "при opt-out сверка имени не выполняется");
                } else {
                    assertThrows(
                            TlsException.class,
                            () -> client.checkServerCertificateLeafOnly(List.of(bundle.cert)),
                            "без opt-out чужое имя должно отвергаться");
                }
            }
        }
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static PkixCertTestHelper.CertBundle bundle(String san) throws Exception {
        return PkixCertTestHelper.createCertWithKey(
                ECParameters.tc26a256(), "20240501120000Z", "21060101120000Z", new String[] {san});
    }

    /** Итог рукопожатия: ошибка клиента (null при успехе) и SNI, полученный сервером. */
    private record HandshakeResult(Throwable clientFailure, String requestedServerName) {}

    private static HandshakeResult handshake(String san, String clientHostname, boolean optOut)
            throws Exception {
        PkixCertTestHelper.CertBundle bundle = bundle(san);
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(tp.getServerTransport(), SUITE, bundle.cert, bundle.priv);
        TlsClientConfig config =
                new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(bundle.cert));
        if (clientHostname != null) {
            config.withServerHostname(clientHostname);
        }
        if (optOut) {
            config.withoutHostnameVerification();
        }
        TlsSession client = TlsSession.createClient(config, tp.getClientTransport());

        ExecutorService exec = Executors.newFixedThreadPool(2);
        try {
            Future<Void> clientFuture =
                    exec.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            Future<Void> serverFuture =
                    exec.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            Throwable clientFailure = null;
            try {
                clientFuture.get(15, TimeUnit.SECONDS);
                serverFuture.get(15, TimeUnit.SECONDS);
            } catch (ExecutionException e) {
                clientFailure = e.getCause();
            }
            // Сессии читаются и закрываются только после завершения потоков рукопожатия; если
            // потоки
            // не завершились, сессии не трогаем: закрытие из другого потока - то самое нарушение
            // контракта, которое помощник должен предотвращать
            TlsSessionConnection.stopHandshakeThreads(exec, clientFuture, serverFuture);
            HandshakeResult result =
                    new HandshakeResult(clientFailure, server.getRequestedServerName());
            server.close();
            client.close();
            return result;
        } finally {
            exec.shutdownNow();
        }
    }
}
