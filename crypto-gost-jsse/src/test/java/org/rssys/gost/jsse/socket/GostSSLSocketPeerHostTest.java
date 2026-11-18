package org.rssys.gost.jsse.socket;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.tls13.TlsCiphersuite;

/**
 * Имя пира у сокетов: без обратного DNS-запроса, по которому потом сверялся бы сертификат, и
 * настройки, передаваемые принятым сокетам.
 */
@DisplayName("GostSSLSocket: имя пира без обратного DNS, настройки принятых сокетов")
class GostSSLSocketPeerHostTest {

    private static final String LOOPBACK_LITERAL = "127.0.0.1";

    private static GostSSLSessionContext sessionContext;

    @BeforeAll
    static void setUp() {
        Security.addProvider(new RssysGostJsseProvider());
        sessionContext =
                new GostSSLSessionContext(
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
    }

    /** Пир в этих тестах не отвечает: рукопожатие из getSession() обрывается тайм-аутом. */
    private static final int SILENT_PEER_TIMEOUT_MS = 200;

    private static InetAddress loopbackWithoutName() throws IOException {
        // Адрес, созданный из байтов, имени не знает: getHostName() пошёл бы в PTR-запись
        return InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    }

    @Test
    @DisplayName("Клиентский сокет по адресу без имени: имя пира - литерал, обратного запроса нет")
    void clientSocketUsesAddressLiteral() throws Exception {
        try (ServerSocket plainServer = new ServerSocket(0, 1, loopbackWithoutName());
                GostSSLSocket client =
                        new GostSSLSocket(
                                loopbackWithoutName(),
                                plainServer.getLocalPort(),
                                new GostX509KeyManager(),
                                GostX509TrustManager.insecureTrustAll(),
                                sessionContext)) {
            // getSession() запускает рукопожатие, а пир молчит: короткий тайм-аут обрывает его,
            // и getSession() отдаёт пустую сессию с именем пира
            client.setSoTimeout(SILENT_PEER_TIMEOUT_MS);
            assertEquals(
                    LOOPBACK_LITERAL,
                    client.getSession().getPeerHost(),
                    "имя для проверки сертификата берётся из адреса без обратного DNS-запроса");
        }
    }

    @Test
    @DisplayName("Принятый сокет: имя пира - литерал адреса клиента")
    void acceptedSocketUsesAddressLiteral() throws Exception {
        try (GostSSLServerSocket server =
                        new GostSSLServerSocket(
                                0,
                                1,
                                loopbackWithoutName(),
                                new GostX509KeyManager(),
                                GostX509TrustManager.insecureTrustAll(),
                                sessionContext);
                Socket plainClient = new Socket(loopbackWithoutName(), server.getLocalPort());
                SSLSocket accepted = (SSLSocket) server.accept()) {
            accepted.setSoTimeout(SILENT_PEER_TIMEOUT_MS);
            assertEquals(
                    LOOPBACK_LITERAL,
                    accepted.getSession().getPeerHost(),
                    "accept() не должен делать блокирующий обратный DNS-запрос");
        }
    }

    @Test
    @DisplayName("accept() сохраняет обязательный режим аутентификации клиента")
    void acceptedSocketKeepsRequiredClientAuth() throws Exception {
        try (GostSSLServerSocket server =
                        new GostSSLServerSocket(
                                0,
                                1,
                                loopbackWithoutName(),
                                new GostX509KeyManager(),
                                GostX509TrustManager.insecureTrustAll(),
                                sessionContext);
                Socket plainClient = new Socket(loopbackWithoutName(), server.getLocalPort())) {
            server.setNeedClientAuth(true);
            assertEquals(true, server.getNeedClientAuth());
            assertEquals(false, server.getWantClientAuth(), "want заменён обязательным режимом");

            try (SSLSocket accepted = (SSLSocket) server.accept()) {
                assertEquals(
                        true,
                        accepted.getNeedClientAuth(),
                        "принятый сокет должен быть в обязательном режиме");
            }
        }
    }

    @Test
    @DisplayName("Селектор ALPN серверного сокета применяется к принятым сокетам")
    void serverSocketAlpnSelectorIsAppliedToAcceptedSockets() throws Exception {
        BiFunction<SSLSocket, List<String>, String> selector =
                (socket, offered) -> offered.isEmpty() ? null : offered.get(0);
        try (GostSSLServerSocket server =
                        new GostSSLServerSocket(
                                0,
                                1,
                                loopbackWithoutName(),
                                new GostX509KeyManager(),
                                GostX509TrustManager.insecureTrustAll(),
                                sessionContext);
                Socket plainClient = new Socket(loopbackWithoutName(), server.getLocalPort())) {
            server.setHandshakeApplicationProtocolSelector(selector);
            assertSame(selector, server.getHandshakeApplicationProtocolSelector());

            try (SSLSocket accepted = (SSLSocket) server.accept()) {
                assertSame(
                        selector,
                        accepted.getHandshakeApplicationProtocolSelector(),
                        "принятый сокет должен получить селектор сервера");
            }
        }
    }

    @Test
    @DisplayName("Запрос max_fragment_length на сокете: 0 допустим, недопустимый код отвергается")
    void maxFragmentLengthRequestOnSocket() throws Exception {
        try (ServerSocket plainServer = new ServerSocket(0, 1, loopbackWithoutName());
                GostSSLSocket client =
                        new GostSSLSocket(
                                loopbackWithoutName(),
                                plainServer.getLocalPort(),
                                new GostX509KeyManager(),
                                GostX509TrustManager.insecureTrustAll(),
                                sessionContext)) {
            client.setMaxFragmentLengthRequest(1);
            client.setMaxFragmentLengthRequest(0);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> client.setMaxFragmentLengthRequest(7),
                    "недопустимый код не должен молча превращаться в «не запрашивать»");
        }
    }
}
