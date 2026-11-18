package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.feedRunningTasks;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.wrapPending;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.socket.GostSSLSocket;
import org.rssys.gost.jsse.testkit.EngineServerPki;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Имя SNI из {@code SSLParameters.getServerNames()}: заменяет только SNI. Сертификат сервера
 * по-прежнему сверяется с {@code peerHost}: SNI выбирает виртуальный сервер, а не того, кому
 * доверяет клиент.
 */
@DisplayName("GostSSLEngine: имя SNI из SSLParameters.setServerNames")
class GostSSLEngineServerNamesTest {

    private static final String VIRTUAL_HOST = "virtual.example";
    private static final int BIG_BUFFER =
            16 * (TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);

    private static EngineServerPki pki;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        pki = EngineServerPki.create();
    }

    /** Клиент проверяет сертификат сервера (SAN localhost) по peerHost=localhost. */
    private static GostSSLEngine client() {
        return GostSSLEngine.createForClient(
                new GostX509KeyManager(),
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(pki.rootCa().cert)),
                "localhost",
                0,
                null);
    }

    private static GostSSLEngine server() {
        return new GostSSLEngine(
                pki.serverKm(), GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
    }

    private static void withServerNames(GostSSLEngine engine, List<SNIServerName> names) {
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setServerNames(names);
        engine.setSSLParameters(parameters);
    }

    private static void handshake(GostSSLEngine client, GostSSLEngine server) throws Exception {
        client.beginHandshake();
        for (int round = 0; round < 4; round++) {
            ByteBuffer toServer = ByteBuffer.allocate(BIG_BUFFER);
            wrapPending(client, toServer);
            toServer.flip();
            feedRunningTasks(server, toServer);
            ByteBuffer toClient = ByteBuffer.allocate(BIG_BUFFER);
            wrapPending(server, toClient);
            toClient.flip();
            feedRunningTasks(client, toClient);
        }
        assertEquals(
                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                client.getHandshakeStatus(),
                "рукопожатие завершено: сертификат сверен по peerHost, а не по SNI");
    }

    @Test
    @DisplayName("Переопределённое имя уходит в SNI, сертификат сверяется по peerHost")
    void overriddenNameGoesToSniCertificateCheckedByPeerHost() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server();
        withServerNames(client, List.of(new SNIHostName(VIRTUAL_HOST)));

        handshake(client, server);

        assertEquals(VIRTUAL_HOST, server.getRequestedServerName(), "сервер получил имя из SNI");
        assertEquals("localhost", client.getSession().getPeerHost());
    }

    @Test
    @DisplayName("Пустой список отключает SNI")
    void emptyListDisablesSni() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server();
        withServerNames(client, List.of());

        handshake(client, server);

        assertNull(server.getRequestedServerName(), "SNI не отправлялся");
    }

    @Test
    @DisplayName("Без setServerNames имя SNI берётся из peerHost")
    void defaultSniFromPeerHost() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server();

        handshake(client, server);

        assertEquals("localhost", server.getRequestedServerName());
    }

    @Test
    @DisplayName("Имена не типа host_name игнорируются, как в JDK")
    void nonHostNameTypesIgnored() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server();
        SNIServerName otherType = new SNIServerName(5, new byte[] {1, 2, 3}) {};
        withServerNames(client, List.of(otherType));

        handshake(client, server);

        assertNull(server.getRequestedServerName(), "имени типа host_name нет: SNI не отправлен");
    }

    @Test
    @DisplayName(
            "getSSLParameters возвращает переопределение: круговой set(get()) его не сбрасывает")
    void roundTripKeepsOverride() throws Exception {
        GostSSLEngine client = client();
        withServerNames(client, List.of(new SNIHostName(VIRTUAL_HOST)));

        client.setSSLParameters(client.getSSLParameters());

        List<SNIServerName> names = client.getSSLParameters().getServerNames();
        assertEquals(List.of(new SNIHostName(VIRTUAL_HOST)), names);
        GostSSLEngine server = server();
        handshake(client, server);
        assertEquals(VIRTUAL_HOST, server.getRequestedServerName());
    }

    @Test
    @DisplayName("SSLParameters без имён (null) не сбрасывает переопределение, как в JDK")
    void nullServerNamesKeepOverride() throws Exception {
        GostSSLEngine client = client();
        withServerNames(client, List.of(new SNIHostName(VIRTUAL_HOST)));

        // JDK SSLConfiguration.setSSLParameters: null означает «не задано», прежние имена остаются
        client.setSSLParameters(new SSLParameters());

        GostSSLEngine server = server();
        handshake(client, server);
        assertEquals(VIRTUAL_HOST, server.getRequestedServerName());
    }

    @Test
    @DisplayName("Сокет передаёт имена в движок: круговой set(get()) сохраняет их")
    void socketDelegatesServerNames() throws Exception {
        try (java.net.ServerSocket listener = new java.net.ServerSocket(0);
                GostSSLSocket socket =
                        new GostSSLSocket(
                                "localhost",
                                listener.getLocalPort(),
                                new GostX509KeyManager(),
                                GostX509TrustManager.insecureTrustAll(),
                                new GostSSLSessionContext(
                                        org.rssys.gost.tls13.TlsCiphersuite
                                                .TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L))) {
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setServerNames(List.of(new SNIHostName(VIRTUAL_HOST)));
            socket.setSSLParameters(parameters);
            socket.setSSLParameters(socket.getSSLParameters());
            assertEquals(
                    List.of(new SNIHostName(VIRTUAL_HOST)),
                    socket.getSSLParameters().getServerNames());
        }
    }

    @Test
    @DisplayName("Имя, которое нельзя отправить в SNI, отвергается сразу в setSSLParameters")
    void invalidNameRejectedImmediately() {
        GostSSLEngine client = client();
        // Пять меток по 60 символов: SNIHostName общую длину не проверяет и принимает, а имя в SNI
        // ограничено 253 символами (RFC 1035)
        SNIHostName tooLong =
                new SNIHostName(String.join(".", java.util.Collections.nCopies(5, "a".repeat(60))));
        assertThrows(
                IllegalArgumentException.class, () -> withServerNames(client, List.of(tooLong)));
        assertTrue(client.getSSLParameters().getServerNames() == null, "переопределения нет");
    }
}
