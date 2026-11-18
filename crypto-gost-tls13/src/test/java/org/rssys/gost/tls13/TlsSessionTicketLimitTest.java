package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Число NewSessionTicket сервера ограничено: клиентский {@code read()} обрабатывает не более
 * {@link TlsConstants#MAX_POST_HANDSHAKE} сообщений подряд, и при большем числе тикетов до данных
 * приложения не дошёл бы.
 */
@DisplayName("TlsServerConfig.withTicketsToSend: предел числа тикетов")
class TlsSessionTicketLimitTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final String SERVER_HOST = "gost.example.com";

    /** Запас лимита клиента на сообщения, не относящиеся к тикетам (KeyUpdate). */
    private static final int RESERVE_FOR_KEY_UPDATE = 2;

    private static TlsServerConfig serverConfig() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {SERVER_HOST},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        return new TlsServerConfig(SUITE, Collections.singletonList(leaf.cert), leaf.priv);
    }

    @Test
    @DisplayName("значения вне 1..MAX_TICKETS_TO_SEND отклоняются")
    void outOfRangeIsRejected() throws Exception {
        TlsServerConfig config = serverConfig();

        assertThrows(IllegalArgumentException.class, () -> config.withTicketsToSend(0));
        assertThrows(
                IllegalArgumentException.class,
                () -> config.withTicketsToSend(TlsConstants.MAX_TICKETS_TO_SEND + 1));
        assertDoesNotThrow(() -> config.withTicketsToSend(1));
        assertDoesNotThrow(() -> config.withTicketsToSend(TlsConstants.MAX_TICKETS_TO_SEND));
    }

    @Test
    @DisplayName("предел тикетов оставляет запас лимита клиента на KeyUpdate")
    void limitLeavesReserveForKeyUpdate() {
        assertTrue(
                TlsConstants.MAX_TICKETS_TO_SEND + RESERVE_FOR_KEY_UPDATE
                        <= TlsConstants.MAX_POST_HANDSHAKE,
                "Тикеты плюс запас на KeyUpdate должны помещаться в лимит клиентского read()");
    }

    @Test
    @DisplayName("сервер с максимумом тикетов: клиентский read() доходит до данных приложения")
    void clientReadsApplicationDataAfterMaximumTickets() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {SERVER_HOST},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        var transports = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(SUITE, Collections.singletonList(leaf.cert), leaf.priv)
                                .withTicketsToSend(TlsConstants.MAX_TICKETS_TO_SEND),
                        transports.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname(SERVER_HOST),
                        transports.getClientTransport());
        // Тикеты выдаются только при заданном хранилище сервера; ёмкость клиентского не меньше
        // числа тикетов, иначе вытеснение исказило бы подсчёт
        InMemoryPskStore serverStore = new InMemoryPskStore(TlsConstants.MAX_TICKETS_TO_SEND);
        InMemoryPskStore clientStore = new InMemoryPskStore(TlsConstants.MAX_TICKETS_TO_SEND);
        server.setPskStore(serverStore);
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

        byte[] message = "после тикетов".getBytes(StandardCharsets.UTF_8);
        server.write(message);

        assertArrayEquals(message, client.read());
        // Без этой проверки тест прошёл бы и в случае, когда сервер вовсе не выдал тикеты
        assertEquals(
                TlsConstants.MAX_TICKETS_TO_SEND,
                serverStore.size(),
                "Сервер сохранил максимум тикетов");
        assertEquals(
                TlsConstants.MAX_TICKETS_TO_SEND,
                clientStore.size(),
                "Клиент разобрал и сохранил все тикеты до данных приложения");
        server.close();
        client.close();
    }
}
