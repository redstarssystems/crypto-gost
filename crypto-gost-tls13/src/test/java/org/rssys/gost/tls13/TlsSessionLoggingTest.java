package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Журнал сессии: по записям DEBUG без отладчика видно стадию рукопожатия, набор шифров, режим PSK,
 * KeyUpdate и алерты с кодом; штатное соединение не пишет WARNING и выше. Причины отказов
 * остаются в исключениях, запись несёт стадию и код alert.
 */
@DisplayName("TlsSession: журнал рукопожатия, PSK, KeyUpdate и алертов")
class TlsSessionLoggingTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final String HOST = "gost.example.com";
    private static final int TIMEOUT_SECONDS = 15;
    private static final byte[] MESSAGE = "данные".getBytes(StandardCharsets.UTF_8);

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

    private record Connection(TlsSession server, TlsSession client) {}

    /** Рукопожатие с хранилищами PSK; сервер пишет данные, клиент их читает (получает тикеты). */
    private static Connection connect(InMemoryPskStore serverStore, InMemoryPskStore clientStore)
            throws Exception {
        var transports = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(SUITE, List.of(leaf.cert), leaf.priv)
                                .withTicketsToSend(1),
                        transports.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname(HOST),
                        transports.getClientTransport());
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
            clientHandshake.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            serverHandshake.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
        server.write(MESSAGE);
        assertArrayEquals(MESSAGE, client.read(), "данные после рукопожатия доходят до клиента");
        return new Connection(server, client);
    }

    private static boolean has(List<String> messages, String fragment) {
        return messages.stream().anyMatch(m -> m.contains(fragment));
    }

    private static String suiteForLog() {
        return SUITE.forLog();
    }

    @Test
    @DisplayName("Полное рукопожатие: WARNING нет, на DEBUG стадии, набор шифров, SNI и тикеты")
    void fullHandshakeIsDescribedAtDebug() throws Exception {
        try (LogCapture log = LogCapture.start(LogCapture.TLS13)) {
            Connection connection = connect(new InMemoryPskStore(10), new InMemoryPskStore(10));
            connection.server().close();
            connection.client().close();

            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "штатное соединение не пишет WARNING и выше");
            List<String> debug = log.messages(Level.FINE);
            assertTrue(
                    has(debug, "TLS handshake started: role=CLIENT, PSK offered=false"),
                    "начало на клиенте: " + debug);
            assertTrue(has(debug, "TLS handshake started: role=SERVER"), "начало на сервере");
            assertFalse(
                    has(debug, "TLS handshake started: role=SERVER, PSK"),
                    "у сервера признак PSK в записи о старте не пишется: " + debug);
            assertTrue(
                    has(
                            debug,
                            "Handshake stage CLIENT_WAIT_SERVER_HELLO ->"
                                    + " CLIENT_WAIT_ENCRYPTED_EXTENSIONS"),
                    "переход стадии клиента: " + debug);
            assertTrue(
                    has(debug, "ServerHello accepted: cipher suite " + suiteForLog()),
                    "набор шифров у клиента: " + debug);
            assertTrue(
                    has(debug, "ClientHello accepted: cipher suite " + suiteForLog()),
                    "набор шифров у сервера: " + debug);
            assertTrue(has(debug, "sni=" + HOST), "имя сервера на DEBUG: " + debug);
            assertTrue(
                    has(
                            debug,
                            "TLS handshake completed: role=CLIENT, cipher suite "
                                    + suiteForLog()
                                    + ", resumed=false"),
                    "итог на клиенте: " + debug);
            assertTrue(has(debug, "NewSessionTicket 0 issued"), "тикет выдан: " + debug);
            assertTrue(has(debug, "NewSessionTicket received"), "тикет получен: " + debug);
            assertTrue(has(debug, "Alert sent: warning, close_notify (0)"), "закрытие: " + debug);
            // Стадии при старте и при отдаче потока: без них нет ни «полёт сервера отправлен»,
            // ни завершения рукопожатия у клиента
            assertTrue(
                    has(debug, "Handshake stage CLIENT_START -> CLIENT_WAIT_SERVER_HELLO"),
                    "старт клиента: " + debug);
            assertTrue(
                    has(debug, "Handshake stage SERVER_SEND_FLIGHT -> SERVER_WAIT_CLIENT_FINISHED"),
                    "полёт сервера отправлен: " + debug);
            assertTrue(
                    has(debug, "Handshake stage CLIENT_SEND_FINISHED -> POST_HANDSHAKE"),
                    "рукопожатие клиента завершено: " + debug);
        }
    }

    @Test
    @DisplayName("Возобновление по PSK: на DEBUG видно предложение, принятие и resumed=true")
    void resumptionIsDescribedAtDebug() throws Exception {
        InMemoryPskStore serverStore = new InMemoryPskStore(10);
        InMemoryPskStore clientStore = new InMemoryPskStore(10);
        Connection first = connect(serverStore, clientStore);
        first.server().close();
        first.client().close();

        try (LogCapture log = LogCapture.start(LogCapture.TLS13)) {
            Connection second = connect(serverStore, clientStore);
            second.server().close();
            second.client().close();

            List<String> debug = log.messages(Level.FINE);
            assertEquals(List.of(), log.messagesAtOrAbove(Level.WARNING), "WARNING нет");
            assertTrue(
                    has(debug, "TLS handshake started: role=CLIENT, PSK offered=true"),
                    "клиент предложил тикет: " + debug);
            assertTrue(
                    has(debug, "PSK offered: 1 identity(ies), accepted=true"),
                    "сервер принял тикет: " + debug);
            assertTrue(has(debug, "resumed=true"), "итог возобновления: " + debug);
        }
    }

    @Test
    @DisplayName(
            "KeyUpdate: на DEBUG видны постановка в очередь и приём с признаком запроса ответа")
    void keyUpdateIsDescribedAtDebug() throws Exception {
        Connection connection = connect(new InMemoryPskStore(10), new InMemoryPskStore(10));
        try (LogCapture log = LogCapture.start(LogCapture.TLS13)) {
            connection.client().initiateKeyUpdate(true);
            connection.client().write(MESSAGE);
            assertArrayEquals(MESSAGE, connection.server().read(), "ключи сторон согласованы");

            List<String> debug = log.messages(Level.FINE);
            assertTrue(has(debug, "KeyUpdate queued: update_requested=true"), "отправка: " + debug);
            assertTrue(has(debug, "KeyUpdate received: update_requested=true"), "приём: " + debug);
            assertEquals(List.of(), log.messagesAtOrAbove(Level.WARNING), "WARNING нет");
        }
        connection.server().close();
        connection.client().close();
    }

    @Test
    @DisplayName("fatal alert пира в рукопожатии: на DEBUG код и стадия, ответного alert нет")
    void alertFromPeerIsLogged() throws Exception {
        var transports = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        transports.getServerTransport(), SUITE, leaf.cert, leaf.priv);
        byte alert = TlsConstants.ALERT_HANDSHAKE_FAILURE;
        transports
                .getClientTransport()
                .sendRecord(
                        TlsMessageBuilder.buildPlaintextRecord(
                                TlsConstants.CT_ALERT,
                                new byte[] {TlsConstants.ALERT_FATAL, alert}));

        try (LogCapture log = LogCapture.start(LogCapture.TLS13)) {
            assertThrows(TlsException.class, server::handshakeAsServer);

            List<String> debug = log.messages(Level.FINE);
            assertTrue(has(debug, "Alert received: " + TlsAlerts.forLog(alert)), "приём: " + debug);
            assertTrue(
                    has(
                            debug,
                            "TLS handshake failed: stage=SERVER_WAIT_CLIENT_HELLO,"
                                    + " alert="
                                    + TlsAlerts.forLog(alert)
                                    + ", alert from peer=true"),
                    "отказ со стадией и кодом: " + debug);
            assertFalse(has(debug, "Alert sent"), "на fatal alert пира ответ не отправляется");
            assertEquals(List.of(), log.messagesAtOrAbove(Level.WARNING), "WARNING нет");
        }
    }

    @Test
    @DisplayName("Нарушение формата от пира: на DEBUG отправленный alert и код в записи отказа")
    void localViolationLogsSentAlert() throws Exception {
        var transports = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        transports.getServerTransport(), SUITE, leaf.cert, leaf.priv);
        // ClientHello нулевой длины: тело не разбирается
        transports
                .getClientTransport()
                .sendRecord(
                        TlsMessageBuilder.buildPlaintextRecord(
                                TlsConstants.CT_HANDSHAKE,
                                new byte[] {TlsConstants.HT_CLIENT_HELLO, 0, 0, 0}));

        try (LogCapture log = LogCapture.start(LogCapture.TLS13)) {
            TlsException error = assertThrows(TlsException.class, server::handshakeAsServer);

            int code = error.getAlertCode() & 0xFF;
            List<String> debug = log.messages(Level.FINE);
            assertFalse(error.isFromPeer(), "нарушение найдено локально");
            assertTrue(
                    has(debug, "Alert sent: fatal, " + TlsAlerts.forLog(code)),
                    "отправка: " + debug);
            assertTrue(
                    has(
                            debug,
                            "stage=SERVER_WAIT_CLIENT_HELLO, alert="
                                    + TlsAlerts.forLog(code)
                                    + ", alert from peer=false"),
                    "отказ со стадией и кодом: " + debug);
            assertEquals(List.of(), log.messagesAtOrAbove(Level.WARNING), "WARNING нет");
        }
    }
}
