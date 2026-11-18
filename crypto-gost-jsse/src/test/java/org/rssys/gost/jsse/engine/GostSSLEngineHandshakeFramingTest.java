package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.feedRunningTasks;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.wrapPending;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.testkit.HandshakeFlightShaper;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageBuilderTestAccess;
import org.rssys.gost.tls13.message.TlsMessageParser;

/**
 * Разбор записей рукопожатия в {@link GostSSLEngine}: несколько сообщений в одной записи, сообщение
 * на многих записях по одному байту, граница записи при смене ключа чтения (RFC 8446 §5.1),
 * пустые записи и пределы размера сообщения по заголовку.
 *
 * <p>Наш движок кладёт каждое сообщение в отдельную запись, поэтому нужную нарезку полёта
 * готовит {@link HandshakeFlightShaper}.
 */
@DisplayName("GostSSLEngine: нарезка сообщений рукопожатия по записям")
class GostSSLEngineHandshakeFramingTest {

    private static final byte[] PAYLOAD = "GET /framing HTTP/1.1".getBytes();
    private static final int BIG_BUFFER =
            64 * (TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
    private static final int ONE_BYTE = 1;
    private static final byte[] NOTHING = new byte[0];

    /** Целое сообщение KeyUpdate (update_not_requested): лишний хвост за сообщением смены ключа. */
    private static final byte[] KEY_UPDATE_FRAME = {TlsConstants.HT_KEY_UPDATE, 0, 0, 1, 0};

    /** Длина тела сверх общего предела сообщения (кроме Certificate). */
    private static final int OVER_NON_CERTIFICATE_LIMIT =
            TlsConstants.MAX_HANDSHAKE_NON_CERTIFICATE_MESSAGE_SIZE
                    - TlsConstants.HANDSHAKE_HEADER_SIZE
                    + 1;

    private static final int[] ALL_GROUPS = {
        TlsConstants.GRP_GC256A,
        TlsConstants.GRP_GC256B,
        TlsConstants.GRP_GC256C,
        TlsConstants.GRP_GC256D,
        TlsConstants.GRP_GC512A,
        TlsConstants.GRP_GC512B,
        TlsConstants.GRP_GC512C
    };
    private static final String UNEXPECTED_MESSAGE_ALERT = "Received fatal alert 10 from peer";

    private static PkixCertTestHelper.CertBundle rootCa;
    private static PkixCertTestHelper.CertBundle foreignRoot;
    private static GostX509KeyManager serverKm;
    private static GostX509KeyManager clientKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        foreignRoot = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert = leaf(params, new String[] {"localhost"});
        PkixCertTestHelper.CertBundle clientCert = leaf(params, null);
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        clientKm = new GostX509KeyManager();
        clientKm.addKeyEntry(
                "client",
                CertificateBridge.toJca(List.of(clientCert.cert, rootCa.cert)),
                clientCert.priv);
    }

    private static PkixCertTestHelper.CertBundle leaf(ECParameters params, String[] dns)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                rootCa.priv,
                rootCa.cert.getPublicKey(),
                rootCa.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                dns,
                new byte[] {(byte) 0x80},
                null,
                false,
                null);
    }

    private static GostSSLEngine server(
            boolean needClientAuth, PkixCertTestHelper.CertBundle trusted) {
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm,
                        GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.ofCertificate(trusted.cert)),
                        "localhost",
                        0,
                        false);
        server.setNeedClientAuth(needClientAuth);
        return server;
    }

    private static GostSSLEngine client() {
        return GostSSLEngine.createForClient(
                clientKm,
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert)),
                "localhost",
                0,
                null);
    }

    private static ByteBuffer wrapAll(GostSSLEngine engine) throws SSLException {
        ByteBuffer out = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(engine, out);
        out.flip();
        return out;
    }

    /** Клиент отправил ClientHello, сервер принял его и поставил свой полёт в очередь. */
    private static void clientHelloTo(GostSSLEngine client, GostSSLEngine server)
            throws SSLException {
        client.beginHandshake();
        feedRunningTasks(server, wrapAll(client));
    }

    /** Отдаёт полёт стороны пиру целиком; задачи пира выполняются по ходу. */
    private static void deliver(GostSSLEngine from, GostSSLEngine to) throws SSLException {
        ByteBuffer flight = wrapAll(from);
        feedRunningTasks(to, flight);
        assertEquals(0, flight.remaining(), "пир должен разобрать весь полёт");
    }

    /**
     * Подаёт байты и выполняет задачи, затем вызывает {@code unwrap} ещё раз: отказ задачи проверки
     * сертификата по контракту отдаётся приложению следующим вызовом движка.
     */
    private static void feedAndSettle(GostSSLEngine engine, ByteBuffer input) throws SSLException {
        feedRunningTasks(engine, input);
        engine.unwrap(
                ByteBuffer.allocate(0), ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
    }

    /** Рукопожатие завершено с обеих сторон, и данные идут в обе стороны. */
    private static void assertConnectionWorks(GostSSLEngine client, GostSSLEngine server)
            throws SSLException {
        assertEquals(
                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                client.getHandshakeStatus(),
                "клиент завершил рукопожатие");
        assertEquals(
                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                server.getHandshakeStatus(),
                "сервер завершил рукопожатие");
        assertArrayEquals(PAYLOAD, transfer(client, server), "данные клиента дошли");
        assertArrayEquals(PAYLOAD, transfer(server, client), "данные сервера дошли");
    }

    private static byte[] transfer(GostSSLEngine from, GostSSLEngine to) throws SSLException {
        ByteBuffer wire = ByteBuffer.allocate(BIG_BUFFER);
        from.wrap(ByteBuffer.wrap(PAYLOAD), wire);
        wire.flip();
        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        while (wire.hasRemaining()) {
            SSLEngineResult r = to.unwrap(wire, app);
            if (r.bytesConsumed() == 0) {
                break;
            }
        }
        app.flip();
        byte[] received = new byte[app.remaining()];
        app.get(received);
        return received;
    }

    /**
     * Отказ стороны {@code failing}: исключение {@code expected} с сообщением, содержащим
     * {@code reason}, и её alert, дошедший до пира как unexpected_message.
     */
    private static void assertUnexpectedMessage(
            GostSSLEngine failing, GostSSLEngine peer, ByteBuffer input, String reason) {
        SSLException failure =
                assertThrows(
                        SSLProtocolException.class,
                        () -> feedAndSettle(failing, input),
                        "нарушение границы записи даёт unexpected_message");
        assertTrue(
                failure.getMessage().contains(reason), "причина отказа: " + failure.getMessage());
        assertPeerGetsAlert(failing, peer, UNEXPECTED_MESSAGE_ALERT);
    }

    private static void assertPeerGetsAlert(
            GostSSLEngine failing, GostSSLEngine peer, String alert) {
        ByteBuffer alertWire = ByteBuffer.allocate(BIG_BUFFER);
        try {
            failing.wrap(ByteBuffer.allocate(0), alertWire);
        } catch (SSLException ignored) {
            // отказ задачи проверки доставляется и через wrap: alert при этом уже собран
            failing.getHandshakeStatus();
        }
        alertWire.flip();
        assertTrue(alertWire.hasRemaining(), "отказавшая сторона отправляет alert");
        SSLException atPeer =
                assertThrows(
                        SSLException.class,
                        () -> feedRunningTasks(peer, alertWire),
                        "пир получает alert");
        assertTrue(atPeer.getMessage().contains(alert), "код alert у пира: " + atPeer.getMessage());
    }

    private static int countRecords(ByteBuffer wire, byte contentType) {
        int count = 0;
        int position = wire.position();
        while (position + TlsConstants.RECORD_HEADER_SIZE <= wire.limit()) {
            int length = ((wire.get(position + 3) & 0xFF) << 8) | (wire.get(position + 4) & 0xFF);
            if (wire.get(position) == contentType) {
                count++;
            }
            position += TlsConstants.RECORD_HEADER_SIZE + length;
        }
        return count;
    }

    private static ByteBuffer plaintextHandshakeRecord(byte[] fragment) {
        return ByteBuffer.wrap(
                TlsMessageBuilder.buildPlaintextRecord(TlsConstants.CT_HANDSHAKE, fragment));
    }

    private static byte[] header(byte type, int bodyLength) {
        return new byte[] {
            type, (byte) (bodyLength >>> 16), (byte) (bodyLength >>> 8), (byte) bodyLength
        };
    }

    // ---------------------------------------------------------------- несколько сообщений

    @Test
    @DisplayName("EE, Certificate, CertificateVerify и Finished сервера в одной записи")
    void serverFlightInOneRecord() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        clientHelloTo(client, server);
        // ServerHello остаётся открытой отдельной записью, остальное склеивается
        HandshakeFlightShaper.reshape(server, 1, HandshakeFlightShaper.ONE_RECORD, NOTHING);

        ByteBuffer flight = wrapAll(server);
        assertEquals(
                1,
                countRecords(flight, TlsConstants.CT_APPLICATION_DATA),
                "зашифрованная часть полёта сервера — одна запись");
        feedRunningTasks(client, flight);
        assertEquals(
                SSLEngineResult.HandshakeStatus.NEED_WRAP,
                client.getHandshakeStatus(),
                "после задачи проверки клиент разобрал Finished и готов ответить");
        deliver(client, server);
        assertConnectionWorks(client, server);
    }

    @Test
    @DisplayName("Зашифрованный полёт сервера записями по одному байту")
    void serverFlightInOneByteRecords() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        clientHelloTo(client, server);
        HandshakeFlightShaper.reshape(server, 1, ONE_BYTE, NOTHING);

        deliver(server, client);
        deliver(client, server);
        assertConnectionWorks(client, server);
    }

    @Test
    @DisplayName("mTLS: Certificate, CertificateVerify и Finished клиента в одной записи")
    void clientFlightInOneRecord() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(true, rootCa);
        clientHelloTo(client, server);
        deliver(server, client);
        HandshakeFlightShaper.reshape(client, 0, HandshakeFlightShaper.ONE_RECORD, NOTHING);

        ByteBuffer flight = wrapAll(client);
        assertEquals(
                1,
                countRecords(flight, TlsConstants.CT_APPLICATION_DATA),
                "полёт клиента — одна запись");
        feedRunningTasks(server, flight);
        assertConnectionWorks(client, server);
    }

    @Test
    @DisplayName("mTLS: полёт клиента записями по одному байту")
    void clientFlightInOneByteRecords() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(true, rootCa);
        clientHelloTo(client, server);
        deliver(server, client);
        HandshakeFlightShaper.reshape(client, 0, ONE_BYTE, NOTHING);

        deliver(client, server);
        assertConnectionWorks(client, server);
    }

    @Test
    @DisplayName("mTLS: склеенный полёт с недоверенным сертификатом клиента отвергается задачей")
    void clientFlightInOneRecordWithUntrustedCertificate() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(true, foreignRoot);
        clientHelloTo(client, server);
        deliver(server, client);
        HandshakeFlightShaper.reshape(client, 0, HandshakeFlightShaper.ONE_RECORD, NOTHING);

        ByteBuffer flight = wrapAll(client);
        assertThrows(
                SSLHandshakeException.class,
                () -> feedAndSettle(server, flight),
                "сертификат вне доверия прерывает рукопожатие");
    }

    // ---------------------------------------------------------------- граница записи

    @Test
    @DisplayName("ClientHello и следующее сообщение в одной записи: unexpected_message")
    void clientHelloWithTail() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        client.beginHandshake();
        HandshakeFlightShaper.reshape(
                client, 0, HandshakeFlightShaper.ONE_RECORD, KEY_UPDATE_FRAME);

        assertUnexpectedMessage(server, client, wrapAll(client), "record boundary");
    }

    @Test
    @DisplayName("Второй ClientHello после HRR и следующее сообщение в одной записи")
    void secondClientHelloWithTail() throws Exception {
        GostSSLEngine server = server(false, rootCa);
        // Первый ClientHello без key_share: сервер отвечает HelloRetryRequest и ключи не меняет
        feedRunningTasks(
                server, ByteBuffer.wrap(clientHelloRecord(new LinkedHashMap<>(), NOTHING)));
        ByteBuffer hrrWire = wrapAll(server);
        byte[] hrrFrame = new byte[hrrWire.getShort(hrrWire.position() + 3) & 0xFFFF];
        hrrWire.position(hrrWire.position() + TlsConstants.RECORD_HEADER_SIZE);
        hrrWire.get(hrrFrame);
        int group =
                TlsMessageParser.parseServerHello(
                                TlsHandshakeMessage.decode(hrrFrame).getBody(),
                                Set.of(
                                        TlsConstants.EXT_SUPPORTED_VERSIONS,
                                        TlsConstants.EXT_KEY_SHARE))
                        .requestedGroup;
        Map<Integer, byte[]> share = new LinkedHashMap<>();
        share.put(
                group,
                TlsEncoding.encodePoint(
                        KeyGenerator.generateKeyPair(TlsCiphersuite.namedGroupToParams(group))
                                .getPublic()));

        // После второго ClientHello сервер переходит на ключи рукопожатия: хвоста быть не должно
        byte[] secondHello = clientHelloFrame(share, NOTHING);
        byte[] glued = new byte[secondHello.length + KEY_UPDATE_FRAME.length];
        System.arraycopy(secondHello, 0, glued, 0, secondHello.length);
        System.arraycopy(KEY_UPDATE_FRAME, 0, glued, secondHello.length, KEY_UPDATE_FRAME.length);
        SSLException failure =
                assertThrows(
                        SSLProtocolException.class,
                        () -> feedRunningTasks(server, plaintextHandshakeRecord(glued)),
                        "хвост после второго ClientHello даёт unexpected_message");
        assertTrue(failure.getMessage().contains("record boundary"), failure.getMessage());
    }

    @Test
    @DisplayName("ServerHello и EncryptedExtensions в одной открытой записи: unexpected_message")
    void serverHelloWithTail() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        clientHelloTo(client, server);
        HandshakeFlightShaper.reshape(server, 0, HandshakeFlightShaper.ONE_RECORD, NOTHING);

        assertUnexpectedMessage(client, server, wrapAll(server), "record boundary");
    }

    @Test
    @DisplayName("Finished сервера и лишнее сообщение в одной записи: отказ в задаче проверки")
    void serverFinishedWithTail() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        clientHelloTo(client, server);
        HandshakeFlightShaper.reshape(
                server, 1, HandshakeFlightShaper.ONE_RECORD, KEY_UPDATE_FRAME);

        // Хвост разбирается в задаче проверки сертификата: отказ приходит оттуда же
        assertUnexpectedMessage(client, server, wrapAll(server), "record boundary");
    }

    @Test
    @DisplayName("Finished клиента и лишнее сообщение в одной записи: unexpected_message")
    void clientFinishedWithTail() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        clientHelloTo(client, server);
        deliver(server, client);
        HandshakeFlightShaper.reshape(
                client, 0, HandshakeFlightShaper.ONE_RECORD, KEY_UPDATE_FRAME);

        SSLException failure =
                assertThrows(
                        SSLProtocolException.class,
                        () -> feedRunningTasks(server, wrapAll(client)),
                        "хвост после Finished клиента даёт unexpected_message");
        assertTrue(failure.getMessage().contains("record boundary"), failure.getMessage());
    }

    @Test
    @DisplayName("KeyUpdate и следующее сообщение в одной записи: unexpected_message")
    void keyUpdateWithTail() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        clientHelloTo(client, server);
        deliver(server, client);
        deliver(client, server);
        // Тикеты сервера доходят до клиента, чтобы очереди обеих сторон были пусты
        deliver(server, client);

        client.initiateKeyUpdate(false);
        HandshakeFlightShaper.pullFromHandshakeEngine(client);
        HandshakeFlightShaper.reshape(
                client, 0, HandshakeFlightShaper.ONE_RECORD, KEY_UPDATE_FRAME);
        ByteBuffer wire = ByteBuffer.allocate(BIG_BUFFER);
        client.wrap(ByteBuffer.allocate(0), wire);
        wire.flip();

        SSLException failure =
                assertThrows(
                        SSLProtocolException.class,
                        () -> feedRunningTasks(server, wire),
                        "хвост после KeyUpdate даёт unexpected_message");
        assertTrue(failure.getMessage().contains("record boundary"), failure.getMessage());
    }

    @Test
    @DisplayName("Два initiateKeyUpdate до wrap: одна запись KeyUpdate, запрос ответа сохранён")
    void secondKeyUpdateBeforeWrapIsMerged() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        clientHelloTo(client, server);
        deliver(server, client);
        deliver(client, server);
        deliver(server, client);

        client.initiateKeyUpdate(false);
        client.initiateKeyUpdate(true);
        ByteBuffer wire = ByteBuffer.allocate(BIG_BUFFER);
        client.wrap(ByteBuffer.allocate(0), wire);
        client.wrap(ByteBuffer.allocate(0), wire);
        wire.flip();
        assertEquals(
                1,
                countRecords(wire, TlsConstants.CT_APPLICATION_DATA),
                "второй вызов объединён с первым: одно обновление");
        feedRunningTasks(server, wire);

        ByteBuffer response = ByteBuffer.allocate(BIG_BUFFER);
        server.wrap(ByteBuffer.allocate(0), response);
        response.flip();
        assertTrue(response.hasRemaining(), "сервер отвечает своим KeyUpdate: запрос не потерян");
        feedRunningTasks(client, response);
        assertConnectionWorks(client, server);
    }

    // ---------------------------------------------------------------- пустые записи

    @Test
    @DisplayName("Пустая открытая запись рукопожатия: unexpected_message")
    void emptyPlaintextHandshakeRecord() {
        GostSSLEngine server = server(false, rootCa);
        SSLException failure =
                assertThrows(
                        SSLProtocolException.class,
                        () -> feedRunningTasks(server, plaintextHandshakeRecord(NOTHING)),
                        "пустая запись рукопожатия недопустима (RFC 8446 §5.1)");
        assertTrue(failure.getMessage().contains("Empty handshake record"), failure.getMessage());
    }

    @Test
    @DisplayName("Пустая зашифрованная запись рукопожатия: unexpected_message")
    void emptyEncryptedHandshakeRecord() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        clientHelloTo(client, server);
        deliver(server, client);
        // Перед Finished клиента — зашифрованная запись рукопожатия нулевой длины
        HandshakeFlightShaper.prependRaw(client, NOTHING);

        SSLException failure =
                assertThrows(
                        SSLProtocolException.class,
                        () -> feedRunningTasks(server, wrapAll(client)),
                        "пустая зашифрованная запись рукопожатия недопустима");
        assertTrue(failure.getMessage().contains("Empty handshake record"), failure.getMessage());
    }

    // ---------------------------------------------------------------- пределы

    @Test
    @DisplayName("ClientHello длиннее предела отвергается по заголовку, до прихода тела")
    void oversizedClientHelloRejectedByHeader() {
        GostSSLEngine server = server(false, rootCa);
        SSLException failure =
                assertThrows(
                        SSLHandshakeException.class,
                        () ->
                                feedRunningTasks(
                                        server,
                                        plaintextHandshakeRecord(
                                                header(
                                                        TlsConstants.HT_CLIENT_HELLO,
                                                        OVER_NON_CERTIFICATE_LIMIT))),
                        "заявленная длина больше предела даёт decode_error сразу");
        assertTrue(failure.getMessage().contains("too large"), failure.getMessage());
    }

    @Test
    @DisplayName("Та же длина у Certificate не отвергается по заголовку: ему разрешено больше")
    void certificateHeaderWithSameLengthWaitsForBody() throws Exception {
        GostSSLEngine server = server(false, rootCa);
        SSLEngineResult r =
                server.unwrap(
                        plaintextHandshakeRecord(
                                header(TlsConstants.HT_CERTIFICATE, OVER_NON_CERTIFICATE_LIMIT)),
                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
        assertEquals(SSLEngineResult.Status.OK, r.getStatus(), "сборщик ждёт тело Certificate");
    }

    @Test
    @DisplayName("После рукопожатия NewSessionTicket длиннее служебного предела отвергается")
    void oversizedPostHandshakeMessageRejectedByHeader() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        clientHelloTo(client, server);
        deliver(server, client);
        deliver(client, server);
        deliver(server, client);

        // Длина меньше предела сообщения рукопожатия, но больше служебного предела
        int bodyLength =
                TlsConstants.MAX_POST_HANDSHAKE_MESSAGE_SIZE
                        - TlsConstants.HANDSHAKE_HEADER_SIZE
                        + 1;
        HandshakeFlightShaper.appendRaw(
                server, header(TlsConstants.HT_NEW_SESSION_TICKET, bodyLength));
        ByteBuffer wire = ByteBuffer.allocate(BIG_BUFFER);
        server.wrap(ByteBuffer.allocate(0), wire);
        wire.flip();

        SSLException failure =
                assertThrows(
                        SSLHandshakeException.class,
                        () -> feedRunningTasks(client, wire),
                        "служебное сообщение больше предела даёт decode_error по заголовку");
        assertTrue(failure.getMessage().contains("too large"), failure.getMessage());
    }

    @Test
    @DisplayName(
            "После рукопожатия больше 8 служебных сообщений в одной записи: unexpected_message")
    void tooManyPostHandshakeMessagesInOneRecord() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(false, rootCa);
        clientHelloTo(client, server);
        deliver(server, client);
        deliver(client, server);
        deliver(server, client);

        // Девять тикетов одной записью: каждый законен, но поток служебных сообщений ограничен
        // тем же бюджетом, что у TlsSession (MAX_POST_HANDSHAKE)
        java.io.ByteArrayOutputStream tickets = new java.io.ByteArrayOutputStream();
        for (int i = 0; i <= TlsConstants.MAX_POST_HANDSHAKE; i++) {
            byte[] body =
                    TlsMessageBuilder.buildNewSessionTicket(
                            3600, i, new byte[] {(byte) i}, new byte[] {1, 2, 3});
            tickets.writeBytes(
                    new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, body).encode());
        }
        HandshakeFlightShaper.appendRaw(server, tickets.toByteArray());
        ByteBuffer wire = ByteBuffer.allocate(BIG_BUFFER);
        server.wrap(ByteBuffer.allocate(0), wire);
        wire.flip();

        SSLException failure =
                assertThrows(
                        SSLProtocolException.class,
                        () -> feedRunningTasks(client, wire),
                        "поток служебных сообщений в одной записи ограничен");
        assertTrue(failure.getMessage().contains("post-handshake"), failure.getMessage());
    }

    // ---------------------------------------------------------------- построение ClientHello

    private static byte[] clientHelloFrame(Map<Integer, byte[]> keyShares, byte[] sessionId)
            throws Exception {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsMessageBuilder builder =
                new TlsMessageBuilder(
                        cs,
                        List.of(cs.getId()),
                        TlsConstants.GRP_GC256A,
                        TlsConstants.SIG_GOST_TC26_A_256,
                        null,
                        null,
                        32);
        TlsMessageBuilderTestAccess.setSupportedGroups(builder, ALL_GROUPS);
        byte[] body =
                TlsMessageBuilderTestAccess.withLegacySessionId(
                        builder.buildClientHello(keyShares, "localhost"), sessionId);
        return new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, body).encode();
    }

    private static byte[] clientHelloRecord(Map<Integer, byte[]> keyShares, byte[] sessionId)
            throws Exception {
        return TlsMessageBuilder.buildPlaintextRecord(
                TlsConstants.CT_HANDSHAKE, clientHelloFrame(keyShares, sessionId));
    }
}
