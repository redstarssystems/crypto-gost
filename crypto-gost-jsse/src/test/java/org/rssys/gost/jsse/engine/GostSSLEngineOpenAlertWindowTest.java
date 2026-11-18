package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.runTasks;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Открытый alert в окне рукопожатия: после ClientHello (сервер) или ServerHello (клиент) ключ
 * чтения рукопожатия уже включён, а пир, ещё не включивший ключ записи, вправе прислать alert
 * открытой записью (RFC 8446 приложение A.1). Окно закрывается первой успешно расшифрованной
 * записью пира и концом рукопожатия.
 */
@DisplayName("GostSSLEngine: открытый alert в окне рукопожатия")
class GostSSLEngineOpenAlertWindowTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final int HEADER = TlsConstants.RECORD_HEADER_SIZE;
    private static final byte ALERT_BAD_CERTIFICATE = 42;

    private static PkixCertTestHelper.CertBundle root;
    private static PkixCertTestHelper.CertBundle serverLeaf;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        root = PkixCertTestHelper.createRootCA(PARAMS);
        serverLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        PARAMS,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
    }

    private static GostSSLEngine engine(SSLContext context, boolean clientMode) {
        GostSSLEngine engine = (GostSSLEngine) context.createSSLEngine("localhost", 0);
        engine.setUseClientMode(clientMode);
        return engine;
    }

    private static GostSSLEngine newServer() throws Exception {
        return engine(
                GostSsl.builder()
                        .certificate(
                                serverLeaf.cert.getEncoded(),
                                GostDerCodec.encodePrivateKey(serverLeaf.priv))
                        .trustCa(root.cert.getEncoded())
                        .buildServerContext(),
                false);
    }

    private static GostSSLEngine newClient() throws Exception {
        return engine(GostSsl.builder().trustCa(root.cert.getEncoded()).buildClientContext(), true);
    }

    private static ByteBuffer networkBuffer() {
        return ByteBuffer.allocate(
                TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
    }

    private static ByteBuffer plainBuffer() {
        return ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
    }

    /** Всё, что движок готов отдать сейчас, разобранное на записи. */
    private static List<byte[]> drainRecords(GostSSLEngine engine) throws SSLException {
        List<byte[]> records = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
            ByteBuffer network = networkBuffer();
            engine.wrap(ByteBuffer.allocate(0), network);
            network.flip();
            if (!network.hasRemaining()) {
                break;
            }
            while (network.hasRemaining()) {
                int length =
                        HEADER
                                + (((network.get(network.position() + 3) & 0xFF) << 8)
                                        | (network.get(network.position() + 4) & 0xFF));
                byte[] record = new byte[length];
                network.get(record);
                records.add(record);
            }
        }
        return records;
    }

    private static void unwrapRecord(GostSSLEngine engine, byte[] record) throws SSLException {
        SSLEngineResult result = engine.unwrap(ByteBuffer.wrap(record), plainBuffer());
        assertEquals(record.length, result.bytesConsumed(), "Запись должна быть принята целиком");
    }

    /** Сервер, принявший ClientHello: ключ чтения рукопожатия уже включён. */
    private static GostSSLEngine serverAfterClientHello() throws Exception {
        GostSSLEngine client = newClient();
        GostSSLEngine server = newServer();
        client.beginHandshake();
        server.beginHandshake();
        for (byte[] record : drainRecords(client)) {
            unwrapRecord(server, record);
        }
        drainRecords(server);
        return server;
    }

    /** Записи первого пролёта сервера (ServerHello, CCS, зашифрованные), клиент ещё не читал. */
    private record ClientAndFlight(GostSSLEngine client, List<byte[]> flight) {}

    private static ClientAndFlight clientAndServerFlight() throws Exception {
        GostSSLEngine client = newClient();
        GostSSLEngine server = newServer();
        client.beginHandshake();
        server.beginHandshake();
        for (byte[] record : drainRecords(client)) {
            unwrapRecord(server, record);
        }
        return new ClientAndFlight(client, drainRecords(server));
    }

    private static byte[] openAlert(byte level, byte description) {
        return new byte[] {TlsConstants.CT_ALERT, 3, 3, 0, 2, level, description};
    }

    private static byte[] openRecord(byte contentType, int length) {
        byte[] record = new byte[HEADER + length];
        record[0] = contentType;
        record[1] = 3;
        record[2] = 3;
        record[3] = (byte) (length >>> 8);
        record[4] = (byte) length;
        return record;
    }

    // ------------------------------------------------------------------ сервер

    @Test
    @DisplayName("сервер: открытый fatal alert после ClientHello - настоящий код пира")
    void serverSeesPlaintextFatalAlert() throws Exception {
        GostSSLEngine server = serverAfterClientHello();

        SSLException error =
                assertThrows(
                        SSLException.class,
                        () ->
                                server.unwrap(
                                        ByteBuffer.wrap(
                                                openAlert(
                                                        TlsConstants.ALERT_FATAL,
                                                        ALERT_BAD_CERTIFICATE)),
                                        plainBuffer()));

        assertTrue(
                error.getMessage().contains("alert " + ALERT_BAD_CERTIFICATE),
                "Ожидался код 42 из alert пира: " + error.getMessage());
        assertTrue(server.isInboundDone(), "Соединение должно быть закрыто");
    }

    @Test
    @DisplayName("сервер: открытый close_notify после ClientHello - закрытие и ответный alert")
    void serverAnswersPlaintextCloseNotify() throws Exception {
        GostSSLEngine server = serverAfterClientHello();

        SSLEngineResult result =
                server.unwrap(
                        ByteBuffer.wrap(
                                openAlert(TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY)),
                        plainBuffer());

        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        server.closeOutbound();
        ByteBuffer network = networkBuffer();
        server.wrap(ByteBuffer.allocate(0), network);
        network.flip();
        assertTrue(network.hasRemaining(), "Ответный close_notify обязан уйти");
        assertEquals(
                TlsConstants.CT_APPLICATION_DATA,
                network.get(0),
                "Ответ уходит под ключами рукопожатия, а не открытым");
    }

    @Test
    @DisplayName("сервер: открытый alert неверной длины - ошибка формата, не шифротекст")
    void serverValidatesPlaintextAlertLength() throws Exception {
        for (int length : new int[] {0, 1, 3}) {
            GostSSLEngine server = serverAfterClientHello();
            byte[] record = openRecord(TlsConstants.CT_ALERT, length);

            SSLException error =
                    assertThrows(
                            SSLException.class,
                            () -> server.unwrap(ByteBuffer.wrap(record), plainBuffer()));

            assertTrue(
                    error.getMessage().contains("alert record"),
                    "Длина "
                            + length
                            + ": нарушение формата alert, а не шифротекст: "
                            + error.getMessage());
        }
    }

    @Test
    @DisplayName("сервер: открытые handshake и application_data в окне не принимаются")
    void serverRejectsOtherPlaintextTypesInWindow() throws Exception {
        for (byte type : new byte[] {TlsConstants.CT_HANDSHAKE, TlsConstants.CT_APPLICATION_DATA}) {
            GostSSLEngine server = serverAfterClientHello();
            byte[] record = openRecord(type, 40);

            SSLException error =
                    assertThrows(
                            SSLException.class,
                            () -> server.unwrap(ByteBuffer.wrap(record), plainBuffer()));

            assertFalse(
                    error.getMessage().contains("from peer"),
                    "Открытая запись типа " + type + " не alert пира: " + error.getMessage());
            if (type == TlsConstants.CT_HANDSHAKE) {
                assertTrue(
                        error.getMessage().contains("outer record type"),
                        "Неожиданный внешний тип: unexpected_message: " + error.getMessage());
            }
        }
    }

    @Test
    @DisplayName(
            "сервер: alert, разрезанный на порции unwrap, ждёт остаток без изменения состояния")
    void serverWaitsForFragmentedPlaintextAlert() throws Exception {
        GostSSLEngine server = serverAfterClientHello();
        byte[] alert = openAlert(TlsConstants.ALERT_FATAL, ALERT_BAD_CERTIFICATE);

        // внутри заголовка и после заголовка, но до 2 байт тела
        for (int cut : new int[] {3, HEADER, HEADER + 1}) {
            SSLEngineResult result =
                    server.unwrap(
                            ByteBuffer.wrap(java.util.Arrays.copyOf(alert, cut)), plainBuffer());
            assertEquals(
                    SSLEngineResult.Status.BUFFER_UNDERFLOW,
                    result.getStatus(),
                    "Нехватка байт при срезе " + cut);
            assertEquals(0, result.bytesConsumed(), "Ничего не потребляется при срезе " + cut);
            assertFalse(server.isInboundDone(), "Состояние не меняется при срезе " + cut);
        }

        assertThrows(
                SSLException.class, () -> server.unwrap(ByteBuffer.wrap(alert), plainBuffer()));
    }

    /** Подаёт запись движку с выполнением его задач до и после (проверка цепочки пира). */
    private static void feed(GostSSLEngine engine, byte[] record) throws SSLException {
        runTasks(engine);
        unwrapRecord(engine, record);
        runTasks(engine);
    }

    @Test
    @DisplayName(
            "сервер mTLS: после первой расшифрованной записи клиента открытый alert не принимается")
    void serverClosesWindowAfterFirstDecryptedClientRecord() throws Exception {
        GostSSLEngine server =
                engine(
                        GostSsl.builder()
                                .certificate(
                                        serverLeaf.cert.getEncoded(),
                                        GostDerCodec.encodePrivateKey(serverLeaf.priv))
                                .trustCa(root.cert.getEncoded())
                                .needClientAuth(true)
                                .buildServerContext(),
                        false);
        GostSSLEngine client =
                engine(
                        GostSsl.builder()
                                .certificate(
                                        serverLeaf.cert.getEncoded(),
                                        GostDerCodec.encodePrivateKey(serverLeaf.priv))
                                .trustCa(root.cert.getEncoded())
                                .buildClientContext(),
                        true);
        client.beginHandshake();
        server.beginHandshake();
        for (byte[] record : drainRecords(client)) {
            feed(server, record);
        }
        for (byte[] record : drainRecords(server)) {
            feed(client, record);
        }
        // Первая зашифрованная запись клиента (Certificate) доходит до сервера и расшифровывается
        boolean decrypted = false;
        for (byte[] record : drainRecords(client)) {
            feed(server, record);
            if (record[0] == TlsConstants.CT_APPLICATION_DATA) {
                decrypted = true;
                break;
            }
        }
        assertTrue(decrypted, "Сервер должен расшифровать хотя бы одну запись клиента");

        assertUnexpectedOuterType(
                server, openAlert(TlsConstants.ALERT_FATAL, ALERT_BAD_CERTIFICATE));
    }

    // ------------------------------------------------------------------ клиент

    /** Клиент, принявший открытые ServerHello и CCS: ключ чтения рукопожатия уже включён. */
    private static GostSSLEngine clientAfterServerHello() throws Exception {
        ClientAndFlight setup = clientAndServerFlight();
        int plaintextRecords = 0;
        for (byte[] record : setup.flight()) {
            if (record[0] == TlsConstants.CT_APPLICATION_DATA) {
                break;
            }
            unwrapRecord(setup.client(), record);
            plaintextRecords++;
        }
        assertTrue(plaintextRecords >= 1, "Пролёт должен начинаться с открытого ServerHello");
        return setup.client();
    }

    private static void assertUnexpectedOuterType(GostSSLEngine receiver, byte[] record) {
        SSLException error =
                assertThrows(
                        SSLException.class,
                        () -> receiver.unwrap(ByteBuffer.wrap(record), plainBuffer()));
        assertTrue(
                error.getMessage().contains("outer record type"),
                "Ожидался unexpected_message на неожиданный внешний тип: " + error.getMessage());
        assertFalse(error.getMessage().contains("from peer"), error.getMessage());
    }

    @Test
    @DisplayName(
            "клиент: открытый alert сервера после ServerHello не принимается (окно только у сервера)")
    void clientRejectsPlaintextAlertAfterServerHello() throws Exception {
        GostSSLEngine client = clientAfterServerHello();

        assertUnexpectedOuterType(
                client, openAlert(TlsConstants.ALERT_FATAL, TlsConstants.ALERT_HANDSHAKE_FAILURE));
    }

    @Test
    @DisplayName("клиент: открытый close_notify до ServerHello - ответ открытым, ключей записи нет")
    void clientAnswersPlaintextCloseNotifyBeforeKeys() throws Exception {
        GostSSLEngine client = newClient();
        client.beginHandshake();
        drainRecords(client);

        SSLEngineResult result =
                client.unwrap(
                        ByteBuffer.wrap(
                                openAlert(TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY)),
                        plainBuffer());

        assertEquals(SSLEngineResult.Status.CLOSED, result.getStatus());
        client.closeOutbound();
        ByteBuffer network = networkBuffer();
        client.wrap(ByteBuffer.allocate(0), network);
        network.flip();
        assertEquals(HEADER + 2, network.remaining(), "Должен уйти ровно один открытый alert");
        assertEquals(
                TlsConstants.CT_ALERT, network.get(0), "Ключей записи ещё нет: ответ открытый");
    }

    @Test
    @DisplayName("клиент: отказ до ServerHello - alert открытый, после ServerHello зашифрован")
    void clientAlertIsPlaintextBeforeServerHelloAndEncryptedAfter() throws Exception {
        // до ServerHello ключей записи нет: мусорный ServerHello даёт открытый alert
        GostSSLEngine early = newClient();
        early.beginHandshake();
        drainRecords(early);
        byte[] junkHello = openRecord(TlsConstants.CT_HANDSHAKE, 7);
        junkHello[HEADER] = 2;
        junkHello[HEADER + 3] = 3;
        assertThrows(
                SSLException.class, () -> early.unwrap(ByteBuffer.wrap(junkHello), plainBuffer()));
        ByteBuffer earlyNetwork = networkBuffer();
        early.wrap(ByteBuffer.allocate(0), earlyNetwork);
        earlyNetwork.flip();
        assertEquals(HEADER + 2, earlyNetwork.remaining(), "Открытый alert: заголовок и 2 байта");
        assertEquals(TlsConstants.CT_ALERT, earlyNetwork.get(0), "Ключей записи ещё нет");

        // после ServerHello ключ записи рукопожатия включён: alert зашифрован
        GostSSLEngine late = clientAfterServerHello();
        assertThrows(
                SSLException.class,
                () ->
                        late.unwrap(
                                ByteBuffer.wrap(openRecord(TlsConstants.CT_APPLICATION_DATA, 40)),
                                plainBuffer()));
        ByteBuffer lateNetwork = networkBuffer();
        late.wrap(ByteBuffer.allocate(0), lateNetwork);
        lateNetwork.flip();
        assertEquals(
                TlsConstants.CT_APPLICATION_DATA,
                lateNetwork.get(0),
                "После ServerHello alert защищён ключом рукопожатия");
    }

    @Test
    @DisplayName(
            "клиент: отказ внутри обработки ServerHello после вывода ключей - alert зашифрован")
    void clientAlertAfterFailureInsideServerHelloProcessingIsEncrypted() throws Exception {
        ClientAndFlight setup = clientAndServerFlight();
        byte[] serverHello = setup.flight().get(0);
        assertEquals(
                TlsConstants.CT_HANDSHAKE, serverHello[0], "Первая запись пролёта: ServerHello");
        // За ServerHello в той же открытой записи идёт лишнее handshake-сообщение: после вывода
        // ключей обработка продолжается и падает до создания записи под ключом рукопожатия
        byte[] extra = {TlsConstants.HT_ENCRYPTED_EXTENSIONS, 0, 0, 3, 1, 2, 3};
        byte[] glued = java.util.Arrays.copyOf(serverHello, serverHello.length + extra.length);
        System.arraycopy(extra, 0, glued, serverHello.length, extra.length);
        int bodyLength = glued.length - HEADER;
        glued[3] = (byte) (bodyLength >>> 8);
        glued[4] = (byte) bodyLength;

        assertThrows(
                SSLException.class,
                () -> setup.client().unwrap(ByteBuffer.wrap(glued), plainBuffer()));

        ByteBuffer network = networkBuffer();
        setup.client().wrap(ByteBuffer.allocate(0), network);
        network.flip();
        assertTrue(network.hasRemaining(), "Клиент должен отдать alert");
        assertEquals(
                TlsConstants.CT_APPLICATION_DATA,
                network.get(0),
                "Ключ записи уже выработан: alert защищён ключом рукопожатия");
    }

    @Test
    @DisplayName("клиент: открытый alert неверной длины до ServerHello - ошибка формата")
    void clientValidatesPlaintextAlertLengthBeforeKeys() throws Exception {
        for (int length : new int[] {0, 1, 3}) {
            GostSSLEngine client = newClient();
            client.beginHandshake();
            drainRecords(client);
            byte[] record = openRecord(TlsConstants.CT_ALERT, length);

            SSLException error =
                    assertThrows(
                            SSLException.class,
                            () -> client.unwrap(ByteBuffer.wrap(record), plainBuffer()));

            assertTrue(
                    error.getMessage().contains("alert record"),
                    "Длина " + length + ": " + error.getMessage());
        }
    }

    @Test
    @DisplayName("клиент: открытый alert после первой расшифрованной записи - unexpected_message")
    void clientRejectsPlaintextAlertAfterFirstDecryptedRecord() throws Exception {
        ClientAndFlight setup = clientAndServerFlight();
        boolean decrypted = false;
        for (byte[] record : setup.flight()) {
            unwrapRecord(setup.client(), record);
            if (record[0] == TlsConstants.CT_APPLICATION_DATA) {
                decrypted = true;
                break;
            }
        }
        assertTrue(decrypted, "Нужна хотя бы одна расшифрованная запись сервера");

        assertUnexpectedOuterType(
                setup.client(),
                openAlert(TlsConstants.ALERT_FATAL, TlsConstants.ALERT_HANDSHAKE_FAILURE));
    }

    @Test
    @DisplayName("после рукопожатия открытый alert не принимается как alert пира")
    void plaintextAlertAfterHandshakeIsNotAccepted() throws Exception {
        GostSSLEngine client = newClient();
        GostSSLEngine server = newServer();
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());

        assertUnexpectedOuterType(
                server, openAlert(TlsConstants.ALERT_FATAL, ALERT_BAD_CERTIFICATE));
    }
}
