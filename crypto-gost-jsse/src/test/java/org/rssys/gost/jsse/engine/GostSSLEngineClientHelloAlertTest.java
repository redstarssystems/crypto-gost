package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.message.TlsMessageBuilder;

/**
 * Код alert, который отдаёт серверный {@link GostSSLEngine} на отвергнутый ClientHello.
 *
 * <p>Движок рукопожатия называет причину точным кодом (RFC 8446 §6.2): версия, имя, формат. Этот
 * код должен дойти до пира в открытой записи alert и до приложения в типе исключения. Раньше
 * {@code GostSSLEngine} заменял любой код на {@code handshake_failure}.
 */
@DisplayName("GostSSLEngine: код alert на отвергнутый ClientHello")
class GostSSLEngineClientHelloAlertTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final int GROUP = TlsConstants.GRP_GC256A;
    private static final int BIG_BUFFER =
            TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM;
    // supported_versions клиента: тип 43, длина 3, список из одной версии 0x0304
    private static final byte[] SUPPORTED_VERSIONS_EXTENSION = {
        0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04
    };
    private static final byte UNKNOWN_EXTENSION_TYPE_BYTE = 0x7A;

    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
    }

    /** Открытая запись с честным ClientHello нашего клиента. */
    private static byte[] clientHelloRecord(String serverName) throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        SUITE,
                        new TlsMessageBuilder(
                                SUITE,
                                List.of(SUITE.getId()),
                                GROUP,
                                TlsConstants.SIG_GOST_TC26_A_256,
                                null,
                                null,
                                SUITE.getHashLen()),
                        TlsCiphersuite.namedGroupToParams(GROUP),
                        GROUP,
                        TlsConstants.SIG_GOST_TC26_A_256,
                        SUITE.getHashLen(),
                        null,
                        false,
                        null);
        client.setServerHostname(serverName);
        return TlsMessageBuilder.buildPlaintextRecord(TlsConstants.CT_HANDSHAKE, client.start());
    }

    private static int indexOf(byte[] data, byte[] pattern) {
        for (int i = 0; i + pattern.length <= data.length; i++) {
            if (Arrays.equals(data, i, i + pattern.length, pattern, 0, pattern.length)) {
                return i;
            }
        }
        throw new AssertionError("образец не найден в ClientHello");
    }

    private static GostSSLEngine newServer() {
        return new GostSSLEngine(
                serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
    }

    /** Отвергает запись и возвращает исключение приложению; alert забирается отдельно. */
    private static SSLException rejectedBy(GostSSLEngine server, byte[] record) {
        return assertThrows(
                SSLException.class,
                () ->
                        server.unwrap(
                                ByteBuffer.wrap(record),
                                ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH)),
                "ClientHello должен быть отвергнут");
    }

    /** Забирает у движка fatal alert, который он отдаёт пиру, и возвращает его описание. */
    private static byte alertDescription(GostSSLEngine server) throws Exception {
        ByteBuffer out = ByteBuffer.allocate(BIG_BUFFER);
        SSLEngineResult result = server.wrap(ByteBuffer.allocate(0), out);
        out.flip();
        assertTrue(out.remaining() > 0, "движок обязан отдать alert пиру: " + result);
        byte[] record = new byte[out.remaining()];
        out.get(record);
        // Открытая запись alert: заголовок (5), уровень (1), описание (1). Ключей записи ещё нет
        assertEquals(TlsConstants.CT_ALERT, record[0], "ожидалась открытая запись alert");
        assertEquals(2, record[TlsConstants.RECORD_HEADER_SIZE], "alert должен быть fatal");
        return record[TlsConstants.RECORD_HEADER_SIZE + 1];
    }

    @Test
    @DisplayName("ClientHello без supported_versions: пир получает protocol_version")
    void clientHelloWithoutSupportedVersionsGetsProtocolVersion() throws Exception {
        byte[] record = clientHelloRecord("a.example");
        // Тип расширения заменяется неизвестным: длина и структура остаются прежними
        record[indexOf(record, SUPPORTED_VERSIONS_EXTENSION)] = UNKNOWN_EXTENSION_TYPE_BYTE;
        GostSSLEngine server = newServer();

        SSLException ex = rejectedBy(server, record);

        assertInstanceOf(
                SSLHandshakeException.class, ex, "protocol_version даёт исключение рукопожатия");
        assertEquals(TlsConstants.ALERT_PROTOCOL_VERSION, alertDescription(server));
    }

    @Test
    @DisplayName("ClientHello с NUL в имени SNI: пир получает unrecognized_name, имя не утекает")
    void clientHelloWithNulInServerNameGetsUnrecognizedName() throws Exception {
        byte[] record = clientHelloRecord("a.example");
        // Точка заменяется нулевым байтом: длина имени и список остаются согласованными
        byte[] name = "a.example".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        record[indexOf(record, name) + 1] = 0x00;
        GostSSLEngine server = newServer();

        SSLException ex = rejectedBy(server, record);

        assertFalse(
                String.valueOf(ex.getMessage()).contains("example"),
                "имя приходит от пира и в сообщение исключения не входит: " + ex.getMessage());
        assertEquals(TlsConstants.ALERT_UNRECOGNIZED_NAME, alertDescription(server));
    }

    @Test
    @DisplayName(
            "Отказ на ClientHello: в журнал идут тип исключения и код alert, текст от пира нет")
    void rejectedClientHelloIsLoggedWithoutPeerText() throws Exception {
        byte[] record = clientHelloRecord("a.example");
        byte[] name = "a.example".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        record[indexOf(record, name) + 1] = 0x00;
        GostSSLEngine server = newServer();

        List<String> all;
        List<String> engineRecords;
        try (LogCapture log = LogCapture.start(LogCapture.JSSE)) {
            rejectedBy(server, record);
            all = log.allMessages();
            engineRecords = log.messages(Level.FINE, "GostSSLEngine");
        }

        assertTrue(
                engineRecords.stream()
                        .anyMatch(
                                m ->
                                        m.startsWith("[conn#")
                                                && m.contains(
                                                        "Handshake error: stage="
                                                                + "SERVER_WAIT_CLIENT_HELLO")
                                                && m.contains("alert=unrecognized_name (112),")
                                                && m.endsWith("TlsException")),
                "запись об отказе с меткой, стадией и именем alert: " + engineRecords);
        assertTrue(
                all.stream().noneMatch(m -> m.contains("example")),
                "имя от пира в журнал не попадает: " + all);
    }
}
