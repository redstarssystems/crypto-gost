package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;

/**
 * Клиент проверяет служебные поля ServerHello и HRR (RFC 8446 §4.1.3): эхо идентификатора сессии
 * должно совпасть с отправленным, сжатие равно нулю. Кадры собирает тот же сборщик, что и у нашего
 * сервера: настоящий сервер всегда присылает пустое эхо, поэтому нарушение недостижимо через него.
 */
@DisplayName("TlsHandshakeEngine: эхо legacy_session_id и сжатие в ServerHello")
class TlsHandshakeEngineServerHelloLegacyFieldsTest {

    private static final ECParameters EC_PARAMS = ECParameters.tc26a256();
    private static final int GROUP = TlsConstants.GRP_GC256A;
    private static final int OTHER_GROUP = TlsConstants.GRP_GC256B;
    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;
    private static final int FRAME_HEADER = 4;
    private static final String ECHO_FIELD = "legacy_session_id_echo";

    private static PkixCertTestHelper.CertBundle serverCert;
    private static byte[] serverPoint;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = PkixCertTestHelper.createCertWithKey(EC_PARAMS);
        serverPoint = TlsEncoding.encodePoint(KeyGenerator.generateKeyPair(EC_PARAMS).getPublic());
    }

    private static TlsCiphersuite suite() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    private static TlsMessageBuilder builder(boolean server) {
        return new TlsMessageBuilder(
                suite(),
                List.of(suite().getId()),
                GROUP,
                SIG_SCHEME,
                server ? serverCert.priv : null,
                server ? List.of(serverCert.cert) : null,
                HASH_LEN);
    }

    private static TlsHandshakeEngine engine(TlsHandshakeEngine.Role role) {
        return new TlsHandshakeEngine(
                role,
                suite(),
                builder(role == TlsHandshakeEngine.Role.SERVER),
                EC_PARAMS,
                GROUP,
                SIG_SCHEME,
                HASH_LEN,
                null,
                false,
                null);
    }

    private static byte[] sessionId() {
        byte[] id = new byte[TlsConstants.SESSION_ID_LENGTH];
        Arrays.fill(id, (byte) 0x5A);
        return id;
    }

    private static byte[] frame(byte type, byte[] body) {
        return new TlsHandshakeMessage(type, body).encode();
    }

    /** ServerHello с эхо указанного идентификатора (пусто: как у штатного сервера). */
    private static byte[] serverHello(byte[] echo) {
        TlsMessageBuilder server = builder(true);
        server.setClientSessionId(echo);
        return frame(TlsConstants.HT_SERVER_HELLO, server.buildServerHello(serverPoint));
    }

    /** ServerHello после HRR: key_share в запрошенной группе, как у корректного сервера. */
    private static byte[] secondServerHello(byte[] echo) {
        TlsMessageBuilder server = builder(true);
        server.setClientSessionId(echo);
        return frame(
                TlsConstants.HT_SERVER_HELLO,
                server.buildServerHello(
                        serverPoint, TlsMessageBuilder.NO_SELECTED_PSK, OTHER_GROUP));
    }

    private static byte[] helloRetryRequest(byte[] echo) {
        TlsMessageBuilder server = builder(true);
        server.setClientSessionId(echo);
        return frame(
                TlsConstants.HT_SERVER_HELLO,
                server.buildHelloRetryRequest(OTHER_GROUP, suite().getId()));
    }

    private static TlsHandshakeEngine startedClient() throws Exception {
        TlsHandshakeEngine client = engine(TlsHandshakeEngine.Role.CLIENT);
        client.start();
        return client;
    }

    /**
     * Клиент отвергает кадр кодом illegal_parameter именно из-за указанного поля: тот же код дают
     * и другие проверки (например, группа key_share), и без сверки текста тест не отличил бы их.
     */
    private static void assertIllegalParameter(
            TlsHandshakeEngine client, byte[] frame, String field) {
        TlsException e = assertThrows(TlsException.class, () -> client.receive(frame));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                e.getAlertCode(),
                "Код alert: " + e.getMessage());
        assertTrue(e.getMessage().contains(field), "Причина отказа: " + e.getMessage());
        assertEquals(TlsHandshakeEngine.State.ERROR, client.getState());
    }

    @Test
    @DisplayName("ClientHello несёт ровно тот идентификатор, с которым сравнивается эхо")
    void clientHelloCarriesSentSessionId() throws Exception {
        TlsMessageBuilder builder = builder(false);

        byte[] sent = builder.getSentLegacySessionId();
        byte[] body = builder.buildClientHello(serverPoint);

        // legacy_version(2) || random(32) || длина || идентификатор
        int offset = 2 + TlsConstants.RANDOM_LENGTH;
        assertEquals(sent.length, body[offset] & 0xFF, "Длина идентификатора в ClientHello");
        assertArrayEquals(sent, Arrays.copyOfRange(body, offset + 1, offset + 1 + sent.length));
    }

    @Test
    @DisplayName("ServerHello с непустым эхо при пустом отправленном: illegal_parameter")
    void nonEmptyEchoInServerHello() throws Exception {
        assertIllegalParameter(startedClient(), serverHello(sessionId()), ECHO_FIELD);
    }

    @Test
    @DisplayName("HRR с непустым эхо при пустом отправленном: illegal_parameter")
    void nonEmptyEchoInHelloRetryRequest() throws Exception {
        assertIllegalParameter(startedClient(), helloRetryRequest(sessionId()), ECHO_FIELD);
    }

    @Test
    @DisplayName("второй ServerHello с чужим эхо после корректного HRR: illegal_parameter")
    void foreignEchoInSecondServerHello() throws Exception {
        TlsHandshakeEngine client = startedClient();
        assertDoesNotThrow(
                () -> client.receive(helloRetryRequest(new byte[0])),
                "HRR с пустым эхо принимается");

        assertIllegalParameter(client, secondServerHello(sessionId()), ECHO_FIELD);
    }

    @Test
    @DisplayName("ServerHello со сжатием не 0: illegal_parameter")
    void nonNullCompression() throws Exception {
        byte[] frame = serverHello(new byte[0]);
        // handshake-заголовок || legacy_version(2) || random(32) || sid_len(1) || cipher_suite(2)
        frame[FRAME_HEADER + 2 + TlsConstants.RANDOM_LENGTH + 1 + 2] = 1;

        assertIllegalParameter(startedClient(), frame, "legacy_compression_method");
    }
}
