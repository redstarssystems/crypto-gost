package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.runTasks;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLProtocolException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.engine.HandshakeOutput;
import org.rssys.gost.tls13.engine.HandshakeOutputs;
import org.rssys.gost.tls13.engine.TlsHandshakeEngine;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.record.TlsTrafficKeys;

/**
 * {@code application_data} до завершения рукопожатия серверного {@link GostSSLEngine}.
 *
 * <p>Пир, дошедший до {@code ServerHello}, знает handshake-ключи и может зашифровать ими запись
 * {@code application_data}. Данные допустимы только после проверки Finished пира: до этого
 * момента они не должны попадать приложению (RFC 8446 §2, §5.1, alert {@code unexpected_message}).
 */
@DisplayName("GostSSLEngine: application_data до завершения рукопожатия")
class GostSSLEngineEarlyAppDataTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final int GROUP = TlsConstants.GRP_GC256A;
    private static final byte[] SECRET_PAYLOAD = "GET /secret HTTP/1.1".getBytes();
    private static final int BIG_BUFFER =
            TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM;

    private static GostX509KeyManager serverKm;
    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        serverCert =
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

    /**
     * Клиент без аутентификации: честный ClientHello, затем запись {@code application_data} под
     * handshake-ключами, которые клиент получил из ServerHello.
     */
    private static final class RawClient {
        final TlsHandshakeEngine engine =
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
        TlsRecord serverToClient;

        /** Ключи записи рукопожатия клиента: смена ключа в его потоке сразу после ServerHello. */
        TlsTrafficKeys handshakeWriteKeys;

        RawClient() {
            engine.setServerHostname("localhost");
        }

        byte[] clientHelloRecord() throws Exception {
            return TlsMessageBuilder.buildPlaintextRecord(
                    TlsConstants.CT_HANDSHAKE, engine.start());
        }

        /**
         * Принимает ответ сервера на ClientHello. Если сервер ответил HelloRetryRequest, клиент
         * отправляет второй ClientHello через {@code retry}, пока не придёт настоящий ServerHello.
         */
        void acceptServerHello(
                List<byte[]> serverFlight, java.util.function.Function<byte[], List<byte[]>> retry)
                throws Exception {
            List<byte[]> flight = serverFlight;
            for (int attempt = 0; attempt < 2; attempt++) {
                byte[] hello = flight.get(0);
                assertEquals(
                        TlsConstants.CT_HANDSHAKE, hello[0], "первой идёт запись ServerHello/HRR");
                engine.receive(
                        Arrays.copyOfRange(hello, TlsConstants.RECORD_HEADER_SIZE, hello.length));
                if (engine.getReadKeys() != null) {
                    engine.acknowledgeReadKeyChange();
                    // Ключ записи рукопожатия клиента встаёт в поток сразу после ServerHello
                    handshakeWriteKeys = ((HandshakeOutput.WriteKeyChange) engine.poll()).keys();
                    break;
                }
                byte[] secondHello = HandshakeOutputs.nextMessage(engine);
                flight =
                        retry.apply(
                                TlsMessageBuilder.buildPlaintextRecord(
                                        TlsConstants.CT_HANDSHAKE, secondHello));
            }
            TlsTrafficKeys read = engine.getReadKeys();
            serverToClient = new TlsRecord(read.getKey(), read.getIv(), SUITE.getTagLen(), SUITE);
            // Читаем зашифрованное продолжение полёта сервера. Собственный Finished клиент не
            // отправляет: данные пойдут ключом рукопожатия, до Finished
            for (byte[] rec : flight.subList(1, flight.size())) {
                if (rec[0] != TlsConstants.CT_APPLICATION_DATA) {
                    continue;
                }
                byte[] messages = serverToClient.unprotect(rec).getData();
                int pos = 0;
                while (pos + TlsConstants.HANDSHAKE_HEADER_SIZE <= messages.length) {
                    int bodyLen =
                            ((messages[pos + 1] & 0xFF) << 16)
                                    | ((messages[pos + 2] & 0xFF) << 8)
                                    | (messages[pos + 3] & 0xFF);
                    int total = TlsConstants.HANDSHAKE_HEADER_SIZE + bodyLen;
                    engine.receive(Arrays.copyOfRange(messages, pos, pos + total));
                    engine.acknowledgeReadKeyChange();
                    if (engine.needsCertificateValidation()) {
                        engine.acknowledgeCertificateValidation(true);
                    }
                    pos += total;
                }
            }
            assertTrue(handshakeWriteKeys != null, "клиентские handshake-ключи записи получены");
        }

        byte[] appDataRecord(byte[] payload) {
            TlsTrafficKeys write = handshakeWriteKeys;
            return new TlsRecord(write.getKey(), write.getIv(), SUITE.getTagLen(), SUITE)
                    .protect(TlsConstants.CT_APPLICATION_DATA, payload);
        }
    }

    private static GostSSLEngine newServer(boolean needClientAuth) {
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
        server.setNeedClientAuth(needClientAuth);
        return server;
    }

    private static List<byte[]> wrapAll(GostSSLEngine engine) throws Exception {
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            if (engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                break;
            }
            ByteBuffer dst = ByteBuffer.allocate(BIG_BUFFER);
            engine.wrap(ByteBuffer.allocate(0), dst);
            dst.flip();
            while (dst.remaining() >= TlsConstants.RECORD_HEADER_SIZE) {
                int len =
                        ((dst.get(dst.position() + 3) & 0xFF) << 8)
                                | (dst.get(dst.position() + 4) & 0xFF);
                byte[] rec = new byte[TlsConstants.RECORD_HEADER_SIZE + len];
                dst.get(rec);
                out.add(rec);
            }
        }
        return out;
    }

    /** Сервер, прошедший ClientHello -> ServerHello, и клиент с handshake-ключами. */
    private static Object[] serverAndRawClient(boolean needClientAuth) throws Exception {
        RawClient client = new RawClient();
        GostSSLEngine server = newServer(needClientAuth);
        SSLEngineResult r =
                server.unwrap(
                        ByteBuffer.wrap(client.clientHelloRecord()),
                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
        assertEquals(SSLEngineResult.Status.OK, r.getStatus(), "ClientHello принят");
        runTasks(server);
        List<byte[]> flight = wrapAll(server);
        client.acceptServerHello(
                flight,
                secondHello -> {
                    try {
                        server.unwrap(
                                ByteBuffer.wrap(secondHello),
                                ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
                        runTasks(server);
                        return wrapAll(server);
                    } catch (Exception e) {
                        throw new AssertionError("второй ClientHello не принят", e);
                    }
                });
        return new Object[] {server, client};
    }

    private static void assertEarlyAppDataRejected(boolean needClientAuth) throws Exception {
        assertEarlyAppDataRejected(needClientAuth, TlsConstants.MAX_PLAINTEXT_LENGTH);
    }

    private static void assertEarlyAppDataRejected(boolean needClientAuth, int dstSize)
            throws Exception {
        Object[] pair = serverAndRawClient(needClientAuth);
        GostSSLEngine server = (GostSSLEngine) pair[0];
        RawClient client = (RawClient) pair[1];

        ByteBuffer dst = ByteBuffer.allocate(dstSize);
        byte[] record = client.appDataRecord(SECRET_PAYLOAD);
        SSLException ex =
                assertThrows(
                        SSLProtocolException.class,
                        () -> server.unwrap(ByteBuffer.wrap(record), dst),
                        "application_data до Finished клиента должна приводить к фатальной ошибке");

        assertEquals(0, dst.position(), "данные не должны попасть в буфер приложения");
        // Сообщение отличает нашу проверку от decrypt_error и ошибки аутентификации клиента
        assertTrue(
                ex.getMessage().contains("before handshake completion"),
                "ожидался отказ unexpected_message по состоянию рукопожатия: " + ex.getMessage());
    }

    @Test
    @DisplayName("Сервер без проверки клиента: application_data до Finished отвергается")
    void serverRejectsEarlyAppData() throws Exception {
        assertEarlyAppDataRejected(false);
    }

    @Test
    @DisplayName("Сервер с needClientAuth: application_data до Certificate клиента отвергается")
    void serverRejectsEarlyAppDataWithClientAuth() throws Exception {
        assertEarlyAppDataRejected(true);
    }

    @Test
    @DisplayName("Пустой приёмник: ранняя application_data даёт alert, а не BUFFER_OVERFLOW")
    void earlyAppDataIsAlertEvenWithoutRoomInDestination() throws Exception {
        // Нехватка места - вопрос контракта буферов, нарушение протокола - fatal alert: второе
        // не должно превращаться в первое, иначе потребитель зациклится на увеличении буфера
        assertEarlyAppDataRejected(false, 0);
    }

    @Test
    @DisplayName("Клиент: application_data сервера до его Finished отвергается")
    void clientRejectsEarlyAppData() throws Exception {
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        null);
        client.beginHandshake();
        ByteBuffer clientHello = ByteBuffer.allocate(BIG_BUFFER);
        client.wrap(ByteBuffer.allocate(0), clientHello);
        clientHello.flip();
        byte[] chRecord = new byte[clientHello.remaining()];
        clientHello.get(chRecord);

        // Сервер без аутентификации клиента: честный ServerHello, затем запись данных под
        // handshake-ключами сервера, не дожидаясь собственного Finished
        TlsHandshakeEngine rawServer =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        SUITE,
                        new TlsMessageBuilder(
                                SUITE,
                                List.of(SUITE.getId()),
                                GROUP,
                                TlsConstants.SIG_GOST_TC26_A_256,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                SUITE.getHashLen()),
                        TlsCiphersuite.namedGroupToParams(GROUP),
                        GROUP,
                        TlsConstants.SIG_GOST_TC26_A_256,
                        SUITE.getHashLen(),
                        null,
                        false,
                        null);
        rawServer.receive(
                Arrays.copyOfRange(chRecord, TlsConstants.RECORD_HEADER_SIZE, chRecord.length));
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        byte[] hello = ((HandshakeOutput.Message) rawServer.poll()).frame();
        // За ServerHello в потоке стоит смена ключа на ключи рукопожатия сервера; за HRR — ничего
        HandshakeOutput afterHello = rawServer.poll();
        // Клиент мог предложить другую группу: тогда сервер отвечает HelloRetryRequest
        // и ждёт второй ClientHello
        for (int attempt = 0; attempt < 2; attempt++) {
            SSLEngineResult r =
                    client.unwrap(
                            ByteBuffer.wrap(
                                    TlsMessageBuilder.buildPlaintextRecord(
                                            TlsConstants.CT_HANDSHAKE, hello)),
                            dst);
            assertEquals(SSLEngineResult.Status.OK, r.getStatus(), "ответ сервера принят");
            runTasks(client);
            if (afterHello instanceof HandshakeOutput.WriteKeyChange) {
                break;
            }
            ByteBuffer secondHello = ByteBuffer.allocate(BIG_BUFFER);
            while (client.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                client.wrap(ByteBuffer.allocate(0), secondHello);
            }
            secondHello.flip();
            byte[] ch2 = new byte[secondHello.remaining()];
            secondHello.get(ch2);
            int pos = 0;
            while (pos < ch2.length) {
                int len = ((ch2[pos + 3] & 0xFF) << 8) | (ch2[pos + 4] & 0xFF);
                if (ch2[pos] == TlsConstants.CT_HANDSHAKE) {
                    rawServer.receive(
                            Arrays.copyOfRange(
                                    ch2,
                                    pos + TlsConstants.RECORD_HEADER_SIZE,
                                    pos + TlsConstants.RECORD_HEADER_SIZE + len));
                }
                pos += TlsConstants.RECORD_HEADER_SIZE + len;
            }
            hello = ((HandshakeOutput.Message) rawServer.poll()).frame();
            afterHello = rawServer.poll();
        }

        TlsTrafficKeys write = ((HandshakeOutput.WriteKeyChange) afterHello).keys();
        byte[] record =
                new TlsRecord(write.getKey(), write.getIv(), SUITE.getTagLen(), SUITE)
                        .protect(TlsConstants.CT_APPLICATION_DATA, SECRET_PAYLOAD);
        SSLException ex =
                assertThrows(
                        SSLProtocolException.class,
                        () -> client.unwrap(ByteBuffer.wrap(record), dst),
                        "application_data сервера до его Finished должна приводить к ошибке");

        assertEquals(0, dst.position(), "данные не должны попасть в буфер приложения");
        assertTrue(
                ex.getMessage().contains("before handshake completion"),
                "ожидался отказ unexpected_message по состоянию рукопожатия: " + ex.getMessage());
    }
}
