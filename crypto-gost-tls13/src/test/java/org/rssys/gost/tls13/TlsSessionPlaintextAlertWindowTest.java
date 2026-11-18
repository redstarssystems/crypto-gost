package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Открытый alert в окне рукопожатия: после ClientHello (сервер) или ServerHello (клиент) ключ
 * чтения рукопожатия уже включён, а пир, ещё не получивший свои ключи записи, вправе прислать alert
 * открытой записью (RFC 8446 приложение A.1, RFC 9846 то же примечание).
 *
 * <p>Окно закрывается первой успешно расшифрованной записью пира и концом рукопожатия: дальше
 * открытая запись типа alert ничем не оправдана и отвергается.
 */
@DisplayName("TlsSession: открытый alert в окне рукопожатия")
class TlsSessionPlaintextAlertWindowTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final byte[] CLOSE_NOTIFY_BODY = {
        TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY
    };

    /** Транспорт-заглушка: отдаёт заданные записи, затем обрывает приём; отправленное копит. */
    private static final class ScriptedTransport implements TlsTransport {
        private final ArrayDeque<byte[]> incoming = new ArrayDeque<>();
        final List<byte[]> sent = new ArrayList<>();

        ScriptedTransport(byte[]... records) {
            Collections.addAll(incoming, records);
        }

        @Override
        public void sendRecord(byte[] record) {
            sent.add(record.clone());
        }

        @Override
        public byte[] receiveRecord() throws IOException {
            byte[] record = incoming.poll();
            if (record == null) {
                throw new IOException("scripted transport: no more records");
            }
            return record;
        }

        @Override
        public void close() {}
    }

    /**
     * Транспорт-прослойка клиента: n-ю по счёту зашифрованную запись (внешний тип 23) от сервера
     * заменяет результатом {@code substitute}, остальные пропускает как есть.
     */
    private static final class SubstitutingTransport implements TlsTransport {
        private final TlsTransport delegate;
        private final int replaceIndex;
        private final UnaryOperator<byte[]> substitute;
        private int encryptedSeen;

        SubstitutingTransport(
                TlsTransport delegate, int replaceIndex, UnaryOperator<byte[]> substitute) {
            this.delegate = delegate;
            this.replaceIndex = replaceIndex;
            this.substitute = substitute;
        }

        @Override
        public void sendRecord(byte[] record) throws IOException {
            delegate.sendRecord(record);
        }

        @Override
        public byte[] receiveRecord() throws IOException {
            byte[] record = delegate.receiveRecord();
            if (record[0] == TlsConstants.CT_APPLICATION_DATA) {
                if (encryptedSeen++ == replaceIndex) {
                    return substitute.apply(record);
                }
            }
            return record;
        }

        @Override
        public int receiveRecord(ByteBuffer dst) throws IOException {
            byte[] record = receiveRecord();
            dst.put(record);
            return record.length;
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }

    private static byte[] plaintextRecord(byte contentType, byte[] body) {
        return TlsMessageBuilder.buildPlaintextRecord(contentType, body);
    }

    private static byte[] openFatalAlert(byte description) {
        return plaintextRecord(
                TlsConstants.CT_ALERT, new byte[] {TlsConstants.ALERT_FATAL, description});
    }

    private static TlsSession serverOver(TlsTransport transport) throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        return TlsSession.createServer(transport, SUITE, bundle.cert, bundle.priv);
    }

    /** Настоящий ClientHello: после него у сервера включён ключ чтения рукопожатия. */
    private static byte[] clientHello() throws Exception {
        ScriptedTransport transport = new ScriptedTransport();
        TlsSession client = TlsSession.createClientWithoutServerAuth(transport, SUITE, null, null);
        assertThrows(IOException.class, client::handshakeAsClient);
        return transport.sent.get(0);
    }

    private static boolean sentAnyAlert(ScriptedTransport transport) {
        return transport.sent.stream().anyMatch(r -> r[0] == TlsConstants.CT_ALERT);
    }

    // ------------------------------------------------------------------ сервер

    @Test
    @DisplayName("сервер: открытый fatal alert после ClientHello - настоящий код, ответа нет")
    void serverSeesPlaintextFatalAlertAfterClientHello() throws Exception {
        ScriptedTransport transport =
                new ScriptedTransport(
                        clientHello(), openFatalAlert(TlsConstants.ALERT_BAD_CERTIFICATE));
        TlsSession server = serverOver(transport);

        TlsException error = assertThrows(TlsException.class, server::handshakeAsServer);

        assertTrue(error.isFromPeer(), "Alert пришёл от пира: " + error.getMessage());
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, error.getAlertCode());
        assertFalse(sentAnyAlert(transport), "На fatal alert пира ответного alert быть не должно");
        assertTrue(server.isClosed(), "Сессия должна быть закрыта");
    }

    @Test
    @DisplayName("сервер: открытый close_notify после ClientHello - PeerClosedException и ответ")
    void serverAnswersPlaintextCloseNotifyAfterClientHello() throws Exception {
        ScriptedTransport transport =
                new ScriptedTransport(
                        clientHello(), plaintextRecord(TlsConstants.CT_ALERT, CLOSE_NOTIFY_BODY));
        TlsSession server = serverOver(transport);

        assertThrows(PeerClosedException.class, server::handshakeAsServer);

        byte[] answer = transport.sent.get(transport.sent.size() - 1);
        assertEquals(
                TlsConstants.CT_APPLICATION_DATA,
                answer[0],
                "Ответный close_notify уходит под ключами рукопожатия, а не открытым");
        assertTrue(server.isClosed(), "Сессия должна быть закрыта");
    }

    @Test
    @DisplayName("сервер: открытый alert неверной длины после ClientHello - формат, не шифротекст")
    void serverValidatesPlaintextAlertLength() throws Exception {
        byte[][] bodies = {
            new byte[0],
            {TlsConstants.ALERT_FATAL},
            {TlsConstants.ALERT_FATAL, 40, TlsConstants.ALERT_FATAL}
        };
        byte[] expectedCodes = {
            TlsConstants.ALERT_UNEXPECTED_MESSAGE,
            TlsConstants.ALERT_DECODE_ERROR,
            TlsConstants.ALERT_DECODE_ERROR
        };
        for (int i = 0; i < bodies.length; i++) {
            ScriptedTransport transport =
                    new ScriptedTransport(
                            clientHello(), plaintextRecord(TlsConstants.CT_ALERT, bodies[i]));
            TlsSession server = serverOver(transport);

            TlsException error = assertThrows(TlsException.class, server::handshakeAsServer);

            assertEquals(
                    expectedCodes[i],
                    error.getAlertCode(),
                    "Длина " + bodies[i].length + ": " + error.getMessage());
            assertFalse(error.isFromPeer(), "Нарушение формата найдено локально");
        }
    }

    @Test
    @DisplayName("сервер: открытые handshake и application_data в окне не принимаются")
    void serverRejectsOtherPlaintextTypesInWindow() throws Exception {
        byte[][] records = {
            plaintextRecord(TlsConstants.CT_HANDSHAKE, new byte[40]),
            plaintextRecord(TlsConstants.CT_APPLICATION_DATA, new byte[40])
        };
        for (byte[] record : records) {
            ScriptedTransport transport = new ScriptedTransport(clientHello(), record);
            TlsSession server = serverOver(transport);

            TlsException error = assertThrows(TlsException.class, server::handshakeAsServer);

            assertFalse(error.isFromPeer(), "Открытая запись типа " + record[0] + ": " + error);
            if (record[0] == TlsConstants.CT_HANDSHAKE) {
                assertEquals(
                        TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                        error.getAlertCode(),
                        "Неожиданный внешний тип: " + error.getMessage());
            }
            assertTrue(server.isClosed(), "Сессия должна быть закрыта");
        }
    }

    /**
     * Рукопожатие с взаимной аутентификацией: n-ю зашифрованную запись клиента (Certificate,
     * CertificateVerify, Finished) сервер получает подменённой; возвращает исход сервера.
     */
    private static Throwable mtlsServerOutcomeWithSubstitution(
            int replaceIndex, UnaryOperator<byte[]> substitute) throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle serverLeaf =
                leafSignedBy(root, new String[] {"gost.example.com"}, GostOids.EXT_SERVER_AUTH);
        PkixCertTestHelper.CertBundle clientLeaf =
                leafSignedBy(root, null, GostOids.EXT_CLIENT_AUTH);
        var pair = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        SUITE,
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        new SubstitutingTransport(
                                pair.getServerTransport(), replaceIndex, substitute));
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        pair.getClientTransport());
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Void> serverRun =
                    executor.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            Future<Void> clientRun =
                    executor.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            try {
                serverRun.get(20, TimeUnit.SECONDS);
            } catch (ExecutionException e) {
                assertTrue(server.isClosed(), "Сессия сервера должна быть закрыта");
                return e.getCause();
            } finally {
                clientRun.cancel(true);
            }
            return null;
        } finally {
            executor.shutdownNow();
        }
    }

    private static PkixCertTestHelper.CertBundle leafSignedBy(
            PkixCertTestHelper.CertBundle issuer, String[] dnsNames, String ekuOid)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                ECParameters.tc26a256(),
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                dnsNames,
                new byte[] {(byte) 0x80},
                new String[] {ekuOid},
                false,
                null);
    }

    @Test
    @DisplayName(
            "сервер mTLS: открытый alert вместо первой записи клиента принимается (окно открыто)")
    @Timeout(60)
    void serverAcceptsPlaintextAlertInPlaceOfFirstClientRecord() throws Exception {
        Throwable outcome =
                mtlsServerOutcomeWithSubstitution(
                        0, record -> openFatalAlert(TlsConstants.ALERT_BAD_CERTIFICATE));

        TlsException error = assertInstanceOf(TlsException.class, outcome);
        assertTrue(error.isFromPeer(), "Окно открыто до первой расшифрованной записи: " + error);
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, error.getAlertCode());
    }

    @Test
    @DisplayName("сервер mTLS: после первой расшифрованной записи клиента окно закрыто")
    @Timeout(60)
    void serverClosesWindowAfterFirstDecryptedClientRecord() throws Exception {
        Throwable outcome =
                mtlsServerOutcomeWithSubstitution(
                        1, record -> openFatalAlert(TlsConstants.ALERT_BAD_CERTIFICATE));

        TlsException error = assertInstanceOf(TlsException.class, outcome);
        assertFalse(error.isFromPeer(), "Флаг расшифрованной записи закрывает окно: " + error);
        assertEquals(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode(), error.getMessage());
    }

    // ------------------------------------------------------------------ клиент

    /** Рукопожатие клиента с подменой n-й зашифрованной записи сервера; возвращает исход клиента. */
    private static Throwable clientOutcomeWithSubstitution(
            int replaceIndex, UnaryOperator<byte[]> substitute) throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        var pair = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(pair.getServerTransport(), SUITE, bundle.cert, bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(
                        new SubstitutingTransport(
                                pair.getClientTransport(), replaceIndex, substitute),
                        SUITE,
                        null,
                        null);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Void> serverRun =
                    executor.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            Future<Void> clientRun =
                    executor.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            try {
                clientRun.get(20, TimeUnit.SECONDS);
            } catch (ExecutionException e) {
                assertTrue(client.isClosed(), "Сессия клиента должна быть закрыта");
                return e.getCause();
            } finally {
                serverRun.cancel(true);
            }
            return null;
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName(
            "клиент: открытый alert сервера после ServerHello не принимается (окно только у сервера)")
    @Timeout(60)
    void clientRejectsPlaintextAlertAfterServerHello() throws Exception {
        Throwable outcome =
                clientOutcomeWithSubstitution(
                        0, record -> openFatalAlert(TlsConstants.ALERT_HANDSHAKE_FAILURE));

        TlsException error = assertInstanceOf(TlsException.class, outcome);
        assertFalse(error.isFromPeer(), "Сервер включает ключ записи на ServerHello: " + error);
        assertEquals(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                error.getAlertCode(),
                "Неожиданный внешний тип записи: unexpected_message (RFC 8446 §5)");
    }

    @Test
    @DisplayName("клиент: открытый alert после первой расшифрованной записи - unexpected_message")
    @Timeout(60)
    void clientRejectsPlaintextAlertAfterFirstDecryptedRecord() throws Exception {
        Throwable outcome =
                clientOutcomeWithSubstitution(
                        1, record -> openFatalAlert(TlsConstants.ALERT_HANDSHAKE_FAILURE));

        TlsException error = assertInstanceOf(TlsException.class, outcome);
        assertFalse(error.isFromPeer(), "Окна нет: " + error);
        assertEquals(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode(), error.getMessage());
    }

    // ------------------------------------------------------------------ оба конца

    @Test
    @DisplayName("клиент отвергает сертификат сервера: сервер видит настоящий код клиента")
    @Timeout(60)
    void serverSeesRealCodeOfClientCertificateRejection() throws Exception {
        PkixCertTestHelper.CertBundle serverBundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle otherBundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        var pair = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        pair.getServerTransport(), SUITE, serverBundle.cert, serverBundle.priv);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(otherBundle.cert))
                                .withoutHostnameVerification(),
                        pair.getClientTransport());
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Void> serverRun =
                    executor.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            Future<Void> clientRun =
                    executor.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            ExecutionException clientFailure =
                    assertThrows(
                            ExecutionException.class, () -> clientRun.get(20, TimeUnit.SECONDS));
            TlsException clientError =
                    assertInstanceOf(TlsException.class, clientFailure.getCause());
            ExecutionException serverFailure =
                    assertThrows(
                            ExecutionException.class, () -> serverRun.get(20, TimeUnit.SECONDS));
            TlsException serverError =
                    assertInstanceOf(TlsException.class, serverFailure.getCause());

            assertTrue(serverError.isFromPeer(), "Alert клиента: " + serverError.getMessage());
            assertEquals(
                    clientError.getAlertCode(),
                    serverError.getAlertCode(),
                    "Сервер должен увидеть тот же код, что поставил клиент");
        } finally {
            executor.shutdownNow();
        }
    }

    // ------------------------------------------------------------------ после рукопожатия

    @Test
    @DisplayName("read(): открытый alert после рукопожатия не принимается как alert пира")
    void readRejectsPlaintextAlertAfterHandshake() throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        connection
                .transports()
                .getClientToServerQueue()
                .add(openFatalAlert(TlsConstants.ALERT_HANDSHAKE_FAILURE));

        TlsException error = assertThrows(TlsException.class, connection.server()::read);

        assertFalse(error.isFromPeer(), "В эпохе ключей приложения окна нет: " + error);
        assertEquals(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode(), error.getMessage());
    }
}
