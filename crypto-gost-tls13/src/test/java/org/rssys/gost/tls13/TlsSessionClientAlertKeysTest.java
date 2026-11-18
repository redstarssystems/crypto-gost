package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
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
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Ключ записи клиента с ServerHello (RFC 8446 приложение A.1: клиент SHOULD сначала сменить ключ на
 * ключ рукопожатия, если возможно): alert клиента после ServerHello зашифрован, до ServerHello
 * открытый, а нумерация записей рукопожатия клиента не сбивается.
 */
@DisplayName("TlsSession: ключ записи клиента с ServerHello")
class TlsSessionClientAlertKeysTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    /** Транспорт клиента: копит отправленные записи, остальное передаёт нижнему транспорту. */
    private static final class RecordingTransport implements TlsTransport {
        private final TlsTransport delegate;
        final List<byte[]> sent = new CopyOnWriteArrayList<>();

        RecordingTransport(TlsTransport delegate) {
            this.delegate = delegate;
        }

        @Override
        public void sendRecord(byte[] record) throws IOException {
            sent.add(record.clone());
            delegate.sendRecord(record);
        }

        @Override
        public byte[] receiveRecord() throws IOException {
            return delegate.receiveRecord();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }

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

    @Test
    @DisplayName("клиент отвергает сертификат сервера: alert уходит под ключами рукопожатия")
    @Timeout(60)
    void clientAlertAfterServerHelloIsEncrypted() throws Exception {
        PkixCertTestHelper.CertBundle serverBundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle otherBundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        var pair = InMemoryTlsTransport.newPair();
        RecordingTransport clientTransport = new RecordingTransport(pair.getClientTransport());
        TlsSession server =
                TlsSession.createServer(
                        pair.getServerTransport(), SUITE, serverBundle.cert, serverBundle.priv);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(otherBundle.cert))
                                .withoutHostnameVerification(),
                        clientTransport);
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

            // ClientHello и alert: alert после ServerHello не открытая запись типа 21
            assertEquals(2, clientTransport.sent.size(), "ClientHello и alert");
            byte[] alert = clientTransport.sent.get(1);
            assertEquals(
                    TlsConstants.CT_APPLICATION_DATA,
                    alert[0],
                    "Alert после ServerHello должен быть защищён ключом рукопожатия");
            assertTrue(
                    alert.length > TlsConstants.RECORD_HEADER_SIZE + 2,
                    "Защищённая запись длиннее открытой");
            assertTrue(serverError.isFromPeer(), "Alert клиента: " + serverError.getMessage());
            assertEquals(
                    clientError.getAlertCode(),
                    serverError.getAlertCode(),
                    "Сервер должен увидеть тот же код, что поставил клиент");
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("через HelloRetryRequest: ключ записи со вторым ServerHello, alert зашифрован")
    @Timeout(60)
    void clientAlertAfterHelloRetryRequestIsEncrypted() throws Exception {
        PkixCertTestHelper.CertBundle serverBundle =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(),
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"});
        PkixCertTestHelper.CertBundle otherBundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        var pair = InMemoryTlsTransport.newPair();
        RecordingTransport clientTransport = new RecordingTransport(pair.getClientTransport());
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        SUITE,
                                        Collections.singletonList(serverBundle.cert),
                                        serverBundle.priv)
                                .withSelectedNamedGroup(TlsConstants.GRP_GC256A),
                        pair.getServerTransport());
        // группа клиента по умолчанию (GC256B) не совпадает с группой сервера (GC256A): HRR
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(otherBundle.cert))
                                .withServerHostname("gost.example.com"),
                        clientTransport);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
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
            assertThrows(ExecutionException.class, () -> clientRun.get(20, TimeUnit.SECONDS));

            assertEquals(3, clientTransport.sent.size(), "ClientHello, второй ClientHello и alert");
            assertEquals(
                    TlsConstants.CT_HANDSHAKE,
                    clientTransport.sent.get(1)[0],
                    "Второй ClientHello");
            assertEquals(
                    TlsConstants.CT_APPLICATION_DATA,
                    clientTransport.sent.get(2)[0],
                    "Alert после второго ServerHello защищён ключом рукопожатия");
        } finally {
            executor.shutdownNow();
        }
    }

    /** Транспорт клиента: портит последний байт n-й зашифрованной записи сервера (тег). */
    private static final class TamperingTransport implements TlsTransport {
        private final RecordingTransport delegate;
        private final int tamperIndex;
        private int encryptedSeen;

        TamperingTransport(RecordingTransport delegate, int tamperIndex) {
            this.delegate = delegate;
            this.tamperIndex = tamperIndex;
        }

        @Override
        public void sendRecord(byte[] record) throws IOException {
            delegate.sendRecord(record);
        }

        @Override
        public byte[] receiveRecord() throws IOException {
            byte[] record = delegate.receiveRecord();
            if (record[0] == TlsConstants.CT_APPLICATION_DATA && encryptedSeen++ == tamperIndex) {
                record[record.length - 1] ^= 0x01;
            }
            return record;
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }

    @Test
    @DisplayName("возобновление по PSK: отказ клиента после ServerHello, alert зашифрован")
    @Timeout(60)
    void clientAlertInPskResumptionIsEncrypted() throws Exception {
        PkixCertTestHelper.CertBundle serverBundle =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(),
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"});
        PskStore serverStore = new InMemoryPskStore(100);
        PskStore clientStore = new InMemoryPskStore(100);

        // Первое соединение полное: клиент получает билет (его NewSessionTicket разбирает read())
        var first = InMemoryTlsTransport.newPair();
        TlsSession firstServer = pskServer(first, serverBundle, serverStore);
        RecordingTransport firstRecording = new RecordingTransport(first.getClientTransport());
        TlsSession firstClient = pskClient(firstRecording, serverBundle, clientStore);
        handshakeBoth(firstClient, firstServer);
        firstServer.close();
        assertThrows(EOFException.class, firstClient::read);
        firstClient.close();

        // Второе соединение идёт по билету; запись EncryptedExtensions сервера портится
        var second = InMemoryTlsTransport.newPair();
        RecordingTransport recording = new RecordingTransport(second.getClientTransport());
        TlsSession server = pskServer(second, serverBundle, serverStore);
        TlsSession client =
                pskClient(new TamperingTransport(recording, 0), serverBundle, clientStore);
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
            assertThrows(ExecutionException.class, () -> clientRun.get(20, TimeUnit.SECONDS));
            ExecutionException serverFailure =
                    assertThrows(
                            ExecutionException.class, () -> serverRun.get(20, TimeUnit.SECONDS));
            TlsException serverError =
                    assertInstanceOf(TlsException.class, serverFailure.getCause());

            assertEquals(2, recording.sent.size(), "ClientHello с PSK и alert");
            assertTrue(
                    recording.sent.get(0).length > firstRecording.sent.get(0).length + 64,
                    "Второй ClientHello несёт PSK (идентификатор билета и binder)");
            assertEquals(
                    TlsConstants.CT_APPLICATION_DATA,
                    recording.sent.get(1)[0],
                    "Alert после ServerHello в PSK-рукопожатии защищён ключом рукопожатия");
            assertTrue(serverError.isFromPeer(), "Alert клиента: " + serverError.getMessage());
            assertEquals(TlsConstants.ALERT_BAD_RECORD_MAC, serverError.getAlertCode());
        } finally {
            executor.shutdownNow();
        }
    }

    private static TlsSession pskServer(
            InMemoryTlsTransport.Pair pair, PkixCertTestHelper.CertBundle bundle, PskStore store) {
        TlsSession session =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        SUITE, Collections.singletonList(bundle.cert), bundle.priv)
                                .withSelectedNamedGroup(TlsConstants.GRP_GC256A),
                        pair.getServerTransport());
        session.setPskStore(store);
        return session;
    }

    private static TlsSession pskClient(
            TlsTransport transport, PkixCertTestHelper.CertBundle bundle, PskStore store) {
        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(bundle.cert))
                                .withServerHostname("gost.example.com")
                                .withSelectedNamedGroup(TlsConstants.GRP_GC256A),
                        transport);
        session.setPskStore(store);
        return session;
    }

    private static void handshakeBoth(TlsSession client, TlsSession server) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Void> clientRun =
                    executor.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            Future<Void> serverRun =
                    executor.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            clientRun.get(20, TimeUnit.SECONDS);
            serverRun.get(20, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("отказ клиента до ServerHello: alert открытый, ключей ещё нет")
    void clientAlertBeforeServerHelloIsPlaintext() throws Exception {
        // ServerHello с мусором в теле: разбор отвергнет его до выработки ключей
        byte[] garbageHello =
                TlsMessageBuilder.buildPlaintextRecord(
                        TlsConstants.CT_HANDSHAKE, new byte[] {2, 0, 0, 3, 1, 2, 3});
        ScriptedTransport transport = new ScriptedTransport(garbageHello);
        TlsSession client = TlsSession.createClientWithoutServerAuth(transport, SUITE, null, null);

        assertThrows(TlsException.class, client::handshakeAsClient);

        assertEquals(2, transport.sent.size(), "ClientHello и alert");
        byte[] alert = transport.sent.get(1);
        assertEquals(TlsConstants.CT_ALERT, alert[0], "До ServerHello ключей записи нет");
        assertEquals(TlsConstants.RECORD_HEADER_SIZE + 2, alert.length);
    }

    @Test
    @DisplayName(
            "mTLS: Certificate, CertificateVerify и Finished клиента идут ключом рукопожатия по порядку")
    @Timeout(60)
    void mtlsHandshakeRecordsKeepNumbering() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle serverLeaf =
                leafSignedBy(root, new String[] {"gost.example.com"}, GostOids.EXT_SERVER_AUTH);
        PkixCertTestHelper.CertBundle clientLeaf =
                leafSignedBy(root, null, GostOids.EXT_CLIENT_AUTH);
        var pair = InMemoryTlsTransport.newPair();
        RecordingTransport clientTransport = new RecordingTransport(pair.getClientTransport());
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        SUITE,
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        pair.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        clientTransport);
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
            clientRun.get(20, TimeUnit.SECONDS);
            serverRun.get(20, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }

        // ClientHello открытый, затем три записи рукопожатия клиента под одним ключом:
        // сервер расшифровал их неявными номерами 0, 1, 2, значит нумерация не сбита
        assertEquals(TlsConstants.CT_HANDSHAKE, clientTransport.sent.get(0)[0]);
        long encrypted =
                clientTransport.sent.stream()
                        .skip(1)
                        .filter(r -> r[0] == TlsConstants.CT_APPLICATION_DATA)
                        .count();
        assertTrue(encrypted >= 3, "Certificate, CertificateVerify и Finished: " + encrypted);
        assertFalse(client.isClosed(), "Рукопожатие должно завершиться успешно");
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
}
