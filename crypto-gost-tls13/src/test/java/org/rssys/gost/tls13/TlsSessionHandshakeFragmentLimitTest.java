package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.config.TlsClientConfig;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Сообщения рукопожатия соблюдают согласованный max_fragment_length (RFC 6066 §4: лимит касается
 * всех записей после согласования, а не только данных приложения).
 *
 * <p>Тест перехватывает записи на транспорте: по успешному завершению рукопожатия нельзя отличить
 * «соблюдаем лимит» от «нарушаем, но пир не проверяет», потому что собственный приёмник лимит
 * рукопожатия не проверяет.
 */
@DisplayName("TlsSession: зашифрованные сообщения рукопожатия укладываются в max_fragment_length")
class TlsSessionHandshakeFragmentLimitTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final String HOST = "gost.example.com";
    private static final String NOT_BEFORE = "20240501120000Z";
    private static final String NOT_AFTER = "21060101120000Z";
    private static final int TIMEOUT_SECONDS = 20;
    private static final int FRAGMENT_LIMIT =
            TlsUtils.maxFragmentLength(TlsConstants.MAX_FRAG_LEN_512);

    // Сертификат заведомо больше 512 байт: ≈ 30 имён по ≈ 70 байт дают около 2 КБ
    private static final int SAN_COUNT = 30;
    private static final String SAN_PADDING = "a".repeat(48);

    private static final byte[] PING = {0x50, 0x49, 0x4E, 0x47};
    private static final byte[] PONG = {0x50, 0x4F, 0x4E, 0x47};

    /** Транспорт, запоминающий каждую отправленную запись. */
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

    @Test
    @DisplayName(
            "Certificate сервера больше 512 байт: записи рукопожатия сервера не длиннее лимита")
    void serverHandshakeRecordsRespectLimit() throws Exception {
        PkixCertTestHelper.CertBundle server =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(), NOT_BEFORE, NOT_AFTER, bigSanNames());
        assertCertificateExceedsLimit(server);

        var pair = InMemoryTlsTransport.newPair();
        RecordingTransport serverTransport = new RecordingTransport(pair.getServerTransport());
        RecordingTransport clientTransport = new RecordingTransport(pair.getClientTransport());
        TlsSession serverSession =
                TlsSession.createServer(
                        new TlsServerConfig(
                                SUITE, Collections.singletonList(server.cert), server.priv),
                        serverTransport);
        TlsSession clientSession =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(server.cert))
                                .withServerHostname(HOST),
                        clientTransport);
        clientSession.setMaxFragmentLengthRequest(TlsConstants.MAX_FRAG_LEN_512);
        try {
            handshake(clientSession, serverSession);

            assertEncryptedRecordsWithinLimit("сервер", serverTransport.sent);
            assertEncryptedRecordsWithinLimit("клиент", clientTransport.sent);
            exchangeApplicationData(clientSession, serverSession);
        } finally {
            serverSession.close();
            clientSession.close();
        }
    }

    @Test
    @DisplayName("Certificate клиента (mTLS) больше 512 байт: записи рукопожатия клиента в лимите")
    void clientHandshakeRecordsRespectLimit() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle ca = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle server = signedByCa(params, ca, new String[] {HOST});
        PkixCertTestHelper.CertBundle client = signedByCa(params, ca, bigSanNames());
        assertCertificateExceedsLimit(client);

        var pair = InMemoryTlsTransport.newPair();
        RecordingTransport serverTransport = new RecordingTransport(pair.getServerTransport());
        RecordingTransport clientTransport = new RecordingTransport(pair.getClientTransport());
        TlsSession serverSession =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        SUITE, Collections.singletonList(server.cert), server.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(ca.cert)),
                        serverTransport);
        TlsSession clientSession =
                TlsSession.createClient(
                        new TlsClientConfig(SUITE, TrustAnchors.ofCertificate(ca.cert))
                                .withServerHostname(HOST)
                                .withClientCertificateChain(client.cert)
                                .withClientPrivateKey(client.priv),
                        clientTransport);
        clientSession.setMaxFragmentLengthRequest(TlsConstants.MAX_FRAG_LEN_512);
        try {
            handshake(clientSession, serverSession);

            assertEncryptedRecordsWithinLimit("клиент", clientTransport.sent);
            assertEncryptedRecordsWithinLimit("сервер", serverTransport.sent);
            exchangeApplicationData(clientSession, serverSession);
        } finally {
            serverSession.close();
            clientSession.close();
        }
    }

    /**
     * Каждая зашифрованная запись несёт не больше FRAGMENT_LIMIT байт внутреннего открытого текста
     * (содержимое и тип), то есть шифртекст не длиннее лимита плюс тег.
     */
    private static void assertEncryptedRecordsWithinLimit(String side, List<byte[]> records) {
        List<Integer> tooLong = new ArrayList<>();
        int encrypted = 0;
        for (byte[] record : records) {
            if ((record[0] & 0xFF) != TlsConstants.CT_APPLICATION_DATA) {
                continue;
            }
            encrypted++;
            int ciphertextLen = record.length - TlsConstants.RECORD_HEADER_SIZE;
            if (ciphertextLen > FRAGMENT_LIMIT + SUITE.getTagLen()) {
                tooLong.add(ciphertextLen);
            }
        }
        assertTrue(encrypted > 0, side + ": предусловие: есть зашифрованные записи");
        assertTrue(
                tooLong.isEmpty(),
                side
                        + ": зашифрованные записи рукопожатия длиннее согласованного лимита "
                        + FRAGMENT_LIMIT
                        + " байт: "
                        + tooLong);
    }

    private static PkixCertTestHelper.CertBundle signedByCa(
            ECParameters params, PkixCertTestHelper.CertBundle ca, String[] sanDnsNames)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                ca.priv,
                ca.cert.getPublicKey(),
                ca.subjectDn,
                NOT_BEFORE,
                NOT_AFTER,
                sanDnsNames,
                null,
                null,
                false,
                null);
    }

    /** Имена SAN: одно нужное для проверки имени хоста и несколько лишних, чтобы раздуть сертификат. */
    private static String[] bigSanNames() {
        String[] names = new String[SAN_COUNT + 1];
        names[0] = HOST;
        for (int i = 1; i <= SAN_COUNT; i++) {
            names[i] = "san-" + i + "-" + SAN_PADDING + ".example.com";
        }
        return names;
    }

    private static void assertCertificateExceedsLimit(PkixCertTestHelper.CertBundle bundle) {
        int size = bundle.cert.getEncoded().length;
        // Без этого условия тест молча превратился бы в проверку обычного рукопожатия
        assertTrue(
                size > FRAGMENT_LIMIT,
                "предусловие: сертификат (" + size + " байт) не помещается в лимит записи");
    }

    private static void exchangeApplicationData(TlsSession client, TlsSession server)
            throws Exception {
        client.write(PING);
        assertArrayEquals(PING, server.read(), "Сервер прочитал данные клиента");
        server.write(PONG);
        assertArrayEquals(PONG, client.read(), "Клиент прочитал данные сервера");
    }

    private static void handshake(TlsSession client, TlsSession server) throws Exception {
        ExecutorService exec = Executors.newFixedThreadPool(2);
        try {
            Future<Void> clientDone =
                    exec.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            Future<Void> serverDone =
                    exec.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            clientDone.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            serverDone.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } finally {
            exec.shutdownNow();
        }
    }
}
