package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Field;
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
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Записи сессии должны строиться по набору шифров, согласованному в рукопожатии, а не по набору из
 * конфигурации создания сессии.
 *
 * <p>Наборы L и S различаются масками TLSTREE: на записях с номерами 0-7 ключи совпадают, с записи
 * 8 у S ключ меняется (C3 = ...FFF8), а у L нет (C3 = ...E000). Поэтому дефект проявляется только
 * после восьми записей в одну сторону.
 */
@DisplayName("TlsSession: записи по согласованному набору шифров")
class TlsSessionNegotiatedSuiteRecordsTest {

    private static final String SERVER_HOST = "gost.example.com";

    /** Больше восьми записей: порог, с которого маски TLSTREE у L и S расходятся. */
    private static final int RECORDS_PER_DIRECTION = 12;

    private static final TlsCiphersuite SUITE_L =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final TlsCiphersuite SUITE_S =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;

    @Test
    @DisplayName("клиент настроен на L, сервер на S: обмен более чем 8 записями в каждую сторону")
    void clientLServerS_exchangeBeyondTreeBoundary() throws Exception {
        exchangeBeyondTreeBoundary(SUITE_L, SUITE_S);
    }

    @Test
    @DisplayName("клиент настроен на S, сервер на L: обмен более чем 8 записями в каждую сторону")
    void clientSServerL_exchangeBeyondTreeBoundary() throws Exception {
        exchangeBeyondTreeBoundary(SUITE_S, SUITE_L);
    }

    @Test
    @DisplayName("одинаковые наборы: обмен более чем 8 записями проходит (контроль)")
    void sameSuite_exchangeBeyondTreeBoundary() throws Exception {
        exchangeBeyondTreeBoundary(SUITE_S, SUITE_S);
    }

    private static void exchangeBeyondTreeBoundary(
            TlsCiphersuite clientSuite, TlsCiphersuite serverSuite) throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(root);

        var transports = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                serverSuite, Collections.singletonList(leaf.cert), leaf.priv),
                        transports.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(clientSuite, TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname(SERVER_HOST),
                        transports.getClientTransport());

        try {
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
                clientHandshake.get(30, TimeUnit.SECONDS);
                serverHandshake.get(30, TimeUnit.SECONDS);
            } finally {
                executor.shutdownNow();
            }

            // Обе стороны обязаны применять один и тот же набор: иначе TLSTREE-ключи разойдутся
            assertEquals(
                    serverSuite.getId(),
                    server.getCipherSuite().getId(),
                    "Сервер должен использовать свой набор шифров");
            assertEquals(
                    serverSuite.getId(),
                    client.getCipherSuite().getId(),
                    "Клиент должен перейти на набор, выбранный сервером");
            for (int i = 0; i < RECORDS_PER_DIRECTION; i++) {
                byte[] fromClient = ("клиент " + i).getBytes(StandardCharsets.UTF_8);
                client.write(fromClient);
                assertArrayEquals(
                        fromClient,
                        server.read(),
                        "Запись клиента №" + i + " должна расшифроваться сервером");
            }
            for (int i = 0; i < RECORDS_PER_DIRECTION; i++) {
                byte[] fromServer = ("сервер " + i).getBytes(StandardCharsets.UTF_8);
                server.write(fromServer);
                assertArrayEquals(
                        fromServer,
                        client.read(),
                        "Запись сервера №" + i + " должна расшифроваться клиентом");
            }
            assertEquals(
                    serverSuite.getSnmax(),
                    recordSnmax(client, "writerRecord"),
                    "SNMAX записи клиента должен быть от согласованного набора");
            assertEquals(
                    serverSuite.getSnmax(),
                    recordSnmax(client, "readerRecord"),
                    "SNMAX читающей записи клиента должен быть от согласованного набора");
        } finally {
            // Сессии закрываем и при падении теста, иначе транспорт останется открытым
            server.close();
            client.close();
        }
    }

    private static PkixCertTestHelper.CertBundle createServerLeaf(
            PkixCertTestHelper.CertBundle issuer) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                ECParameters.tc26a256(),
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                new String[] {SERVER_HOST},
                new byte[] {(byte) 0x80},
                new String[] {GostOids.EXT_SERVER_AUTH},
                false,
                null);
    }

    private static long recordSnmax(TlsSession session, String recordField) throws Exception {
        Field sessionField = TlsSession.class.getDeclaredField(recordField);
        sessionField.setAccessible(true);
        TlsRecord record = (TlsRecord) sessionField.get(session);
        Field snmaxField = TlsRecord.class.getDeclaredField("snmax");
        snmaxField.setAccessible(true);
        return snmaxField.getLong(record);
    }
}
