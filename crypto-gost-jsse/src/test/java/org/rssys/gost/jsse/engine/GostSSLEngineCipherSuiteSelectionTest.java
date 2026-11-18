package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import java.util.List;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
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
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Включённые наборы шифров и протоколы действительно ограничивают рукопожатие: клиент не
 * предлагает отключённый набор, сервер его не выбирает и не принимает от пира.
 */
@DisplayName("GostSSLEngine: выбор набора шифров по включённым наборам")
class GostSSLEngineCipherSuiteSelectionTest {

    private static final String LONG_SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L.getIanaName();
    private static final String SHORT_SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S.getIanaName();

    /** Корни в цепочке клиента сверх листа: полёт клиента выходит за 8 записей по 512 байт. */
    private static final int LONG_CHAIN_EXTRA_CERTS = 8;

    private static final int BUFFER = 1 << 16;

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

    private static GostSSLEngine server(String... suites) {
        GostSSLEngine engine =
                GostSSLEngine.createForServer(
                        serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, null);
        if (suites.length > 0) {
            engine.setEnabledCipherSuites(suites);
        }
        return engine;
    }

    private static GostSSLEngine client(String... suites) {
        GostSSLEngine engine =
                GostSSLEngine.createForClientNoHostnameCheck(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        null);
        if (suites.length > 0) {
            engine.setEnabledCipherSuites(suites);
        }
        return engine;
    }

    private static void handshake(GostSSLEngine client, GostSSLEngine server) throws Exception {
        GostSSLEngineLoopbackTest.doLoopback(client, server, InMemoryTlsTransport.newPair());
    }

    @Test
    @DisplayName("Обе стороны разрешили только короткий набор: согласуется он")
    void bothOnlyShortSuite() throws Exception {
        GostSSLEngine client = client(SHORT_SUITE);
        GostSSLEngine server = server(SHORT_SUITE);

        handshake(client, server);

        assertEquals(SHORT_SUITE, client.getSession().getCipherSuite(), "набор клиента");
        assertEquals(SHORT_SUITE, server.getSession().getCipherSuite(), "набор сервера");
    }

    @Test
    @DisplayName("Клиент разрешил только короткий набор, сервер оба: сервер выбирает короткий")
    void clientOnlyShortSuite() throws Exception {
        GostSSLEngine client = client(SHORT_SUITE);
        GostSSLEngine server = server();

        handshake(client, server);

        assertEquals(SHORT_SUITE, server.getSession().getCipherSuite(), "набор сервера");
        assertEquals(SHORT_SUITE, client.getSession().getCipherSuite(), "набор клиента");
    }

    @Test
    @DisplayName("Сервер разрешил только короткий набор, клиент оба: сервер не выбирает длинный")
    void serverOnlyShortSuiteIgnoresLongSuiteOfferedByClient() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server(SHORT_SUITE);

        handshake(client, server);

        assertEquals(
                SHORT_SUITE,
                server.getSession().getCipherSuite(),
                "отключённый на сервере набор не должен выбираться, даже если клиент предпочёл его");
        assertEquals(SHORT_SUITE, client.getSession().getCipherSuite(), "набор клиента");
    }

    @Test
    @DisplayName(
            "mTLS: клиент предпочёл длинный набор, сервер разрешил только короткий: полёт клиента"
                    + " защищён согласованным набором")
    void mutualTlsClientFlightUsesNegotiatedSuite() throws Exception {
        // Маски TLSTREE длинного и короткого наборов дают один ключ на номерах записей 0..7, а с
        // номера 8 ключи расходятся (C3 короткого набора 0xFFFFFFFFFFFFFFF8). Полёт клиента
        // растягивается на 8 и более записей: max_fragment_length 512 и цепочка в несколько
        // килобайт. Запись, собранная по первому предложенному набору вместо согласованного, не
        // расшифровалась бы у сервера
        PkixCertTestHelper.CertBundle clientCert =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        List<org.rssys.gost.pkix.cert.GostCertificate> chain = new java.util.ArrayList<>();
        chain.add(clientCert.cert);
        for (int i = 0; i < LONG_CHAIN_EXTRA_CERTS; i++) {
            chain.add(PkixCertTestHelper.createRootCA(ECParameters.tc26a256()).cert);
        }
        GostX509KeyManager clientKm = new GostX509KeyManager();
        clientKm.addKeyEntry("client", CertificateBridge.toJca(chain), clientCert.priv);
        GostSSLEngine client =
                GostSSLEngine.createForClientNoHostnameCheck(
                        clientKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, null);
        client.setEnabledCipherSuites(new String[] {LONG_SUITE, SHORT_SUITE});
        client.setClientMaxFragLenRequest(org.rssys.gost.tls13.TlsConstants.MAX_FRAG_LEN_512);
        GostSSLEngine server = server(SHORT_SUITE);
        server.setNeedClientAuth(true);

        handshake(client, server);

        assertEquals(SHORT_SUITE, client.getSession().getCipherSuite(), "набор клиента");
        assertEquals(SHORT_SUITE, server.getSession().getCipherSuite(), "набор сервера");
    }

    @Test
    @DisplayName("После ServerHello запись отправки клиента собрана по согласованному набору")
    void clientWriterAfterServerHelloUsesNegotiatedSuite() throws Exception {
        GostSSLEngine client = client(LONG_SUITE, SHORT_SUITE);
        GostSSLEngine server = server(SHORT_SUITE);
        client.beginHandshake();
        java.nio.ByteBuffer hello = java.nio.ByteBuffer.allocate(BUFFER);
        org.rssys.gost.jsse.testkit.EngineTestSupport.wrapPending(client, hello);
        hello.flip();
        org.rssys.gost.jsse.testkit.EngineTestSupport.feedRunningTasks(server, hello);
        java.nio.ByteBuffer flight = java.nio.ByteBuffer.allocate(BUFFER);
        org.rssys.gost.jsse.testkit.EngineTestSupport.wrapPending(server, flight);
        flight.flip();
        // Только первая запись полёта - ServerHello: за ней клиент включает ключ записи
        int serverHelloLength =
                org.rssys.gost.tls13.TlsConstants.RECORD_HEADER_SIZE
                        + (((flight.get(3) & 0xFF) << 8) | (flight.get(4) & 0xFF));
        flight.limit(serverHelloLength);
        client.unwrap(flight, java.nio.ByteBuffer.allocate(BUFFER));

        assertEquals(
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S.getC3(),
                tlsTreeMaskC3(writerRecordOf(client)),
                "маски TLSTREE записи - согласованного короткого набора, а не первого предложенного");
    }

    private static Object writerRecordOf(GostSSLEngine engine) throws Exception {
        java.lang.reflect.Field field = GostSSLEngine.class.getDeclaredField("writerRecord");
        field.setAccessible(true);
        return field.get(engine);
    }

    private static long tlsTreeMaskC3(Object record) throws Exception {
        java.lang.reflect.Field field = record.getClass().getDeclaredField("c3");
        field.setAccessible(true);
        return field.getLong(record);
    }

    @Test
    @DisplayName("Сервер разрешил только длинный набор, клиент оба: согласуется длинный")
    void serverOnlyLongSuite() throws Exception {
        GostSSLEngine client = client(SHORT_SUITE, LONG_SUITE);
        GostSSLEngine server = server(LONG_SUITE);

        handshake(client, server);

        assertEquals(LONG_SUITE, server.getSession().getCipherSuite(), "набор сервера");
        assertEquals(LONG_SUITE, client.getSession().getCipherSuite(), "набор клиента");
    }

    @Test
    @DisplayName("Наборы сторон не пересекаются: рукопожатие отвергается")
    void disjointSuitesFailTheHandshake() {
        GostSSLEngine client = client(LONG_SUITE);
        GostSSLEngine server = server(SHORT_SUITE);

        RuntimeException failure =
                assertThrows(
                        RuntimeException.class,
                        () -> handshake(client, server),
                        "нет общего набора шифров: рукопожатие не должно завершиться");
        assertTrue(
                failure.getCause() instanceof SSLException,
                "причина - отказ рукопожатия (SSLException), а не сбой теста: "
                        + failure.getCause());
    }

    @Test
    @DisplayName("Все наборы отключены: beginHandshake даёт SSLHandshakeException")
    void noEnabledSuitesRejectsHandshake() {
        GostSSLEngine client = client();
        client.setEnabledCipherSuites(new String[0]);

        assertThrows(
                SSLHandshakeException.class,
                client::beginHandshake,
                "без наборов шифров рукопожатие невозможно (как в JDK)");
    }

    @Test
    @DisplayName("TLS 1.3 отключён: beginHandshake даёт SSLHandshakeException")
    void noEnabledProtocolsRejectsHandshake() {
        GostSSLEngine server = server();
        server.setEnabledProtocols(new String[0]);

        assertThrows(
                SSLHandshakeException.class,
                server::beginHandshake,
                "без протокола TLS 1.3 рукопожатие невозможно (как в JDK)");
    }
}
