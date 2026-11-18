package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.feedUntilTask;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.runTasks;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.wrapPending;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Параметры {@link GostSSLEngine}: снимок при начале рукопожатия, семантика
 * {@code setSSLParameters} как в JDK, проверка значений, размеры буферов.
 */
@DisplayName("GostSSLEngine: параметры SSLParameters и размеры буферов")
class GostSSLEngineParametersTest {

    private static final int BIG_BUFFER =
            4 * (TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);

    private static PkixCertTestHelper.CertBundle rootCa;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
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

    private static GostSSLEngine server() {
        return new GostSSLEngine(
                serverKm,
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert)),
                "localhost",
                0,
                false);
    }

    /** Клиент с проверкой имени (HTTPS) к хосту, имя которого в сертификате сервера не значится. */
    private static GostSSLEngine clientForWrongHost() {
        return GostSSLEngine.createForClient(
                new GostX509KeyManager(),
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert)),
                "wrong.example",
                0,
                null);
    }

    @Test
    @DisplayName(
            "Поздний setSSLParameters без проверки имени не отключает сверку у идущего рукопожатия")
    void lateEndpointIdentificationChangeDoesNotDisableNameCheck() throws Exception {
        GostSSLEngine client = clientForWrongHost();
        GostSSLEngine server = server();

        client.beginHandshake();
        ByteBuffer clientHello = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(client, clientHello);
        clientHello.flip();
        feedUntilTask(server, clientHello);
        ByteBuffer serverFlight = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(server, serverFlight);
        serverFlight.flip();
        feedUntilTask(client, serverFlight);
        assertEquals(
                SSLEngineResult.HandshakeStatus.NEED_TASK,
                client.getHandshakeStatus(),
                "предусловие: проверка сертификата сервера ещё не выполнена");

        // Приложение снимает проверку имени между началом проверки и её выполнением
        SSLParameters lateParameters = client.getSSLParameters();
        lateParameters.setEndpointIdentificationAlgorithm(null);
        client.setSSLParameters(lateParameters);
        assertEquals(
                null,
                client.getSSLParameters().getEndpointIdentificationAlgorithm(),
                "геттер показывает новое значение");

        runTasks(client);

        assertThrows(
                SSLException.class,
                () -> client.wrap(ByteBuffer.allocate(0), ByteBuffer.allocate(BIG_BUFFER)),
                "сертификат с чужим именем должен быть отвергнут по снимку параметров");
    }

    @Test
    @DisplayName(
            "После кругового вызова обязательный режим работает: клиент без сертификата отвергается")
    void clientWithoutCertificateIsRejectedAfterRoundTrip() {
        GostSSLEngine server = server();
        server.setNeedClientAuth(true);
        server.setSSLParameters(server.getSSLParameters());
        GostSSLEngine client =
                GostSSLEngine.createForClientNoHostnameCheck(
                        new GostX509KeyManager(),
                        GostX509TrustManager.insecureTrustAll(),
                        "localhost",
                        0,
                        null);

        RuntimeException failure =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                GostSSLEngineLoopbackTest.doLoopback(
                                        client,
                                        server,
                                        org.rssys.gost.tls13.transport.InMemoryTlsTransport
                                                .newPair()),
                        "mTLS обязателен: рукопожатие без клиентского сертификата не завершается");
        assertTrue(
                failure.getCause() instanceof SSLException,
                "причина отказа - ошибка рукопожатия: " + failure.getCause());
    }

    @Test
    @DisplayName("Сеттеры need и want заменяют друг друга, как в JDK")
    void clientAuthSettersReplaceEachOther() {
        GostSSLEngine engine = server();

        engine.setNeedClientAuth(true);
        engine.setWantClientAuth(true);
        assertFalse(engine.getNeedClientAuth(), "want заменил need");
        assertTrue(engine.getWantClientAuth());

        engine.setNeedClientAuth(true);
        assertTrue(engine.getNeedClientAuth(), "need заменил want");
        assertFalse(engine.getWantClientAuth());

        engine.setWantClientAuth(false);
        assertFalse(engine.getNeedClientAuth(), "want(false) даёт режим «не запрашивать»");
        assertFalse(engine.getWantClientAuth());
    }

    @Test
    @DisplayName("setSSLParameters: need включает обязательный режим и сбрасывает want")
    void needClientAuthOverridesWant() {
        GostSSLEngine engine = server();
        engine.setWantClientAuth(true);

        SSLParameters parameters = new SSLParameters();
        parameters.setNeedClientAuth(true);
        engine.setSSLParameters(parameters);

        assertTrue(engine.getNeedClientAuth(), "обязательный режим включён");
        assertFalse(engine.getWantClientAuth(), "запрашиваемый режим сброшен");
    }

    @Test
    @DisplayName("setSSLParameters: want включает запрашиваемый режим и сбрасывает need")
    void wantClientAuthOverridesNeed() {
        GostSSLEngine engine = server();
        engine.setNeedClientAuth(true);

        SSLParameters parameters = new SSLParameters();
        parameters.setWantClientAuth(true);
        engine.setSSLParameters(parameters);

        assertFalse(engine.getNeedClientAuth(), "обязательный режим сброшен");
        assertTrue(engine.getWantClientAuth(), "запрашиваемый режим включён");
    }

    @Test
    @DisplayName("setSSLParameters без need и want: клиентский сертификат не запрашивается")
    void noClientAuthResetsBothFlags() {
        GostSSLEngine engine = server();
        engine.setNeedClientAuth(true);
        engine.setSSLParameters(new SSLParameters());

        assertFalse(engine.getNeedClientAuth(), "need сброшен");
        assertFalse(engine.getWantClientAuth(), "want сброшен");
    }

    @Test
    @DisplayName("setSSLParameters: пустой массив ALPN снимает ранее заданные протоколы")
    void emptyAlpnArrayClearsProtocols() {
        GostSSLEngine engine = server();
        SSLParameters withProtocols = new SSLParameters();
        withProtocols.setApplicationProtocols(new String[] {"h2", "http/1.1"});
        engine.setSSLParameters(withProtocols);
        assertArrayEquals(
                new String[] {"h2", "http/1.1"},
                engine.getSSLParameters().getApplicationProtocols(),
                "предусловие: протоколы заданы");

        SSLParameters cleared = new SSLParameters();
        cleared.setApplicationProtocols(new String[0]);
        engine.setSSLParameters(cleared);

        assertEquals(
                0,
                engine.getSSLParameters().getApplicationProtocols().length,
                "пустой массив должен снять протоколы");
    }

    @Test
    @DisplayName("Наборы шифров и протоколы: пустой массив допустим, неизвестное имя отвергается")
    void enabledNamesValidation() {
        GostSSLEngine engine = server();

        engine.setEnabledCipherSuites(new String[0]);
        engine.setEnabledProtocols(new String[0]);
        assertEquals(0, engine.getEnabledCipherSuites().length, "пустой набор допустим, как в JDK");
        assertEquals(0, engine.getEnabledProtocols().length, "пустой набор допустим, как в JDK");

        assertThrows(
                IllegalArgumentException.class,
                () -> engine.setEnabledCipherSuites(new String[] {"TLS_NO_SUCH_SUITE"}),
                "неизвестный набор");
        assertThrows(
                IllegalArgumentException.class,
                () -> engine.setEnabledProtocols(new String[] {"TLSv1.2"}),
                "неподдерживаемый протокол");
        assertThrows(IllegalArgumentException.class, () -> engine.setEnabledCipherSuites(null));
        assertThrows(IllegalArgumentException.class, () -> engine.setEnabledProtocols(null));
    }

    @Test
    @DisplayName("Запрос max_fragment_length: 0 допустим, недопустимый код отвергается")
    void maxFragmentLengthRequestValidation() {
        GostSSLEngine engine = clientForWrongHost();

        engine.setClientMaxFragLenRequest(TlsConstants.MAX_FRAG_LEN_512);
        engine.setClientMaxFragLenRequest(0);
        assertThrows(
                IllegalArgumentException.class,
                () -> engine.setClientMaxFragLenRequest(7),
                "код вне 0 и 1-4 не должен молча превращаться в «не запрашивать»");
    }

    @Test
    @DisplayName("Размер сетевого буфера вмещает запись наибольшей длины с заголовком")
    void packetBufferSizeFitsLargestRecord() {
        int packetSize = server().getSession().getPacketBufferSize();

        assertEquals(
                GostJsseConstants.DEFAULT_PACKET_BUFFER_SIZE,
                packetSize,
                "размер из сессии совпадает с константой модуля");
        assertEquals(
                TlsConstants.RECORD_HEADER_SIZE
                        + TlsConstants.MAX_CIPHERTEXT_LENGTH
                        + TlsConstants.RECORD_BUFFER_HEADROOM,
                packetSize,
                "заголовок + наибольшее тело записи + запас движка");
        assertTrue(
                packetSize >= TlsConstants.RECORD_HEADER_SIZE + TlsConstants.MAX_CIPHERTEXT_LENGTH,
                "запись наибольшей длины должна помещаться");
    }

    @Test
    @DisplayName("Списки поддерживаемых протоколов и наборов отдаются копиями")
    void supportedListsAreCopies() {
        String[] protocols = GostJsseConstants.supportedProtocols();
        String[] suites = GostJsseConstants.supportedCipherSuites();
        protocols[0] = "изменено";
        suites[0] = "изменено";

        assertEquals(
                GostJsseConstants.PROTOCOL_TLS_1_3,
                GostJsseConstants.supportedProtocols()[0],
                "правка копии не должна менять глобальный список протоколов");
        assertFalse(
                "изменено".equals(GostJsseConstants.supportedCipherSuites()[0]),
                "правка копии не должна менять глобальный список наборов");
    }
}
