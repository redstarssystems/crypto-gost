package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.crl.CrlFetcher;
import org.rssys.gost.jsse.crl.CrlPolicy;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.ocsp.OcspPolicy;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Отказ клиента из-за отзыва сертификата сервера по CRL: пир получает alert certificate_revoked
 * (44), а не общий bad_certificate. Проверка CRL выбрасывает исключение без {@code TlsException},
 * поэтому код alert выбирается по цепочке причин.
 */
@DisplayName("GostSSLEngine: отзыв сертификата сервера по CRL даёт alert 44 пиру")
class GostSSLEngineRevocationAlertTest {

    private static final int BIG_BUFFER =
            4 * (TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);

    private static PkixCertTestHelper.CertBundle rootCa;
    private static PkixCertTestHelper.CertBundle serverLeaf;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        serverLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        (String[]) null,
                        new byte[] {(byte) 0x80},
                        (String[]) null,
                        false,
                        null,
                        PkixCertTestHelper.buildCdpExtension("http://crl.example.com/root.crl"));
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverLeaf.cert, rootCa.cert)),
                serverLeaf.priv);
    }

    private static GostSSLEngine server() {
        return new GostSSLEngine(
                serverKm,
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert)),
                "localhost",
                0,
                false);
    }

    private static GostSSLEngine clientChecking(CrlFetcher fetcher) {
        return GostSSLEngine.createForClient(
                new GostX509KeyManager(),
                GostX509TrustManager.fromTrustAnchors(
                        TrustAnchors.ofCertificate(rootCa.cert),
                        OcspPolicy.IF_PRESENT,
                        null,
                        CrlPolicy.IF_CDP_PRESENT,
                        fetcher),
                "localhost",
                0,
                null);
    }

    /** Доводит клиента до отказа и возвращает отправленную им запись с alert. */
    private static ByteBuffer clientFailureAlert(GostSSLEngine client, GostSSLEngine server)
            throws SSLException {
        client.beginHandshake();
        ByteBuffer clientHello = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(client, clientHello);
        clientHello.flip();
        feedUntilTask(server, clientHello);
        ByteBuffer serverFlight = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(server, serverFlight);
        serverFlight.flip();
        feedUntilTask(client, serverFlight);
        runTasks(client);
        // первый вызов сообщает приложению причину отказа, следующий отдаёт alert пиру
        assertThrows(
                SSLException.class,
                () -> client.wrap(ByteBuffer.allocate(0), ByteBuffer.allocate(BIG_BUFFER)),
                "клиент должен отвергнуть сертификат сервера");
        ByteBuffer alert = ByteBuffer.allocate(BIG_BUFFER);
        client.wrap(ByteBuffer.allocate(0), alert);
        alert.flip();
        return alert;
    }

    @Test
    @DisplayName("Сертификат сервера отозван по CRL: пир получает alert 44")
    void revokedByCrlGivesAlert44() throws Exception {
        byte[] revokedCrl =
                PkixCertTestHelper.buildCrl(
                        new byte[][] {serverLeaf.cert.getSerialNumber()},
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "21060101120000Z",
                        false);
        GostSSLEngine server = server();
        GostSSLEngine client = clientChecking(uri -> revokedCrl.clone());

        ByteBuffer alert = clientFailureAlert(client, server);

        SSLHandshakeException peerView =
                assertThrows(
                        SSLHandshakeException.class,
                        () ->
                                server.unwrap(
                                        alert,
                                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH)),
                        "сервер получает отказ клиента как ошибку рукопожатия");
        assertTrue(
                peerView.getMessage()
                        .contains(String.valueOf(TlsConstants.ALERT_CERTIFICATE_REVOKED)),
                "в сообщении код alert 44: " + peerView.getMessage());
    }

    @Test
    @DisplayName("Отказ без отзыва (CRL не удалось получить при REQUIRE-подобной ошибке) - не 44")
    void failureWithoutRevocationIsNotAlert44() throws Exception {
        GostSSLEngine server = server();
        // Сертификат с чужим именем: отказ проверки имени, а не отзыв
        GostSSLEngine client =
                GostSSLEngine.createForClient(
                        new GostX509KeyManager(),
                        GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.ofCertificate(rootCa.cert)),
                        "wrong.example",
                        0,
                        null);

        ByteBuffer alert = clientFailureAlert(client, server);

        SSLHandshakeException peerView =
                assertThrows(
                        SSLHandshakeException.class,
                        () ->
                                server.unwrap(
                                        alert,
                                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH)));
        assertEquals(
                false,
                peerView.getMessage()
                        .contains(String.valueOf(TlsConstants.ALERT_CERTIFICATE_REVOKED)),
                "не отзыв не должен получать код 44: " + peerView.getMessage());
    }

    /** Подаёт записи отправителя получателю, пока тот не дойдёт до задачи проверки или конца. */
    private static void deliverFlight(GostSSLEngine from, GostSSLEngine to) throws SSLException {
        ByteBuffer flight = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(from, flight);
        flight.flip();
        feedUntilTask(to, flight);
    }

    /** Подаёт все записи отправителя получателю, выполняя его задачи проверки по ходу. */
    private static void deliverAll(GostSSLEngine from, GostSSLEngine to) throws SSLException {
        ByteBuffer flight = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(from, flight);
        flight.flip();
        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        while (flight.hasRemaining()) {
            SSLEngineResult r = to.unwrap(flight, app);
            runTasks(to);
            if (r.bytesConsumed() == 0
                    && to.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                continue;
            }
            if (r.bytesConsumed() == 0) {
                break;
            }
        }
    }

    /** Отказавший движок отдаёт сначала причину приложению, затем alert пиру. */
    private static ByteBuffer rejectionAlert(GostSSLEngine rejecting) throws SSLException {
        runTasks(rejecting);
        assertThrows(
                SSLException.class,
                () -> rejecting.wrap(ByteBuffer.allocate(0), ByteBuffer.allocate(BIG_BUFFER)),
                "движок должен отвергнуть сертификат пира");
        ByteBuffer alert = ByteBuffer.allocate(BIG_BUFFER);
        rejecting.wrap(ByteBuffer.allocate(0), alert);
        alert.flip();
        return alert;
    }

    private static void assertPeerSeesRevocationAlert(GostSSLEngine peer, ByteBuffer alert) {
        SSLHandshakeException peerView =
                assertThrows(
                        SSLHandshakeException.class,
                        () ->
                                peer.unwrap(
                                        alert,
                                        ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH)),
                        "пир получает отказ как ошибку рукопожатия");
        assertTrue(
                peerView.getMessage()
                        .contains(String.valueOf(TlsConstants.ALERT_CERTIFICATE_REVOKED)),
                "в сообщении код alert 44: " + peerView.getMessage());
    }

    @Test
    @DisplayName(
            "mTLS: промежуточный УЦ клиентской цепочки отозван по CRL - сервер отказывает кодом 44")
    void revokedIntermediateOfClientChainGivesAlert44() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle intermediate =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        new byte[] {(byte) 0x04},
                        null,
                        true,
                        0,
                        PkixCertTestHelper.buildCdpExtension("http://crl.example.com/root.crl"));
        PkixCertTestHelper.CertBundle clientLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn,
                        "240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x80},
                        new String[] {org.rssys.gost.pkix.GostOids.EXT_CLIENT_AUTH},
                        false,
                        null);
        byte[] revokedIntermediateCrl =
                PkixCertTestHelper.buildCrl(
                        new byte[][] {intermediate.cert.getSerialNumber()},
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "21060101120000Z",
                        false);
        GostX509KeyManager clientKm = new GostX509KeyManager();
        clientKm.addKeyEntry(
                "client",
                CertificateBridge.toJca(List.of(clientLeaf.cert, intermediate.cert, rootCa.cert)),
                clientLeaf.priv);
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm,
                        GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.ofCertificate(rootCa.cert),
                                OcspPolicy.IF_PRESENT,
                                null,
                                CrlPolicy.IF_CDP_PRESENT,
                                uri -> revokedIntermediateCrl.clone()),
                        "localhost",
                        0,
                        false);
        server.setNeedClientAuth(true);
        GostSSLEngine client =
                GostSSLEngine.createForClientNoHostnameCheck(
                        clientKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, null);

        client.beginHandshake();
        deliverFlight(client, server);
        // клиент принимает сертификат сервера (доверие ко всем) и отвечает своей цепочкой
        deliverAll(server, client);
        deliverFlight(client, server);
        assertEquals(
                SSLEngineResult.HandshakeStatus.NEED_TASK,
                server.getHandshakeStatus(),
                "предусловие: сервер проверяет клиентскую цепочку");

        // Сервер отказывает после своего Finished: его alert защищён ключами приложения, которыми
        // клиент уже читает (RFC 8446 §4.4.4), поэтому код 44 доходит до клиента по проводу
        assertPeerSeesRevocationAlert(client, rejectionAlert(server));
    }

    @Test
    @DisplayName(
            "Отозванный OCSP-ответ сервера (staple): клиент отвергает, сервер получает alert 44")
    void revokedStapleGivesAlert44() throws Exception {
        byte[] revokedStaple =
                org.rssys.gost.pkix.cert.GostOcspResponseBuilder.create(
                                serverLeaf.cert.getSerialNumber())
                        .issuerDn(rootCa.subjectDn)
                        .thisUpdate(java.time.Instant.now())
                        .noNextUpdate()
                        .revoked("20250101000000Z")
                        .sign(rootCa.priv);
        GostSSLEngine server = server();
        server.setOcspResponse(revokedStaple);
        GostSSLEngine client = clientChecking(uri -> null);

        client.beginHandshake();
        deliverFlight(client, server);
        deliverFlight(server, client);
        assertEquals(
                SSLEngineResult.HandshakeStatus.NEED_TASK,
                client.getHandshakeStatus(),
                "предусловие: клиент проверяет сертификат сервера");

        assertPeerSeesRevocationAlert(server, rejectionAlert(client));
    }
}
