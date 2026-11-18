package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.feedRunningTasks;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.runTasks;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.wrapPending;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.List;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Серверный {@link GostSSLEngine} при mTLS, пока идёт проверка сертификата клиента (NEED_TASK).
 *
 * <p>Законный клиент шлёт Certificate, CertificateVerify, Finished и сразу за ними данные одним
 * полётом. Пока задача проверки сертификата не выполнена, {@code unwrap} ничего не потребляет:
 * иначе запись данных, зашифрованная ключами приложения, расшифровывалась бы handshake-ключами
 * и давала ложный {@code decrypt_error}, а данные пира с недоверенным сертификатом уходили бы приложению.
 */
@DisplayName("GostSSLEngine: unwrap при ожидании проверки сертификата клиента (NEED_TASK)")
class GostSSLEngineCertificateTaskTest {

    private static final byte[] PAYLOAD = "GET /ok HTTP/1.1".getBytes();
    private static final int BIG_BUFFER =
            4 * (TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);

    private static PkixCertTestHelper.CertBundle rootCa;
    private static PkixCertTestHelper.CertBundle foreignRoot;
    private static GostX509KeyManager serverKm;
    private static GostX509KeyManager clientKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = PkixCertTestHelper.createRootCA(params);
        foreignRoot = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert = leaf(params, new String[] {"localhost"});
        PkixCertTestHelper.CertBundle clientCert = leaf(params, null);
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        clientKm = new GostX509KeyManager();
        clientKm.addKeyEntry(
                "client",
                CertificateBridge.toJca(List.of(clientCert.cert, rootCa.cert)),
                clientCert.priv);
    }

    private static PkixCertTestHelper.CertBundle leaf(ECParameters params, String[] dns)
            throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                params,
                rootCa.priv,
                rootCa.cert.getPublicKey(),
                rootCa.subjectDn,
                "240501120000Z",
                "21060101120000Z",
                dns,
                new byte[] {(byte) 0x80},
                null,
                false,
                null);
    }

    private static GostSSLEngine server(PkixCertTestHelper.CertBundle clientTrustRoot) {
        GostSSLEngine server =
                new GostSSLEngine(
                        serverKm,
                        GostX509TrustManager.fromTrustAnchors(
                                TrustAnchors.ofCertificate(clientTrustRoot.cert)),
                        "localhost",
                        0,
                        false);
        server.setNeedClientAuth(true);
        return server;
    }

    private static GostSSLEngine client() {
        return GostSSLEngine.createForClient(
                clientKm,
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert)),
                "localhost",
                0,
                null);
    }

    /**
     * Последний полёт клиента (Certificate, CertificateVerify, Finished) и запись данных
     * приложения за ним. Сервер получил ClientHello, клиент обработал весь флайт сервера.
     */
    private static ByteBuffer clientFinalFlight(GostSSLEngine client, GostSSLEngine server)
            throws SSLException {
        client.beginHandshake();
        ByteBuffer clientHello = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(client, clientHello);
        clientHello.flip();
        feedRunningTasks(server, clientHello);

        ByteBuffer serverFlight = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(server, serverFlight);
        serverFlight.flip();
        feedRunningTasks(client, serverFlight);

        ByteBuffer flight = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(client, flight);
        client.wrap(ByteBuffer.wrap(PAYLOAD), flight);
        flight.flip();
        return flight;
    }

    /** Подаёт серверу полёт по одной записи до первого NEED_TASK. */
    private static boolean unwrapUntilTask(GostSSLEngine server, ByteBuffer flight, ByteBuffer dst)
            throws SSLException {
        while (flight.hasRemaining()) {
            SSLEngineResult r = server.unwrap(flight, dst);
            if (server.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                return true;
            }
            if (r.bytesConsumed() == 0) {
                break;
            }
        }
        return false;
    }

    @Test
    @DisplayName("Пока задача проверки сертификата не выполнена, unwrap ничего не потребляет")
    void unwrapConsumesNothingWhileTaskPending() throws Exception {
        GostSSLEngine server = server(rootCa);
        ByteBuffer flight = clientFinalFlight(client(), server);
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        assertTrue(unwrapUntilTask(server, flight, dst), "ожидалась задача проверки сертификата");
        assertTrue(flight.hasRemaining(), "за Certificate в полёте остались записи");

        int positionBefore = flight.position();
        SSLEngineResult r = server.unwrap(flight, dst);

        assertEquals(SSLEngineResult.Status.OK, r.getStatus());
        assertEquals(SSLEngineResult.HandshakeStatus.NEED_TASK, r.getHandshakeStatus());
        assertEquals(0, r.bytesConsumed(), "до выполнения задачи записи не потребляются");
        assertEquals(0, r.bytesProduced());
        assertEquals(positionBefore, flight.position(), "src не должен сдвигаться");
        assertEquals(0, dst.position(), "данные приложения не должны появиться");
    }

    @Test
    @DisplayName("После задачи Finished и данные клиента из того же полёта проходят без ошибок")
    void flightWithDataCompletesAfterTask() throws Exception {
        GostSSLEngine server = server(rootCa);
        ByteBuffer flight = clientFinalFlight(client(), server);
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        assertTrue(unwrapUntilTask(server, flight, dst), "ожидалась задача проверки сертификата");
        runTasks(server);
        while (flight.hasRemaining()) {
            SSLEngineResult r = server.unwrap(flight, dst);
            if (r.bytesConsumed() == 0) {
                break;
            }
        }

        assertEquals(0, flight.remaining(), "весь полёт должен быть обработан");
        dst.flip();
        byte[] received = new byte[dst.remaining()];
        dst.get(received);
        assertArrayEquals(PAYLOAD, received, "данные клиента после Finished должны дойти целыми");
    }

    @Test
    @DisplayName("Отвергнутый сертификат клиента: данные из полёта приложению не отдаются")
    void rejectedCertificateNeverDeliversData() throws Exception {
        GostSSLEngine server = server(foreignRoot);
        ByteBuffer flight = clientFinalFlight(client(), server);
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        assertTrue(unwrapUntilTask(server, flight, dst), "ожидалась задача проверки сертификата");
        runTasks(server);
        assertThrows(
                SSLException.class,
                () -> {
                    while (flight.hasRemaining()) {
                        server.unwrap(flight, dst);
                    }
                },
                "сертификат вне доверия должен прервать рукопожатие");
        assertEquals(0, dst.position(), "данные приложению не отдаются");
    }
}
