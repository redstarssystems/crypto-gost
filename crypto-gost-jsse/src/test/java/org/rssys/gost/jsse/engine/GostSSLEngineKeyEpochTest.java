package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.feedRunningTasks;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.runTasks;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.wrapPending;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.security.Security;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.testkit.EngineServerPki;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.record.TlsRecord;

/**
 * Эпохи ключей на проводе (RFC 8446 §4.4.4): сразу после своего Finished сервер пишет ключами
 * приложения, а клиент, приняв Finished сервера, сразу ими читает — ещё до отправки своего
 * Finished. Порядок вызовов {@code unwrap}/{@code wrap} у приложения на это влиять не должен.
 */
@DisplayName("GostSSLEngine: эпохи ключей между Finished сервера и Finished клиента")
class GostSSLEngineKeyEpochTest {

    private static final byte[] PAYLOAD = "данные сервера сразу за Finished".getBytes();
    private static final int BIG_BUFFER =
            16 * (TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);

    private static PkixCertTestHelper.CertBundle rootCa;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        EngineServerPki pki = EngineServerPki.create();
        rootCa = pki.rootCa();
        serverKm = pki.serverKm();
    }

    private static GostSSLEngine client() {
        return GostSSLEngine.createForClient(
                new GostX509KeyManager(),
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert)),
                "localhost",
                0,
                null);
    }

    private static GostSSLEngine server() {
        return new GostSSLEngine(
                serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
    }

    /**
     * Полёт сервера (ServerHello…Finished) и сразу за ним запись данных приложения, как у сервера,
     * пишущего до Finished клиента (0.5-RTT). Запись данных собирается текущей записью отправки
     * сервера: после отправки полёта это уже эпоха ключей приложения.
     */
    private static ByteBuffer serverFlightWithData(GostSSLEngine client, GostSSLEngine server)
            throws Exception {
        client.beginHandshake();
        ByteBuffer hello = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(client, hello);
        hello.flip();
        feedRunningTasks(server, hello);

        ByteBuffer wire = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(server, wire);
        wire.put(writerRecord(server).protect(TlsConstants.CT_APPLICATION_DATA, PAYLOAD));
        wire.flip();
        return wire;
    }

    private static TlsRecord writerRecord(GostSSLEngine engine) throws Exception {
        Field field = GostSSLEngine.class.getDeclaredField("writerRecord");
        field.setAccessible(true);
        return (TlsRecord) field.get(engine);
    }

    /** Подаёт байты, пока они потребляются; задачи выполняются по ходу; wrap не вызывается. */
    private static byte[] unwrapAll(GostSSLEngine engine, ByteBuffer wire) throws SSLException {
        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        while (wire.hasRemaining()) {
            SSLEngineResult r = engine.unwrap(wire, app);
            runTasks(engine);
            if (r.bytesConsumed() == 0 && engine.getDelegatedTask() == null) {
                break;
            }
        }
        app.flip();
        byte[] data = new byte[app.remaining()];
        app.get(data);
        return data;
    }

    @Test
    @DisplayName("(б) Finished сервера и его данные в одном буфере, unwrap подряд без wrap")
    void serverDataRightAfterFinishedWithoutWrap() throws Exception {
        GostSSLEngine client = client();
        ByteBuffer wire = serverFlightWithData(client, server());

        byte[] received = unwrapAll(client, wire);

        assertEquals(0, wire.remaining(), "клиент разобрал полёт и запись данных");
        assertArrayEquals(PAYLOAD, received, "данные за Finished читаются ключом приложения сразу");
    }

    @Test
    @DisplayName("(а) unwrap полёта, wrap своего Finished, затем unwrap данных сервера")
    void serverDataAfterClientFinished() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server();
        ByteBuffer wire = serverFlightWithData(client, server);
        // Записи данных в полёте нет: отрезаем её и подаём после wrap клиента
        int dataLength = TlsConstants.RECORD_HEADER_SIZE + PAYLOAD.length + 1 + 16;
        ByteBuffer flight = wire.duplicate();
        flight.limit(wire.limit() - dataLength);
        ByteBuffer data = wire.duplicate();
        data.position(wire.limit() - dataLength);

        assertEquals(0, unwrapAll(client, flight).length);
        ByteBuffer finished = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(client, finished);
        assertTrue(finished.position() > 0, "клиент отправил Finished");

        assertArrayEquals(
                PAYLOAD, unwrapAll(client, data), "данные сервера после Finished клиента");
    }

    @Test
    @DisplayName("close_notify сервера между его Finished и Finished клиента читается клиентом")
    void serverCloseNotifyBeforeClientFinished() throws Exception {
        GostSSLEngine client = client();
        GostSSLEngine server = server();
        client.beginHandshake();
        ByteBuffer hello = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(client, hello);
        hello.flip();
        feedRunningTasks(server, hello);

        ByteBuffer wire = ByteBuffer.allocate(BIG_BUFFER);
        wrapPending(server, wire);
        // Сервер закрывается, не дождавшись Finished клиента: close_notify уходит ключом приложения
        server.closeOutbound();
        server.wrap(ByteBuffer.allocate(0), wire);
        wire.flip();

        ByteBuffer app = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLEngineResult last = null;
        while (wire.hasRemaining()) {
            last = client.unwrap(wire, app);
            runTasks(client);
            if (last.bytesConsumed() == 0) {
                break;
            }
        }
        assertEquals(0, wire.remaining(), "клиент разобрал полёт и close_notify без ошибки");
        assertTrue(client.isInboundDone(), "close_notify сервера принят как закрытие");
    }
}
