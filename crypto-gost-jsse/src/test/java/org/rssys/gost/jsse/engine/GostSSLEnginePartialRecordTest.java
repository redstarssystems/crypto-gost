package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.jsse.testkit.EngineTestSupport.runTasks;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Arrays;
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
import org.rssys.gost.tls13.TlsConstants;

/**
 * Тесты частичных TLS-записей (partial records) в GostSSLEngine.
 * Проверяет поведение при неполном заголовке, неполном теле,
 * и недопустимом типе контента во время handshake.
 */
@DisplayName("GostSSLEngine: неполные записи")
class GostSSLEnginePartialRecordTest {

    private static PkixCertTestHelper.CertBundle rootCa;
    private static PkixCertTestHelper.CertBundle serverCert;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        EngineServerPki pki = EngineServerPki.create();
        rootCa = pki.rootCa();
        serverCert = pki.serverCert();
        serverKm = pki.serverKm();
    }

    // ========================================================================
    // 3 байта — неполный заголовок
    // ========================================================================

    @Test
    @DisplayName("3 байта (неполный TLS record header) -> BUFFER_UNDERFLOW, handshake не стартует")
    void testPartialHeader() throws Exception {
        GostSSLEngine server = createServerEngine();
        byte[] partial = new byte[] {22, 0x03, 0x03}; // 3 байта заголовка

        ByteBuffer src = ByteBuffer.wrap(partial);
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        SSLEngineResult r = server.unwrap(src, dst);

        assertEquals(
                SSLEngineResult.Status.BUFFER_UNDERFLOW,
                r.getStatus(),
                "Неполный заголовок — BUFFER_UNDERFLOW");
        assertEquals(
                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                r.getHandshakeStatus(),
                "Handshake не должен начинаться при неполном заголовке");
        assertEquals(0, r.bytesConsumed(), "Байты не должны быть потреблены");
    }

    // ========================================================================
    // Неполное тело: заголовок + 10 байт -> досылка остатка
    // ========================================================================

    @Test
    @DisplayName("Неполное тело ClientHello -> BUFFER_UNDERFLOW, досылка -> OK")
    void testPartialBodyThenComplete() throws Exception {
        // Получаем валидный ClientHello
        GostSSLEngine client = createClientEngine();
        client.beginHandshake();
        ByteBuffer clientHelloBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        client.wrap(ByteBuffer.allocate(0), clientHelloBuf);
        clientHelloBuf.flip();
        byte[] fullRecord = new byte[clientHelloBuf.remaining()];
        clientHelloBuf.get(fullRecord);

        // Разрезаем: заголовок (5) + первые 10 байт тела — неполная запись
        int splitPos = TlsConstants.RECORD_HEADER_SIZE + 10;
        byte[] firstPart = new byte[splitPos];
        System.arraycopy(fullRecord, 0, firstPart, 0, splitPos);

        GostSSLEngine server = createServerEngine();
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        // Первая часть — неполное тело -> BUFFER_UNDERFLOW
        SSLEngineResult r1 = server.unwrap(ByteBuffer.wrap(firstPart), dst);
        assertEquals(
                SSLEngineResult.Status.BUFFER_UNDERFLOW,
                r1.getStatus(),
                "Неполное тело — BUFFER_UNDERFLOW");
        assertEquals(0, r1.bytesConsumed(), "Байты не должны быть потреблены при неполном теле");

        // Досылаем ПОЛНУЮ запись (все байты) — эмуляция того, как
        // XNIO/Netty накапливает буфер и повторяет unwrap с полными данными
        SSLEngineResult r2 = server.unwrap(ByteBuffer.wrap(fullRecord), dst);
        assertEquals(
                SSLEngineResult.Status.OK, r2.getStatus(), "Полная запись после неполной — OK");
        assertTrue(r2.bytesConsumed() > 0, "Байты должны быть потреблены");
        assertEquals(
                SSLEngineResult.HandshakeStatus.NEED_WRAP,
                server.getHandshakeStatus(),
                "Сервер должен быть готов к ответу после ClientHello");
    }

    // ========================================================================
    // Application data во время handshake
    // ========================================================================

    @Test
    @DisplayName("CT_APPLICATION_DATA во время handshake -> SSLException(unexpected_message)")
    void testAppDataDuringHandshake() throws Exception {
        // Получаем ClientHello для implicit start
        GostSSLEngine client = createClientEngine();
        client.beginHandshake();
        ByteBuffer chBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        client.wrap(ByteBuffer.allocate(0), chBuf);
        chBuf.flip();
        byte[] fullRecord = new byte[chBuf.remaining()];
        chBuf.get(fullRecord);

        // Разрезаем: 5 (заголовок) + 10 байт -> частичная запись для implicit start
        int splitPos = TlsConstants.RECORD_HEADER_SIZE + 10;
        byte[] partialCH = new byte[splitPos];
        System.arraycopy(fullRecord, 0, partialCH, 0, splitPos);

        GostSSLEngine server = createServerEngine();
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        // Первая часть запускает handshake (implicit start) -> BUFFER_UNDERFLOW
        SSLEngineResult r1 = server.unwrap(ByteBuffer.wrap(partialCH), dst);
        assertEquals(SSLEngineResult.Status.BUFFER_UNDERFLOW, r1.getStatus());
        // Engine теперь в HANDSHAKE

        // Создаём plaintext запись с CT_APPLICATION_DATA
        byte[] appRecord =
                GostSSLEngine.buildPlaintextRecord(
                        TlsConstants.CT_APPLICATION_DATA, new byte[] {0x01, 0x02, 0x03});

        // Должен выбросить SSLException -> ALERT_UNEXPECTED_MESSAGE
        SSLException ex =
                assertThrows(
                        SSLException.class,
                        () -> server.unwrap(ByteBuffer.wrap(appRecord), dst),
                        "App data во время handshake — SSLException");
        assertTrue(
                ex.getMessage().toLowerCase().contains("unexpected")
                        || ex.getMessage().toLowerCase().contains("expected handshake"),
                "Сообщение об ошибке должно содержать 'unexpected'"
                        + " или 'expected handshake': "
                        + ex.getMessage());
    }

    // ========================================================================
    // change_cipher_spec (RFC 8446 §5, §D.4)
    // ========================================================================

    private static byte[] ccsRecord(byte... payload) {
        return GostSSLEngine.buildPlaintextRecord(TlsConstants.CT_CHANGE_CIPHER_SPEC, payload);
    }

    private static byte[] wrapOnce(GostSSLEngine engine) throws Exception {
        ByteBuffer buf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        engine.wrap(ByteBuffer.allocate(0), buf);
        buf.flip();
        byte[] out = new byte[buf.remaining()];
        buf.get(out);
        return out;
    }

    /** Клиент, отправивший ClientHello и ожидающий ответ сервера (открытая фаза). */
    private static GostSSLEngine clientAfterClientHello() throws Exception {
        GostSSLEngine client = createClientEngine();
        client.beginHandshake();
        wrapOnce(client);
        return client;
    }

    /**
     * Клиент, получивший ServerHello: ключи рукопожатия установлены, дальнейшие записи сервера
     * зашифрованы. Вспомогательный шов для проверки CCS в зашифрованной фазе до Finished.
     */
    private static GostSSLEngine clientAfterServerHello() throws Exception {
        GostSSLEngine client = createClientEngine();
        client.beginHandshake();
        byte[] clientHello = wrapOnce(client);

        GostSSLEngine server = createServerEngine();
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        server.unwrap(ByteBuffer.wrap(clientHello), dst);
        runTasks(server);
        // первая запись сервера - открытый ServerHello
        byte[] serverHello = wrapOnce(server);
        int shLen =
                TlsConstants.RECORD_HEADER_SIZE
                        + (((serverHello[3] & 0xFF) << 8) | (serverHello[4] & 0xFF));
        client.unwrap(
                ByteBuffer.wrap(Arrays.copyOf(serverHello, shLen)),
                ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
        runTasks(client);
        assertTrue(hasReaderRecord(client), "после ServerHello клиент читает зашифрованные записи");
        return client;
    }

    /** Тестовая проверка внутреннего состояния: установлены ли ключи чтения рукопожатия. */
    private static boolean hasReaderRecord(GostSSLEngine engine) throws Exception {
        java.lang.reflect.Field f = GostSSLEngine.class.getDeclaredField("readerRecord");
        f.setAccessible(true);
        return f.get(engine) != null;
    }

    private static SSLEngineResult unwrapBytes(GostSSLEngine engine, byte[] bytes)
            throws SSLException {
        return engine.unwrap(
                ByteBuffer.wrap(bytes), ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH));
    }

    @Test
    @DisplayName("Совместимый change_cipher_spec (0x01) в открытой фазе молча игнорируется")
    void testCompatibilityCcsIgnoredInPlaintextPhase() throws Exception {
        GostSSLEngine client = clientAfterClientHello();
        byte[] ccs = ccsRecord((byte) 0x01);

        SSLEngineResult r = unwrapBytes(client, ccs);

        assertEquals(ccs.length, r.bytesConsumed(), "запись потреблена целиком");
        assertEquals(0, r.bytesProduced(), "данных приложения нет");
    }

    @Test
    @DisplayName("change_cipher_spec с недопустимым содержимым в открытой фазе -> SSLException")
    void testMalformedCcsRejectedInPlaintextPhase() throws Exception {
        assertThrows(
                SSLException.class,
                () -> unwrapBytes(clientAfterClientHello(), ccsRecord((byte) 0x02)));
        assertThrows(SSLException.class, () -> unwrapBytes(clientAfterClientHello(), ccsRecord()));
        assertThrows(
                SSLException.class,
                () -> unwrapBytes(clientAfterClientHello(), ccsRecord((byte) 0x01, (byte) 0x01)));
    }

    @Test
    @DisplayName("Неполный CCS в открытой фазе -> BUFFER_UNDERFLOW, затем потребляется целиком")
    void testIncompleteCcsInPlaintextPhase() throws Exception {
        GostSSLEngine client = clientAfterClientHello();
        byte[] ccs = ccsRecord((byte) 0x01);

        SSLEngineResult partial =
                unwrapBytes(client, Arrays.copyOf(ccs, TlsConstants.RECORD_HEADER_SIZE));
        assertEquals(SSLEngineResult.Status.BUFFER_UNDERFLOW, partial.getStatus());
        assertEquals(0, partial.bytesConsumed());

        assertEquals(ccs.length, unwrapBytes(client, ccs).bytesConsumed());
    }

    @Test
    @DisplayName("CCS до первого ClientHello отвергается на сервере и на клиенте")
    void testCcsBeforeClientHelloRejected() {
        byte[] ccs = ccsRecord((byte) 0x01);

        assertThrows(SSLException.class, () -> unwrapBytes(createServerEngine(), ccs));
        assertThrows(SSLException.class, () -> unwrapBytes(createClientEngine(), ccs));
    }

    @Test
    @DisplayName("Сервер с явным beginHandshake(): CCS первой записью -> SSLException")
    void testCcsBeforeClientHelloRejectedAfterExplicitBeginOnServer() throws Exception {
        GostSSLEngine server = createServerEngine();
        server.beginHandshake();

        assertThrows(SSLException.class, () -> unwrapBytes(server, ccsRecord((byte) 0x01)));
    }

    @Test
    @DisplayName(
            "Клиент с beginHandshake(), но до записи ClientHello: входящий CCS -> SSLException")
    void testCcsRejectedOnClientBeforeClientHelloWritten() throws Exception {
        GostSSLEngine client = createClientEngine();
        client.beginHandshake();

        assertThrows(SSLException.class, () -> unwrapBytes(client, ccsRecord((byte) 0x01)));
    }

    @Test
    @DisplayName("Клиент после записи ClientHello принимает совместимый CCS")
    void testCcsAcceptedOnClientAfterClientHelloWritten() throws Exception {
        GostSSLEngine client = clientAfterClientHello();
        byte[] ccs = ccsRecord((byte) 0x01);

        assertEquals(ccs.length, unwrapBytes(client, ccs).bytesConsumed());
    }

    @Test
    @DisplayName("Сервер после принятого ClientHello принимает совместимый CCS")
    void testCcsAcceptedOnServerAfterClientHello() throws Exception {
        GostSSLEngine client = createClientEngine();
        client.beginHandshake();
        byte[] clientHello = wrapOnce(client);
        GostSSLEngine server = createServerEngine();
        server.beginHandshake();
        unwrapBytes(server, clientHello);
        runTasks(server);
        byte[] ccs = ccsRecord((byte) 0x01);

        assertEquals(ccs.length, unwrapBytes(server, ccs).bytesConsumed());
    }

    @Test
    @DisplayName("Совместимый CCS в зашифрованной фазе до Finished молча игнорируется")
    void testCcsIgnoredInEncryptedPhaseBeforeFinished() throws Exception {
        GostSSLEngine client = clientAfterServerHello();
        byte[] ccs = ccsRecord((byte) 0x01);

        SSLEngineResult r = unwrapBytes(client, ccs);

        assertEquals(ccs.length, r.bytesConsumed());
        assertEquals(0, r.bytesProduced());
    }

    @Test
    @DisplayName("CCS в зашифрованной фазе, разрезанный между заголовком и телом, ждёт остаток")
    void testCcsSplitBetweenHeaderAndBodyInEncryptedPhase() throws Exception {
        GostSSLEngine client = clientAfterServerHello();
        byte[] ccs = ccsRecord((byte) 0x01);

        SSLEngineResult partial =
                unwrapBytes(client, Arrays.copyOf(ccs, TlsConstants.RECORD_HEADER_SIZE));
        assertEquals(SSLEngineResult.Status.BUFFER_UNDERFLOW, partial.getStatus());
        assertEquals(0, partial.bytesConsumed(), "неполный CCS не потребляется");

        assertEquals(ccs.length, unwrapBytes(client, ccs).bytesConsumed());
    }

    @Test
    @DisplayName("CCS с недопустимыми длиной или значением в зашифрованной фазе -> SSLException")
    void testMalformedCcsRejectedInEncryptedPhase() throws Exception {
        assertThrows(
                SSLException.class,
                () -> unwrapBytes(clientAfterServerHello(), ccsRecord((byte) 0x02)));
        assertThrows(SSLException.class, () -> unwrapBytes(clientAfterServerHello(), ccsRecord()));
        assertThrows(
                SSLException.class,
                () -> unwrapBytes(clientAfterServerHello(), ccsRecord((byte) 0x01, (byte) 0x01)));
    }

    // ========================================================================
    // Размер plaintext-записи: TLSPlaintext.length ≤ 2^14 (RFC 8446 §5.1)
    // ========================================================================

    @Test
    @DisplayName("Plaintext-запись payloadLen > 2^14 -> SSLException(record_overflow)")
    void testPlaintextRecordOverflow() throws Exception {
        GostSSLEngine server = createServerEngine();
        // Только заголовок: проверка размера срабатывает до ожидания полного тела,
        // поэтому досылать 16 КБ не нужно — оверсайз отвергается сразу.
        byte[] oversized = plaintextHeader(TlsConstants.MAX_PLAINTEXT_LENGTH + 1);
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        SSLException ex =
                assertThrows(
                        SSLException.class,
                        () -> server.unwrap(ByteBuffer.wrap(oversized), dst),
                        "Оверсайз plaintext-запись должна отвергаться");
        assertTrue(
                ex.getMessage().toLowerCase().contains("too large")
                        || ex.getMessage().toLowerCase().contains("overflow"),
                "Сообщение должно указывать на превышение размера: " + ex.getMessage());
    }

    @Test
    @DisplayName("Plaintext-запись payloadLen == 2^14 -> без overflow (граница включительна)")
    void testPlaintextRecordAtLimit() throws Exception {
        GostSSLEngine server = createServerEngine();
        // Ровно предел: overflow не должен срабатывать; тело не досылаем -> BUFFER_UNDERFLOW.
        byte[] atLimit = plaintextHeader(TlsConstants.MAX_PLAINTEXT_LENGTH);
        ByteBuffer dst = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        SSLEngineResult r = server.unwrap(ByteBuffer.wrap(atLimit), dst);
        assertEquals(
                SSLEngineResult.Status.BUFFER_UNDERFLOW,
                r.getStatus(),
                "Запись ровно в предел не должна давать overflow");
    }

    private static byte[] plaintextHeader(int payloadLen) {
        return new byte[] {
            TlsConstants.CT_HANDSHAKE,
            0x03,
            0x03,
            (byte) ((payloadLen >> 8) & 0xFF),
            (byte) (payloadLen & 0xFF)
        };
    }

    private static GostSSLEngine createClientEngine() {
        return new GostSSLEngine(
                new GostX509KeyManager(),
                GostX509TrustManager.insecureTrustAll(),
                "localhost",
                0,
                true);
    }

    private static GostSSLEngine createServerEngine() {
        return new GostSSLEngine(
                serverKm, GostX509TrustManager.insecureTrustAll(), "localhost", 0, false);
    }
}
