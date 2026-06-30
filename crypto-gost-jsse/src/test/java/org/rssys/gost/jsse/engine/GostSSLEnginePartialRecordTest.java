package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

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
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTestHelper;

/**
 * Тесты частичных TLS-записей (partial records) в GostSSLEngine.
 * Проверяет поведение при неполном заголовке, неполном теле,
 * и недопустимом типе контента во время handshake.
 */
class GostSSLEnginePartialRecordTest {

    private static TlsTestHelper.CertBundle rootCa;
    private static TlsTestHelper.CertBundle serverCert;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = TlsTestHelper.createRootCA(params);
        serverCert =
                TlsTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
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

    private static GostSSLEngine createClientEngine() {
        return new GostSSLEngine(
                new GostX509KeyManager(),
                new GostX509TrustManager(null, false),
                "localhost",
                0,
                true);
    }

    private static GostSSLEngine createServerEngine() {
        return new GostSSLEngine(
                serverKm, new GostX509TrustManager(null, false), "localhost", 0, false);
    }
}
