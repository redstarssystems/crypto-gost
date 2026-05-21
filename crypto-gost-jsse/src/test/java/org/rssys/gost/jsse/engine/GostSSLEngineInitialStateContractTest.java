package org.rssys.gost.jsse.engine;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.manager.GostX509KeyManager;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.tls13.TlsTestHelper;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.nio.ByteBuffer;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Проверяет JSSE-контракт для GostSSLEngine в INITIAL состоянии
 * (до вызова beginHandshake).
 * <p>
 * Каждый баг, найденный здесь — нарушение JSSE-спецификации,
 * которое могло бы проявиться при интеграции через Netty или
 * любой другой JSSE-consumer.
 */
class GostSSLEngineInitialStateContractTest {

    private static TlsTestHelper.CertBundle rootCa;
    private static TlsTestHelper.CertBundle serverCert;
    private static GostX509KeyManager serverKm;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        rootCa = TlsTestHelper.createRootCA(params);
        serverCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
        serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("default", CertificateBridge.toJcaChain(serverCert.cert, rootCa.cert), serverCert.priv);
    }

    @Test
    @DisplayName("getHandshakeStatus() в INITIAL возвращает NOT_HANDSHAKING")
    void testHandshakeStatusInInitial() {
        GostSSLEngine clientEng = createClientEngine();
        GostSSLEngine serverEng = createServerEngine();

        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                clientEng.getHandshakeStatus(),
                "клиент INITIAL -> NOT_HANDSHAKING");
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                serverEng.getHandshakeStatus(),
                "сервер INITIAL -> NOT_HANDSHAKING");
    }

    @Test
    @DisplayName("getSession() в INITIAL: не null, SSL_NULL_WITH_NULL_NULL")
    void testGetSessionInInitial() {
        GostSSLEngine engine = createClientEngine();
        var session = engine.getSession();
        assertNotNull(session, "session не должен быть null в INITIAL");
        assertEquals(GostJsseConstants.SSL_NULL_CIPHER, session.getCipherSuite(),
                "cipher suite до handshake должен быть SSL_NULL_WITH_NULL_NULL");
        assertTrue(session.getPacketBufferSize() > 0,
                "packetBufferSize должен быть > 0");
        assertTrue(session.getApplicationBufferSize() > 0,
                "applicationBufferSize должен быть > 0");
    }

    @Test
    @DisplayName("getHandshakeSession() в INITIAL возвращает null")
    void testGetHandshakeSessionInInitial() {
        GostSSLEngine engine = createClientEngine();
        assertNull(engine.getHandshakeSession(),
                "getHandshakeSession() должен быть null до beginHandshake");
    }

    @Test
    @DisplayName("getDelegatedTask() в INITIAL возвращает null")
    void testGetDelegatedTaskInInitial() {
        GostSSLEngine engine = createClientEngine();
        assertNull(engine.getDelegatedTask(),
                "getDelegatedTask() должен быть null до beginHandshake");
    }

    @Test
    @DisplayName("isInboundDone() / isOutboundDone() в INITIAL: false")
    void testIsDoneInInitial() {
        GostSSLEngine engine = createClientEngine();
        assertFalse(engine.isInboundDone(), "isInboundDone() должен быть false в INITIAL");
        assertFalse(engine.isOutboundDone(), "isOutboundDone() должен быть false в INITIAL");
    }

    @Test
    @DisplayName("getEnabledCipherSuites() в INITIAL: не пуст, содержит ГОСТ-наборы")
    void testEnabledCipherSuitesInInitial() {
        GostSSLEngine engine = createClientEngine();
        String[] suites = engine.getEnabledCipherSuites();
        assertNotNull(suites);
        assertTrue(suites.length > 0, "enabled cipher suites не должны быть пусты");
        boolean hasGost = false;
        for (String s : suites) {
            if (s.contains("GOST")) {
                hasGost = true;
                break;
            }
        }
        assertTrue(hasGost, "enabled cipher suites должны содержать ГОСТ-набор");
    }

    @Test
    @DisplayName("getUseClientMode() после setUseClientMode по экземпляру")
    void testUseClientMode() {
        GostSSLEngine clientEng = createClientEngine();
        GostSSLEngine serverEng = createServerEngine();

        assertTrue(clientEng.getUseClientMode(), "клиентский engine должен вернуть true");
        assertFalse(serverEng.getUseClientMode(), "серверный engine должен вернуть false");
    }

    @Test
    @DisplayName("setEnableSessionCreation() не бросает в INITIAL")
    void testEnableSessionCreation() {
        GostSSLEngine engine = createClientEngine();
        // По контракту не бросает в любом состоянии
        engine.setEnableSessionCreation(true);
        engine.setEnableSessionCreation(false);
    }

    @Test
    @DisplayName("Клиент: wrap() в INITIAL стартует handshake")
    void testClientWrapImplicitStart() throws Exception {
        GostSSLEngine engine = createClientEngine();
        ByteBuffer dst = ByteBuffer.allocate(16640);
        SSLEngineResult r = engine.wrap(ByteBuffer.allocate(0), dst);
        dst.flip();

        // Должен произвести ClientHello
        assertTrue(r.bytesProduced() > 0, "wrap должен произвести ClientHello");
        assertEquals(SSLEngineResult.Status.OK, r.getStatus());
        assertEquals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
                engine.getHandshakeStatus(),
                "после implicit-start engine должен быть в HANDSHAKE");
    }

    @Test
    @DisplayName("Сервер: wrap() в INITIAL возвращает NEED_UNWRAP")
    void testServerWrapInInitial() throws Exception {
        GostSSLEngine engine = createServerEngine();
        ByteBuffer dst = ByteBuffer.allocate(16640);
        SSLEngineResult r = engine.wrap(ByteBuffer.allocate(0), dst);

        assertEquals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
                r.getHandshakeStatus(),
                "серверный wrap в INITIAL должен вернуть NEED_UNWRAP");
        assertEquals(0, r.bytesProduced(),
                "серверный wrap в INITIAL должен произвести 0 байт");
    }

    @Test
    @DisplayName("unwraps c пустым src: BUFFER_UNDERFLOW, не начинает handshake")
    void testUnwrapEmptyBufferUnderflow() throws Exception {
        // Клиент
        GostSSLEngine clientEng = createClientEngine();
        ByteBuffer empty = ByteBuffer.allocate(0);
        ByteBuffer dst = ByteBuffer.allocate(16640);
        SSLEngineResult r = clientEng.unwrap(empty, dst);
        assertEquals(SSLEngineResult.Status.BUFFER_UNDERFLOW, r.getStatus(),
                "пустой unwrap на клиенте должен вернуть BUFFER_UNDERFLOW");
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                r.getHandshakeStatus(),
                "должен остаться NOT_HANDSHAKING");

        // Сервер — важно: не должен начать handshake с пустым src
        GostSSLEngine serverEng = createServerEngine();
        empty.clear();
        dst.clear();
        r = serverEng.unwrap(empty, dst);
        assertEquals(SSLEngineResult.Status.BUFFER_UNDERFLOW, r.getStatus(),
                "пустой unwrap на сервере должен вернуть BUFFER_UNDERFLOW");
        assertEquals(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                r.getHandshakeStatus(),
                "не должен начинать handshake на пустом unwrap");
    }

    @Test
    @DisplayName("Сервер: unwrap() с валидным ClientHello стартует handshake")
    void testServerUnwrapImplicitStart() throws Exception {
        // Сначала получаем ClientHello от клиента
        GostSSLEngine clientEng = createClientEngine();
        clientEng.beginHandshake();
        ByteBuffer dst = ByteBuffer.allocate(16640);
        SSLEngineResult wrapR = clientEng.wrap(ByteBuffer.allocate(0), dst);
        dst.flip();
        assertTrue(wrapR.bytesProduced() > 0, "клиент должен произвести ClientHello");

        GostSSLEngine serverEng = createServerEngine();
        ByteBuffer serverDst = ByteBuffer.allocate(16640);
        SSLEngineResult unwrapR = serverEng.unwrap(dst, serverDst);

        assertEquals(SSLEngineResult.Status.OK, unwrapR.getStatus(),
                "сервер должен принять ClientHello");
        assertTrue(unwrapR.bytesConsumed() > 0,
                "сервер должен потребить ClientHello");
        assertEquals(SSLEngineResult.HandshakeStatus.NEED_WRAP,
                serverEng.getHandshakeStatus(),
                "сервер должен быть готов отправить ServerHello");
    }

    @Test
    @DisplayName("closeOutbound() легален, closeInbound() без closeOutbound закрывает inbound (RFC 8446 §6.1)")
    void testCloseInInitial() throws Exception {
        GostSSLEngine engine = createClientEngine();
        // closeOutbound() всегда легален по JSSE-контракту
        engine.closeOutbound();
        assertTrue(engine.isOutboundDone(), "closeOutbound должен пометить outbound как done");
        assertFalse(engine.isInboundDone(), "inbound не должен быть закрыт на этом этапе");

        // WHY: RFC 8446 §6.1 не требует closeSent перед closeInbound.
        // Netty SslHandler вызывает closeInbound() при channelInactive
        // (обрыв TCP, таймаут) — без close_notify.
        GostSSLEngine engine2 = createClientEngine();
        engine2.closeInbound();
        assertTrue(engine2.isInboundDone(),
                "inbound должен быть done после closeInbound без closeOutbound");

        GostSSLEngine engine3 = createClientEngine();
        engine3.closeOutbound();
        engine3.closeInbound();
        assertTrue(engine3.isOutboundDone(), "outbound должен быть done");
        assertTrue(engine3.isInboundDone(), "inbound должен быть done");
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static GostSSLEngine createClientEngine() {
        GostX509KeyManager km = new GostX509KeyManager();
        GostX509TrustManager tm = new GostX509TrustManager(null, false);
        return new GostSSLEngine(km, tm, "localhost", 0, true);
    }

    private static GostSSLEngine createServerEngine() {
        GostX509TrustManager tm = new GostX509TrustManager(null, false);
        return new GostSSLEngine(serverKm, tm, "localhost", 0, false);
    }

}
