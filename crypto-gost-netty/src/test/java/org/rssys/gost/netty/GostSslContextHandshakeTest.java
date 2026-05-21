package org.rssys.gost.netty;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslHandler;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.util.CryptoRandom;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты GostSslContext через Netty EmbeddedChannel.
 * Избегает TCP — вся коммуникация в памяти, оба SslHandler
 * в одном потоке.
 */
class GostSslContextHandshakeTest {

    private static GostSslContext serverCtx;
    private static GostSslContext clientCtx;
    private static GostSslContext serverMtlsCtx;
    private static GostSslContext clientMtlsCtx;
    private static GostSslContext serverAlpnCtx;
    private static GostSslContext clientAlpnCtx;

    private static TlsTestHelper.CertBundle rootCa;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();

        rootCa = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle serverCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
        TlsTestHelper.CertBundle clientCert = TlsTestHelper.createCertSignedBy(
                params, rootCa.priv, rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x80}, null,
                false, null);

        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry("default", CertificateBridge.toJcaChain(serverCert.cert, rootCa.cert), serverCert.priv);
        serverCtx = GostSslContextBuilder.forServer(serverKm).build();

        GostX509TrustManager trustAll = new GostX509TrustManager(rootCa.cert.getPublicKey(), false);
        clientCtx = GostSslContextBuilder.forClient()
                .trustManager(trustAll)
                .build();

        GostX509KeyManager clientKm = new GostX509KeyManager();
        clientKm.addKeyEntry("client", CertificateBridge.toJcaChain(clientCert.cert, rootCa.cert), clientCert.priv);

        serverMtlsCtx = GostSslContextBuilder.forServer(serverKm)
                .trustManager(new GostX509TrustManager(rootCa.cert.getPublicKey(), false))
                .clientAuth(io.netty.handler.ssl.ClientAuth.REQUIRE)
                .build();
        clientMtlsCtx = GostSslContextBuilder.forClient()
                .trustManager(trustAll)
                .keyManager(clientKm)
                .build();

        serverAlpnCtx = GostSslContextBuilder.forServer(serverKm)
                .applicationProtocols("h2", "http/1.1")
                .build();
        clientAlpnCtx = GostSslContextBuilder.forClient()
                .trustManager(trustAll)
                .applicationProtocols("h2", "http/1.1")
                .build();
    }

    @Test
    @DisplayName("Embedded: send data after handshake")
    void testSendData() throws Exception {
        SslHandler clientSsl = clientCtx.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler serverSsl = serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        EmbeddedChannel clientCh = new EmbeddedChannel(clientSsl);
        EmbeddedChannel serverCh = new EmbeddedChannel(serverSsl);
        doHandshake(clientSsl, serverSsl, clientCh, serverCh);

        clientCh.writeOutbound(Unpooled.wrappedBuffer("hello".getBytes()));
        ByteBuf encrypted = clientCh.readOutbound();
        assertNotNull(encrypted, "зашифрованные данные должны быть");

        serverCh.writeInbound(encrypted.retain());
        encrypted.release();
        ByteBuf decrypted = serverCh.readInbound();
        assertNotNull(decrypted, "расшифрованные данные должны быть");

        String received = decrypted.toString(java.nio.charset.StandardCharsets.UTF_8);
        assertEquals("hello", received);
        decrypted.release();
    }

    @Test
    @DisplayName("ALPN: h2 согласован между клиентом и сервером")
    void testAlpnNegotiation() throws Exception {
        GostX509KeyManager skm = new GostX509KeyManager();
        TlsTestHelper.CertBundle sc = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), rootCa.priv,
                rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
        skm.addKeyEntry("default", CertificateBridge.toJcaChain(sc.cert, rootCa.cert), sc.priv);

        GostSslContext srv = GostSslContextBuilder.forServer(skm)
                .applicationProtocols("h2").build();
        GostSslContext cli = GostSslContextBuilder.forClient()
                .trustManager(new GostX509TrustManager(rootCa.cert.getPublicKey(), false))
                .applicationProtocols("h2").build();

        SslHandler cs = cli.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler ss = srv.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        doHandshake(cs, ss);

        assertEquals("h2", cs.applicationProtocol(),
                "клиентский протокол должен быть h2");
        assertEquals("h2", ss.applicationProtocol(),
                "серверный протокол должен быть h2");
    }

    @Test
    @DisplayName("ALPN mismatch: Netty 4.2+ кидает SSLHandshakeException")
    void testAlpnMismatch() throws Exception {
        GostX509KeyManager skm = new GostX509KeyManager();
        TlsTestHelper.CertBundle sc = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), rootCa.priv,
                rootCa.cert.getPublicKey(), rootCa.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, new byte[]{(byte) 0x80}, null,
                false, null);
        skm.addKeyEntry("default", CertificateBridge.toJcaChain(sc.cert, rootCa.cert), sc.priv);

        GostSslContext srv = GostSslContextBuilder.forServer(skm)
                .applicationProtocols("http/1.1").build();
        GostSslContext cli = GostSslContextBuilder.forClient()
                .trustManager(new GostX509TrustManager(rootCa.cert.getPublicKey(), false))
                .applicationProtocols("h2").build();

        SslHandler cs = cli.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler ss = srv.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);

        assertThrows(Exception.class, () -> doHandshake(cs, ss),
                "handshake при ALPN mismatch падает в Netty 4.2+");
    }

    @Test
    @DisplayName("Embedded: 256 KB round-trip через SslHandler")
    void testLargePayloadRoundTrip() throws Exception {
        SslHandler clientSsl = clientCtx.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler serverSsl = serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        EmbeddedChannel clientCh = new EmbeddedChannel(clientSsl);
        EmbeddedChannel serverCh = new EmbeddedChannel(serverSsl);
        doHandshake(clientSsl, serverSsl, clientCh, serverCh);

        byte[] payload = new byte[256 * 1024];
        CryptoRandom.INSTANCE.nextBytes(payload);
        clientCh.writeOutbound(Unpooled.wrappedBuffer(payload));
        clientCh.flush();

        // WHY: 256 KB не помещаются в одну TLS-запись (max 2^14), wrap()
        // фрагментирует их на несколько записей. Читаем все outbound'ы.
        ByteBuf enc;
        while ((enc = clientCh.readOutbound()) != null) {
            serverCh.writeInbound(enc.retain());
            enc.release();
        }
        serverCh.runPendingTasks();

        // WHY: unwrap() может вернуть данные частями — дренируем все входящие.
        ByteArrayOutputStream baos = new ByteArrayOutputStream(payload.length);
        ByteBuf dec;
        while ((dec = serverCh.readInbound()) != null) {
            byte[] chunk = new byte[dec.readableBytes()];
            dec.readBytes(chunk);
            baos.write(chunk);
            dec.release();
        }
        assertArrayEquals(payload, baos.toByteArray(),
                "256 KB должны пройти round-trip без искажений");
    }

    @Test
    @DisplayName("Embedded: handshake с неверным CA — SSLException")
    void testInvalidCertRejected() throws Exception {
        TlsTestHelper.CertBundle otherCa = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        GostSslContext wrongClient = GostSslContextBuilder.forClient()
                .trustManager(new GostX509TrustManager(otherCa.cert.getPublicKey(), false))
                .build();

        SslHandler cs = wrongClient.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler ss = serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);

        // WHY: assertThrows(Exception.class) слишком широк — поймал бы NPE
        // при сломанной инициализации. Проверяем, что причина — SSL-ошибка.
        // SslHandler оборачивает SSL-исключение в DecoderException.
        try {
            doHandshake(cs, ss);
            fail("handshake с неверным CA должен упасть");
        } catch (Exception e) {
            Throwable cause = (e instanceof ExecutionException) ? e.getCause() : e;
            cause = (cause instanceof DecoderException) ? cause.getCause() : cause;
            assertInstanceOf(SSLException.class, cause,
                    "ошибка должна быть SSL-исключением: " + cause);
        }
    }

    @Test
    @DisplayName("Embedded: частичная доставка TLS-записи (2+3+N байт)")
    void testPartialRecordDelivery() throws Exception {
        SslHandler clientSsl = clientCtx.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler serverSsl = serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        EmbeddedChannel clientCh = new EmbeddedChannel(clientSsl);
        EmbeddedChannel serverCh = new EmbeddedChannel(serverSsl);
        doHandshake(clientSsl, serverSsl, clientCh, serverCh);

        // WHY: TCP может доставить данные частями (2 байта, потом 3, потом остаток).
        // SslHandler.cumulator накапливает до полной записи и лишь тогда
        // вызывает unwrap(). Проверяем, что readInbound() возвращает null
        // пока запись не собрана целиком.
        clientCh.writeOutbound(Unpooled.wrappedBuffer("test".getBytes()));
        ByteBuf fullRecord = clientCh.readOutbound();
        assertNotNull(fullRecord, "зашифрованная запись должна быть");
        byte[] recordBytes = new byte[fullRecord.readableBytes()];
        fullRecord.readBytes(recordBytes);
        fullRecord.release();

        serverCh.writeInbound(Unpooled.wrappedBuffer(recordBytes, 0, 2));
        serverCh.runPendingTasks();
        assertNull(serverCh.readInbound(), "после 2 байт данных быть не должно");

        // WHY: 5 байт = минимальный TLS record header (content type + version + length).
        // SslHandler.cumulator не вызывает unwrap(), пока тело записи не собрано целиком.
        serverCh.writeInbound(Unpooled.wrappedBuffer(recordBytes, 2, 3));
        serverCh.runPendingTasks();
        assertNull(serverCh.readInbound(), "после 5 байт данных быть не должно");

        serverCh.writeInbound(Unpooled.wrappedBuffer(recordBytes, 5, recordBytes.length - 5));
        serverCh.runPendingTasks();

        ByteBuf decrypted = serverCh.readInbound();
        assertNotNull(decrypted, "после полной записи данные должны появиться");
        assertEquals("test", decrypted.toString(StandardCharsets.UTF_8));
        decrypted.release();
    }

    @Test
    @DisplayName("Embedded: KeyUpdate через SslHandler — данные доходят")
    void testKeyUpdateThroughNetty() throws Exception {
        SslHandler clientSsl = clientCtx.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler serverSsl = serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        EmbeddedChannel clientCh = new EmbeddedChannel(clientSsl);
        EmbeddedChannel serverCh = new EmbeddedChannel(serverSsl);
        doHandshake(clientSsl, serverSsl, clientCh, serverCh);

        // WHY: initiateKeyUpdate() — нестандартный метод GostSSLEngine.
        // SslHandler не знает о KeyUpdate, поэтому вызываем напрямую.
        GostSSLEngine gostEngine = (GostSSLEngine) clientSsl.engine();
        gostEngine.initiateKeyUpdate(false);

        clientCh.writeOutbound(Unpooled.wrappedBuffer("after-ku".getBytes()));
        clientCh.flush();

        // WHY: проверяем, что KU действительно отправился. engine.wrap() сперва
        // выталкивает KU (Handshake record), затем — app data. Если KU не был
        // отправлен — readOutbound() вернёт 1 запись, и тест будет false positive.
        int recordCount = 0;
        ByteBuf rec;
        while ((rec = clientCh.readOutbound()) != null) {
            recordCount++;
            serverCh.writeInbound(rec.retain());
            rec.release();
        }
        assertTrue(recordCount > 1,
                "ожидалось >= 2 outbound-записей (KU + данные), получено: " + recordCount);
        serverCh.runPendingTasks();

        ByteBuf decrypted = serverCh.readInbound();
        assertNotNull(decrypted, "данные после KeyUpdate должны расшифроваться");
        assertEquals("after-ku", decrypted.toString(StandardCharsets.UTF_8));
        decrypted.release();
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static void doHandshake(GostSslContext serverCtx, GostSslContext clientCtx)
            throws Exception {
        SslHandler clientSsl = clientCtx.newHandler(UnpooledByteBufAllocator.DEFAULT);
        SslHandler serverSsl = serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        doHandshake(clientSsl, serverSsl);
    }

    private static void doHandshake(SslHandler clientSsl, SslHandler serverSsl)
            throws Exception {
        EmbeddedChannel clientCh = new EmbeddedChannel(clientSsl);
        EmbeddedChannel serverCh = new EmbeddedChannel(serverSsl);
        doHandshake(clientSsl, serverSsl, clientCh, serverCh);
    }

    private static void doHandshake(SslHandler clientSsl, SslHandler serverSsl,
                                    EmbeddedChannel clientCh, EmbeddedChannel serverCh)
            throws Exception {
        // WHY: обмениваемся handshake-сообщениями, пока обе стороны не завершат.
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);

        while (!clientSsl.handshakeFuture().isDone()
                || !serverSsl.handshakeFuture().isDone()) {
            if (System.nanoTime() > deadline) {
                fail("Handshake timed out");
            }

            boolean progressed = false;

            ByteBuf clientOut = clientCh.readOutbound();
            if (clientOut != null) {
                serverCh.writeInbound(clientOut.retain());
                clientOut.release();
                serverCh.runPendingTasks();
                progressed = true;
            }

            ByteBuf serverOut = serverCh.readOutbound();
            if (serverOut != null) {
                clientCh.writeInbound(serverOut.retain());
                serverOut.release();
                clientCh.runPendingTasks();
                progressed = true;
            }

            clientCh.runPendingTasks();
            serverCh.runPendingTasks();

            if (!progressed) {
                Thread.sleep(10);
            }
        }

        clientSsl.handshakeFuture().sync();
        serverSsl.handshakeFuture().sync();
    }

}
