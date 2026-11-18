package org.rssys.gost.netty;

import static org.junit.jupiter.api.Assertions.*;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;

class GostSslContextHandshakePskResumptionTest {

    private static GostSslContext serverCtx;
    private static GostSslContext clientCtx;
    private static GostSSLSessionContext serverSessionCtx;
    private static GostSSLSessionContext clientSessionCtx;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();

        // ----- Сертификаты -----
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle serverCert =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootCa.priv,
                        rootCa.cert.getPublicKey(),
                        rootCa.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        null,
                        false,
                        null);

        GostX509KeyManager serverKm = new GostX509KeyManager();
        serverKm.addKeyEntry(
                "default",
                CertificateBridge.toJca(List.of(serverCert.cert, rootCa.cert)),
                serverCert.priv);
        GostX509TrustManager trustRootCa =
                GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert));

        // ----- Раздельные PSK-контексты клиента и сервера -----
        // Клиентская и серверная записи с одним тикетом имеют разные привязки, а ключ
        // хранилища - байты тикета: в общем контексте они затирали бы друг друга.
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        serverSessionCtx = new GostSSLSessionContext(cs);
        clientSessionCtx = new GostSSLSessionContext(cs);

        serverCtx =
                GostSslContextBuilder.forServer(serverKm).sessionContext(serverSessionCtx).build();
        clientCtx =
                GostSslContextBuilder.forClient()
                        .trustManager(trustRootCa)
                        .sessionContext(clientSessionCtx)
                        .build();
    }

    @Test
    @DisplayName("PSK: полное рукопожатие -> NST -> переподключение -> данные доходят")
    void testPskResumption() throws Exception {
        // ----- 1. Первое соединение — full handshake -----
        SslHandler clientSsl1 =
                clientCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        SslHandler serverSsl1 =
                serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        EmbeddedChannel clientCh1 = new EmbeddedChannel(clientSsl1);
        EmbeddedChannel serverCh1 = new EmbeddedChannel(serverSsl1);
        doHandshake(clientSsl1, serverSsl1, clientCh1, serverCh1);

        // Данные — базовое шифрование работает
        clientCh1.writeOutbound(Unpooled.wrappedBuffer("hello".getBytes()));
        clientCh1.flush();
        drainTo(clientCh1, serverCh1);
        serverCh1.runPendingTasks();
        ByteBuf decrypted = serverCh1.readInbound();
        assertNotNull(decrypted, "данные после полного рукопожатия должны расшифроваться");
        assertEquals("hello", decrypted.toString(StandardCharsets.UTF_8));
        decrypted.release();

        // NST создан в finishHandshake() и ждёт в outgoingQueue.
        // SslHandler не вызывает wrap() после handshake — триггерим writeOutbound,
        // который заодно вытолкнет NST как первый record в outbound.
        serverCh1.writeOutbound(Unpooled.wrappedBuffer(new byte[1]));
        serverCh1.flush();
        serverCh1.runPendingTasks();
        ByteBuf nstRecord = serverCh1.readOutbound();
        assertNotNull(nstRecord, "NST должен быть отправлен после полного рукопожатия");
        clientCh1.writeInbound(nstRecord.retain());
        nstRecord.release();
        // Discard the 1-byte trigger data
        ByteBuf oneByteRecord = serverCh1.readOutbound();
        if (oneByteRecord != null) oneByteRecord.release();
        clientCh1.runPendingTasks();
        // Клиент сохраняет тикет в своём контексте, сервер - в своём (RFC 8446 §8.1).

        // RFC 8446 §8.1 — PSK-тикет одноразовый. Сервер сохраняет
        // PSK в finishHandshake() + клиент в saveNewSessionTicket(, PskEntry.NO_CERTIFICATE_BOUND).
        // После второго handshake тикет будет израсходован.
        assertTrue(
                clientSessionCtx.getPskStore().size() > 0,
                "клиент должен сохранить тикет после полного рукопожатия");
        assertTrue(
                serverSessionCtx.getPskStore().size() > 0,
                "сервер должен сохранить тикет после полного рукопожатия");

        // без drain close() сгенерирует close_notify outbound —
        // ResourceLeakDetector (PARANOID) зафиксирует leak.
        ByteBuf tail;
        while ((tail = clientCh1.readOutbound()) != null) tail.release();
        while ((tail = serverCh1.readOutbound()) != null) tail.release();
        clientCh1.close();
        serverCh1.close();

        // newHandler должен указывать host+port — иначе engine создастся
        // с peerHost=null и PSK lookup по null не найдёт NST из первого handshake.
        SslHandler clientSsl2 =
                clientCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        SslHandler serverSsl2 =
                serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        EmbeddedChannel clientCh2 = new EmbeddedChannel(clientSsl2);
        EmbeddedChannel serverCh2 = new EmbeddedChannel(serverSsl2);
        doHandshake(clientSsl2, serverSsl2, clientCh2, serverCh2);

        // Возобновление действительно произошло: сертификаты не обменивались
        assertTrue(
                ((GostSSLEngine) clientSsl2.engine()).wasResumed(),
                "второе рукопожатие клиента должно быть возобновлением по PSK");
        assertTrue(
                ((GostSSLEngine) serverSsl2.engine()).wasResumed(),
                "второе рукопожатие сервера должно быть возобновлением по PSK");

        // Данные после resumption
        clientCh2.writeOutbound(Unpooled.wrappedBuffer("world".getBytes()));
        clientCh2.flush();
        drainTo(clientCh2, serverCh2);
        serverCh2.runPendingTasks();
        decrypted = serverCh2.readInbound();
        assertNotNull(decrypted, "данные после PSK-возобновления должны расшифроваться");
        assertEquals("world", decrypted.toString(StandardCharsets.UTF_8));
        decrypted.release();

        // Drain + close
        while ((tail = clientCh2.readOutbound()) != null) tail.release();
        while ((tail = serverCh2.readOutbound()) != null) tail.release();
        clientCh2.close();
        serverCh2.close();
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static void doHandshake(
            SslHandler clientSsl,
            SslHandler serverSsl,
            EmbeddedChannel clientCh,
            EmbeddedChannel serverCh)
            throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);

        while (!clientSsl.handshakeFuture().isDone() || !serverSsl.handshakeFuture().isDone()) {
            if (System.nanoTime() > deadline) {
                fail("Тайм-аут рукопожатия");
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

    private static void drainTo(EmbeddedChannel from, EmbeddedChannel to) {
        ByteBuf buf;
        while ((buf = from.readOutbound()) != null) {
            to.writeInbound(buf.retain());
            buf.release();
        }
    }
}
