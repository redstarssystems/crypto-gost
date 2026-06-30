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
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsTestHelper;

class GostSslContextHandshakePskResumptionTest {

    private static GostSslContext serverCtx;
    private static GostSslContext clientCtx;
    private static GostSSLSessionContext sharedSessionCtx;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();

        // ----- Сертификаты -----
        TlsTestHelper.CertBundle rootCa = TlsTestHelper.createRootCA(params);
        TlsTestHelper.CertBundle serverCert =
                TlsTestHelper.createCertSignedBy(
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
        GostX509TrustManager trustAll = new GostX509TrustManager(rootCa.cert.getPublicKey(), false);

        // ----- Shared PSK-контекст -----
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        sharedSessionCtx = new GostSSLSessionContext(cs, cs.getHashLen());

        // ----- GostSslContext с shared-контекстом -----
        serverCtx =
                GostSslContextBuilder.forServer(serverKm).sessionContext(sharedSessionCtx).build();
        clientCtx =
                GostSslContextBuilder.forClient()
                        .trustManager(trustAll)
                        .sessionContext(sharedSessionCtx)
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
        // isResumed() в GostSSLSession — JDK 9 default, всегда false.
        // Верифицируем через RFC 8446 §8.1: после отправки NST сервер сохраняет
        // PSK в sharedSessionCtx.pskStore. Если redirectToSharedState не сработала
        // — pskStore будет пуст.

        // RFC 8446 §8.1 — PSK-тикет одноразовый. Сервер сохраняет
        // PSK в finishHandshake() + клиент в saveNewSessionTicket().
        // После второго handshake тикет будет израсходован.
        int pskSizeBeforeClose = sharedSessionCtx.getPskStore().size();
        assertTrue(
                pskSizeBeforeClose > 0,
                "PSK должен быть сохранён после полного рукопожатия: " + pskSizeBeforeClose);

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

        // isResumed() в GostSSLSession — JDK 9 default, всегда false.
        // Детерминированная верификация PSK-пути (peer cert отсутствует,
        // handshake короче) на уровне Netty-интеграции не реализована.
        // PSK-протокол верифицирован в GostSSLEnginePostHandshakeTest.

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
