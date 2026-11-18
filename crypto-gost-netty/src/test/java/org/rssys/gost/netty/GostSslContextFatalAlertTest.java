package org.rssys.gost.netty;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslHandler;
import java.security.Security;
import java.util.List;
import java.util.concurrent.TimeUnit;
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
 * Что получает пир, когда одна сторона отказала соединению: {@code SslHandler} Netty обязан
 * довести до сети fatal alert с настоящим кодом, а не оставить пира с обрывом. Тест фиксирует
 * реакцию контейнера: вызывает ли {@code SslHandler} {@code wrap()} после {@code SSLException} из
 * {@code unwrap()}.
 */
@DisplayName("Netty: fatal alert пиру после отказа соединения")
class GostSslContextFatalAlertTest {

    private static final int ALERT_UNKNOWN_CA = 48;
    private static final int ALERT_BAD_RECORD_MAC = 20;
    private static final long HANDSHAKE_TIMEOUT_SECONDS = 15;

    private static GostSslContext serverCtx;
    private static GostSslContext clientCtx;
    private static GostSslContext clientDistrustingCtx;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle rootCa = PkixCertTestHelper.createRootCA(params);
        PkixCertTestHelper.CertBundle otherRoot = PkixCertTestHelper.createRootCA(params);
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
        serverCtx = GostSslContextBuilder.forServer(serverKm).build();
        clientCtx =
                GostSslContextBuilder.forClient()
                        .trustManager(
                                GostX509TrustManager.fromTrustAnchors(
                                        TrustAnchors.ofCertificate(rootCa.cert)))
                        .build();
        // клиент доверяет другому корню: цепочка сервера проверку не пройдёт
        clientDistrustingCtx =
                GostSslContextBuilder.forClient()
                        .trustManager(
                                GostX509TrustManager.fromTrustAnchors(
                                        TrustAnchors.ofCertificate(otherRoot.cert)))
                        .build();
    }

    /** Пара каналов с обработчиками; рукопожатие прокачивается вручную. */
    private record Channels(
            SslHandler clientSsl,
            SslHandler serverSsl,
            EmbeddedChannel client,
            EmbeddedChannel server) {

        void close() {
            // finishAndReleaseAll повторно бросает исключение канала и затёр бы настоящую
            // причину падения теста
            closeQuietly(client);
            closeQuietly(server);
        }
    }

    private static void closeQuietly(EmbeddedChannel channel) {
        try {
            channel.finishAndReleaseAll();
        } catch (RuntimeException ignored) {
            // исключение канала уже обработано проверками теста
        }
    }

    private static Channels open(GostSslContext client) {
        SslHandler clientSsl = client.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        SslHandler serverSsl =
                serverCtx.newHandler(UnpooledByteBufAllocator.DEFAULT, "localhost", 0);
        return new Channels(
                clientSsl,
                serverSsl,
                new EmbeddedChannel(clientSsl),
                new EmbeddedChannel(serverSsl));
    }

    private static void shuttleOnce(Channels channels) {
        ByteBuf clientOut = channels.client().readOutbound();
        if (clientOut != null) {
            channels.server().writeInbound(clientOut);
            channels.server().runPendingTasks();
        }
        ByteBuf serverOut = channels.server().readOutbound();
        if (serverOut != null) {
            channels.client().writeInbound(serverOut);
            channels.client().runPendingTasks();
        }
        channels.client().runPendingTasks();
        channels.server().runPendingTasks();
    }

    private static void completeHandshake(Channels channels) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(HANDSHAKE_TIMEOUT_SECONDS);
        while (!channels.clientSsl().handshakeFuture().isDone()
                || !channels.serverSsl().handshakeFuture().isDone()) {
            if (System.nanoTime() > deadline) {
                fail("Тайм-аут рукопожатия");
            }
            shuttleOnce(channels);
        }
        channels.clientSsl().handshakeFuture().sync();
        channels.serverSsl().handshakeFuture().sync();
    }

    private static boolean hasAlertCode(Throwable error, int code) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            String message = t.getMessage();
            if (message != null && message.contains("alert " + code)) {
                return true;
            }
        }
        return false;
    }

    @Test
    @DisplayName("Испорченная запись на сервере -> клиент получает fatal alert, не обрыв")
    void tamperedRecordDeliversAlertToClient() throws Exception {
        Channels channels = open(clientCtx);
        try {
            completeHandshake(channels);
            channels.client().writeOutbound(Unpooled.wrappedBuffer(new byte[] {1, 2, 3, 4, 5}));
            ByteBuf record = channels.client().readOutbound();
            assertNotNull(record, "Клиент должен отправить запись с данными");
            // портим последний байт: тег аутентификации не сойдётся, запись дойдёт до проверки
            int last = record.writerIndex() - 1;
            record.setByte(last, record.getByte(last) ^ 0x42);

            // сервер отказывает записи; исключение может прийти из writeInbound
            try {
                channels.server().writeInbound(record);
            } catch (Exception expected) {
                // ошибка проверки записи ожидаема
            }
            try {
                channels.server().runPendingTasks();
            } catch (Exception expected) {
                // повторная выдача исключения канала ожидаема
            }

            ByteBuf alert = channels.server().readOutbound();
            assertNotNull(
                    alert, "Сервер должен отправить fatal alert после ошибки проверки записи");
            DecoderException clientFailure =
                    assertThrows(
                            DecoderException.class,
                            () -> channels.client().writeInbound(alert),
                            "Клиент должен увидеть fatal alert");
            assertTrue(
                    hasAlertCode(clientFailure, ALERT_BAD_RECORD_MAC),
                    "Клиент должен получить код bad_record_mac (20): " + clientFailure);
        } finally {
            channels.close();
        }
    }

    @Test
    @DisplayName("Отказ проверки сертификата клиентом: alert с настоящим кодом уходит на сеть")
    void certificateRejectionDeliversAlertToServer() throws Exception {
        Channels channels = open(clientDistrustingCtx);
        try {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(HANDSHAKE_TIMEOUT_SECONDS);
            while (!channels.clientSsl().handshakeFuture().isDone()) {
                if (System.nanoTime() > deadline) {
                    fail("Тайм-аут: клиент не отверг сертификат (зависание при отказе)");
                }
                try {
                    shuttleOnce(channels);
                } catch (Exception failureDuringShuttle) {
                    // исключение контейнера при отказе допустимо, важен alert на сети
                    break;
                }
            }
            assertTrue(
                    channels.clientSsl().handshakeFuture().isDone(),
                    "Клиент должен завершить рукопожатие отказом");
            assertFalse(
                    channels.clientSsl().handshakeFuture().isSuccess(),
                    "Клиент должен отвергнуть сертификат сервера");

            ByteBuf alert = channels.client().readOutbound();
            assertNotNull(alert, "Клиент должен отправить alert серверу после отказа сертификата");
            // После ServerHello клиент защищает свой alert ключом рукопожатия: внешний тип записи
            // application_data, а настоящий код (unknown_ca) сервер видит после расшифровки
            assertTrue(
                    alert.getUnsignedByte(0) == TlsConstants.CT_APPLICATION_DATA,
                    "Тип записи: application_data (alert защищён ключом рукопожатия)");
            assertTrue(alert.readableBytes() > 7, "Защищённая запись длиннее открытого alert");
            DecoderException serverFailure =
                    assertThrows(
                            DecoderException.class,
                            () -> channels.server().writeInbound(alert.retain()),
                            "Сервер должен увидеть alert клиента");
            assertTrue(
                    hasAlertCode(serverFailure, ALERT_UNKNOWN_CA),
                    "Сервер должен увидеть настоящий код unknown_ca: " + serverFailure);
            alert.release();
        } finally {
            channels.close();
        }
    }
}
