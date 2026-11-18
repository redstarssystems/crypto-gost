package org.rssys.gost.netty;

import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslHandler;
import java.security.Security;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Общая оснастка тестов Netty: сертификаты, менеджеры и прокачка рукопожатия между двумя
 * {@link EmbeddedChannel} с сохранением причин отказа обеих сторон. Алерты, отправленные
 * отказавшей стороной, доходят до пира: это отличает отказ с настоящим кодом от обрыва.
 */
final class NettyTestSupport {

    private static final long HANDSHAKE_TIMEOUT_SECONDS = 15;

    /** Сертификаты и менеджеры одного УЦ. */
    static final class Fixture {
        final PkixCertTestHelper.CertBundle rootCa;
        final PkixCertTestHelper.CertBundle serverCert;
        final PkixCertTestHelper.CertBundle clientCert;

        Fixture() throws Exception {
            Security.addProvider(new RssysGostJsseProvider());
            ECParameters params = ECParameters.tc26a256();
            rootCa = PkixCertTestHelper.createRootCA(params);
            serverCert = leaf(params, new String[] {"localhost"});
            clientCert = leaf(params, null);
        }

        private PkixCertTestHelper.CertBundle leaf(ECParameters params, String[] dnsNames)
                throws Exception {
            return PkixCertTestHelper.createCertSignedBy(
                    params,
                    rootCa.priv,
                    rootCa.cert.getPublicKey(),
                    rootCa.subjectDn,
                    "20240501120000Z",
                    "21060101120000Z",
                    dnsNames,
                    new byte[] {(byte) 0x80},
                    null,
                    false,
                    null);
        }

        GostX509KeyManager serverKeyManager() throws Exception {
            return keyManager("default", serverCert);
        }

        GostX509KeyManager clientKeyManager() throws Exception {
            return keyManager("client", clientCert);
        }

        /** Менеджер доверия с единственным якорем: корнем этого УЦ. */
        GostX509TrustManager rootTrust() {
            return GostX509TrustManager.fromTrustAnchors(TrustAnchors.ofCertificate(rootCa.cert));
        }

        private GostX509KeyManager keyManager(String alias, PkixCertTestHelper.CertBundle bundle)
                throws Exception {
            GostX509KeyManager km = new GostX509KeyManager();
            km.addKeyEntry(
                    alias, CertificateBridge.toJca(List.of(bundle.cert, rootCa.cert)), bundle.priv);
            return km;
        }
    }

    /** Итог рукопожатия: причина отказа каждой стороны или null, если сторона завершила успешно. */
    record Outcome(Throwable clientFailure, Throwable serverFailure) {

        boolean succeeded() {
            return clientFailure == null && serverFailure == null;
        }

        /** Есть ли в цепочке причин клиента алерт пира с таким кодом. */
        boolean clientSawAlert(int code) {
            return hasAlertCode(clientFailure, code);
        }
    }

    private NettyTestSupport() {}

    static Outcome handshake(SslHandler clientSsl, SslHandler serverSsl) {
        return handshake(
                new EmbeddedChannel(clientSsl),
                new EmbeddedChannel(serverSsl),
                clientSsl,
                serverSsl);
    }

    /**
     * Прокачивает рукопожатие, пока обе стороны не завершат его или одна не откажет. Обмен
     * продолжается, пока есть исходящие записи, чтобы алерт отказавшей стороны дошёл до пира, в
     * том числе когда пир уже завершил своё рукопожатие успешно.
     */
    static Outcome handshake(
            EmbeddedChannel clientCh,
            EmbeddedChannel serverCh,
            SslHandler clientSsl,
            SslHandler serverSsl) {
        Throwable clientError = null;
        Throwable serverError = null;
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(HANDSHAKE_TIMEOUT_SECONDS);
        int idleRounds = 0;
        try {
            while (true) {
                boolean bothDone =
                        clientSsl.handshakeFuture().isDone()
                                && serverSsl.handshakeFuture().isDone();
                boolean anyFailed =
                        failed(clientSsl)
                                || failed(serverSsl)
                                || clientError != null
                                || serverError != null;
                // Выходим только после пустого раунда: рукопожатие одной стороны может
                // закончиться раньше, чем до неё дойдёт отказ другой (алерт в пути)
                if (idleRounds >= 3 && (bothDone || anyFailed)) {
                    break;
                }
                if (System.nanoTime() > deadline) {
                    fail("Тайм-аут рукопожатия");
                }
                boolean progressed = false;
                ByteBuf clientOut = clientCh.readOutbound();
                if (clientOut != null) {
                    progressed = true;
                    try {
                        serverCh.writeInbound(clientOut);
                    } catch (Exception e) {
                        serverError = unwrap(e);
                    }
                }
                ByteBuf serverOut = serverCh.readOutbound();
                if (serverOut != null) {
                    progressed = true;
                    try {
                        clientCh.writeInbound(serverOut);
                    } catch (Exception e) {
                        clientError = unwrap(e);
                    }
                }
                clientError = runTasks(clientCh, clientError);
                serverError = runTasks(serverCh, serverError);
                idleRounds = progressed ? 0 : idleRounds + 1;
                if (!progressed) {
                    sleepBriefly();
                }
            }
            return new Outcome(
                    failureOf(clientSsl, clientError), failureOf(serverSsl, serverError));
        } finally {
            closeQuietly(clientCh);
            closeQuietly(serverCh);
        }
    }

    private static boolean failed(SslHandler handler) {
        return handler.handshakeFuture().isDone() && !handler.handshakeFuture().isSuccess();
    }

    private static Throwable failureOf(SslHandler handler, Throwable caught) {
        if (handler.handshakeFuture().isDone() && !handler.handshakeFuture().isSuccess()) {
            return unwrap(handler.handshakeFuture().cause());
        }
        return caught;
    }

    private static Throwable runTasks(EmbeddedChannel channel, Throwable previous) {
        try {
            channel.runPendingTasks();
        } catch (Exception e) {
            return previous != null ? previous : unwrap(e);
        }
        return previous;
    }

    private static void sleepBriefly() {
        try {
            Thread.sleep(5);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fail("Поток прерван во время рукопожатия");
        }
    }

    static void closeQuietly(EmbeddedChannel channel) {
        try {
            channel.finishAndReleaseAll();
        } catch (RuntimeException ignored) {
            // исключение канала уже учтено в итоге рукопожатия
        }
    }

    static Throwable unwrap(Throwable t) {
        Throwable cause = t instanceof ExecutionException ? t.getCause() : t;
        return cause instanceof DecoderException && cause.getCause() != null
                ? cause.getCause()
                : cause;
    }

    static boolean hasAlertCode(Throwable error, int code) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            String message = t.getMessage();
            if (message != null && message.contains("alert " + code)) {
                return true;
            }
        }
        return false;
    }
}
