package org.rssys.gost.jsse.socket;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.Security;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.jsse.GostSsl;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.testkit.GostTestCerts;

/**
 * Закрытие сокета после {@code closeOutbound()} движка: собранный, но не отданный
 * {@code close_notify} должен дойти до пира. Раньше сокет считал выходную сторону закрытой по
 * самому вызову {@code closeOutbound()}, пропускал отправку, а затем разрушал движок вместе с
 * записью.
 */
@DisplayName("GostSSLSocket.close(): close_notify после closeOutbound движка доходит до пира")
class GostSSLSocketCloseNotifyTest {

    private static SSLContext serverContext;
    private static SSLContext clientContext;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        GostTestCerts.CertChain chain = GostTestCerts.createServerCert();
        String certPem = chain.chain().get(0).toPem();
        String keyPem =
                "-----BEGIN PRIVATE KEY-----\n"
                        + Base64.getMimeEncoder(64, new byte[] {'\n'})
                                .encodeToString(GostDerCodec.encodePrivateKey(chain.key()))
                        + "\n-----END PRIVATE KEY-----\n";
        String caPem = chain.caCert().toPem();
        serverContext = GostSsl.serverContext(certPem, keyPem, caPem);
        clientContext = GostSsl.clientContext(caPem);
    }

    private static GostSSLEngine engineOf(SSLSocket socket) throws Exception {
        Field field = GostSSLSocket.class.getDeclaredField("engine");
        field.setAccessible(true);
        return (GostSSLEngine) field.get(socket);
    }

    private static boolean closeNotifyReceived(GostSSLEngine engine) throws Exception {
        Field field = GostSSLEngine.class.getDeclaredField("closeReceived");
        field.setAccessible(true);
        return field.getBoolean(engine);
    }

    @Test
    @DisplayName("closeOutbound() движка до close() сокета: пир получает close_notify")
    void closeNotifyReachesPeerWhenEngineWasClosedEarlier() throws Exception {
        try (SSLServerSocket server = GostSsl.serverSocket(0, serverContext)) {
            CompletableFuture<Boolean> serverSide =
                    CompletableFuture.supplyAsync(
                            () -> {
                                try (SSLSocket accepted = (SSLSocket) server.accept()) {
                                    accepted.setSoTimeout(5000);
                                    accepted.startHandshake();
                                    InputStream in = accepted.getInputStream();
                                    int value;
                                    do {
                                        value = in.read();
                                    } while (value != -1);
                                    return closeNotifyReceived(engineOf(accepted));
                                } catch (Exception e) {
                                    throw new IllegalStateException(e);
                                }
                            });

            SSLSocket client = GostSsl.socket("localhost", server.getLocalPort(), clientContext);
            // приложение или контейнер закрыли выходную сторону движка раньше сокета
            engineOf(client).closeOutbound();
            client.close();

            assertTrue(
                    serverSide.get(10, TimeUnit.SECONDS),
                    "пир должен получить close_notify, а не просто обрыв соединения");
        }
    }

    @Test
    @DisplayName("Обычное close() без раннего closeOutbound тоже отправляет close_notify")
    void plainCloseSendsCloseNotify() throws Exception {
        try (SSLServerSocket server = GostSsl.serverSocket(0, serverContext)) {
            CompletableFuture<Boolean> serverSide =
                    CompletableFuture.supplyAsync(
                            () -> {
                                try (SSLSocket accepted = (SSLSocket) server.accept()) {
                                    accepted.setSoTimeout(5000);
                                    accepted.startHandshake();
                                    InputStream in = accepted.getInputStream();
                                    int value;
                                    do {
                                        value = in.read();
                                    } while (value != -1);
                                    return closeNotifyReceived(engineOf(accepted));
                                } catch (Exception e) {
                                    throw new IllegalStateException(e);
                                }
                            });

            SSLSocket client = GostSsl.socket("localhost", server.getLocalPort(), clientContext);
            client.close();

            assertEquals(true, serverSide.get(10, TimeUnit.SECONDS));
        }
    }

    @Test
    @DisplayName("close() затирает буфер расшифровки и непрочитанный остаток открытого текста")
    void closeWipesApplicationPlaintext() throws Exception {
        try (SSLServerSocket server = GostSsl.serverSocket(0, serverContext)) {
            CompletableFuture<Void> serverSide =
                    CompletableFuture.runAsync(
                            () -> {
                                try (SSLSocket accepted = (SSLSocket) server.accept()) {
                                    accepted.setSoTimeout(5000);
                                    accepted.startHandshake();
                                    accepted.getOutputStream().write("0123456789".getBytes());
                                    accepted.getOutputStream().flush();
                                    // ждём закрытия клиента, чтобы данные не были потеряны сбросом
                                    while (accepted.getInputStream().read() != -1) {
                                        // до close_notify или обрыва
                                    }
                                } catch (Exception e) {
                                    throw new IllegalStateException(e);
                                }
                            });

            SSLSocket client = GostSsl.socket("localhost", server.getLocalPort(), clientContext);
            client.setSoTimeout(5000);
            InputStream in = client.getInputStream();
            assertEquals('0', in.read(), "прочитан один байт, девять остались в потоке");

            byte[] leftover = (byte[]) fieldOf(in, "leftover");
            byte[] decryptBuffer = ((java.nio.ByteBuffer) fieldOf(in, "readDst")).array();
            assertTrue(leftover != null && leftover.length > 0, "предусловие: остаток есть");

            client.close();

            assertTrue(isZeroed(leftover), "остаток открытого текста затёрт");
            assertTrue(isZeroed(decryptBuffer), "буфер расшифровки затёрт");
            serverSide.get(10, TimeUnit.SECONDS);
        }
    }

    @Test
    @DisplayName(
            "close() из другого потока при идущем чтении: ни нулей вместо данных, ни NPE, буферы затёрты")
    void closeFromAnotherThreadDuringReadKeepsDataIntact() throws Exception {
        final int iterations = 15;
        for (int i = 0; i < iterations; i++) {
            try (SSLServerSocket server = GostSsl.serverSocket(0, serverContext)) {
                CompletableFuture<Void> serverSide =
                        CompletableFuture.runAsync(
                                () -> {
                                    try (SSLSocket accepted = (SSLSocket) server.accept()) {
                                        accepted.setSoTimeout(5000);
                                        accepted.startHandshake();
                                        byte[] chunk = new byte[3000];
                                        java.util.Arrays.fill(chunk, (byte) 'A');
                                        // пишем, пока клиент не закроется: читатель всегда в работе
                                        while (true) {
                                            accepted.getOutputStream().write(chunk);
                                            accepted.getOutputStream().flush();
                                        }
                                    } catch (java.io.IOException expectedWhenClientCloses) {
                                        // клиент закрыт: ожидаемое завершение
                                    } catch (Exception e) {
                                        throw new IllegalStateException(e);
                                    }
                                });

                SSLSocket client =
                        GostSsl.socket("localhost", server.getLocalPort(), clientContext);
                client.setSoTimeout(5000);
                InputStream in = client.getInputStream();
                CompletableFuture<Throwable> reader =
                        CompletableFuture.supplyAsync(
                                () -> {
                                    // чтение маленькими порциями: остаток (leftover) живёт всё
                                    // время
                                    byte[] buf = new byte[7];
                                    try {
                                        while (true) {
                                            int n = in.read(buf);
                                            if (n == -1) {
                                                return null;
                                            }
                                            for (int k = 0; k < n; k++) {
                                                if (buf[k] != 'A') {
                                                    return new AssertionError(
                                                            "вместо данных получен байт " + buf[k]);
                                                }
                                            }
                                        }
                                    } catch (java.io.IOException expectedAfterClose) {
                                        return null;
                                    } catch (Throwable unexpected) {
                                        return unexpected;
                                    }
                                });

                Thread.sleep(20 + (i % 5) * 7L);
                byte[] decryptBuffer = ((java.nio.ByteBuffer) fieldOf(in, "readDst")).array();
                client.close();

                Throwable failure = reader.get(10, TimeUnit.SECONDS);
                assertEquals(
                        null, failure, "читатель получил искажённые данные или сбой: " + failure);
                byte[] leftover = (byte[]) fieldOf(in, "leftover");
                assertTrue(leftover == null || isZeroed(leftover), "остаток затёрт");
                assertTrue(isZeroed(decryptBuffer), "буфер расшифровки затёрт");
                serverSide.get(10, TimeUnit.SECONDS);
            }
        }
    }

    @Test
    @DisplayName(
            "close() не затирает буферы, пока замок чтения занят, и затирает после его освобождения")
    void closeDoesNotWipeUnderBusyReadLock() throws Exception {
        try (SSLServerSocket server = GostSsl.serverSocket(0, serverContext)) {
            CompletableFuture<Void> serverSide =
                    CompletableFuture.runAsync(
                            () -> {
                                try (SSLSocket accepted = (SSLSocket) server.accept()) {
                                    accepted.setSoTimeout(5000);
                                    accepted.startHandshake();
                                    accepted.getOutputStream().write("0123456789".getBytes());
                                    accepted.getOutputStream().flush();
                                    while (accepted.getInputStream().read() != -1) {
                                        // до close_notify или обрыва
                                    }
                                } catch (Exception e) {
                                    throw new IllegalStateException(e);
                                }
                            });

            SSLSocket client = GostSsl.socket("localhost", server.getLocalPort(), clientContext);
            client.setSoTimeout(5000);
            InputStream in = client.getInputStream();
            assertEquals('0', in.read());
            byte[] leftover = (byte[]) fieldOf(in, "leftover");
            assertTrue(!isZeroed(leftover), "предусловие: остаток содержит данные");

            // «занятый читатель»: другой поток держит замок чтения, как при блокирующем read()
            java.util.concurrent.locks.ReentrantLock readLock =
                    (java.util.concurrent.locks.ReentrantLock) fieldOf(client, "readLock");
            java.util.concurrent.CountDownLatch locked = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.CountDownLatch release =
                    new java.util.concurrent.CountDownLatch(1);
            CompletableFuture<Throwable> busyReader =
                    CompletableFuture.supplyAsync(
                            () -> {
                                readLock.lock();
                                try {
                                    locked.countDown();
                                    release.await();
                                    return null;
                                } catch (Throwable unexpected) {
                                    return unexpected;
                                } finally {
                                    readLock.unlock();
                                }
                            });
            assertTrue(locked.await(5, TimeUnit.SECONDS));

            client.close();
            assertTrue(
                    !isZeroed(leftover),
                    "пока читатель владеет замком, close() не должен затирать его данные");

            release.countDown();
            assertEquals(null, busyReader.get(10, TimeUnit.SECONDS));
            // замок свободен: затирание не пересекается с чтением и выполняется
            in.close();
            assertTrue(isZeroed(leftover), "после освобождения замка остаток затёрт");
            serverSide.get(10, TimeUnit.SECONDS);
        }
    }

    private static Object fieldOf(Object target, String name) throws Exception {
        Class<?> type = target.getClass();
        while (type != null) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(target);
            } catch (NoSuchFieldException notHere) {
                type = type.getSuperclass();
            }
        }
        // поле может принадлежать внешнему классу сокета
        Field outer = target.getClass().getDeclaredField("this$0");
        outer.setAccessible(true);
        return fieldOf(outer.get(target), name);
    }

    private static boolean isZeroed(byte[] bytes) {
        for (byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
