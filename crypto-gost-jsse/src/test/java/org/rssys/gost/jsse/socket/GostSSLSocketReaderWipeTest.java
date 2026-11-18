package org.rssys.gost.jsse.socket;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.engine.GostSSLEngine;
import org.rssys.gost.jsse.engine.GostSSLSessionContext;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.testkit.EngineServerPki;
import org.rssys.gost.jsse.testkit.EngineSocketPeer;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.tls13.TlsCiphersuite;

/**
 * Закрытие сокета из другого потока, пока читатель заблокирован в {@code read()}: закрывающий поток
 * не может затереть буфер расшифровки (замок у читателя), и затирание остаётся читателю, когда он
 * выйдет из чтения. Нижележащий сокет не закрывается ({@code autoClose=false}), поэтому читатель
 * не просыпается от закрытия и действительно держит замок.
 */
@DisplayName("GostSSLSocket: читатель затирает буферы сам, если сокет закрыли во время чтения")
class GostSSLSocketReaderWipeTest {

    private static final byte[] SECRET = "открытый текст первого чтения".getBytes();
    private static final int TIMEOUT_MS = 10_000;

    private static EngineServerPki pki;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        pki = EngineServerPki.create();
    }

    @Test
    @DisplayName("Буфер расшифровки затирается читателем по выходе из заблокированного read()")
    void blockedReaderWipesBuffersAfterConcurrentClose() throws Exception {
        CountDownLatch closeTcp = new CountDownLatch(1);
        try (ServerSocket listener = new ServerSocket(0)) {
            CompletableFuture<Void> peer =
                    CompletableFuture.runAsync(
                            () -> {
                                try (Socket socket = listener.accept()) {
                                    socket.setSoTimeout(TIMEOUT_MS);
                                    GostSSLEngine engine =
                                            new GostSSLEngine(
                                                    pki.serverKm(),
                                                    GostX509TrustManager.insecureTrustAll(),
                                                    "localhost",
                                                    0,
                                                    false);
                                    EngineSocketPeer.handshake(engine, socket);
                                    socket.getOutputStream()
                                            .write(EngineSocketPeer.wrapData(engine, SECRET));
                                    socket.getOutputStream().flush();
                                    // TCP закрывается по команде теста: это будит читателя
                                    closeTcp.await(TIMEOUT_MS, TimeUnit.MILLISECONDS);
                                } catch (Exception e) {
                                    throw new IllegalStateException(e);
                                }
                            });

            Socket tcp = new Socket("localhost", listener.getLocalPort());
            tcp.setSoTimeout(TIMEOUT_MS);
            GostSSLSocket client =
                    new GostSSLSocket(
                            tcp,
                            "localhost",
                            listener.getLocalPort(),
                            false,
                            new GostX509KeyManager(),
                            GostX509TrustManager.fromTrustAnchors(
                                    TrustAnchors.ofCertificate(pki.rootCa().cert)),
                            new GostSSLSessionContext(
                                    TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L));
            try {
                byte[] first = client.getInputStream().readNBytes(SECRET.length);
                assertArrayEquals(SECRET, first);
                assertTrue(contains(readDst(client), SECRET), "предусловие: текст в буфере");

                CompletableFuture<Integer> reader =
                        CompletableFuture.supplyAsync(
                                () -> {
                                    try {
                                        return client.getInputStream().read(new byte[16]);
                                    } catch (Exception e) {
                                        return -2;
                                    }
                                });
                ReentrantLock readLock = readLock(client);
                long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(TIMEOUT_MS);
                while (!readLock.isLocked() && System.nanoTime() < deadline) {
                    Thread.onSpinWait();
                }
                assertTrue(readLock.isLocked(), "читатель вошёл в read() и держит замок");

                client.close();
                assertTrue(
                        contains(readDst(client), SECRET),
                        "закрывающий поток не трогает буфер, пока читатель держит замок");

                closeTcp.countDown();
                reader.get(TIMEOUT_MS, TimeUnit.MILLISECONDS);
                assertFalse(
                        contains(readDst(client), SECRET),
                        "читатель по выходе из read() затирает открытый текст сам");
                assertEquals(0, nonZeroBytes(readDst(client)), "буфер расшифровки обнулён");
            } finally {
                tcp.close();
            }
            peer.get(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }
    }

    private static byte[] readDst(GostSSLSocket socket) throws Exception {
        Field field = GostSSLSocket.class.getDeclaredField("readDst");
        field.setAccessible(true);
        return ((ByteBuffer) field.get(socket)).array();
    }

    private static ReentrantLock readLock(GostSSLSocket socket) throws Exception {
        Field field = GostSSLSocket.class.getDeclaredField("readLock");
        field.setAccessible(true);
        return (ReentrantLock) field.get(socket);
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static int nonZeroBytes(byte[] bytes) {
        int count = 0;
        for (byte b : bytes) {
            if (b != 0) {
                count++;
            }
        }
        return count;
    }
}
