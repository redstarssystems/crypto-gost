package org.rssys.gost.jsse.engine;

import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.bridge.CertificateBridge;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.jsse.manager.GostX509KeyManager;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

import javax.net.ssl.SSLEngineResult;
import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class GostSSLEngineCoalescingTest {

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
        serverKm.addKeyEntry("default",
                CertificateBridge.toJcaChain(serverCert.cert, rootCa.cert),
                serverCert.priv);
    }

    @Test
    @DisplayName("Несколько склеенных TLS-записей: bytesProduced совпадает с суммой данных")
    void testCoalescedRecordsProducedCount() throws Exception {
        // Подготавливаем движки и хендшейк
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngine client = createClient();
        GostSSLEngine server = createServer();
        doHandshake(client, server, pair);

        // Три записи разного размера
        byte[][] records = {
                new byte[100],
                new byte[1024],
                new byte[16383],
        };
        for (int i = 0; i < records.length; i++) {
            Arrays.fill(records[i], (byte) (i + 1));
        }

        // Шифруем каждую отдельно
        ByteBuffer tmp = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        ByteBuffer[] encrypted = new ByteBuffer[records.length];
        for (int i = 0; i < records.length; i++) {
            encrypted[i] = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
            tmp.clear();
            tmp.put(records[i]);
            tmp.flip();
            client.wrap(tmp, encrypted[i]);
            encrypted[i].flip();
        }

        // Склеиваем все записи в один буфер
        int totalEncrypted = 0;
        for (ByteBuffer eb : encrypted) totalEncrypted += eb.remaining();
        ByteBuffer combined = ByteBuffer.allocate(totalEncrypted);
        for (ByteBuffer eb : encrypted) combined.put(eb);
        combined.flip();

        // Сервер читает всё одним потоком, unwrap в цикле
        int totalProduced = 0;
        int totalConsumed = 0;
        int recordIndex = 0;
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        while (combined.hasRemaining()) {
            appBuf.clear();
            SSLEngineResult r = server.unwrap(combined, appBuf);
            totalConsumed += r.bytesConsumed();

            if (r.bytesProduced() > 0) {
                totalProduced += r.bytesProduced();

                // Проверяем содержимое
                appBuf.flip();
                byte[] received = new byte[appBuf.remaining()];
                appBuf.get(received);
                assertArrayEquals(records[recordIndex], received,
                        "Содержимое записи " + recordIndex + " должно совпадать");
                recordIndex++;
            }

            if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                // Не хватило данных — это ожидаемо для частичной записи
                break;
            }
        }

        // Все записи должны быть получены
        assertEquals(records.length, recordIndex,
                "Должны быть получены все " + records.length + " записей");

        // bytesProduced должен равняться сумме всех данных
        int totalData = 0;
        for (byte[] rec : records) totalData += rec.length;
        assertEquals(totalData, totalProduced,
                "bytesProduced должен равняться сумме всех plaintext данных");
    }

    @Test
    @DisplayName("Склейка 16 записей по 100 байт: стабильность под последовательной нагрузкой")
    void testManyCoalescedRecords() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();
        GostSSLEngine client = createClient();
        GostSSLEngine server = createServer();
        doHandshake(client, server, pair);

        int count = 16;
        byte[][] records = new byte[count][];
        for (int i = 0; i < count; i++) {
            records[i] = new byte[100];
            Arrays.fill(records[i], (byte) (i + 1));
        }

        ByteBuffer tmp = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        ByteBuffer[] encrypted = new ByteBuffer[count];
        for (int i = 0; i < count; i++) {
            encrypted[i] = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
            tmp.clear();
            tmp.put(records[i]);
            tmp.flip();
            client.wrap(tmp, encrypted[i]);
            encrypted[i].flip();
        }

        int totalEncrypted = 0;
        for (ByteBuffer eb : encrypted) totalEncrypted += eb.remaining();
        ByteBuffer combined = ByteBuffer.allocate(totalEncrypted);
        for (ByteBuffer eb : encrypted) combined.put(eb);
        combined.flip();

        int totalProduced = 0;
        int recordIndex = 0;
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        while (combined.hasRemaining() && recordIndex < count) {
            appBuf.clear();
            SSLEngineResult r = server.unwrap(combined, appBuf);

            if (r.bytesProduced() > 0) {
                totalProduced += r.bytesProduced();
                appBuf.flip();
                byte[] received = new byte[appBuf.remaining()];
                appBuf.get(received);
                assertArrayEquals(records[recordIndex], received,
                        "Содержимое записи " + recordIndex);
                recordIndex++;
            }

            if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) break;
        }

        assertEquals(count, recordIndex,
                "Должны быть получены все " + count + " записей");
        assertEquals(count * 100, totalProduced,
                "bytesProduced должен равняться " + (count * 100));
    }

    private static GostSSLEngine createClient() {
        return new GostSSLEngine(
                new GostX509KeyManager(), new GostX509TrustManager(null, false),
                "localhost", 0, true);
    }

    private static GostSSLEngine createServer() {
        return new GostSSLEngine(
                serverKm, new GostX509TrustManager(null, false),
                "localhost", 0, false);
    }

    private static void doHandshake(GostSSLEngine client, GostSSLEngine server,
                                    InMemoryTlsTransport.Pair pair) throws Exception {
        client.beginHandshake();
        server.beginHandshake();

        java.util.concurrent.atomic.AtomicReference<Throwable> clientError =
                new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<Throwable> serverError =
                new java.util.concurrent.atomic.AtomicReference<>();

        Thread ct = new Thread(() -> {
            try {
                handshakeLoop(client, pair.getClientTransport());
            } catch (Exception e) { clientError.set(e); }
        }, "hs-client");
        Thread st = new Thread(() -> {
            try {
                handshakeLoop(server, pair.getServerTransport());
            } catch (Exception e) { serverError.set(e); }
        }, "hs-server");

        ct.start(); st.start();
        ct.join(10000); st.join(10000);
        if (ct.isAlive()) { ct.interrupt(); fail("Client HS timeout"); }
        if (st.isAlive()) { st.interrupt(); fail("Server HS timeout"); }
        if (clientError.get() != null) throw new RuntimeException(clientError.get());
        if (serverError.get() != null) throw new RuntimeException(serverError.get());
    }

    private static void handshakeLoop(GostSSLEngine engine,
                                       InMemoryTlsTransport transport) throws Exception {
        ByteBuffer netBuf = ByteBuffer.allocate(TlsConstants.MAX_CIPHERTEXT_LENGTH + 64);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        for (int i = 0; i < 80; i++) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.FINISHED
                    || hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) return;

            switch (hs) {
                case NEED_WRAP:
                    netBuf.clear();
                    engine.wrap(ByteBuffer.allocate(0), netBuf);
                    netBuf.flip();
                    if (netBuf.hasRemaining()) {
                        byte[] out = new byte[netBuf.remaining()];
                        netBuf.get(out);
                        transport.sendRecord(out);
                    }
                    break;
                case NEED_UNWRAP: {
                    byte[] in = transport.receiveRecord();
                    if (in != null) {
                        netBuf.clear();
                        netBuf.put(in);
                        netBuf.flip();
                        appBuf.clear();
                        engine.unwrap(netBuf, appBuf);
                    } else {
                        Thread.sleep(10);
                    }
                    break;
                }
                case NEED_TASK: {
                    Runnable t = engine.getDelegatedTask();
                    if (t != null) t.run();
                    break;
                }
            }
        }
        throw new RuntimeException("Handshake timeout");
    }
}
