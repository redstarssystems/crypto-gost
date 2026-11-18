package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.Security;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngineResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.jsse.GostJsseConstants;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.jsse.manager.GostX509KeyManager;
import org.rssys.gost.jsse.manager.GostX509TrustManager;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsSession;
import org.rssys.gost.tls13.config.TlsServerConfig;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;

/**
 * Интеграционные тесты GostSSLEngine.
 */
@DisplayName("GostSSLEngine: совместимость с TlsSession")
class GostSSLEngineTest {

    private static GostCertificate serverCert;
    private static PrivateKeyParameters serverPriv;
    private static TlsCiphersuite cs;

    private static GostCertificate caCert;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(),
                        "20250101000000Z",
                        "21010101000000Z",
                        new String[] {"localhost"});
        serverCert = bundle.cert;
        serverPriv = bundle.priv;

        // собственный CA для теста цепочки — нужна подпись, которой мы доверяем
        PkixCertTestHelper.CertBundle caBundle =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        caCert = caBundle.cert;
    }

    @Test
    @DisplayName("Клиент GostSSLEngine -> сервер TlsSession: handshake + app data + close")
    void testEngineClientToTlsSessionServer() throws Exception {
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsServerConfig serverConfig =
                new TlsServerConfig(cs, Collections.singletonList(serverCert), serverPriv);
        TlsSession serverSession = TlsSession.createServer(serverConfig, pair.getServerTransport());

        AtomicReference<Throwable> serverError = new AtomicReference<>();
        Thread serverThread =
                new Thread(
                        () -> {
                            try {
                                serverSession.handshakeAsServer();
                            } catch (Exception e) {
                                serverError.set(e);
                                throw new RuntimeException("Рукопожатие сервера не удалось", e);
                            }
                        },
                        "tls-server");
        serverThread.start();

        GostX509TrustManager trustManager = GostX509TrustManager.insecureTrustAll();
        GostX509KeyManager keyManager = new GostX509KeyManager();
        GostSSLEngine clientEngine =
                GostSSLEngine.createForClient(keyManager, trustManager, "localhost", 0, null);

        clientEngine.beginHandshake();
        doHandshake(clientEngine, pair);

        // ждём серверный handshake — без него app data принять не сможем
        serverThread.join(5000);
        if (serverThread.isAlive()) {
            throw new RuntimeException("Рукопожатие сервера не завершено");
        }
        if (serverError.get() != null) {
            Throwable se = serverError.get();
            throw new RuntimeException("Ошибка рукопожатия сервера: " + se.getMessage(), se);
        }

        assertTrue(
                clientEngine.getSession().getCipherSuite().startsWith("TLS_GOSTR341112_256"),
                "Набор: " + clientEngine.getSession().getCipherSuite());
        assertEquals(GostJsseConstants.PROTOCOL_TLS_1_3, clientEngine.getSession().getProtocol());

        // отправляем app-данные, чтобы убедиться, что шифрование работает
        String msg = "Hello from GostSSLEngine!";
        byte[] msgBytes = msg.getBytes("UTF-8");
        ByteBuffer wrapBuf = ByteBuffer.wrap(msgBytes);
        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        SSLEngineResult wr = clientEngine.wrap(wrapBuf, netBuf);
        netBuf.flip();
        byte[] enc = new byte[netBuf.remaining()];
        netBuf.get(enc);
        pair.getClientTransport().sendRecord(enc);

        byte[] received = serverSession.read();
        assertEquals(msg, new String(received, "UTF-8"));

        // ответные app-данные — двусторонняя проверка шифрования
        String resp = "Hello back!";
        serverSession.write(resp.getBytes("UTF-8"));

        // после handshake сервер мог прислать NST — читаем в цикле,
        // отбрасывая post-handshake сообщения, пока не получим app-данные
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);
        byte[] respData;
        outer:
        while (true) {
            byte[] serverRaw = pair.getClientTransport().receiveRecord();
            netBuf.clear();
            netBuf.put(serverRaw);
            netBuf.flip();
            appBuf.clear();
            SSLEngineResult rr = clientEngine.unwrap(netBuf, appBuf);
            appBuf.flip();
            respData = new byte[appBuf.remaining()];
            appBuf.get(respData);
            if (respData.length > 0) break;
        }
        assertEquals(resp, new String(respData, "UTF-8"));

        clientEngine.closeOutbound();
        serverSession.close();
        serverThread.join(5000);
    }

    /**
     * Выполняет handshake для клиентского engine до состояния FINISHED.
     *
     * @param engine клиентский GostSSLEngine
     * @param pair   пара in-memory транспортов для обмена данными
     * @throws Exception если handshake не завершился за 50 итераций
     *
     * Предусловие: engine.beginHandshake() уже вызван.
     * Постусловие: engine.getHandshakeStatus() == FINISHED или NOT_HANDSHAKING.
     */
    private void doHandshake(GostSSLEngine engine, InMemoryTlsTransport.Pair pair)
            throws Exception {
        ByteBuffer netBuf =
                ByteBuffer.allocate(
                        TlsConstants.MAX_CIPHERTEXT_LENGTH + TlsConstants.RECORD_BUFFER_HEADROOM);
        ByteBuffer appBuf = ByteBuffer.allocate(TlsConstants.MAX_PLAINTEXT_LENGTH);

        for (int i = 0; i < 50; i++) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.FINISHED
                    || hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) return;

            switch (hs) {
                case NEED_WRAP:
                    netBuf.clear();
                    engine.wrap(ByteBuffer.allocate(0), netBuf);
                    netBuf.flip();
                    if (netBuf.hasRemaining()) {
                        byte[] outData = new byte[netBuf.remaining()];
                        netBuf.get(outData);
                        pair.getClientTransport().sendRecord(outData);
                    }
                    break;
                case NEED_UNWRAP:
                    byte[] inData = pair.getClientTransport().receiveRecord();
                    if (inData != null) {
                        netBuf.clear();
                        netBuf.put(inData);
                        netBuf.flip();
                        appBuf.clear();
                        engine.unwrap(netBuf, appBuf);
                    }
                    break;
                case NEED_TASK:
                    Runnable task = engine.getDelegatedTask();
                    if (task != null) task.run();
                    break;
            }
        }
        throw new RuntimeException("Рукопожатие не завершено за 50 итераций");
    }
}
