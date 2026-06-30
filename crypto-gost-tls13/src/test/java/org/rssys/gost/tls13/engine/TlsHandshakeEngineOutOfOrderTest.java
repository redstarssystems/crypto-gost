package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.tls13.TlsTestHelper.*;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.message.TlsMessageBuilder;

/**
 * Тесты out-of-order handshake сообщений в TlsHandshakeEngine.
 * Проверяет, что state machine отвергает дубликаты и сообщения
 * после завершения handshake (RFC 8446 §4.1.3).
 */
@DisplayName("TlsHandshakeEngine — out-of-order сообщения")
class TlsHandshakeEngineOutOfOrderTest {

    private static final ECParameters EC_PARAMS = ECParameters.tc26a256();
    private static final int NAMED_GROUP = TlsConstants.GRP_GC256A;
    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;

    private static TlsTestHelper.CertBundle serverCert;
    private static TlsTestHelper.CertBundle clientCert;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = TlsTestHelper.createCertWithKey(EC_PARAMS);
        clientCert = TlsTestHelper.createCertWithKey(EC_PARAMS);
    }

    private static TlsCiphersuite cs() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    // ========================================================================
    // Duplicate ServerHello
    // ========================================================================

    @Test
    @DisplayName("Duplicate ServerHello вызывает ALERT_UNEXPECTED_MESSAGE")
    void testDuplicateServerHello() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                NAMED_GROUP,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                NAMED_GROUP,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        // Нормальный handshake до получения ServerHello
        byte[] ch = client.start();
        assertNotNull(ch);
        server.receive(ch);
        byte[] sh = server.poll();
        assertNotNull(sh, "Сервер должен сгенерировать ServerHello");
        // Пропускаем остальные сообщения сервера — не нужны для теста

        // Клиент получает первый ServerHello
        client.receive(sh);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_ENCRYPTED_EXTENSIONS, client.getState());

        // Клиент получает второй ServerHello — out-of-order
        TlsException ex = assertThrows(TlsException.class, () -> client.receive(sh));
        assertEquals(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                ex.getAlertCode(),
                "Duplicate ServerHello должен вызывать ALERT_UNEXPECTED_MESSAGE");
        assertTrue(client.isError(), "Клиент должен перейти в ERROR");
    }

    // ========================================================================
    // Certificate после Finished (режим POST_HANDSHAKE)
    // ========================================================================

    @Test
    @DisplayName("Certificate после Finished вызывает ALERT_UNEXPECTED_MESSAGE")
    void testCertificateAfterFinished() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                NAMED_GROUP,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                NAMED_GROUP,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        // Полный handshake
        byte[] ch = client.start();
        assertNotNull(ch);
        server.receive(ch);

        byte[] sh = server.poll();
        byte[] ee = server.poll();
        byte[] cert = server.poll();
        byte[] cv = server.poll();
        byte[] sf = server.poll();
        assertNotNull(sf, "Серверный Finished");
        assertNull(server.poll(), "После Finished очередь сервера пуста");
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        client.receive(cert);
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.receive(sf);

        byte[] cf = client.poll();
        assertNotNull(cf, "Клиентский Finished");
        assertNull(client.poll(), "После Finished очередь клиента пуста");
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, client.getState());

        server.receive(cf);
        assertTrue(server.isDone());
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, server.getState());

        // После handshake клиент в POST_HANDSHAKE — передаём Certificate
        TlsException ex = assertThrows(TlsException.class, () -> client.receive(cert));
        assertEquals(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                ex.getAlertCode(),
                "Certificate после Finished должен вызывать ALERT_UNEXPECTED_MESSAGE");
        assertTrue(client.isError(), "Клиент должен перейти в ERROR");
    }
}
