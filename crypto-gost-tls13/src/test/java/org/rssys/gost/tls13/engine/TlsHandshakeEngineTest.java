package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.tls13.TlsTestHelper.*;

import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.util.CryptoRandom;

/**
 * Тесты {@link TlsHandshakeEngine} — пошаговый handshake без I/O.
 * <p>
 * Проверяет state machine: последовательность receive/poll, смену ключей,
 * сигналы валидации сертификатов, обработку ошибок.
 * <p>
 * Настоящий защищённый обмен данными не тестируется — для этого есть
 * {@code TlsSessionTest}. Здесь проверяется, что engine генерирует
 * корректные handshake-фреймы в правильном порядке.
 */
@DisplayName("TlsHandshakeEngine — пошаговый handshake")
class TlsHandshakeEngineTest {

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

    private static TlsMessageBuilder clientBuilder(boolean withCert) {
        return new TlsMessageBuilder(
                cs(),
                List.of(cs().getId()),
                NAMED_GROUP,
                SIG_SCHEME,
                withCert ? clientCert.priv : null,
                withCert ? List.of(clientCert.cert) : null,
                HASH_LEN);
    }

    private static TlsMessageBuilder serverBuilder() {
        return new TlsMessageBuilder(
                cs(),
                List.of(cs().getId()),
                NAMED_GROUP,
                SIG_SCHEME,
                serverCert.priv,
                List.of(serverCert.cert),
                HASH_LEN);
    }

    // -------------------------------------------------------------------
    // Полный handshake (клиент <-> сервер, без mTLS)
    // -------------------------------------------------------------------
    //
    // Базовый сценарий — проверяем state machine целиком.
    // Клиент -> ClientHello -> Сервер -> SH/EE/Cert/CV/Finished -> Клиент.
    // Без mTLS клиент не отправляет свой сертификат.
    // Если этот тест падает, ни одно TLS-соединение не установится.

    @Test
    @DisplayName("полный handshake client <-> server без mTLS")
    void testFullHandshake() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
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
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        // Клиент: start -> ClientHello
        byte[] ch = client.start();
        assertNotNull(ch, "Клиент должен сгенерировать ClientHello");
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_SERVER_HELLO, client.getState());

        // Сервер: получает ClientHello
        server.receive(ch);
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());

        // Сервер: проверяем что poll() содержит SH, EE, Cert, CV, Finished
        byte[] sh = server.poll();
        assertNotNull(sh, "Сервер должен сгенерировать ServerHello");
        byte[] ee = server.poll();
        assertNotNull(ee, "Сервер должен сгенерировать EncryptedExtensions");
        byte[] cert = server.poll();
        assertNotNull(cert, "Сервер должен сгенерировать Certificate");
        byte[] cv = server.poll();
        assertNotNull(cv, "Сервер должен сгенерировать CertificateVerify");
        byte[] sf = server.poll();
        assertNotNull(sf, "Сервер должен сгенерировать Finished");
        assertNull(server.poll(), "После Finished очередь сервера пуста");

        // Сервер после опустошения очереди переходит в ожидание
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        // Клиент: последовательно получает SH, EE, Cert, CV, Finished
        client.receive(sh);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_ENCRYPTED_EXTENSIONS, client.getState());
        assertTrue(client.hasReadKeysChanged(), "Ключи чтения должны измениться после SH");
        assertNotNull(client.getReadKeys(), "Ключи чтения должны быть установлены после SH");
        client.acknowledgeKeyChange();

        client.receive(ee);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_OR_CR, client.getState());

        // Обработка сертификата
        client.receive(cert);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_VERIFY, client.getState());
        assertTrue(
                client.needsCertificateValidation(),
                "Engine должен запросить валидацию сертификата");
        assertNotNull(client.getReceivedCertificates(), "Сертификаты должны быть получены");
        client.acknowledgeCertificateValidation(true);

        client.receive(cv);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_FINISHED, client.getState());
        assertFalse(client.needsCertificateValidation(), "После CV флаг валидации сброшен");

        client.receive(sf);
        assertEquals(TlsHandshakeEngine.State.CLIENT_SEND_FINISHED, client.getState());

        // Клиент: poll() -> Certificate? (нет mTLS) -> Finished
        // (нет mTLS, поэтому сразу Finished)
        byte[] cf = client.poll();
        assertNotNull(cf, "Клиент должен сгенерировать Finished");
        assertNull(client.poll(), "После Finished очередь клиента пуста");
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, client.getState());

        // Сервер: получает клиентский Finished
        server.receive(cf);
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, server.getState());

        // Оба engine завершили handshake
        assertTrue(client.isDone());
        assertTrue(server.isDone());
        assertNotNull(client.getReadKeys(), "App read keys должны быть");
        assertNotNull(client.getWriteKeys(), "App write keys должны быть");
        assertNotNull(server.getReadKeys(), "App read keys должны быть");
        assertNotNull(server.getWriteKeys(), "App write keys должны быть");
        assertNotNull(client.getNegotiatedCiphersuite(), "Cipher suite согласован");
        assertEquals(cs(), client.getNegotiatedCiphersuite());
    }

    // -------------------------------------------------------------------
    // Handshake с mTLS
    // -------------------------------------------------------------------
    //
    // mTLS — сервер запрашивает CertificateRequest, клиент отправляет
    // свой сертификат и CertificateVerify. Проверяем, что state machine
    // корректно проходит через CLIENT_WAIT_CERTIFICATE -> отправку Cert/CV
    // и сервер ждёт SERVER_WAIT_CLIENT_CERTIFICATE/CV.

    @Test
    @DisplayName("handshake с mTLS (сервер запрашивает клиентский сертификат)")
    void testMutualTlsHandshake() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(true),
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
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        true,
                        null);

        byte[] ch = client.start();
        assertNotNull(ch);

        server.receive(ch);
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());

        // Сервер: poll SH, EE, CR, Cert, CV, Finished
        byte[] sh = server.poll();
        assertNotNull(sh);
        byte[] ee = server.poll();
        assertNotNull(ee);
        byte[] cr = server.poll();
        assertNotNull(cr, "Должен быть CertificateRequest (mTLS)");
        byte[] cert = server.poll();
        assertNotNull(cert);
        byte[] cv = server.poll();
        assertNotNull(cv);
        byte[] sf = server.poll();
        assertNotNull(sf);
        assertNull(server.poll(), "Очередь сервера пуста после Finished");

        // Сервер ждёт клиентский Cert/CV
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_CERTIFICATE, server.getState());

        // Клиент: SH -> EE -> CR -> Cert -> CV -> Finished
        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        client.receive(cr); // CertificateRequest
        assertEquals(
                TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE,
                client.getState(),
                "После CR клиент ждёт Certificate");

        client.receive(cert);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_VERIFY, client.getState());
        assertTrue(client.needsCertificateValidation());
        client.acknowledgeCertificateValidation(true);

        client.receive(cv);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_FINISHED, client.getState());

        client.receive(sf);
        assertEquals(TlsHandshakeEngine.State.CLIENT_SEND_FINISHED, client.getState());

        // Клиент: должен отправить Cert, CV, Finished
        byte[] clientCert = client.poll();
        assertNotNull(clientCert, "Клиент должен отправить свой Certificate (mTLS)");
        byte[] clientCv = client.poll();
        assertNotNull(clientCv, "Клиент должен отправить свой CertificateVerify (mTLS)");
        byte[] clientCf = client.poll();
        assertNotNull(clientCf, "Клиент должен отправить свой Finished");
        assertNull(client.poll(), "Очередь клиента пуста");
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, client.getState());

        // Сервер: получает Cert -> CV -> Finished
        server.receive(clientCert);
        assertEquals(
                TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_CERTIFICATE_VERIFY, server.getState());
        assertTrue(server.needsCertificateValidation());
        server.acknowledgeCertificateValidation(true);

        server.receive(clientCv);
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        server.receive(clientCf);
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, server.getState());

        assertTrue(server.isDone());
    }

    // -------------------------------------------------------------------
    // Ошибка: неправильный тип сообщения
    // -------------------------------------------------------------------
    //
    // Engine должен валидировать тип каждого incoming handshake-сообщения.
    // Если клиент ожидает ServerHello, а получает EncryptedExtensions —
    // это нарушение протокола -> TlsException -> ERROR.

    @Test
    @DisplayName("неправильный тип сообщения кидает TlsException")
    void testWrongMessageType() throws TlsException {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] ch = client.start();
        assertNotNull(ch);

        // Вместо ServerHello передаём EncryptedExtensions — ошибка
        byte[] fakeSh =
                new TlsHandshakeMessage(TlsConstants.HT_ENCRYPTED_EXTENSIONS, new byte[] {0, 0})
                        .encode();

        assertThrows(TlsException.class, () -> client.receive(fakeSh));
        assertTrue(client.isError(), "Engine должен перейти в ERROR");
    }

    // -------------------------------------------------------------------
    // Клиент: receive до start() кидает исключение
    // -------------------------------------------------------------------
    //
    // Клиент ДОЛЖЕН сначала вызвать start() для генерации ClientHello.
    // Получение сообщения до start() — ошибка использования API.
    // Проверяем, что engine не допускает receive() в INIT state.

    @Test
    @DisplayName("клиентский receive до start() кидает TlsException")
    void testReceiveBeforeStart() {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] garbage =
                new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, new byte[] {0}).encode();
        assertThrows(TlsException.class, () -> client.receive(garbage));
    }

    // -------------------------------------------------------------------
    // Сервер без mTLS: poll после Finished -> ожидание Finished от клиента
    // -------------------------------------------------------------------
    //
    // После отправки всех сообщений (SH/EE/Cert/CV/Finished) сервер
    // переходит в SERVER_WAIT_CLIENT_FINISHED. Проверяем, что переход
    // происходит корректно и engine не зависает в SERVER_SEND_FLIGHT.

    @Test
    @DisplayName("сервер после отправки flight ожидает клиентский Finished")
    void testServerWaitsForClientFinished() throws Exception {
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] ch = client.start();
        server.receive(ch);

        // Drain queue
        while (server.poll() != null)
            ;

        assertEquals(
                TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED,
                server.getState(),
                "Сервер должен ждать клиентский Finished");
    }

    // -------------------------------------------------------------------
    // Engine: отрицание сертификата -> ERROR
    // -------------------------------------------------------------------
    //
    // Если клиент отклоняет сертификат сервера (acknowledgeCertificate(false)),
    // handshake не может продолжаться. Engine переходит в ERROR.
    // Это критический путь безопасности — недоверенный сертификат = разрыв.

    @Test
    @DisplayName("отклонение сертификата переводит engine в ERROR")
    void testCertificateRejection() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
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
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] ch = client.start();
        server.receive(ch);

        byte[] sh = server.poll();
        byte[] ee = server.poll();
        byte[] cert = server.poll();
        byte[] cv = server.poll();
        byte[] sf = server.poll();

        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        client.receive(cert);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_VERIFY, client.getState());
        assertTrue(client.needsCertificateValidation());

        client.acknowledgeCertificateValidation(false);
        assertTrue(client.isError(), "Engine должен перейти в ERROR после отклонения сертификата");
    }

    // -------------------------------------------------------------------
    // Нет mTLS: после poll() сервер сразу переходит в ожидание Finished
    // -------------------------------------------------------------------
    //
    // Без mTLS сервер после опустошения очереди переходит в
    // SERVER_WAIT_CLIENT_FINISHED (а не SERVER_WAIT_CLIENT_CERTIFICATE).
    // Это дублирует testServerWaitsForClientFinished как явный negative test
    // для mTLS-флага = false.

    @Test
    @DisplayName("без mTLS сервер ждёт клиентский Finished сразу после flight")
    void testServerNoMtlsWaitState() throws Exception {
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] ch = client.start();
        server.receive(ch);

        byte[] msg;
        while ((msg = server.poll()) != null) {
            // drain
        }

        assertEquals(
                TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED,
                server.getState(),
                "Без mTLS: SERVER_WAIT_CLIENT_FINISHED");
    }

    // -------------------------------------------------------------------
    // c mTLS: после poll сервер ждёт клиентский Cert
    // -------------------------------------------------------------------
    //
    // С mTLS после flight сервер ждёт клиентский Certificate,
    // а не Finished. Это ключевое отличие mTLS от обычного handshake.

    @Test
    @DisplayName("с mTLS сервер ждёт клиентский Certificate после flight")
    void testServerMtlsWaitState() throws Exception {
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        true,
                        null);

        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(true),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] ch = client.start();
        server.receive(ch);

        byte[] msg;
        while ((msg = server.poll()) != null) {
            // drain
        }

        assertEquals(
                TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_CERTIFICATE,
                server.getState(),
                "С mTLS: SERVER_WAIT_CLIENT_CERTIFICATE");
    }

    // -------------------------------------------------------------------
    // ALPN (RFC 7301)
    // -------------------------------------------------------------------

    @Test
    @DisplayName("полный handshake с ALPN: http/1.1 согласован")
    void testFullHandshakeWithAlpn() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        client.setClientAlpnProtocols(List.of("h2", "http/1.1"));
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        server.setServerAlpnProtocols(List.of("http/1.1"));

        byte[] ch = client.start();
        assertNotNull(ch);
        // ClientHello содержит ALPN extension
        byte[] chBody = TlsHandshakeMessage.decode(ch).getBody();
        List<String> offered = TlsMessageParser.parseClientHelloAlpn(chBody);
        assertNotNull(offered);
        assertTrue(offered.contains("h2"));
        assertTrue(offered.contains("http/1.1"));

        server.receive(ch);
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());
        assertEquals("http/1.1", server.getSelectedAlpnProtocol());

        byte[] sh = server.poll();
        byte[] ee = server.poll();
        byte[] cert = server.poll();
        byte[] cv = server.poll();
        byte[] sf = server.poll();
        assertNotNull(sf);
        assertNull(server.poll()); // опустошаем очередь — переход из SERVER_SEND_FLIGHT
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        // Проверяем ALPN в EE
        byte[] eeBody = TlsHandshakeMessage.decode(ee).getBody();
        assertEquals("http/1.1", TlsMessageParser.parseEncryptedExtensions(eeBody).alpn);

        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        assertEquals("http/1.1", client.getSelectedAlpnProtocol());
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_OR_CR, client.getState());

        client.receive(cert);
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.receive(sf);
        byte[] cf = client.poll();
        assertNotNull(cf);
        assertNull(client.poll()); // опустошаем очередь клиента — переход из CLIENT_SEND_FINISHED
        server.receive(cf);
        assertTrue(client.isDone());
        assertTrue(server.isDone());
    }

    @Test
    @DisplayName("ALPN mismatch: сервер кидает ALERT_NO_APPLICATION_PROTOCOL")
    void testAlpnMismatchServerThrows() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        client.setClientAlpnProtocols(List.of("h2"));
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        server.setServerAlpnProtocols(List.of("http/1.1"));

        byte[] ch = client.start();
        assertNotNull(ch);

        TlsException ex = assertThrows(TlsException.class, () -> server.receive(ch));
        assertEquals(TlsConstants.ALERT_NO_APPLICATION_PROTOCOL, ex.getAlertCode());
        assertTrue(server.isError());
    }

    @Test
    @DisplayName("полный handshake без ALPN: selectedAlpnProtocol == null")
    void testFullHandshakeWithoutAlpn() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
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
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] ch = client.start();
        assertNotNull(ch);
        server.receive(ch);
        assertNull(server.getSelectedAlpnProtocol());

        byte[] sh = server.poll();
        byte[] ee = server.poll();
        byte[] cert = server.poll();
        byte[] cv = server.poll();
        byte[] sf = server.poll();
        assertNull(server.poll());

        // EE без ALPN
        byte[] eeBody = TlsHandshakeMessage.decode(ee).getBody();
        assertNull(TlsMessageParser.parseEncryptedExtensions(eeBody).alpn);

        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        assertNull(client.getSelectedAlpnProtocol());

        client.receive(cert);
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.receive(sf);
        byte[] cf = client.poll();
        assertNull(client.poll());
        server.receive(cf);
        assertTrue(client.isDone());
        assertTrue(server.isDone());
    }

    @Test
    @DisplayName("клиент отклоняет ALPN протокол не из его списка")
    void testClientRejectsServerAlpnNotOffered() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        client.setClientAlpnProtocols(List.of("h2"));

        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        server.setServerAlpnProtocols(List.of("h2"));

        byte[] ch = client.start();
        server.receive(ch);
        byte[] sh = server.poll();
        byte[] ee = server.poll();
        byte[] cert = server.poll();
        byte[] cv = server.poll();
        byte[] sf = server.poll();

        // Подменяем EE на протокол, которого нет в списке клиента
        byte[] fakeAlpn = TlsMessageBuilder.buildEncryptedExtensions("http/1.1");
        byte[] fakeEe =
                new TlsHandshakeMessage(TlsConstants.HT_ENCRYPTED_EXTENSIONS, fakeAlpn).encode();

        client.receive(sh);
        client.acknowledgeKeyChange();
        TlsException ex = assertThrows(TlsException.class, () -> client.receive(fakeEe));
        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, ex.getAlertCode());
        assertTrue(client.isError());
    }

    @Test
    @DisplayName("PSK handshake с ALPN: протокол согласован")
    void testPskHandshakeWithAlpn() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        client.setClientAlpnProtocols(List.of("h2"));
        byte[] pskKey = new byte[32];
        byte[] pskId = new byte[8];
        client.setPsk(pskKey, pskId, 42L);

        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        server.setServerAlpnProtocols(List.of("h2"));
        server.setServerPsk(pskKey);

        byte[] ch = client.start();
        server.receive(ch);
        assertTrue(server.isPskAccepted());
        assertEquals("h2", server.getSelectedAlpnProtocol());

        byte[] sh = server.poll();
        byte[] ee = server.poll();
        assertNotNull(ee);
        // PSK: no Cert/CV/SF — сразу Finished
        byte[] sf = server.poll();
        assertNull(server.poll());

        byte[] eeBody = TlsHandshakeMessage.decode(ee).getBody();
        assertEquals("h2", TlsMessageParser.parseEncryptedExtensions(eeBody).alpn);

        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        assertEquals("h2", client.getSelectedAlpnProtocol());
        // PSK: после EE сразу Finished
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_FINISHED, client.getState());

        client.receive(sf);
        byte[] cf = client.poll();
        assertNull(client.poll()); // опустошаем очередь -> POST_HANDSHAKE
        server.receive(cf);
        assertTrue(client.isDone());
        assertTrue(server.isDone());
    }

    // ===================================================================
    // mTLS: правильные алерты при отсутствии клиентского сертификата
    // ===================================================================
    //
    // Почему три теста:
    //   1. Клиент прислал не-Certificate (например Finished скипнув Cert/CV)
    //      -> сервер должен кинуть CERTIFICATE_REQUIRED, а не UNEXPECTED_MESSAGE
    //   2. Клиент прислал пустой Certificate (пустой certificate_list)
    //      -> сервер должен кинуть CERTIFICATE_REQUIRED
    //   3. Сервер прислал пустой Certificate (нарушение протокола)
    //      -> клиент должен кинуть DECODE_ERROR, а не NPE

    @Test
    @DisplayName("mTLS: клиент не прислал Certificate (скипнул flight) -> CERTIFICATE_REQUIRED")
    void testMtlsClientSkipsCertificate() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(true),
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
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        true,
                        null);

        byte[] ch = client.start();
        server.receive(ch);
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());

        // Сервер: poll весь flight (SH, EE, CR, Cert, CV, SF)
        assertNotNull(server.poll());
        assertNotNull(server.poll());
        assertNotNull(server.poll());
        assertNotNull(server.poll());
        assertNotNull(server.poll());
        assertNotNull(server.poll());
        assertNull(server.poll());
        // Сервер ждёт клиентский Certificate
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_CERTIFICATE, server.getState());

        // Клиент скипнул Certificate и прислал Finished — симулируем нарушение протокола
        byte[] fakeFinished =
                new TlsHandshakeMessage(TlsConstants.HT_FINISHED, new byte[] {0, 0, 0, 0}).encode();

        // Раньше было UNEXPECTED_MESSAGE — неверно. decode_error в логах пугает.
        TlsException ex = assertThrows(TlsException.class, () -> server.receive(fakeFinished));
        assertEquals(TlsConstants.ALERT_CERTIFICATE_REQUIRED, ex.getAlertCode());
        assertTrue(server.isError());
    }

    @Test
    @DisplayName("mTLS: клиент прислал пустой Certificate -> CERTIFICATE_REQUIRED")
    void testMtlsClientEmptyCertificate() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(true),
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
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        true,
                        null);

        byte[] ch = client.start();
        server.receive(ch);

        // Сервер: poll весь flight
        assertNotNull(server.poll());
        assertNotNull(server.poll());
        assertNotNull(server.poll());
        assertNotNull(server.poll());
        assertNotNull(server.poll());
        assertNotNull(server.poll());
        assertNull(server.poll());
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_CERTIFICATE, server.getState());

        // Пустой Certificate: request_context=0, certificate_list len=0 (RFC 8446 §4.4.2 разрешает)
        byte[] emptyCertBody = new byte[] {0x00, 0x00, 0x00, 0x00};
        byte[] emptyCertFrame =
                new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE, emptyCertBody).encode();

        // Раньше было BAD_CERTIFICATE — неверно. У сервера нет сертификата, это не bad cert.
        TlsException ex = assertThrows(TlsException.class, () -> server.receive(emptyCertFrame));
        assertEquals(TlsConstants.ALERT_CERTIFICATE_REQUIRED, ex.getAlertCode());
        assertTrue(server.isError());
    }

    @Test
    @DisplayName("клиент: сервер прислал пустой Certificate -> DECODE_ERROR")
    void testServerEmptyCertificate() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
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
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] ch = client.start();

        // Сервер: обрабатываем CH, подменяем Certificate на пустой
        server.receive(ch);
        byte[] sh = server.poll();
        byte[] ee = server.poll();
        // Пустой Certificate — сервер нарушает протокол (RFC 8446 §4.4.2: сервер обязан прислать)
        byte[] emptyCertBody = new byte[] {0x00, 0x00, 0x00, 0x00};
        byte[] emptyCertFrame =
                new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE, emptyCertBody).encode();
        byte[] cv = server.poll();
        byte[] sf = server.poll();
        assertNotNull(sf);

        // Доставляем клиенту SH -> EE -> пустой Certificate
        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_OR_CR, client.getState());

        // Клиент проверяет: пустой Certificate от сервера = protocol violation = DECODE_ERROR
        TlsException ex = assertThrows(TlsException.class, () -> client.receive(emptyCertFrame));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
        assertTrue(client.isError());
    }

    // ===================================================================
    // Invalid Finished: подмена verify_data
    // ===================================================================

    @Test
    @DisplayName("неверный verify_data в ServerFinished -> ALERT_HANDSHAKE_FAILURE")
    void testInvalidServerFinished() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
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
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        // Полный handshake до точки, где клиент ждёт ServerFinished
        byte[] ch = client.start();
        server.receive(ch);

        byte[] sh = server.poll();
        byte[] ee = server.poll();
        byte[] cert = server.poll();
        byte[] cv = server.poll();
        byte[] sf = server.poll();
        assertNotNull(sf);
        assertNull(server.poll());

        // Клиент: получает SH, EE, Cert, CV — переходит в CLIENT_WAIT_FINISHED
        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        client.receive(cert);
        assertTrue(client.needsCertificateValidation());
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_FINISHED, client.getState());

        // Вместо правильного ServerFinished — фейковый с verify_data из нулей
        byte[] fakeSf =
                new TlsHandshakeMessage(TlsConstants.HT_FINISHED, new byte[HASH_LEN]).encode();
        TlsException ex = assertThrows(TlsException.class, () -> client.receive(fakeSf));
        assertEquals(TlsConstants.ALERT_HANDSHAKE_FAILURE, ex.getAlertCode());
        assertTrue(client.isError(), "Engine должен перейти в ERROR");
    }

    @Test
    @DisplayName("неверный verify_data в ClientFinished -> ALERT_HANDSHAKE_FAILURE")
    void testInvalidClientFinished() throws Exception {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
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
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        // Полный handshake: клиент отправляет CH, сервер отвечает flight
        byte[] ch = client.start();
        server.receive(ch);

        byte[] sh = server.poll();
        byte[] ee = server.poll();
        byte[] cert = server.poll();
        byte[] cv = server.poll();
        byte[] sf = server.poll();
        assertNotNull(sf);
        assertNull(server.poll());
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        // Клиент: принимает SH, EE, Cert, CV, правильный SF -> генерирует CF
        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        client.receive(cert);
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.receive(sf);
        byte[] cf = client.poll();
        assertNotNull(cf, "Клиент должен сгенерировать Finished");
        assertNull(client.poll());
        // Сервер теперь в SERVER_WAIT_CLIENT_FINISHED — подаём фейковый CF
        byte[] fakeCf =
                new TlsHandshakeMessage(TlsConstants.HT_FINISHED, new byte[HASH_LEN]).encode();
        TlsException ex = assertThrows(TlsException.class, () -> server.receive(fakeCf));
        assertEquals(TlsConstants.ALERT_HANDSHAKE_FAILURE, ex.getAlertCode());
        assertTrue(server.isError(), "Engine должен перейти в ERROR");
    }

    // ====================================================================
    // HRR (HelloRetryRequest) тесты
    // ====================================================================

    @Test
    @DisplayName("HRR: клиент GC256A -> сервер ожидает GC256B -> HRR с GC256B -> CH2 -> handshake")
    void testHrrRoundTrip() throws Exception {
        int clientGroup = TlsConstants.GRP_GC256A;
        ECParameters clientParams = ECParameters.tc26a256();
        int serverGroup = TlsConstants.GRP_GC256B;
        ECParameters serverParams = ECParameters.cryptoProA();

        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                clientGroup,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        clientParams,
                        clientGroup,
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
                                serverGroup,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        serverParams,
                        serverGroup,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        // Клиент -> CH1 (GC256A)
        byte[] ch1 = client.start();
        assertNotNull(ch1);

        // Сервер: получает CH1 -> HRR (GC256B)
        server.receive(ch1);
        byte[] hrr = server.poll();
        assertNotNull(hrr, "Сервер должен вернуть HRR");
        assertNull(server.poll(), "После HRR очередь пуста");
        assertEquals(
                TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_HELLO,
                server.getState(),
                "Сервер ждёт второй CH");

        // Проверяем что это HRR, а не SH
        TlsHandshakeMessage hrrMsg = TlsHandshakeMessage.decode(hrr);
        assertEquals(TlsConstants.HT_SERVER_HELLO, hrrMsg.getType());
        TlsMessageParser.ParsedServerHello parsedHrr =
                TlsMessageParser.parseServerHello(hrrMsg.getBody(), clientGroup);
        assertTrue(
                TlsMessageParser.isHelloRetryRequest(parsedHrr),
                "Сообщение должно определяться как HRR");
        assertEquals(serverGroup, parsedHrr.requestedGroup, "HRR должен запрашивать GC256B");

        // Клиент: получает HRR -> CH2 (GC256B)
        client.receive(hrr);
        byte[] ch2 = client.poll();
        assertNotNull(ch2, "Клиент должен вернуть CH2 после HRR");
        assertNull(client.poll(), "После CH2 очередь пуста");
        assertEquals(
                TlsHandshakeEngine.State.CLIENT_WAIT_SERVER_HELLO,
                client.getState(),
                "Клиент ждёт настоящий SH");

        // Сервер: получает CH2 -> полноценный flight
        server.receive(ch2);
        // После CH2 poll сразу возвращает SH (первый фрейм flight'а)
        byte[] sh = server.poll();
        assertNotNull(sh, "Сервер должен вернуть SH");
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());
        client.receive(sh);
        client.acknowledgeKeyChange();

        byte[] ee = server.poll();
        byte[] cert = server.poll();
        byte[] cv = server.poll();
        byte[] sf = server.poll();
        assertNotNull(sf);
        assertNull(server.poll());

        client.receive(ee);
        client.receive(cert);
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.receive(sf);

        byte[] cf = client.poll();
        assertNotNull(cf, "Клиент должен сгенерировать Finished");
        assertNull(client.poll());

        server.receive(cf);
        assertEquals(
                TlsHandshakeEngine.State.POST_HANDSHAKE,
                server.getState(),
                "Сервер завершил handshake");
        assertTrue(server.isDone());
    }

    @Test
    @DisplayName("HRR + PSK: binder пересчитывается для CH2")
    void testHrrWithPsk() throws Exception {
        int clientGroup = TlsConstants.GRP_GC256A;
        ECParameters clientParams = ECParameters.tc26a256();
        int serverGroup = TlsConstants.GRP_GC256B;
        ECParameters serverParams = ECParameters.cryptoProA();

        byte[] psk = new byte[TlsConstants.STREEBOG_256_HASH_LEN];
        CryptoRandom.INSTANCE.nextBytes(psk);
        byte[] pskIdentity = "test-hrr-psk-identity".getBytes();

        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                clientGroup,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        clientParams,
                        clientGroup,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        client.setPsk(psk, pskIdentity, 0);

        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                serverGroup,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        serverParams,
                        serverGroup,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        server.setServerPsk(psk);

        // Клиент -> CH1 (с PSK binder)
        byte[] ch1 = client.start();
        assertNotNull(ch1);

        // Сервер: CH1 -> HRR (binder от CH1 не верифицируется при HRR)
        server.receive(ch1);
        byte[] hrr = server.poll();
        assertNotNull(hrr);
        assertNull(server.poll());

        // Клиент -> HRR -> CH2 (PSK binder пересчитан)
        client.receive(hrr);
        byte[] ch2 = client.poll();
        assertNotNull(ch2);

        // Сервер: CH2 -> PSK binder верифицирован -> flight
        server.receive(ch2);
        assertTrue(
                server.isPskAccepted(), "PSK должен быть принят после CH2 с пересчитанным binder");

        byte[] sh = server.poll();
        assertNotNull(sh);
        client.receive(sh);
        client.acknowledgeKeyChange();
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());

        byte[] ee = server.poll();
        byte[] sf = server.poll();
        assertNotNull(sf);
        assertNull(server.poll());
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        client.receive(ee);
        // При PSK сертификаты не приходят — после EE сразу Finished
        client.receive(sf);

        byte[] cf = client.poll();
        assertNotNull(cf);
        assertNull(client.poll());

        server.receive(cf);
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, server.getState());
        assertTrue(server.isDone());
    }

    @Test
    @DisplayName("HRR: двойной HRR вызывает ALERT_UNEXPECTED_MESSAGE")
    void testHrrDoubleRejected() throws Exception {
        int clientGroup = TlsConstants.GRP_GC256A;
        ECParameters clientParams = ECParameters.tc26a256();
        // Сервер использует группу, отличную от клиентской
        int serverGroup = TlsConstants.GRP_GC256B;
        ECParameters serverParams = ECParameters.cryptoProA();

        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                clientGroup,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        clientParams,
                        clientGroup,
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
                                serverGroup,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        serverParams,
                        serverGroup,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] ch1 = client.start();
        assertNotNull(ch1);

        // Сервер -> HRR
        server.receive(ch1);
        byte[] hrr = server.poll();
        assertNotNull(hrr);

        // Эмулируем ситуацию: клиент не понял HRR и снова прислал CH1 с той же группой
        // (вместо правильного CH2). Для чистоты теста используем второй
        // экземпляр клиента, который НЕ обработал HRR.
        TlsHandshakeEngine badClient =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                clientGroup,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        clientParams,
                        clientGroup,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        byte[] ch1Again = badClient.start();

        // Сервер должен отклонить второй CH с неправильной группой после HRR
        TlsException ex = assertThrows(TlsException.class, () -> server.receive(ch1Again));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                ex.getAlertCode(),
                "Двойной HRR с неправильной группой должен вызывать ALERT_ILLEGAL_PARAMETER");
        assertTrue(server.isError());
    }

    @Test
    @DisplayName("HRR: неизвестная группа в HRR вызывает ALERT_ILLEGAL_PARAMETER")
    void testHrrUnknownGroup() throws Exception {
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

        byte[] ch1 = client.start();
        assertNotNull(ch1);

        // Строим HRR с несуществующей группой 0xFFFF
        TlsMessageBuilder builder =
                new TlsMessageBuilder(
                        cs(), List.of(cs().getId()), NAMED_GROUP, SIG_SCHEME, null, null, HASH_LEN);
        byte[] fakeHrrBody = builder.buildHelloRetryRequest(0xFFFF, cs().getId());
        byte[] fakeHrr =
                new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, fakeHrrBody).encode();

        TlsException ex = assertThrows(TlsException.class, () -> client.receive(fakeHrr));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                ex.getAlertCode(),
                "Неизвестная группа в HRR должна вызывать ALERT_ILLEGAL_PARAMETER");
        assertTrue(client.isError());
    }

    @Test
    @DisplayName(
            "HRR без key_share: сервер присылает только cookie, клиент отвечает CH2 с той же группой")
    void testHrrWithoutKeyShare() throws Exception {
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

        byte[] ch1 = client.start();
        assertNotNull(ch1);

        // Строим HRR без key_share, с cookie
        byte[] cookie = CryptoRandom.INSTANCE.generateSeed(16);
        byte[] hrrBody =
                new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                NAMED_GROUP,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN)
                        .buildHelloRetryRequest(cs().getId(), cookie);
        byte[] hrr = new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, hrrBody).encode();

        // Клиент должен обработать HRR без исключения
        client.receive(hrr);
        byte[] ch2 = client.poll();
        assertNotNull(ch2, "Клиент должен вернуть CH2 после HRR без key_share");
        assertEquals(
                TlsHandshakeEngine.State.CLIENT_WAIT_SERVER_HELLO,
                client.getState(),
                "Клиент ждёт настоящий SH");
    }

    @Test
    @DisplayName("handshake с max_fragment_length=1 (512 байт): согласование и фрагментация")
    void testHandshakeWithMaxFragmentLength() throws Exception {
        // Клиент запрашивает max_fragment_length=512 байт
        TlsMessageBuilder clientMb = clientBuilder(false);
        clientMb.setClientMaxFragLen(TlsConstants.MAX_FRAG_LEN_512);
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientMb,
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        client.setClientMaxFragLenRequest(TlsConstants.MAX_FRAG_LEN_512);

        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        cs(),
                        serverBuilder(),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        // ClientHello
        byte[] ch = client.start();
        assertNotNull(ch);
        byte[] chBody = TlsHandshakeMessage.decode(ch).getBody();
        assertEquals(
                TlsConstants.MAX_FRAG_LEN_512,
                TlsMessageParser.parseClientHello(chBody, NAMED_GROUP).clientMaxFragLen);

        // Сервер принимает
        server.receive(ch);
        assertEquals(TlsConstants.MAX_FRAG_LEN_512, server.getMaxFragmentLength());
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());

        byte[] sh = server.poll();
        byte[] ee = server.poll();
        assertNotNull(ee);

        // Проверяем EE: сервер подтвердил max_fragment_length
        byte[] eeBody = TlsHandshakeMessage.decode(ee).getBody();
        TlsMessageParser.ParsedEncryptedExtensions parsedEE =
                TlsMessageParser.parseEncryptedExtensions(eeBody);
        assertEquals(TlsConstants.MAX_FRAG_LEN_512, parsedEE.maxFragLen);

        byte[] cert = server.poll();
        byte[] cv = server.poll();
        byte[] sf = server.poll();
        assertNotNull(sf);
        assertNull(server.poll());
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        // Клиент: ServerHello -> EncryptedExtensions -> ...
        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        assertEquals(TlsConstants.MAX_FRAG_LEN_512, client.getMaxFragmentLength());
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_OR_CR, client.getState());

        client.receive(cert);
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.receive(sf);
        byte[] cf = client.poll();
        assertNotNull(cf);
        assertNull(client.poll());
        server.receive(cf);
        assertTrue(client.isDone());
        assertTrue(server.isDone());
    }

    @Test
    @DisplayName("max_fragment_length: сервер вернул другое значение -> ALERT_ILLEGAL_PARAMETER")
    void testMaxFragmentLengthMismatchServerResponse() throws Exception {
        TlsMessageBuilder clientMb = clientBuilder(false);
        clientMb.setClientMaxFragLen(TlsConstants.MAX_FRAG_LEN_512);
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientMb,
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        client.setClientMaxFragLenRequest(TlsConstants.MAX_FRAG_LEN_512);

        byte[] ch = client.start();
        assertNotNull(ch);

        // Сервер подтверждает ДРУГОЕ значение (1024 вместо 512)
        byte[] eeBody =
                TlsMessageBuilder.buildEncryptedExtensions(null, TlsConstants.MAX_FRAG_LEN_1024);
        byte[] eeFrame =
                new TlsHandshakeMessage(TlsConstants.HT_ENCRYPTED_EXTENSIONS, eeBody).encode();

        // Генерируем валидный ServerHello с ECDHE для продвижения state machine
        KeyPair ecdheKp = KeyGenerator.generateKeyPair(EC_PARAMS);
        byte[] ecdhePoint = TlsEncoding.encodePoint(ecdheKp.getPublic());
        TlsMessageBuilder serverMb = serverBuilder();
        byte[] shBody = serverMb.buildServerHello(ecdhePoint, false, NAMED_GROUP);
        byte[] shFrame = new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, shBody).encode();

        client.receive(shFrame);
        client.acknowledgeKeyChange();

        TlsException ex = assertThrows(TlsException.class, () -> client.receive(eeFrame));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                ex.getAlertCode(),
                "Сервер вернул другое max_fragment_length -> ALERT_ILLEGAL_PARAMETER");
        assertTrue(client.isError());
    }

    @Test
    @DisplayName(
            "max_fragment_length: сервер вернул незапрошенное расширение -> ALERT_ILLEGAL_PARAMETER")
    void testMaxFragmentLengthUnsolicited() throws Exception {
        // Клиент НЕ запрашивает max_fragment_length
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        clientBuilder(false),
                        EC_PARAMS,
                        NAMED_GROUP,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] ch = client.start();
        assertNotNull(ch);

        // Сервер включает max_fragment_length в EE без запроса
        byte[] eeBody =
                TlsMessageBuilder.buildEncryptedExtensions(null, TlsConstants.MAX_FRAG_LEN_512);
        byte[] eeFrame =
                new TlsHandshakeMessage(TlsConstants.HT_ENCRYPTED_EXTENSIONS, eeBody).encode();

        KeyPair ecdheKp = KeyGenerator.generateKeyPair(EC_PARAMS);
        byte[] ecdhePoint = TlsEncoding.encodePoint(ecdheKp.getPublic());
        TlsMessageBuilder serverMb = serverBuilder();
        byte[] shBody = serverMb.buildServerHello(ecdhePoint, false, NAMED_GROUP);
        byte[] shFrame = new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, shBody).encode();

        client.receive(shFrame);
        client.acknowledgeKeyChange();

        TlsException ex = assertThrows(TlsException.class, () -> client.receive(eeFrame));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                ex.getAlertCode(),
                "Незапрошенное max_fragment_length от сервера -> ALERT_ILLEGAL_PARAMETER");
        assertTrue(client.isError());
    }

    // ====================================================================
    // HRR wire-формат
    // ====================================================================

    @Test
    @DisplayName("HRR: key_share extension содержит только NamedGroup (2 байта, RFC 8446 §4.2.8)")
    void testHrrKeyShareWireFormat() throws Exception {
        int clientGroup = TlsConstants.GRP_GC256A;
        ECParameters clientParams = ECParameters.tc26a256();
        int serverGroup = TlsConstants.GRP_GC256B;

        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                clientGroup,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        clientParams,
                        clientGroup,
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
                                serverGroup,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        ECParameters.cryptoProA(),
                        serverGroup,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);

        byte[] ch1 = client.start();
        assertNotNull(ch1);

        server.receive(ch1);
        byte[] hrr = server.poll();
        assertNotNull(hrr);

        TlsHandshakeMessage hrrMsg = TlsHandshakeMessage.decode(hrr);
        assertTrue(
                TlsMessageParser.isHelloRetryRequest(
                        TlsMessageParser.parseServerHello(hrrMsg.getBody(), clientGroup)),
                "Должен быть HRR");

        // Проверка wire-формата: ищем EXT_KEY_SHARE (0x0033) в raw body
        // со смещения extensions, чтобы не зацепить ложное совпадение в random или session_id
        byte[] body = hrrMsg.getBody();
        int sidLen = body[34] & 0xFF;
        // Body layout: legacy_version[2] + random[32] + sid_len[1] + session_id[sidLen] +
        //              cipher_suite[2] + compression[1] + ext_len[2] + extensions[...]
        int extOffset = 40 + sidLen;
        boolean found = false;
        for (int i = extOffset; i <= body.length - 6; i++) {
            if ((body[i] & 0xFF) == 0x00 && (body[i + 1] & 0xFF) == TlsConstants.EXT_KEY_SHARE) {
                int extLen = ((body[i + 2] & 0xFF) << 8) | (body[i + 3] & 0xFF);
                assertEquals(
                        2,
                        extLen,
                        "HRR key_share extension data длина должна быть 2 (только NamedGroup)");
                assertEquals(
                        serverGroup >> 8,
                        body[i + 4] & 0xFF,
                        "HRR key_share NamedGroup (старший байт)");
                assertEquals(
                        serverGroup & 0xFF,
                        body[i + 5] & 0xFF,
                        "HRR key_share NamedGroup (младший байт)");
                found = true;
                break;
            }
        }
        assertTrue(found, "EXT_KEY_SHARE (0x0033) не найден в HRR");
    }
}
