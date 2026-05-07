package org.rssys.gost.tls13.engine;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.TlsTestHelper;
import static org.rssys.gost.tls13.TlsTestHelper.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

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
        return new TlsMessageBuilder(cs(), NAMED_GROUP, SIG_SCHEME,
                withCert ? clientCert.priv : null,
                withCert ? List.of(clientCert.cert) : null,
                HASH_LEN);
    }

    private static TlsMessageBuilder serverBuilder() {
        return new TlsMessageBuilder(cs(), NAMED_GROUP, SIG_SCHEME,
                serverCert.priv,
                List.of(serverCert.cert),
                HASH_LEN);
    }

    // -------------------------------------------------------------------
    // Полный handshake (клиент ↔ сервер, без mTLS)
    // -------------------------------------------------------------------
    //
    // WHY: Базовый сценарий — проверяем state machine целиком.
    // Клиент → ClientHello → Сервер → SH/EE/Cert/CV/Finished → Клиент.
    // Без mTLS клиент не отправляет свой сертификат.
    // Если этот тест падает, ни одно TLS-соединение не установится.

    @Test
    @DisplayName("полный handshake client ↔ server без mTLS")
    void testFullHandshake() throws Exception {
        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);

        // Клиент: start → ClientHello
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
        assertTrue(client.needsCertificateValidation(), "Engine должен запросить валидацию сертификата");
        assertNotNull(client.getReceivedCertificates(), "Сертификаты должны быть получены");
        client.acknowledgeCertificateValidation(true);

        client.receive(cv);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_FINISHED, client.getState());
        assertFalse(client.needsCertificateValidation(), "После CV флаг валидации сброшен");

        client.receive(sf);
        assertEquals(TlsHandshakeEngine.State.CLIENT_SEND_FINISHED, client.getState());

        // Клиент: poll() → Certificate? (нет mTLS) → Finished
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
    // WHY: mTLS — сервер запрашивает CertificateRequest, клиент отправляет
    // свой сертификат и CertificateVerify. Проверяем, что state machine
    // корректно проходит через CLIENT_WAIT_CERTIFICATE → отправку Cert/CV
    // и сервер ждёт SERVER_WAIT_CLIENT_CERTIFICATE/CV.

    @Test
    @DisplayName("handshake с mTLS (сервер запрашивает клиентский сертификат)")
    void testMutualTlsHandshake() throws Exception {
        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(true),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, true);

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

        // Клиент: SH → EE → CR → Cert → CV → Finished
        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        client.receive(cr); // CertificateRequest
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE, client.getState(),
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

        // Сервер: получает Cert → CV → Finished
        server.receive(clientCert);
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_CERTIFICATE_VERIFY, server.getState());
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
    // WHY: Engine должен валидировать тип каждого incoming handshake-сообщения.
    // Если клиент ожидает ServerHello, а получает EncryptedExtensions —
    // это нарушение протокола → TlsException → ERROR.

    @Test
    @DisplayName("неправильный тип сообщения кидает TlsException")
    void testWrongMessageType() throws TlsException {
        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);

        byte[] ch = client.start();
        assertNotNull(ch);

        // Вместо ServerHello передаём EncryptedExtensions — ошибка
        byte[] fakeSh = new TlsHandshakeMessage(
                TlsConstants.HT_ENCRYPTED_EXTENSIONS, new byte[]{0, 0}).encode();

        assertThrows(TlsException.class, () -> client.receive(fakeSh));
        assertTrue(client.isError(), "Engine должен перейти в ERROR");
    }

    // -------------------------------------------------------------------
    // Клиент: receive до start() кидает исключение
    // -------------------------------------------------------------------
    //
    // WHY: Клиент ДОЛЖЕН сначала вызвать start() для генерации ClientHello.
    // Получение сообщения до start() — ошибка использования API.
    // Проверяем, что engine не допускает receive() в INIT state.

    @Test
    @DisplayName("клиентский receive до start() кидает TlsException")
    void testReceiveBeforeStart() {
        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);

        byte[] garbage = new TlsHandshakeMessage(
                TlsConstants.HT_SERVER_HELLO, new byte[]{0}).encode();
        assertThrows(TlsException.class, () -> client.receive(garbage));
    }

    // -------------------------------------------------------------------
    // Сервер без mTLS: poll после Finished → ожидание Finished от клиента
    // -------------------------------------------------------------------
    //
    // WHY: После отправки всех сообщений (SH/EE/Cert/CV/Finished) сервер
    // переходит в SERVER_WAIT_CLIENT_FINISHED. Проверяем, что переход
    // происходит корректно и engine не зависает в SERVER_SEND_FLIGHT.

    @Test
    @DisplayName("сервер после отправки flight ожидает клиентский Finished")
    void testServerWaitsForClientFinished() throws Exception {
        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);

        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);

        byte[] ch = client.start();
        server.receive(ch);

        // Drain queue
        while (server.poll() != null) ;

        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState(),
                "Сервер должен ждать клиентский Finished");
    }

    // -------------------------------------------------------------------
    // Engine: отрицание сертификата → ERROR
    // -------------------------------------------------------------------
    //
    // WHY: Если клиент отклоняет сертификат сервера (acknowledgeCertificate(false)),
    // handshake не может продолжаться. Engine переходит в ERROR.
    // Это критический путь безопасности — недоверенный сертификат = разрыв.

    @Test
    @DisplayName("отклонение сертификата переводит engine в ERROR")
    void testCertificateRejection() throws Exception {
        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);

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
    // WHY: Без mTLS сервер после опустошения очереди переходит в
    // SERVER_WAIT_CLIENT_FINISHED (а не SERVER_WAIT_CLIENT_CERTIFICATE).
    // Это дублирует testServerWaitsForClientFinished как явный negative test
    // для mTLS-флага = false.

    @Test
    @DisplayName("без mTLS сервер ждёт клиентский Finished сразу после flight")
    void testServerNoMtlsWaitState() throws Exception {
        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);

        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);

        byte[] ch = client.start();
        server.receive(ch);

        byte[] msg;
        while ((msg = server.poll()) != null) {
            // drain
        }

        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState(),
                "Без mTLS: SERVER_WAIT_CLIENT_FINISHED");
    }

    // -------------------------------------------------------------------
    // c mTLS: после poll сервер ждёт клиентский Cert
    // -------------------------------------------------------------------
    //
    // WHY: С mTLS после flight сервер ждёт клиентский Certificate,
    // а не Finished. Это ключевое отличие mTLS от обычного handshake.

    @Test
    @DisplayName("с mTLS сервер ждёт клиентский Certificate после flight")
    void testServerMtlsWaitState() throws Exception {
        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, true);

        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(true),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);

        byte[] ch = client.start();
        server.receive(ch);

        byte[] msg;
        while ((msg = server.poll()) != null) {
            // drain
        }

        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_CERTIFICATE, server.getState(),
                "С mTLS: SERVER_WAIT_CLIENT_CERTIFICATE");
    }

    // -------------------------------------------------------------------
    // ALPN (RFC 7301)
    // -------------------------------------------------------------------

    @Test
    @DisplayName("полный handshake с ALPN: http/1.1 согласован")
    void testFullHandshakeWithAlpn() throws Exception {
        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
        client.setClientAlpnProtocols(List.of("h2", "http/1.1"));
        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
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
        assertEquals("http/1.1", TlsMessageParser.parseEncryptedExtensionsAlpn(eeBody));

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
        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
        client.setClientAlpnProtocols(List.of("h2"));
        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
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
        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);

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
        assertNull(TlsMessageParser.parseEncryptedExtensionsAlpn(eeBody));

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
        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
        client.setClientAlpnProtocols(List.of("h2"));

        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
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
        byte[] fakeEe = new TlsHandshakeMessage(TlsConstants.HT_ENCRYPTED_EXTENSIONS, fakeAlpn).encode();

        client.receive(sh);
        client.acknowledgeKeyChange();
        TlsException ex = assertThrows(TlsException.class, () -> client.receive(fakeEe));
        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, ex.getAlertCode());
        assertTrue(client.isError());
    }

    @Test
    @DisplayName("PSK handshake с ALPN: протокол согласован")
    void testPskHandshakeWithAlpn() throws Exception {
        TlsHandshakeEngine client = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT, cs(), clientBuilder(false),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
        client.setClientAlpnProtocols(List.of("h2"));
        byte[] pskKey = new byte[32];
        byte[] pskId = new byte[8];
        client.setPsk(pskKey, pskId, 42L);

        TlsHandshakeEngine server = new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER, cs(), serverBuilder(),
                EC_PARAMS, NAMED_GROUP, SIG_SCHEME, HASH_LEN, null, false);
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
        assertEquals("h2", TlsMessageParser.parseEncryptedExtensionsAlpn(eeBody));

        client.receive(sh);
        client.acknowledgeKeyChange();
        client.receive(ee);
        assertEquals("h2", client.getSelectedAlpnProtocol());
        // PSK: после EE сразу Finished
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_FINISHED, client.getState());

        client.receive(sf);
        byte[] cf = client.poll();
        assertNull(client.poll()); // опустошаем очередь → POST_HANDSHAKE
        server.receive(cf);
        assertTrue(client.isDone());
        assertTrue(server.isDone());
    }
}
