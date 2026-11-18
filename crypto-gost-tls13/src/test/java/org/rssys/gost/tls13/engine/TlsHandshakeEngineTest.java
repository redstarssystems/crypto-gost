package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.*;
import org.rssys.gost.tls13.config.SniCertificateSelector;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageBuilderTestAccess;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.*;
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

    /** Типы расширений ClientHello, на которые тест якобы получает ответ в ServerHello. */
    private static final Set<Integer> SERVER_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_SUPPORTED_VERSIONS,
                    TlsConstants.EXT_KEY_SHARE,
                    TlsConstants.EXT_PRE_SHARED_KEY);

    /** Типы ответных расширений EE, на которые клиент якобы отправил запрос. */
    private static final Set<Integer> ALL_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                    TlsConstants.EXT_MAX_FRAGMENT_LENGTH,
                    TlsConstants.EXT_SERVER_NAME);

    private static final ECParameters EC_PARAMS = ECParameters.tc26a256();
    private static final int NAMED_GROUP = TlsConstants.GRP_GC256A;
    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;

    private static PkixCertTestHelper.CertBundle serverCert;
    private static PkixCertTestHelper.CertBundle clientCert;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = PkixCertTestHelper.createCertWithKey(EC_PARAMS);
        clientCert = PkixCertTestHelper.createCertWithKey(EC_PARAMS);
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
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);

        // Клиент: start -> ClientHello
        byte[] ch = client.start();
        assertNotNull(ch, "Клиент должен сгенерировать ClientHello");
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_SERVER_HELLO, client.getState());

        // Сервер: получает ClientHello
        server.receive(ch);
        server.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());

        // Сервер: проверяем что poll() содержит SH, EE, Cert, CV, Finished
        byte[] sh = HandshakeOutputs.nextMessage(server);
        assertNotNull(sh, "Сервер должен сгенерировать ServerHello");
        byte[] ee = HandshakeOutputs.nextMessage(server);
        assertNotNull(ee, "Сервер должен сгенерировать EncryptedExtensions");
        byte[] cert = HandshakeOutputs.nextMessage(server);
        assertNotNull(cert, "Сервер должен сгенерировать Certificate");
        byte[] cv = HandshakeOutputs.nextMessage(server);
        assertNotNull(cv, "Сервер должен сгенерировать CertificateVerify");
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNotNull(sf, "Сервер должен сгенерировать Finished");
        assertNull(HandshakeOutputs.nextMessage(server), "После Finished очередь сервера пуста");

        // Сервер после опустошения очереди переходит в ожидание
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        // Клиент: последовательно получает SH, EE, Cert, CV, Finished
        client.receive(sh);
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_ENCRYPTED_EXTENSIONS, client.getState());
        assertTrue(client.hasReadKeysChanged(), "Ключи чтения должны измениться после SH");
        assertNotNull(client.getReadKeys(), "Ключи чтения должны быть установлены после SH");
        client.acknowledgeReadKeyChange();

        client.receive(ee);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_OR_CR, client.getState());

        // Обработка сертификата
        client.receive(cert);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_VERIFY, client.getState());
        assertTrue(
                client.needsCertificateValidation(),
                "Engine должен запросить валидацию сертификата");
        assertNotNull(client.getReceivedCertificates(), "Сертификаты должны быть получены");
        client.acknowledgeCertificateValidation(true);

        client.receive(cv);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_FINISHED, client.getState());
        assertFalse(client.needsCertificateValidation(), "После CV флаг валидации сброшен");

        client.receive(sf);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.CLIENT_SEND_FINISHED, client.getState());

        // Клиент: poll() -> Certificate? (нет mTLS) -> Finished
        // (нет mTLS, поэтому сразу Finished)
        byte[] cf = HandshakeOutputs.nextMessage(client);
        assertNotNull(cf, "Клиент должен сгенерировать Finished");
        assertNull(HandshakeOutputs.nextMessage(client), "После Finished очередь клиента пуста");
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, client.getState());

        // Сервер: получает клиентский Finished
        server.receive(cf);
        server.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, server.getState());

        // Оба engine завершили handshake
        assertTrue(client.isDone());
        assertTrue(server.isDone());
        // Ключи записи в движке не хранятся: их смены стоят в выходном потоке и проверяются
        // тестами порядка потока
        assertNotNull(client.getReadKeys(), "App read keys должны быть");
        assertNotNull(server.getReadKeys(), "App read keys должны быть");
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
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, true, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, true);

        byte[] ch = client.start();
        assertNotNull(ch);

        server.receive(ch);
        server.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());

        // Сервер: poll SH, EE, CR, Cert, CV, Finished
        byte[] sh = HandshakeOutputs.nextMessage(server);
        assertNotNull(sh);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        assertNotNull(ee);
        byte[] cr = HandshakeOutputs.nextMessage(server);
        assertNotNull(cr, "Должен быть CertificateRequest (mTLS)");
        byte[] cert = HandshakeOutputs.nextMessage(server);
        assertNotNull(cert);
        byte[] cv = HandshakeOutputs.nextMessage(server);
        assertNotNull(cv);
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNotNull(sf);
        assertNull(HandshakeOutputs.nextMessage(server), "Очередь сервера пуста после Finished");

        // Сервер ждёт клиентский Cert/CV
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_CERTIFICATE, server.getState());

        // Клиент: SH -> EE -> CR -> Cert -> CV -> Finished
        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
        client.receive(cr); // CertificateRequest
        assertEquals(
                TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE,
                client.getState(),
                "После CR клиент ждёт Certificate");

        client.receive(cert);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_VERIFY, client.getState());
        assertTrue(client.needsCertificateValidation());
        client.acknowledgeCertificateValidation(true);

        client.receive(cv);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_FINISHED, client.getState());

        client.receive(sf);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.CLIENT_SEND_FINISHED, client.getState());

        // Клиент: должен отправить Cert, CV, Finished
        byte[] clientCert = HandshakeOutputs.nextMessage(client);
        assertNotNull(clientCert, "Клиент должен отправить свой Certificate (mTLS)");
        byte[] clientCv = HandshakeOutputs.nextMessage(client);
        assertNotNull(clientCv, "Клиент должен отправить свой CertificateVerify (mTLS)");
        byte[] clientCf = HandshakeOutputs.nextMessage(client);
        assertNotNull(clientCf, "Клиент должен отправить свой Finished");
        assertNull(HandshakeOutputs.nextMessage(client), "Очередь клиента пуста");
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, client.getState());

        // Сервер: получает Cert -> CV -> Finished
        server.receive(clientCert);
        server.acknowledgeReadKeyChange();
        assertEquals(
                TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_CERTIFICATE_VERIFY, server.getState());
        assertTrue(server.needsCertificateValidation());
        server.acknowledgeCertificateValidation(true);

        server.receive(clientCv);
        server.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        server.receive(clientCf);
        server.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, server.getState());

        assertTrue(server.isDone());
    }

    /** Портит последний байт кадра CertificateVerify: он принадлежит подписи. */
    private static byte[] withCorruptedSignature(byte[] certificateVerifyFrame) {
        byte[] corrupted = certificateVerifyFrame.clone();
        corrupted[corrupted.length - 1] ^= 0x01;
        return corrupted;
    }

    @Test
    @DisplayName("Неверная подпись CertificateVerify сервера: клиент отвечает decrypt_error")
    void testInvalidServerCertificateVerify() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        server.receive(client.start());
        server.acknowledgeReadKeyChange();
        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        byte[] cert = HandshakeOutputs.nextMessage(server);
        byte[] cv = HandshakeOutputs.nextMessage(server);

        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
        client.receive(cert);
        client.acknowledgeReadKeyChange();
        client.acknowledgeCertificateValidation(true);

        byte[] corrupted = withCorruptedSignature(cv);
        TlsException ex = assertThrows(TlsException.class, () -> client.receive(corrupted));
        assertEquals(TlsConstants.ALERT_DECRYPT_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName("mTLS: неверная подпись CertificateVerify клиента: сервер отвечает decrypt_error")
    void testInvalidClientCertificateVerify() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, true, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, true);
        server.receive(client.start());
        server.acknowledgeReadKeyChange();
        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        byte[] cr = HandshakeOutputs.nextMessage(server);
        byte[] cert = HandshakeOutputs.nextMessage(server);
        byte[] cv = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNull(
                HandshakeOutputs.nextMessage(server),
                "очередь сервера опустошена: он ждёт клиентский Certificate");

        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
        client.receive(cr);
        client.acknowledgeReadKeyChange();
        client.receive(cert);
        client.acknowledgeReadKeyChange();
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.acknowledgeReadKeyChange();
        client.receive(sf);
        client.acknowledgeReadKeyChange();
        byte[] clientCertificate = HandshakeOutputs.nextMessage(client);
        byte[] clientCv = HandshakeOutputs.nextMessage(client);

        server.receive(clientCertificate);
        server.acknowledgeReadKeyChange();
        server.acknowledgeCertificateValidation(true);
        byte[] corrupted = withCorruptedSignature(clientCv);
        TlsException ex = assertThrows(TlsException.class, () -> server.receive(corrupted));
        assertEquals(TlsConstants.ALERT_DECRYPT_ERROR, ex.getAlertCode());
    }

    private static TlsHandshakeEngine newEngine(
            TlsHandshakeEngine.Role role, boolean clientWithCert, boolean requestClientAuth) {
        boolean client = role == TlsHandshakeEngine.Role.CLIENT;
        return new TlsHandshakeEngine(
                role,
                cs(),
                client ? clientBuilder(clientWithCert) : serverBuilder(),
                EC_PARAMS,
                NAMED_GROUP,
                SIG_SCHEME,
                HASH_LEN,
                null,
                requestClientAuth,
                null);
    }

    @Test
    @DisplayName("сервер: эфемерный ключ ECDHE затирается сразу после расчёта общего секрета")
    void testServerEcdhePrivateKeyDestroyedAfterSharedSecret() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);

        server.receive(client.start());
        server.acknowledgeReadKeyChange();

        // Рукопожатие ещё не закончено, контекст жив: ключ в нём уже должен быть затёрт
        java.lang.reflect.Field contextField = TlsHandshakeEngine.class.getDeclaredField("ctx");
        contextField.setAccessible(true);
        HandshakeContext context = (HandshakeContext) contextField.get(server);
        assertNotNull(context.getEcdhePrivateKey(), "Ключ должен был быть создан");
        assertTrue(
                context.getEcdhePrivateKey().isDestroyed(),
                "Эфемерный ключ сервера нужно затирать, а не только терять на него ссылку");
    }

    /** Находит в ClientHello расширение signature_algorithms и заменяет схемы на заданные. */
    private static byte[] withSignatureAlgorithms(byte[] frame, int... schemes) {
        byte[] result = frame.clone();
        int pos = 4 + 2 + 32;
        pos += 1 + (result[pos] & 0xFF);
        pos += 2 + (((result[pos] & 0xFF) << 8) | (result[pos + 1] & 0xFF));
        pos += 1 + (result[pos] & 0xFF);
        int extensionsEnd = pos + 2 + (((result[pos] & 0xFF) << 8) | (result[pos + 1] & 0xFF));
        pos += 2;
        while (pos < extensionsEnd) {
            int type = ((result[pos] & 0xFF) << 8) | (result[pos + 1] & 0xFF);
            int length = ((result[pos + 2] & 0xFF) << 8) | (result[pos + 3] & 0xFF);
            if (type == TlsConstants.EXT_SIGNATURE_ALGORITHMS) {
                assertEquals(2 + 2 * schemes.length, length, "Длина списка схем должна совпасть");
                result[pos + 4] = (byte) ((2 * schemes.length) >>> 8);
                result[pos + 5] = (byte) (2 * schemes.length);
                for (int i = 0; i < schemes.length; i++) {
                    result[pos + 6 + 2 * i] = (byte) (schemes[i] >>> 8);
                    result[pos + 7 + 2 * i] = (byte) schemes[i];
                }
                return result;
            }
            pos += 4 + length;
        }
        throw new AssertionError("В ClientHello нет signature_algorithms");
    }

    @Test
    @DisplayName(
            "клиент не предложил схему сертификата сервера: сервер продолжает (RFC 8446 §4.4.3)")
    void testServerContinuesWhenClientDidNotOfferCertificateScheme() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        byte[] frame = client.start();
        // Семь схем клиента по умолчанию заменяем семью чужими (ECDSA и RSA-PSS), длина та же
        byte[] foreign =
                withSignatureAlgorithms(
                        frame, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807);

        // У сервера одна цепочка, и составить другую, подписанную предложенными алгоритмами, он не
        // может: это исключение RFC 8446 §4.4.3, рукопожатие продолжается схемой ключа сертификата.
        // Строгий отказ (handshake_failure) сознательно не вводится: безопасности он не прибавляет,
        // а клиенты со строгой проверкой (OpenSSL: wrong signature type) отвергают подпись сами
        server.receive(foreign);
        server.acknowledgeReadKeyChange();

        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());
    }

    @Test
    @DisplayName("клиент предложил схему сертификата среди прочих: рукопожатие продолжается")
    void testServerAcceptsClientOfferingCertificateScheme() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        byte[] frame = client.start();
        // Схема кривой сервера стоит последней среди чужих: порядок списка не важен
        byte[] mixed =
                withSignatureAlgorithms(
                        frame, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, SIG_SCHEME);

        server.receive(mixed);
        server.acknowledgeReadKeyChange();

        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());
    }

    @Test
    @DisplayName("ClientHello с хвостом после расширений: decode_error")
    void testClientHelloTrailingBytesRejected() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        byte[] frame = client.start();
        // Хвост внутри объявленной длины сообщения: за блоком расширений два лишних байта
        byte[] withTrail = java.util.Arrays.copyOf(frame, frame.length + 2);
        int bodyLength = frame.length - 4 + 2;
        withTrail[1] = (byte) (bodyLength >>> 16);
        withTrail[2] = (byte) (bodyLength >>> 8);
        withTrail[3] = (byte) bodyLength;

        TlsException error = assertThrows(TlsException.class, () -> server.receive(withTrail));

        assertEquals(TlsConstants.ALERT_DECODE_ERROR, error.getAlertCode());
    }

    @Test
    @DisplayName("Клиентский CertificateEntry с status_request -> unsupported_extension")
    void testClientCertificateUnexpectedStatusRequestRejected() throws Exception {
        TlsHandshakeEngine server = createServerWaitingForClientCertificate();

        byte[] body =
                clientBuilder(true).buildCertificateBody(new byte[] {(byte) 0x01, (byte) 0x02});
        byte[] frame = new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE, body).encode();

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () -> server.receive(frame),
                        "клиент не должен присылать status_request, если его не запрашивали");
        assertEquals(
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                ex.getAlertCode(),
                "ожидался alert unsupported_extension");
    }

    @Test
    @DisplayName("Клиентский CertificateEntry с неизвестным расширением -> unsupported_extension")
    void testClientCertificateUnknownExtensionRejected() throws Exception {
        TlsHandshakeEngine server = createServerWaitingForClientCertificate();

        byte[] body =
                clientBuilder(true).buildCertificateBody(new byte[] {(byte) 0x01, (byte) 0x02});
        // Хвост записи: type(2) || data_len(2) || status_type(1) || ocsp_len(3) || ocsp(2).
        // Меняем только тип на заведомо неизвестный 0x1234: клиент его не запрашивал, а ответ на
        // незапрошенное расширение запрещён (RFC 8446 §4.2).
        int typeOffset = body.length - (2 + 2 + 1 + 3 + 2);
        body[typeOffset] = 0x12;
        body[typeOffset + 1] = 0x34;
        byte[] frame = new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE, body).encode();

        TlsException ex = assertThrows(TlsException.class, () -> server.receive(frame));
        assertEquals(
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                ex.getAlertCode(),
                "неизвестное расширение без запроса -> unsupported_extension");
    }

    @Test
    @DisplayName(
            "CertificateRequest: status_request отсутствует, signature_algorithms присутствует")
    void testCertificateRequestHasNoStatusRequest() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, true, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, true);
        server.receive(client.start());
        server.acknowledgeReadKeyChange();
        assertNotNull(HandshakeOutputs.nextMessage(server), "SH");
        assertNotNull(HandshakeOutputs.nextMessage(server), "EE");
        byte[] cr = HandshakeOutputs.nextMessage(server);
        assertNotNull(cr, "CR");

        byte[] body = TlsHandshakeMessage.decode(cr).getBody();
        assertFalse(
                hasCertificateRequestExtension(body, TlsConstants.EXT_STATUS_REQUEST),
                "мы не запрашиваем status_request у клиента");
        assertTrue(
                hasCertificateRequestExtension(body, TlsConstants.EXT_SIGNATURE_ALGORITHMS),
                "signature_algorithms должен быть в CertificateRequest");
    }

    private static boolean hasCertificateRequestExtension(byte[] body, int extType) {
        int pos = 0;
        int contextLen = body[pos++] & 0xFF;
        pos += contextLen;
        int extLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        pos += 2;
        int end = pos + extLen;
        while (pos + 4 <= end) {
            int type = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int len = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            if (type == extType) {
                return true;
            }
            pos += 4 + len;
        }
        return false;
    }

    private static TlsHandshakeEngine createServerWaitingForClientCertificate() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, true, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, true);
        server.receive(client.start());
        server.acknowledgeReadKeyChange();
        assertNotNull(HandshakeOutputs.nextMessage(server), "SH");
        assertNotNull(HandshakeOutputs.nextMessage(server), "EE");
        assertNotNull(HandshakeOutputs.nextMessage(server), "CR");
        assertNotNull(HandshakeOutputs.nextMessage(server), "Cert");
        assertNotNull(HandshakeOutputs.nextMessage(server), "CV");
        assertNotNull(HandshakeOutputs.nextMessage(server), "Finished");
        assertNull(HandshakeOutputs.nextMessage(server), "очередь сервера пуста после Finished");
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_CERTIFICATE, server.getState());
        return server;
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
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);

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
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);

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
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);

        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);

        byte[] ch = client.start();
        server.receive(ch);
        server.acknowledgeReadKeyChange();

        // Drain queue
        while (HandshakeOutputs.nextMessage(server) != null)
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
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);

        byte[] ch = client.start();
        server.receive(ch);
        server.acknowledgeReadKeyChange();

        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        byte[] cert = HandshakeOutputs.nextMessage(server);
        byte[] cv = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);

        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
        client.receive(cert);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_VERIFY, client.getState());
        assertTrue(client.needsCertificateValidation());

        client.acknowledgeCertificateValidation(false);
        assertTrue(client.isError(), "Engine должен перейти в ERROR после отклонения сертификата");
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
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, true);

        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, true, false);

        byte[] ch = client.start();
        server.receive(ch);
        server.acknowledgeReadKeyChange();

        byte[] msg;
        while ((msg = HandshakeOutputs.nextMessage(server)) != null) {
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
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        client.setClientAlpnProtocols(List.of("h2", "http/1.1"));
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
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
        server.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());
        assertEquals("http/1.1", server.getSelectedAlpnProtocol());

        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        byte[] cert = HandshakeOutputs.nextMessage(server);
        byte[] cv = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNotNull(sf);
        assertNull(
                HandshakeOutputs.nextMessage(
                        server)); // опустошаем очередь — переход из SERVER_SEND_FLIGHT
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        // Проверяем ALPN в EE
        byte[] eeBody = TlsHandshakeMessage.decode(ee).getBody();
        assertEquals(
                "http/1.1",
                TlsMessageParser.parseEncryptedExtensions(eeBody, ALL_RESPONSE_TYPES_SENT).alpn);

        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
        assertEquals("http/1.1", client.getSelectedAlpnProtocol());
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_OR_CR, client.getState());

        client.receive(cert);
        client.acknowledgeReadKeyChange();
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.acknowledgeReadKeyChange();
        client.receive(sf);
        client.acknowledgeReadKeyChange();
        byte[] cf = HandshakeOutputs.nextMessage(client);
        assertNotNull(cf);
        assertNull(
                HandshakeOutputs.nextMessage(
                        client)); // опустошаем очередь клиента — переход из CLIENT_SEND_FINISHED
        server.receive(cf);
        server.acknowledgeReadKeyChange();
        assertTrue(client.isDone());
        assertTrue(server.isDone());
    }

    @Test
    @DisplayName("ALPN mismatch: сервер кидает ALERT_NO_APPLICATION_PROTOCOL")
    void testAlpnMismatchServerThrows() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        client.setClientAlpnProtocols(List.of("h2"));
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        server.setServerAlpnProtocols(List.of("http/1.1"));

        byte[] ch = client.start();
        assertNotNull(ch);

        TlsException ex = assertThrows(TlsException.class, () -> server.receive(ch));
        assertEquals(TlsConstants.ALERT_NO_APPLICATION_PROTOCOL, ex.getAlertCode());
        assertTrue(server.isError());
    }

    @Test
    @DisplayName("ALPN-селектор вернул null: сервер кидает ALERT_NO_APPLICATION_PROTOCOL")
    void testAlpnSelectorNullRejectsHandshake() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        client.setClientAlpnProtocols(List.of("h2", "http/1.1"));
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        server.setAlpnSelector(clientList -> null);

        byte[] ch = client.start();

        TlsException ex = assertThrows(TlsException.class, () -> server.receive(ch));
        assertEquals(
                TlsConstants.ALERT_NO_APPLICATION_PROTOCOL,
                ex.getAlertCode(),
                "null от селектора - отказ с алертом no_application_protocol, а не продолжение");
        assertTrue(server.isError(), "после отказа движок должен быть в состоянии ошибки");
        assertNull(server.getSelectedAlpnProtocol(), "протокол не должен быть выбран");
    }

    @Test
    @DisplayName("ALPN-селектор вернул пустую строку: рукопожатие продолжается без ALPN")
    void testAlpnSelectorEmptyContinuesWithoutAlpn() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        client.setClientAlpnProtocols(List.of("h2"));
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        server.setAlpnSelector(clientList -> "");

        byte[] ch = client.start();
        server.receive(ch);
        server.acknowledgeReadKeyChange();

        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());
        assertNull(
                server.getSelectedAlpnProtocol(),
                "пустая строка от селектора означает отсутствие ALPN");
    }

    @Test
    @DisplayName("полный handshake без ALPN: selectedAlpnProtocol == null")
    void testFullHandshakeWithoutAlpn() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);

        byte[] ch = client.start();
        assertNotNull(ch);
        server.receive(ch);
        server.acknowledgeReadKeyChange();
        assertNull(server.getSelectedAlpnProtocol());

        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        byte[] cert = HandshakeOutputs.nextMessage(server);
        byte[] cv = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNull(HandshakeOutputs.nextMessage(server));

        // EE без ALPN
        byte[] eeBody = TlsHandshakeMessage.decode(ee).getBody();
        assertNull(TlsMessageParser.parseEncryptedExtensions(eeBody, ALL_RESPONSE_TYPES_SENT).alpn);

        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
        assertNull(client.getSelectedAlpnProtocol());

        client.receive(cert);
        client.acknowledgeReadKeyChange();
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.acknowledgeReadKeyChange();
        client.receive(sf);
        client.acknowledgeReadKeyChange();
        byte[] cf = HandshakeOutputs.nextMessage(client);
        assertNull(HandshakeOutputs.nextMessage(client));
        server.receive(cf);
        server.acknowledgeReadKeyChange();
        assertTrue(client.isDone());
        assertTrue(server.isDone());
    }

    @Test
    @DisplayName("клиент отклоняет ALPN протокол не из его списка")
    void testClientRejectsServerAlpnNotOffered() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        client.setClientAlpnProtocols(List.of("h2"));

        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        server.setServerAlpnProtocols(List.of("h2"));

        byte[] ch = client.start();
        server.receive(ch);
        server.acknowledgeReadKeyChange();
        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        byte[] cert = HandshakeOutputs.nextMessage(server);
        byte[] cv = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);

        // Подменяем EE на протокол, которого нет в списке клиента
        byte[] fakeAlpn = TlsMessageBuilder.buildEncryptedExtensions("http/1.1");
        byte[] fakeEe =
                new TlsHandshakeMessage(TlsConstants.HT_ENCRYPTED_EXTENSIONS, fakeAlpn).encode();

        client.receive(sh);
        client.acknowledgeReadKeyChange();
        TlsException ex = assertThrows(TlsException.class, () -> client.receive(fakeEe));
        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, ex.getAlertCode());
        assertTrue(client.isError());
    }

    @Test
    @DisplayName("setServerPsk запрещён при запросе клиентского сертификата")
    void testServerPskRejectedWithClientAuth() {
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, true);
        assertThrows(
                IllegalStateException.class,
                () -> server.setServerPsk(new byte[32]),
                "явный PSK при mTLS не должен приниматься");
        assertTrue(server.isClientAuthRequested(), "сервер должен сообщать о запросе mTLS");
    }

    @Test
    @DisplayName("setPsk на серверном engine -> IllegalStateException")
    void testSetPskRejectedOnServer() {
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, true);
        assertThrows(
                IllegalStateException.class,
                () -> server.setPsk(new byte[32], new byte[8], 0L),
                "клиентский PSK на сервере отключил бы клиентскую аутентификацию");
    }

    @Test
    @DisplayName("setServerPsk и setServerPskStore на клиентском engine -> IllegalStateException")
    void testServerPskSettersRejectedOnClient() {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        assertThrows(
                IllegalStateException.class,
                () -> client.setServerPsk(new byte[32]),
                "серверный PSK на клиенте недопустим");
        assertThrows(
                IllegalStateException.class,
                () -> client.setServerPskStore(new InMemoryPskStore(10)),
                "серверное хранилище PSK на клиенте недопустимо");
    }

    @Test
    @DisplayName("mTLS (need): PSK клиента не принимается, сервер запрашивает сертификат")
    void testPskIgnoredWhenClientAuthNeeded() throws Exception {
        assertPskIgnoredWithClientAuth(false);
    }

    @Test
    @DisplayName("mTLS (want): PSK клиента не принимается, сервер запрашивает сертификат")
    void testPskIgnoredWhenClientAuthWanted() throws Exception {
        assertPskIgnoredWithClientAuth(true);
    }

    /** Клиент предлагает валидный PSK из серверного стора; mTLS-сервер обязан его проигнорировать. */
    private void assertPskIgnoredWithClientAuth(boolean optionalClientAuth) throws Exception {
        byte[] psk = new byte[TlsConstants.STREEBOG_256_HASH_LEN];
        CryptoRandom.INSTANCE.nextBytes(psk);
        byte[] ticket = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(ticket);
        PskStore store = new InMemoryPskStore(10);
        store.onTicketReceived(
                new PskEntry(
                        ticket,
                        86400,
                        0,
                        new byte[8],
                        psk,
                        System.currentTimeMillis(),
                        PskBinding.forServer(null),
                        PskEntry.NO_CERTIFICATE_BOUND));

        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        client.setPsk(psk, ticket, 0L);

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
                        null,
                        optionalClientAuth);
        server.setServerPskStore(store);

        server.receive(client.start());
        server.acknowledgeReadKeyChange();

        assertFalse(server.isPskAccepted(), "PSK не должен приниматься при запросе сертификата");
        assertNotNull(HandshakeOutputs.nextMessage(server), "ServerHello");
        assertNotNull(HandshakeOutputs.nextMessage(server), "EncryptedExtensions");
        byte[] third = HandshakeOutputs.nextMessage(server);
        assertNotNull(third, "после EncryptedExtensions ожидается CertificateRequest");
        assertEquals(
                TlsConstants.HT_CERTIFICATE_REQUEST,
                TlsHandshakeMessage.decode(third).getType(),
                "сервер обязан запросить клиентский сертификат");
        assertNotNull(store.peek(ticket), "тикет не должен быть потреблён игнорируемым PSK");
    }

    /**
     * Клиент предлагает тикет, выпущенный для SNI {@code issuedFor}, с SNI {@code clientSni}.
     *
     * @return принял ли сервер возобновление; {@code store} оставляет в {@code ticketOut[0]}
     *         тикет, чтобы тест проверил, не расходован ли он
     */
    private boolean resumeWithSni(String issuedFor, String clientSni, PskStore store, byte[] ticket)
            throws Exception {
        byte[] psk = new byte[TlsConstants.STREEBOG_256_HASH_LEN];
        CryptoRandom.INSTANCE.nextBytes(psk);
        CryptoRandom.INSTANCE.nextBytes(ticket);
        store.onTicketReceived(
                new PskEntry(
                        ticket,
                        86400,
                        0,
                        new byte[8],
                        psk,
                        System.currentTimeMillis(),
                        PskBinding.forServer(issuedFor),
                        PskEntry.NO_CERTIFICATE_BOUND));

        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        if (clientSni != null) {
            client.setServerHostname(clientSni);
        }
        client.setPsk(psk, ticket, 0L);

        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        server.setServerPskStore(store);
        server.receive(client.start());
        server.acknowledgeReadKeyChange();
        return server.isPskAccepted();
    }

    @Test
    @DisplayName(
            "Серверный PSK: тикет, выпущенный для SNI A, при SNI B не принимается и не расходуется")
    void testServerPskRejectedForDifferentSni() throws Exception {
        PskStore store = new InMemoryPskStore(10);
        byte[] ticket = new byte[32];

        assertFalse(
                resumeWithSni("a.example", "b.example", store, ticket),
                "RFC 6066 §3: при другом имени SNI сервер переходит к полному рукопожатию");
        assertNotNull(store.peek(ticket), "несовпадение SNI не должно расходовать тикет");
    }

    @Test
    @DisplayName("Серверный PSK: тот же SNI (без учёта регистра) принимается")
    void testServerPskAcceptedForSameSni() throws Exception {
        assertTrue(
                resumeWithSni("A.Example", "a.example", new InMemoryPskStore(10), new byte[32]),
                "тот же сервер должен возобновляться");
    }

    private TlsHandshakeEngine newPlainClient() throws Exception {
        return newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
    }

    private TlsHandshakeEngine newServer(SniCertificateSelector selector) throws Exception {
        return new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER,
                cs(),
                serverBuilder(),
                EC_PARAMS,
                NAMED_GROUP,
                SIG_SCHEME,
                HASH_LEN,
                null,
                false,
                selector);
    }

    /** Заменяет первую точку имени в ClientHello нулевым байтом: длина и структура те же. */
    private static byte[] withNulInsteadOfDot(byte[] clientHelloFrame, String name) {
        byte[] nameBytes = name.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        int at = -1;
        for (int i = 0; i + nameBytes.length <= clientHelloFrame.length && at < 0; i++) {
            if (java.util.Arrays.equals(
                    clientHelloFrame, i, i + nameBytes.length, nameBytes, 0, nameBytes.length)) {
                at = i;
            }
        }
        assertTrue(at >= 0, "имя должно быть в ClientHello");
        byte[] patched = clientHelloFrame.clone();
        patched[at + name.indexOf('.')] = 0x00;
        return patched;
    }

    @Test
    @DisplayName(
            "setServerHostname: недопустимое имя -> IllegalArgumentException сразу, не в start()")
    void testSetServerHostnameRejectsUnsafeName() throws Exception {
        TlsHandshakeEngine client = newPlainClient();
        String tooLong = ("a".repeat(63) + ".").repeat(3) + "b".repeat(62);
        for (String name : List.of("evil\u0000.example", "a..example", "é.example", tooLong)) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> client.setServerHostname(name),
                    "имя нельзя отправить в SNI");
        }
        // Допустимые имена, IP-литерал и null (без SNI) проходят
        assertDoesNotThrow(() -> client.setServerHostname("example.com"));
        assertDoesNotThrow(() -> client.setServerHostname("192.0.2.1"));
        assertDoesNotThrow(() -> client.setServerHostname(null));
    }

    @Test
    @DisplayName("Сервер: SNI с NUL отвергается до выбора сертификата, sniSelector не вызывается")
    void testServerRejectsUnsafeSniBeforeSelector() throws Exception {
        java.util.concurrent.atomic.AtomicInteger selectorCalls =
                new java.util.concurrent.atomic.AtomicInteger();
        SniCertificateSelector selector =
                name -> {
                    selectorCalls.incrementAndGet();
                    return null;
                };
        TlsHandshakeEngine client = newPlainClient();
        client.setServerHostname("a.example");
        byte[] frame = client.start();

        // Контроль: исходный ClientHello доходит до селектора
        newServer(selector).receive(frame);
        assertEquals(1, selectorCalls.get(), "допустимое имя должно дойти до селектора");

        byte[] patched = withNulInsteadOfDot(frame, "a.example");
        TlsHandshakeEngine server = newServer(selector);
        TlsException e = assertThrows(TlsException.class, () -> server.receive(patched));
        assertEquals(TlsConstants.ALERT_UNRECOGNIZED_NAME, e.getAlertCode());
        assertEquals(1, selectorCalls.get(), "имя с NUL не должно дойти до селектора");
    }

    @Test
    @DisplayName("Сервер: SNI с NUL отвергается до проверки PSK, тикет не расходуется")
    void testServerRejectsUnsafeSniBeforePsk() throws Exception {
        PskStore store = new InMemoryPskStore(10);
        byte[] ticket = new byte[32];
        byte[] psk = new byte[TlsConstants.STREEBOG_256_HASH_LEN];
        CryptoRandom.INSTANCE.nextBytes(psk);
        CryptoRandom.INSTANCE.nextBytes(ticket);
        store.onTicketReceived(
                new PskEntry(
                        ticket,
                        86400,
                        0,
                        new byte[8],
                        psk,
                        System.currentTimeMillis(),
                        PskBinding.forServer("a.example"),
                        PskEntry.NO_CERTIFICATE_BOUND));
        TlsHandshakeEngine client = newPlainClient();
        client.setServerHostname("a.example");
        client.setPsk(psk, ticket, 0L);
        byte[] patched = withNulInsteadOfDot(client.start(), "a.example");

        TlsHandshakeEngine server = newServer(null);
        server.setServerPskStore(store);
        // Binder подделанного ClientHello неверен: без раннего разбора SNI алерт был бы
        // алертом binder, а не имени
        TlsException e = assertThrows(TlsException.class, () -> server.receive(patched));
        assertEquals(TlsConstants.ALERT_UNRECOGNIZED_NAME, e.getAlertCode());
        assertNotNull(store.peek(ticket), "отвергнутое имя не должно расходовать тикет");
        assertFalse(server.isPskAccepted(), "PSK не должен приниматься");
    }

    @Test
    @DisplayName("Серверный PSK: «нет SNI» совпадает только с «нет SNI»")
    void testServerPskNoSniMatchesOnlyNoSni() throws Exception {
        assertTrue(
                resumeWithSni(null, null, new InMemoryPskStore(10), new byte[32]),
                "оба без SNI: возобновление допустимо");
        assertFalse(
                resumeWithSni("a.example", null, new InMemoryPskStore(10), new byte[32]),
                "тикет с SNI не принимается без SNI");
        assertFalse(
                resumeWithSni(null, "a.example", new InMemoryPskStore(10), new byte[32]),
                "тикет без SNI не принимается с SNI");
    }

    @Test
    @DisplayName("PSK handshake с ALPN: протокол согласован")
    void testPskHandshakeWithAlpn() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        client.setClientAlpnProtocols(List.of("h2"));
        byte[] pskKey = new byte[32];
        byte[] pskId = new byte[8];
        client.setPsk(pskKey, pskId, 42L);

        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        server.setServerAlpnProtocols(List.of("h2"));
        server.setServerPsk(pskKey);

        byte[] ch = client.start();
        server.receive(ch);
        server.acknowledgeReadKeyChange();
        assertTrue(server.isPskAccepted());
        assertEquals("h2", server.getSelectedAlpnProtocol());

        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        assertNotNull(ee);
        // PSK: no Cert/CV/SF — сразу Finished
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNull(HandshakeOutputs.nextMessage(server));

        byte[] eeBody = TlsHandshakeMessage.decode(ee).getBody();
        assertEquals(
                "h2",
                TlsMessageParser.parseEncryptedExtensions(eeBody, ALL_RESPONSE_TYPES_SENT).alpn);

        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
        assertEquals("h2", client.getSelectedAlpnProtocol());
        // PSK: после EE сразу Finished
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_FINISHED, client.getState());

        client.receive(sf);
        client.acknowledgeReadKeyChange();
        byte[] cf = HandshakeOutputs.nextMessage(client);
        assertNull(HandshakeOutputs.nextMessage(client)); // опустошаем очередь -> POST_HANDSHAKE
        server.receive(cf);
        server.acknowledgeReadKeyChange();
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
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, true, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, true);

        byte[] ch = client.start();
        server.receive(ch);
        server.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());

        // Сервер: poll весь flight (SH, EE, CR, Cert, CV, SF)
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNull(HandshakeOutputs.nextMessage(server));
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
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, true, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, true);

        byte[] ch = client.start();
        server.receive(ch);
        server.acknowledgeReadKeyChange();

        // Сервер: poll весь flight
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNotNull(HandshakeOutputs.nextMessage(server));
        assertNull(HandshakeOutputs.nextMessage(server));
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
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);

        byte[] ch = client.start();

        // Сервер: обрабатываем CH, подменяем Certificate на пустой
        server.receive(ch);
        server.acknowledgeReadKeyChange();
        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        // Пустой Certificate — сервер нарушает протокол (RFC 8446 §4.4.2: сервер обязан прислать)
        byte[] emptyCertBody = new byte[] {0x00, 0x00, 0x00, 0x00};
        byte[] emptyCertFrame =
                new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE, emptyCertBody).encode();
        byte[] cv = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNotNull(sf);

        // Доставляем клиенту SH -> EE -> пустой Certificate
        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
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
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);

        // Полный handshake до точки, где клиент ждёт ServerFinished
        byte[] ch = client.start();
        server.receive(ch);
        server.acknowledgeReadKeyChange();

        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        byte[] cert = HandshakeOutputs.nextMessage(server);
        byte[] cv = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNotNull(sf);
        assertNull(HandshakeOutputs.nextMessage(server));

        // Клиент: получает SH, EE, Cert, CV — переходит в CLIENT_WAIT_FINISHED
        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
        client.receive(cert);
        client.acknowledgeReadKeyChange();
        assertTrue(client.needsCertificateValidation());
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_FINISHED, client.getState());

        // Вместо правильного ServerFinished — фейковый с verify_data из нулей
        byte[] fakeSf =
                new TlsHandshakeMessage(TlsConstants.HT_FINISHED, new byte[HASH_LEN]).encode();
        TlsException ex = assertThrows(TlsException.class, () -> client.receive(fakeSf));
        assertEquals(TlsConstants.ALERT_DECRYPT_ERROR, ex.getAlertCode());
        assertTrue(client.isError(), "Engine должен перейти в ERROR");
    }

    @Test
    @DisplayName("неверный verify_data в ClientFinished -> ALERT_HANDSHAKE_FAILURE")
    void testInvalidClientFinished() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);

        // Полный handshake: клиент отправляет CH, сервер отвечает flight
        byte[] ch = client.start();
        server.receive(ch);
        server.acknowledgeReadKeyChange();

        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        byte[] cert = HandshakeOutputs.nextMessage(server);
        byte[] cv = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNotNull(sf);
        assertNull(HandshakeOutputs.nextMessage(server));
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        // Клиент: принимает SH, EE, Cert, CV, правильный SF -> генерирует CF
        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
        client.receive(cert);
        client.acknowledgeReadKeyChange();
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.acknowledgeReadKeyChange();
        client.receive(sf);
        client.acknowledgeReadKeyChange();
        byte[] cf = HandshakeOutputs.nextMessage(client);
        assertNotNull(cf, "Клиент должен сгенерировать Finished");
        assertNull(HandshakeOutputs.nextMessage(client));
        // Сервер теперь в SERVER_WAIT_CLIENT_FINISHED — подаём фейковый CF
        byte[] fakeCf =
                new TlsHandshakeMessage(TlsConstants.HT_FINISHED, new byte[HASH_LEN]).encode();
        TlsException ex = assertThrows(TlsException.class, () -> server.receive(fakeCf));
        assertEquals(TlsConstants.ALERT_DECRYPT_ERROR, ex.getAlertCode());
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
        server.acknowledgeReadKeyChange();
        byte[] hrr = HandshakeOutputs.nextMessage(server);
        assertNotNull(hrr, "Сервер должен вернуть HRR");
        assertNull(HandshakeOutputs.nextMessage(server), "После HRR очередь пуста");
        assertEquals(
                TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_HELLO,
                server.getState(),
                "Сервер ждёт второй CH");

        // Проверяем что это HRR, а не SH
        TlsHandshakeMessage hrrMsg = TlsHandshakeMessage.decode(hrr);
        assertEquals(TlsConstants.HT_SERVER_HELLO, hrrMsg.getType());
        TlsMessageParser.ParsedServerHello parsedHrr =
                TlsMessageParser.parseServerHello(hrrMsg.getBody(), SERVER_RESPONSE_TYPES_SENT);
        assertTrue(
                TlsMessageParser.isHelloRetryRequest(parsedHrr),
                "Сообщение должно определяться как HRR");
        assertEquals(serverGroup, parsedHrr.requestedGroup, "HRR должен запрашивать GC256B");

        // Клиент: получает HRR -> CH2 (GC256B)
        client.receive(hrr);
        client.acknowledgeReadKeyChange();
        byte[] ch2 = HandshakeOutputs.nextMessage(client);
        assertNotNull(ch2, "Клиент должен вернуть CH2 после HRR");
        assertNull(HandshakeOutputs.nextMessage(client), "После CH2 очередь пуста");
        assertEquals(
                TlsHandshakeEngine.State.CLIENT_WAIT_SERVER_HELLO,
                client.getState(),
                "Клиент ждёт настоящий SH");

        // Сервер: получает CH2 -> полноценный flight
        server.receive(ch2);
        server.acknowledgeReadKeyChange();
        // После CH2 poll сразу возвращает SH (первый фрейм flight'а)
        byte[] sh = HandshakeOutputs.nextMessage(server);
        assertNotNull(sh, "Сервер должен вернуть SH");
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());
        client.receive(sh);
        client.acknowledgeReadKeyChange();

        byte[] ee = HandshakeOutputs.nextMessage(server);
        byte[] cert = HandshakeOutputs.nextMessage(server);
        byte[] cv = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNotNull(sf);
        assertNull(HandshakeOutputs.nextMessage(server));

        client.receive(ee);
        client.acknowledgeReadKeyChange();
        client.receive(cert);
        client.acknowledgeReadKeyChange();
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.acknowledgeReadKeyChange();
        client.receive(sf);
        client.acknowledgeReadKeyChange();

        byte[] cf = HandshakeOutputs.nextMessage(client);
        assertNotNull(cf, "Клиент должен сгенерировать Finished");
        assertNull(HandshakeOutputs.nextMessage(client));

        server.receive(cf);
        server.acknowledgeReadKeyChange();
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
        server.acknowledgeReadKeyChange();
        byte[] hrr = HandshakeOutputs.nextMessage(server);
        assertNotNull(hrr);
        assertNull(HandshakeOutputs.nextMessage(server));

        // Клиент -> HRR -> CH2 (PSK binder пересчитан)
        client.receive(hrr);
        client.acknowledgeReadKeyChange();
        byte[] ch2 = HandshakeOutputs.nextMessage(client);
        assertNotNull(ch2);

        // Сервер: CH2 -> PSK binder верифицирован -> flight
        server.receive(ch2);
        server.acknowledgeReadKeyChange();
        assertTrue(
                server.isPskAccepted(), "PSK должен быть принят после CH2 с пересчитанным binder");

        byte[] sh = HandshakeOutputs.nextMessage(server);
        assertNotNull(sh);
        client.receive(sh);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());

        byte[] ee = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNotNull(sf);
        assertNull(HandshakeOutputs.nextMessage(server));
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        client.receive(ee);
        client.acknowledgeReadKeyChange();
        // При PSK сертификаты не приходят — после EE сразу Finished
        client.receive(sf);
        client.acknowledgeReadKeyChange();

        byte[] cf = HandshakeOutputs.nextMessage(client);
        assertNotNull(cf);
        assertNull(HandshakeOutputs.nextMessage(client));

        server.receive(cf);
        server.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.State.POST_HANDSHAKE, server.getState());
        assertTrue(server.isDone());
    }

    @Test
    @DisplayName(
            "PSK: explicit setServerPsk + setServerPskStore одновременно — pskKeyFromStore флаг корректно различает источник")
    void testPskExplicitWithStore() throws Exception {
        byte[] psk = new byte[TlsConstants.STREEBOG_256_HASH_LEN];
        CryptoRandom.INSTANCE.nextBytes(psk);
        byte[] pskIdentity = "explicit-with-store".getBytes();

        PskStore store = new InMemoryPskStore(100);
        byte[] storeTicket = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(storeTicket);
        byte[] wrongPsk = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(wrongPsk);
        store.onTicketReceived(
                new PskEntry(
                        storeTicket,
                        86400,
                        0,
                        new byte[8],
                        wrongPsk,
                        System.currentTimeMillis(),
                        PskBinding.forServer(null),
                        PskEntry.NO_CERTIFICATE_BOUND));

        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        cs(),
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                TlsConstants.GRP_GC256B,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        ECParameters.cryptoProA(),
                        TlsConstants.GRP_GC256B,
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
                                TlsConstants.GRP_GC256B,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        ECParameters.cryptoProA(),
                        TlsConstants.GRP_GC256B,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        server.setServerPsk(psk);
        server.setServerPskStore(store);

        byte[] ch1 = client.start();
        assertNotNull(ch1);
        server.receive(ch1);
        server.acknowledgeReadKeyChange();
        assertTrue(server.isPskAccepted(), "Явный PSK должен быть принят даже при наличии store");
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
        server.acknowledgeReadKeyChange();
        byte[] hrr = HandshakeOutputs.nextMessage(server);
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
                TlsMessageBuilderTestAccess.buildHelloRetryRequestWithCookie(
                        new TlsMessageBuilder(
                                cs(),
                                List.of(cs().getId()),
                                NAMED_GROUP,
                                SIG_SCHEME,
                                null,
                                null,
                                HASH_LEN),
                        cs().getId(),
                        cookie);
        byte[] hrr = new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, hrrBody).encode();

        // Клиент должен обработать HRR без исключения
        client.receive(hrr);
        client.acknowledgeReadKeyChange();
        byte[] ch2 = HandshakeOutputs.nextMessage(client);
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

        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);

        // ClientHello
        byte[] ch = client.start();
        assertNotNull(ch);
        byte[] chBody = TlsHandshakeMessage.decode(ch).getBody();
        assertEquals(
                TlsConstants.MAX_FRAG_LEN_512,
                TlsMessageParser.parseClientHello(chBody, NAMED_GROUP).clientMaxFragLen);

        // Сервер принимает
        server.receive(ch);
        server.acknowledgeReadKeyChange();
        assertEquals(TlsConstants.MAX_FRAG_LEN_512, server.getMaxFragmentLength());
        assertEquals(TlsHandshakeEngine.State.SERVER_SEND_FLIGHT, server.getState());

        byte[] sh = HandshakeOutputs.nextMessage(server);
        byte[] ee = HandshakeOutputs.nextMessage(server);
        assertNotNull(ee);

        // Проверяем EE: сервер подтвердил max_fragment_length
        byte[] eeBody = TlsHandshakeMessage.decode(ee).getBody();
        TlsMessageParser.ParsedEncryptedExtensions parsedEE =
                TlsMessageParser.parseEncryptedExtensions(eeBody, ALL_RESPONSE_TYPES_SENT);
        assertEquals(TlsConstants.MAX_FRAG_LEN_512, parsedEE.maxFragLen);

        byte[] cert = HandshakeOutputs.nextMessage(server);
        byte[] cv = HandshakeOutputs.nextMessage(server);
        byte[] sf = HandshakeOutputs.nextMessage(server);
        assertNotNull(sf);
        assertNull(HandshakeOutputs.nextMessage(server));
        assertEquals(TlsHandshakeEngine.State.SERVER_WAIT_CLIENT_FINISHED, server.getState());

        // Клиент: ServerHello -> EncryptedExtensions -> ...
        client.receive(sh);
        client.acknowledgeReadKeyChange();
        client.receive(ee);
        client.acknowledgeReadKeyChange();
        assertEquals(TlsConstants.MAX_FRAG_LEN_512, client.getMaxFragmentLength());
        assertEquals(TlsHandshakeEngine.State.CLIENT_WAIT_CERTIFICATE_OR_CR, client.getState());

        client.receive(cert);
        client.acknowledgeReadKeyChange();
        client.acknowledgeCertificateValidation(true);
        client.receive(cv);
        client.acknowledgeReadKeyChange();
        client.receive(sf);
        client.acknowledgeReadKeyChange();
        byte[] cf = HandshakeOutputs.nextMessage(client);
        assertNotNull(cf);
        assertNull(HandshakeOutputs.nextMessage(client));
        server.receive(cf);
        server.acknowledgeReadKeyChange();
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
        byte[] shBody =
                serverMb.buildServerHello(
                        ecdhePoint, TlsMessageBuilder.NO_SELECTED_PSK, NAMED_GROUP);
        byte[] shFrame = new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, shBody).encode();

        client.receive(shFrame);
        client.acknowledgeReadKeyChange();

        TlsException ex = assertThrows(TlsException.class, () -> client.receive(eeFrame));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                ex.getAlertCode(),
                "Сервер вернул другое max_fragment_length -> ALERT_ILLEGAL_PARAMETER");
        assertTrue(client.isError());
    }

    @Test
    @DisplayName(
            "max_fragment_length: сервер вернул незапрошенное расширение ->"
                    + " ALERT_UNSUPPORTED_EXTENSION")
    void testMaxFragmentLengthUnsolicited() throws Exception {
        // Клиент НЕ запрашивает max_fragment_length
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);

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
        byte[] shBody =
                serverMb.buildServerHello(
                        ecdhePoint, TlsMessageBuilder.NO_SELECTED_PSK, NAMED_GROUP);
        byte[] shFrame = new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, shBody).encode();

        client.receive(shFrame);
        client.acknowledgeReadKeyChange();

        TlsException ex = assertThrows(TlsException.class, () -> client.receive(eeFrame));
        assertEquals(
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                ex.getAlertCode(),
                "Незапрошенное max_fragment_length от сервера -> ALERT_UNSUPPORTED_EXTENSION");
        assertTrue(client.isError());
    }

    // ====================================================================
    // Ответные расширения EncryptedExtensions: сверка с отправленным ClientHello
    // ====================================================================

    /** Клиент, получивший настоящий ServerHello и готовый принять EncryptedExtensions. */
    private static TlsHandshakeEngine clientReadyForEncryptedExtensions(
            List<String> alpnProtocols, String serverHostname) throws Exception {
        TlsHandshakeEngine client = newEeTestClient(alpnProtocols, serverHostname);
        assertNotNull(client.start());
        deliverServerHello(client);
        return client;
    }

    private static TlsHandshakeEngine newEeTestClient(
            List<String> alpnProtocols, String serverHostname) {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        if (alpnProtocols != null) {
            client.setClientAlpnProtocols(alpnProtocols);
        }
        client.setServerHostname(serverHostname);
        return client;
    }

    private static void deliverServerHello(TlsHandshakeEngine client) throws Exception {
        KeyPair ecdheKp = KeyGenerator.generateKeyPair(EC_PARAMS);
        byte[] shBody =
                serverBuilder()
                        .buildServerHello(
                                TlsEncoding.encodePoint(ecdheKp.getPublic()),
                                TlsMessageBuilder.NO_SELECTED_PSK,
                                NAMED_GROUP);
        client.receive(new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, shBody).encode());
        client.acknowledgeReadKeyChange();
    }

    /** Extension: type(2) || length(2) || data. */
    private static byte[] extension(int type, byte[] data) {
        byte[] ext = new byte[4 + data.length];
        ext[0] = (byte) (type >>> 8);
        ext[1] = (byte) type;
        ext[2] = (byte) (data.length >>> 8);
        ext[3] = (byte) data.length;
        System.arraycopy(data, 0, ext, 4, data.length);
        return ext;
    }

    /** ProtocolNameList: listLength(2) || (nameLength(1) || name)*. */
    private static byte[] alpnData(String... names) {
        java.io.ByteArrayOutputStream list = new java.io.ByteArrayOutputStream();
        for (String name : names) {
            byte[] bytes = name.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            list.write(bytes.length);
            list.write(bytes, 0, bytes.length);
        }
        byte[] listBytes = list.toByteArray();
        byte[] data = new byte[2 + listBytes.length];
        data[0] = (byte) (listBytes.length >>> 8);
        data[1] = (byte) listBytes.length;
        System.arraycopy(listBytes, 0, data, 2, listBytes.length);
        return data;
    }

    /** Полный фрейм EncryptedExtensions из готовых расширений. */
    private static byte[] encryptedExtensionsFrame(byte[]... extensions) {
        java.io.ByteArrayOutputStream block = new java.io.ByteArrayOutputStream();
        for (byte[] ext : extensions) {
            block.write(ext, 0, ext.length);
        }
        byte[] blockBytes = block.toByteArray();
        byte[] body = new byte[2 + blockBytes.length];
        body[0] = (byte) (blockBytes.length >>> 8);
        body[1] = (byte) blockBytes.length;
        System.arraycopy(blockBytes, 0, body, 2, blockBytes.length);
        return new TlsHandshakeMessage(TlsConstants.HT_ENCRYPTED_EXTENSIONS, body).encode();
    }

    private static void assertEeRejected(
            TlsHandshakeEngine client, byte[] eeFrame, int expectedAlert, String message) {
        TlsException ex = assertThrows(TlsException.class, () -> client.receive(eeFrame));
        assertEquals(expectedAlert, ex.getAlertCode(), message);
        assertTrue(client.isError(), "Движок должен перейти в состояние ошибки");
    }

    private static Stream<Arguments> rejectedEncryptedExtensions() {
        byte[] alpnH2 = alpnData("h2");
        int alpn = TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION;
        int sni = TlsConstants.EXT_SERVER_NAME;
        int unsupported = TlsConstants.ALERT_UNSUPPORTED_EXTENSION;
        return Stream.of(
                Arguments.of("ALPN без запроса", null, null, alpn, alpnH2, unsupported),
                Arguments.of(
                        "ALPN при пустом списке клиента (расширение не отправлялось)",
                        List.of(),
                        null,
                        alpn,
                        alpnH2,
                        unsupported),
                Arguments.of(
                        "битое тело незапрошенного ALPN: тип проверяется раньше тела",
                        null,
                        null,
                        alpn,
                        new byte[] {0x00},
                        unsupported),
                Arguments.of(
                        "ответ ALPN с двумя именами (RFC 7301 §3.1)",
                        List.of("h2", "http/1.1"),
                        null,
                        alpn,
                        alpnData("h2", "http/1.1"),
                        TlsConstants.ALERT_DECODE_ERROR),
                Arguments.of(
                        "ALPN вне списка клиента",
                        List.of("h2"),
                        null,
                        alpn,
                        alpnData("spdy/3"),
                        TlsConstants.ALERT_ILLEGAL_PARAMETER),
                Arguments.of(
                        "server_name без отправленного SNI",
                        null,
                        null,
                        sni,
                        new byte[0],
                        unsupported),
                Arguments.of(
                        "server_name при соединении по IP-литералу (SNI не отправлялся)",
                        null,
                        "127.0.0.1",
                        sni,
                        new byte[0],
                        unsupported),
                Arguments.of(
                        "server_name с непустым телом при отправленном SNI",
                        null,
                        "example.com",
                        sni,
                        new byte[] {0x00, 0x00},
                        TlsConstants.ALERT_DECODE_ERROR));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rejectedEncryptedExtensions")
    @DisplayName("EE: недопустимый ответ сервера -> алерт, протокол ALPN не сохраняется")
    void testEeInvalidResponseRejected(
            String name,
            List<String> offeredAlpn,
            String host,
            int extensionType,
            byte[] extensionData,
            int expectedAlert)
            throws Exception {
        TlsHandshakeEngine client = clientReadyForEncryptedExtensions(offeredAlpn, host);
        assertEeRejected(
                client,
                encryptedExtensionsFrame(extension(extensionType, extensionData)),
                expectedAlert,
                name);
        assertNull(client.getSelectedAlpnProtocol(), "Отвергнутый ответ не задаёт протокол");
    }

    @Test
    @DisplayName("EE: два ALPN без запроса -> ALERT_ILLEGAL_PARAMETER (структура раньше отправки)")
    void testEeDuplicateAlpnUnsolicited() throws Exception {
        TlsHandshakeEngine client = clientReadyForEncryptedExtensions(null, null);
        byte[] alpn =
                extension(TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, alpnData("h2"));
        assertEeRejected(
                client,
                encryptedExtensionsFrame(alpn, alpn),
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                "Дубль расширения -> ALERT_ILLEGAL_PARAMETER, код не зависит от факта запроса");
    }

    @Test
    @DisplayName("EE: запрошенный ALPN принимается")
    void testEeRequestedAlpnAccepted() throws Exception {
        TlsHandshakeEngine client =
                clientReadyForEncryptedExtensions(List.of("h2", "http/1.1"), null);
        client.receive(
                encryptedExtensionsFrame(
                        extension(
                                TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                                alpnData("http/1.1"))));
        assertEquals("http/1.1", client.getSelectedAlpnProtocol());
        assertFalse(client.isError());
    }

    @Test
    @DisplayName("EE короче двух байт (0 и 1 байт) -> ALERT_DECODE_ERROR")
    void testEeShorterThanLengthField() throws Exception {
        for (int bodyLength = 0; bodyLength <= 1; bodyLength++) {
            TlsHandshakeEngine client = clientReadyForEncryptedExtensions(null, null);
            byte[] ee =
                    new TlsHandshakeMessage(
                                    TlsConstants.HT_ENCRYPTED_EXTENSIONS, new byte[bodyLength])
                            .encode();
            assertEeRejected(
                    client,
                    ee,
                    TlsConstants.ALERT_DECODE_ERROR,
                    "EE длиной " + bodyLength + " байт нарушает RFC 8446 §4.3.1");
        }
    }

    @Test
    @DisplayName("EE: пустой блок расширений (00 00) принимается")
    void testEeEmptyExtensionBlockAccepted() throws Exception {
        TlsHandshakeEngine client = clientReadyForEncryptedExtensions(null, null);
        client.receive(encryptedExtensionsFrame());
        client.acknowledgeReadKeyChange();
        assertFalse(client.isError());
        assertNull(client.getSelectedAlpnProtocol());
    }

    @Test
    @DisplayName("EE: пустой server_name при отправленном SNI принимается")
    void testEeServerNameAckAccepted() throws Exception {
        TlsHandshakeEngine client = clientReadyForEncryptedExtensions(null, "example.com");
        client.receive(
                encryptedExtensionsFrame(extension(TlsConstants.EXT_SERVER_NAME, new byte[0])));
        assertFalse(client.isError());
    }

    @Test
    @DisplayName("EE: supported_groups принимается, GREASE отвергается")
    void testEeSupportedGroupsAcceptedGreaseRejected() throws Exception {
        // supported_groups клиент отправляет сам, поэтому ответ законен; содержимое по RFC 8446
        // §4.2.7 до конца рукопожатия не используется
        TlsHandshakeEngine client = clientReadyForEncryptedExtensions(null, null);
        client.receive(
                encryptedExtensionsFrame(
                        extension(
                                TlsConstants.EXT_SUPPORTED_GROUPS,
                                new byte[] {0x00, 0x02, 0x00, 0x23})));
        assertFalse(client.isError());

        // GREASE клиент не отправлял: неизвестное расширение без запроса (RFC 8446 §4.2)
        TlsHandshakeEngine greaseClient = clientReadyForEncryptedExtensions(null, null);
        assertEeRejected(
                greaseClient,
                encryptedExtensionsFrame(extension(0x0A0A, new byte[0])),
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                "Неизвестное расширение без запроса -> ALERT_UNSUPPORTED_EXTENSION");
    }

    @Test
    @DisplayName("EE: early_data без запроса -> ALERT_UNSUPPORTED_EXTENSION")
    void testEeEarlyDataUnsolicited() throws Exception {
        TlsHandshakeEngine client = clientReadyForEncryptedExtensions(null, null);
        assertEeRejected(
                client,
                encryptedExtensionsFrame(extension(TlsConstants.EXT_EARLY_DATA, new byte[0])),
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                "early_data допустим в EE, но клиент его не запрашивал");
    }

    @Test
    @DisplayName("EE: известное расширение не из EncryptedExtensions -> ALERT_ILLEGAL_PARAMETER")
    void testEeKnownExtensionFromOtherMessage() throws Exception {
        TlsHandshakeEngine client = clientReadyForEncryptedExtensions(null, null);
        assertEeRejected(
                client,
                encryptedExtensionsFrame(
                        extension(TlsConstants.EXT_KEY_SHARE, new byte[] {0x00, 0x23})),
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                "key_share не принадлежит EncryptedExtensions, даже отправленный клиентом");
    }

    @Test
    @DisplayName(
            "EE после HRR: ALPN, которого не было ни в одном ClientHello -> ALERT_UNSUPPORTED_EXTENSION")
    void testEeAfterHrrUnsolicitedAlpn() throws Exception {
        TlsHandshakeEngine client = newEeTestClient(null, null);
        assertNotNull(client.start());
        deliverHrrWithCookie(client);
        deliverServerHello(client);
        assertEeRejected(
                client,
                encryptedExtensionsFrame(
                        extension(
                                TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                                alpnData("h2"))),
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                "После HRR ответ ALPN без запроса по-прежнему отвергается");
    }

    @Test
    @DisplayName("HRR с cookie: рукопожатие проходит до EE с запрошенным ALPN")
    void testHrrWithCookieThenRequestedAlpnAccepted() throws Exception {
        // Расширения второго ClientHello (cookie, key_share) не отменяют запрошенный ALPN
        TlsHandshakeEngine client = newEeTestClient(List.of("h2"), null);
        assertNotNull(client.start());
        deliverHrrWithCookie(client);
        deliverServerHello(client);
        client.receive(
                encryptedExtensionsFrame(
                        extension(
                                TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                                alpnData("h2"))));
        assertEquals("h2", client.getSelectedAlpnProtocol());
    }

    @Test
    @DisplayName(
            "Типы расширений ClientHello берутся из отправленных байт: пустой список ALPN не в счёт")
    void testSentExtensionTypesFollowActualBytes() throws Exception {
        Set<Integer> withoutAlpn =
                sentTypesOfFirstClientHello(newEeTestClient(List.of(), "example.com"));
        assertFalse(
                withoutAlpn.contains(TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
                "Пустой список ALPN расширения не порождает");
        assertTrue(withoutAlpn.contains(TlsConstants.EXT_SERVER_NAME), "SNI отправлен");

        Set<Integer> withAlpn = sentTypesOfFirstClientHello(newEeTestClient(List.of("h2"), null));
        assertTrue(withAlpn.contains(TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION));
        assertFalse(withAlpn.contains(TlsConstants.EXT_SERVER_NAME), "SNI без имени не уходит");
    }

    private static Set<Integer> sentTypesOfFirstClientHello(TlsHandshakeEngine client)
            throws Exception {
        byte[] chBody = TlsHandshakeMessage.decode(client.start()).getBody();
        return TlsMessageParser.extensionTypesOfClientHello(chBody);
    }

    @Test
    @DisplayName("extensionTypesOfClientHello: битые собственные байты -> IllegalStateException")
    void testExtensionTypesOfMalformedClientHello() {
        assertThrows(
                IllegalStateException.class,
                () -> TlsMessageParser.extensionTypesOfClientHello(new byte[] {0x03, 0x03, 0x00}),
                "Дефект собственных байт - ошибка программы, а не alert пира");
    }

    @Test
    @DisplayName(
            "ALPN: имя с байтами 0x80..0xFF (GREASE 8A8A) уходит в ClientHello и читается без"
                    + " искажений")
    void testAlpnNameWithHighBytesRoundTrip() throws Exception {
        String greaseName = "\u008A\u008A";
        TlsHandshakeEngine client = newEeTestClient(List.of(greaseName, "h2"), null);
        byte[] chBody = TlsHandshakeMessage.decode(client.start()).getBody();

        byte[] wireName = {(byte) 0x8A, (byte) 0x8A};
        assertTrue(
                indexOf(chBody, wireName) >= 0,
                "В ClientHello имя должно лежать байтами 8A 8A, а не знаками вопроса");

        // Ответ сервера с тем же именем клиент читает тем же String
        deliverServerHello(client);
        client.receive(
                encryptedExtensionsFrame(
                        extension(
                                TlsConstants.EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                                alpnData(greaseName))));
        assertEquals(
                greaseName,
                client.getSelectedAlpnProtocol(),
                "Приложение должно видеть именно то имя, которое задало");
    }

    @Test
    @DisplayName("ALPN: имя из 255 байт 0xFF проходит, из 256 отвергается")
    void testAlpnNameLengthBoundary() {
        TlsHandshakeEngine client = newEeTestClient(null, null);
        client.setClientAlpnProtocols(List.of("\u00FF".repeat(255)));
        assertThrows(
                IllegalArgumentException.class,
                () -> client.setClientAlpnProtocols(List.of("\u00FF".repeat(256))),
                "256 байт не помещаются в однобайтовую длину имени");
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    @Test
    @DisplayName(
            "Сеттеры ALPN движка: плохое имя отвергается сразу, null и пустой список допустимы")
    void testEngineAlpnSettersValidation() {
        TlsHandshakeEngine client = newEeTestClient(null, null);
        assertThrows(
                IllegalArgumentException.class,
                () -> client.setClientAlpnProtocols(List.of("")),
                "Пустое имя запрещено RFC 7301 §3.1");
        assertThrows(
                IllegalArgumentException.class,
                () -> client.setClientAlpnProtocols(List.of("x".repeat(256))),
                "Имя длиннее 255 байт обрезалось бы в длине");
        assertThrows(
                IllegalArgumentException.class,
                () -> client.setServerAlpnProtocols(List.of("h\u0100")),
                "Символ выше U+00FF не помещается в один байт и молча исказился бы");
        client.setClientAlpnProtocols(null);
        client.setClientAlpnProtocols(List.of());
        client.setServerAlpnProtocols(null);
        client.setServerAlpnProtocols(List.of());
    }

    private static void deliverHrrWithCookie(TlsHandshakeEngine client) throws Exception {
        byte[] cookie = CryptoRandom.INSTANCE.generateSeed(16);
        byte[] hrrBody =
                TlsMessageBuilderTestAccess.buildHelloRetryRequestWithCookie(
                        serverBuilder(), cs().getId(), cookie);
        client.receive(new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, hrrBody).encode());
        client.acknowledgeReadKeyChange();
        assertNotNull(
                HandshakeOutputs.nextMessage(client),
                "Клиент должен вернуть второй ClientHello после HRR");
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
        server.acknowledgeReadKeyChange();
        byte[] hrr = HandshakeOutputs.nextMessage(server);
        assertNotNull(hrr);

        TlsHandshakeMessage hrrMsg = TlsHandshakeMessage.decode(hrr);
        assertTrue(
                TlsMessageParser.isHelloRetryRequest(
                        TlsMessageParser.parseServerHello(
                                hrrMsg.getBody(), SERVER_RESPONSE_TYPES_SENT)),
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

    // -------------------------------------------------------------------
    // Post-handshake: NewSessionTicket
    // -------------------------------------------------------------------

    private static byte[] newSessionTicketFrame() {
        byte[] body = TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], new byte[] {1});
        return new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, body).encode();
    }

    @Test
    @DisplayName("сервер отклоняет NewSessionTicket от клиента")
    void testServerRejectsNewSessionTicket() {
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        server.initForTesting(new byte[HASH_LEN], new byte[HASH_LEN]);

        // Основной путь интеграторов — прямой вызов receivePostHandshake.
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () -> server.receivePostHandshake(newSessionTicketFrame()));
        assertEquals(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                ex.getAlertCode(),
                "NST от клиента должен отклоняться как unexpected_message");
    }

    @Test
    @DisplayName("обёртка receive() отклоняет NST на сервере и переводит state в ERROR")
    void testReceiveRejectsNewSessionTicketOnServer() {
        TlsHandshakeEngine server = newEngine(TlsHandshakeEngine.Role.SERVER, false, false);
        server.initForTesting(new byte[HASH_LEN], new byte[HASH_LEN]);

        TlsException ex =
                assertThrows(TlsException.class, () -> server.receive(newSessionTicketFrame()));
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, ex.getAlertCode());
        assertEquals(TlsHandshakeEngine.State.ERROR, server.getState());
    }

    @Test
    @DisplayName("клиент по-прежнему принимает NewSessionTicket от сервера")
    void testClientAcceptsNewSessionTicket() throws Exception {
        TlsHandshakeEngine client = newEngine(TlsHandshakeEngine.Role.CLIENT, false, false);
        client.initForTesting(new byte[HASH_LEN], new byte[HASH_LEN]);

        TlsHandshakeEngine.PostHandshakeResult result =
                client.receivePostHandshake(newSessionTicketFrame());
        client.acknowledgeReadKeyChange();
        assertEquals(TlsHandshakeEngine.PostHandshakeResult.Type.NEW_SESSION_TICKET, result.type);
    }
}
