package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.cert.*;
import org.rssys.gost.tls13.config.*;
import org.rssys.gost.tls13.crypto.*;
import org.rssys.gost.tls13.engine.*;
import org.rssys.gost.tls13.message.*;
import org.rssys.gost.tls13.psk.*;
import org.rssys.gost.tls13.record.*;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * Тесты TlsSession — TLS 1.3 handshake, передача данных, утилиты.
 */
@DisplayName("TlsSession: handshake, передача данных, утилиты")
class TlsSessionTest {

    /** Типы расширений ClientHello, на которые тест якобы получает ответ в ServerHello. */
    private static final Set<Integer> SERVER_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_SUPPORTED_VERSIONS,
                    TlsConstants.EXT_KEY_SHARE,
                    TlsConstants.EXT_PRE_SHARED_KEY);

    // =======================================================================
    // Тесты parseCertificate
    // =======================================================================

    @Test
    @DisplayName("parseCertificate: пустой certificate_list теперь валиден (RFC 8446)")
    void testParseCertificateEmptyListReturnsEmpty() throws TlsException {
        // Почему больше не кидает: RFC 8446 §4.4.2 разрешает клиенту прислать
        // пустой certificate_list. Парсер не знает контекст (клиент/сервер),
        // поэтому пустой список — валидный wire-формат. Решение о том,
        // обязателен ли сертификат, принимает engine (receiveClientCertificate).
        byte[] emptyCertBody = new byte[] {0x00, 0x00, 0x00, 0x00};
        List<GostCertificate> chain =
                TlsMessageParser.parseCertificate(
                        emptyCertBody, Set.of(TlsConstants.EXT_STATUS_REQUEST));
        assertNotNull(chain);
        assertTrue(chain.isEmpty());
    }

    @Test
    @DisplayName("parseCertificate: известное расширение не из Certificate -> illegal_parameter")
    void testParseCertificateWithKnownForeignExtension() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        byte[] certDer = bundle.cert.getEncoded();
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlsEncoding.encodeUint24(entry, certDer.length);
        entry.write(certDer, 0, certDer.length);
        TlsEncoding.encodeUint16(entry, 4); // ext_len=4
        // ext_type=1 (max_fragment_length): известно, но допустимо только в ClientHello и EE
        entry.write(new byte[] {0x00, 0x01, 0x00, 0x00}); // ext_data_len=0

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0); // request context
        byte[] entryBytes = entry.toByteArray();
        TlsEncoding.encodeUint24(body, entryBytes.length);
        body.write(entryBytes, 0, entryBytes.length);

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                TlsMessageParser.parseCertificate(
                                        body.toByteArray(),
                                        Set.of(TlsConstants.EXT_STATUS_REQUEST)));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                ex.getAlertCode(),
                "известное расширение не из Certificate -> illegal_parameter");
    }

    @Test
    @DisplayName("parseCertificate: 512-битный ключ в сертификате")
    void testParseCertificate512() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a512());
        byte[] certDer = bundle.cert.getEncoded();
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlsEncoding.encodeUint24(entry, certDer.length);
        entry.write(certDer, 0, certDer.length);
        TlsEncoding.encodeUint16(entry, 0); // расширения отсутствуют

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0); // request context
        byte[] entryBytes = entry.toByteArray();
        TlsEncoding.encodeUint24(body, entryBytes.length);
        body.write(entryBytes, 0, entryBytes.length);

        List<GostCertificate> chain =
                TlsMessageParser.parseCertificate(
                        body.toByteArray(), Set.of(TlsConstants.EXT_STATUS_REQUEST));
        assertEquals(1, chain.size());
        assertEquals(512, chain.get(0).getKeySize());
    }

    // =======================================================================
    // Тесты parsePlaintextRecord
    // =======================================================================

    @Test
    @DisplayName("parsePlaintextRecord: null бросает TlsException(ALERT_DECODE_ERROR)")
    void testParsePlaintextRecordNull() {
        TlsException ex =
                assertThrows(TlsException.class, () -> TlsMessageParser.parsePlaintextRecord(null));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName(
            "parsePlaintextRecord: слишком короткая запись -> TlsException(ALERT_DECODE_ERROR)")
    void testParsePlaintextRecordTooShort() {
        byte[] shortRecord = new byte[3];
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () -> TlsMessageParser.parsePlaintextRecord(shortRecord));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName(
            "parsePlaintextRecord: поле len превышает длину записи -> TlsException(ALERT_DECODE_ERROR)")
    void testParsePlaintextRecordTruncated() {
        byte[] record = new byte[] {TlsConstants.CT_HANDSHAKE, 0x03, 0x03, 0x10, 0x00};
        TlsException ex =
                assertThrows(
                        TlsException.class, () -> TlsMessageParser.parsePlaintextRecord(record));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName("parsePlaintextRecord: хвост после записи -> TlsException(ALERT_DECODE_ERROR)")
    void testParsePlaintextRecordTrailingBytes() {
        byte[] record = new byte[] {TlsConstants.CT_HANDSHAKE, 0x03, 0x03, 0x00, 0x01, 0x07, 0x09};
        TlsException ex =
                assertThrows(
                        TlsException.class, () -> TlsMessageParser.parsePlaintextRecord(record));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName("parsePlaintextRecord: длина больше 2^14 -> record_overflow")
    void testParsePlaintextRecordOverflow() {
        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE];
        record[0] = TlsConstants.CT_HANDSHAKE;
        record[3] = 0x40;
        record[4] = 0x01;
        TlsException ex =
                assertThrows(
                        TlsException.class, () -> TlsMessageParser.parsePlaintextRecord(record));
        assertEquals(TlsConstants.ALERT_RECORD_OVERFLOW, ex.getAlertCode());
    }

    @Test
    @DisplayName("parsePlaintextRecord: корректная запись возвращает тип и тело, версия не важна")
    void testParsePlaintextRecordValid() throws Exception {
        byte[] body = "hello".getBytes();
        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + body.length];
        record[0] = TlsConstants.CT_HANDSHAKE;
        // Версия записи игнорируется (RFC 8446 §5.1): допустим и 0x0301
        record[1] = 0x03;
        record[2] = 0x01;
        record[3] = 0;
        record[4] = (byte) body.length;
        System.arraycopy(body, 0, record, TlsConstants.RECORD_HEADER_SIZE, body.length);

        TlsMessageParser.PlaintextRecord result = TlsMessageParser.parsePlaintextRecord(record);

        assertEquals(TlsConstants.CT_HANDSHAKE, result.contentType);
        assertArrayEquals(body, result.body);
    }

    // =======================================================================
    // Тесты factory методов и жизненного цикла
    // =======================================================================

    @Test
    @DisplayName("createClient: корректное создание сессии клиента")
    void testCreateClient() {
        TlsSession s =
                TlsSession.createClientWithoutServerAuth(
                        new InMemoryTlsTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        null,
                        null);
        assertNotNull(s);
        assertFalse(s.isHandshakeDone());
        assertFalse(s.isClosed());
    }

    @Test
    @DisplayName("createClientWithoutServerAuth: self-signed принимается")
    void testClientWithoutServerAuthAcceptsSelfSigned() throws Exception {
        PkixCertTestHelper.CertBundle selfSigned =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(),
                        "20250101000000Z",
                        "21010101000000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH});

        handshakeWithoutServerAuth(selfSigned);
    }

    @Test
    @DisplayName("createClientWithoutServerAuth: просроченный leaf отклоняется")
    void testClientWithoutServerAuthRejectsExpired() {
        PkixCertTestHelper.CertBundle expired =
                PkixCertTestHelper.createCertWithKey(
                        ECParameters.tc26a256(),
                        "20200101000000Z",
                        "20210101000000Z",
                        new String[] {"localhost"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH});

        ExecutionException ex =
                assertThrows(
                        ExecutionException.class,
                        () -> handshakeWithoutServerAuth(expired),
                        "leaf-проверки должны работать и без проверки цепочки");
        assertInstanceOf(TlsException.class, ex.getCause(), "причина должна быть TlsException");
        assertTrue(
                ex.getCause().getMessage().contains("Server certificate expired"),
                () -> "ожидался отказ по сроку, получено: " + ex.getCause().getMessage());
    }

    private void handshakeWithoutServerAuth(PkixCertTestHelper.CertBundle bundle) throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        tp.getServerTransport(), getCsL(), bundle.cert, bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(
                        tp.getClientTransport(), getCsL(), null, null);

        ExecutorService exec = Executors.newFixedThreadPool(2);
        Phaser phaser = new Phaser(3);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });

        try {
            phaser.arriveAndAwaitAdvance();
            cf.get(15, TimeUnit.SECONDS);
            sf.get(15, TimeUnit.SECONDS);
            assertTrue(client.isHandshakeDone(), "Клиент: handshake завершён");
            assertTrue(server.isHandshakeDone(), "Сервер: handshake завершён");
        } finally {
            exec.shutdownNow();
            client.close();
            server.close();
        }
    }

    @Test
    @DisplayName("createServer: корректное создание сессии сервера")
    void testCreateServer() {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        TlsSession s =
                TlsSession.createServer(
                        new InMemoryTlsTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);
        assertNotNull(s);
        assertFalse(s.isHandshakeDone());
        assertFalse(s.isClosed());
    }

    @Test
    @DisplayName("createServer: null вместо сертификата -> IllegalArgumentException сразу")
    void testCreateServerNullCertificateRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        TlsSession.createServer(
                                new InMemoryTlsTransport(),
                                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                                null,
                                null),
                "Сертификата нет: ошибка настройки должна быть видна при создании, а не при рукопожатии");
    }

    @Test
    @DisplayName("factory: null транспорт бросает исключение")
    void testCreateNullTransport() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        TlsSession.createClientWithoutServerAuth(
                                null,
                                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                                null,
                                null));
    }

    @Test
    @DisplayName("factory: null cipher suite бросает исключение")
    void testCreateNullCiphersuite() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        TlsSession.createClientWithoutServerAuth(
                                new InMemoryTlsTransport(), null, null, null));
    }

    @Test
    @DisplayName("Конфигурация: пустой набор якорей и null-элементы отвергаются")
    void testTrustAnchorsValidation() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());

        assertThrows(
                IllegalArgumentException.class,
                () -> new TlsClientConfig(getCsL(), TrustAnchors.ofCertificates(List.of())));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new TlsClientConfig(
                                getCsL(),
                                TrustAnchors.ofCertificates(
                                        Arrays.asList((GostCertificate) null))));
        assertThrows(
                IllegalArgumentException.class,
                () -> new TlsClientConfig(getCsL(), (TrustAnchors) null));

        TlsServerConfig serverConfig =
                new TlsServerConfig(getCsL(), List.of(bundle.cert), bundle.priv);
        assertThrows(
                IllegalArgumentException.class,
                () -> serverConfig.needClientAuth(TrustAnchors.empty()),
                "Пустой набор якорей должен отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> serverConfig.needClientAuth(null),
                "null вместо якорей не должен молча отключать mTLS");
        assertThrows(
                IllegalArgumentException.class,
                () -> serverConfig.wantClientAuth(TrustAnchors.empty()),
                "Пустой набор якорей должен отвергаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> serverConfig.wantClientAuth(null),
                "null вместо якорей не должен молча отключать mTLS");
    }

    @Test
    @DisplayName(
            "factory: без hostname и без withoutHostnameVerification -> IllegalArgumentException")
    void testCreateClientMissingHostnameThrows() throws Exception {
        GostCertificate caCert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256()).cert;
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        TlsSession.createClient(
                                new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(caCert)),
                                noopTransport()));
    }

    @Test
    @DisplayName("write до handshake: IllegalStateException")
    void testWriteBeforeHandshake() {
        TlsSession s =
                TlsSession.createClientWithoutServerAuth(
                        new InMemoryTlsTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        null,
                        null);
        assertThrows(IllegalStateException.class, () -> s.write(new byte[] {1}));
    }

    @Test
    @DisplayName("read до handshake: IllegalStateException")
    void testReadBeforeHandshake() {
        TlsSession s =
                TlsSession.createClientWithoutServerAuth(
                        new InMemoryTlsTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        null,
                        null);
        assertThrows(IllegalStateException.class, s::read);
    }

    @Test
    @DisplayName("close: идемпотентность")
    void testCloseIdempotent() throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        TlsSession s =
                TlsSession.createClientWithoutServerAuth(
                        tp.getClientTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        null,
                        null);
        s.close();
        assertTrue(s.isClosed());
        s.close();
        assertTrue(s.isClosed());
    }

    @Test
    @DisplayName("handshakeAsClient в закрытой сессии: IllegalStateException")
    void testHandshakeAsClientWhenClosed() throws Exception {
        TlsSession s =
                TlsSession.createClientWithoutServerAuth(
                        new InMemoryTlsTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        null,
                        null);
        s.close();
        assertThrows(IllegalStateException.class, s::handshakeAsClient);
    }

    @Test
    @DisplayName("handshakeAsServer в закрытой сессии: IllegalStateException")
    void testHandshakeAsServerWhenClosed() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        TlsSession s =
                TlsSession.createServer(
                        new InMemoryTlsTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);
        s.close();
        assertThrows(IllegalStateException.class, s::handshakeAsServer);
    }

    // =======================================================================
    // Полный handshake клиент-сервер
    // =======================================================================

    @Test
    @DisplayName("Полный handshake: клиент-сервер tc26-A-256")
    void testFullHandshake256() throws Exception {
        testHandshake(
                ECParameters.tc26a256(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
    }

    @Test
    @DisplayName("Полный handshake: сертификат CryptoPro-A (GC256B)")
    void testFullHandshakeCryptoProA() throws Exception {
        testHandshake(
                ECParameters.cryptoProA(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
    }

    @Test
    @DisplayName("Полный handshake: сертификат tc26-A-512")
    void testFullHandshake512() throws Exception {
        testHandshake(
                ECParameters.tc26a512(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
    }

    private void testHandshake(ECParameters params, TlsCiphersuite cs) throws Exception {
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(tp.getServerTransport(), cs, bundle.cert, bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(tp.getClientTransport(), cs, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);

        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });

        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });

        phaser.arriveAndAwaitAdvance();

        try {
            cf.get(15, TimeUnit.SECONDS);
            sf.get(15, TimeUnit.SECONDS);
        } finally {
            exec.shutdown();
        }

        assertTrue(client.isHandshakeDone(), "Клиент: handshake завершён");
        assertTrue(server.isHandshakeDone(), "Сервер: handshake завершён");

        // Передача данных
        client.write("Hello".getBytes());
        assertArrayEquals("Hello".getBytes(), server.read());

        server.write("Reply".getBytes());
        assertArrayEquals("Reply".getBytes(), client.read());

        server.close();
        client.close();
    }

    @Test
    @DisplayName("Middlebox CCS (20) молча игнорируется в TLS 1.3 (RFC 8446 §D.4)")
    void testSilentlyIgnoreChangeCipherSpec() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        var c2s = new LinkedBlockingQueue<byte[]>();
        var s2c = new LinkedBlockingQueue<byte[]>();
        var ccsInjected = new AtomicBoolean(false);

        // Серверный транспорт: при первом sendRecord сначала отправляем ServerHello,
        // затем следом CCS — имитация middlebox-вставки (RFC 8446 §D.4)
        InMemoryTlsTransport serverTransport =
                new InMemoryTlsTransport(c2s) {
                    @Override
                    public void sendRecord(byte[] record) throws IOException {
                        s2c.add(record.clone());
                        if (ccsInjected.compareAndSet(false, true)) {
                            // CCS: content_type=20, legacy_record_version=0x0303, length=1,
                            // payload=0x01
                            s2c.add(
                                    new byte[] {
                                        TlsConstants.CT_CHANGE_CIPHER_SPEC,
                                        0x03,
                                        0x03,
                                        0x00,
                                        0x01,
                                        0x01
                                    });
                        }
                    }
                };
        InMemoryTlsTransport clientTransport =
                new InMemoryTlsTransport(s2c) {
                    @Override
                    public void sendRecord(byte[] record) throws IOException {
                        c2s.add(record.clone());
                    }
                };

        TlsSession server = TlsSession.createServer(serverTransport, cs, bundle.cert, bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(clientTransport, cs, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);

        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();

        assertTrue(client.isHandshakeDone(), "Клиент: handshake завершён despite CCS");
        assertTrue(server.isHandshakeDone(), "Сервер: handshake завершён despite CCS");

        // Прикладные данные проходят сквозь установленное соединение
        client.write("data".getBytes());
        assertArrayEquals("data".getBytes(), server.read());

        server.write("reply".getBytes());
        assertArrayEquals("reply".getBytes(), client.read());

        server.close();
        client.close();
    }

    // =======================================================================
    // Валидация совместимого CCS (RFC 8446 §5, §D.4)
    // =======================================================================

    private static byte[] ccsRecord(byte... payload) {
        byte[] r = new byte[TlsConstants.RECORD_HEADER_SIZE + payload.length];
        r[0] = TlsConstants.CT_CHANGE_CIPHER_SPEC;
        r[1] = 0x03;
        r[2] = 0x03;
        r[3] = (byte) (payload.length >> 8);
        r[4] = (byte) payload.length;
        System.arraycopy(payload, 0, r, TlsConstants.RECORD_HEADER_SIZE, payload.length);
        return r;
    }

    /** Клиент получает от сервера после первой записи CCS с недопустимым содержимым. */
    private void assertClientRejectsInjectedCcs(byte[] badCcs) throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        var c2s = new LinkedBlockingQueue<byte[]>();
        var s2c = new LinkedBlockingQueue<byte[]>();
        var injected = new AtomicBoolean(false);

        InMemoryTlsTransport serverTransport =
                new InMemoryTlsTransport(c2s) {
                    @Override
                    public void sendRecord(byte[] record) throws IOException {
                        s2c.add(record.clone());
                        if (injected.compareAndSet(false, true)) {
                            s2c.add(badCcs.clone());
                        }
                    }
                };
        InMemoryTlsTransport clientTransport =
                new InMemoryTlsTransport(s2c) {
                    @Override
                    public void sendRecord(byte[] record) throws IOException {
                        c2s.add(record.clone());
                    }
                };
        TlsSession server = TlsSession.createServer(serverTransport, cs, bundle.cert, bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(clientTransport, cs, null, null);

        ExecutorService exec = Executors.newFixedThreadPool(2);
        try {
            Future<Void> sf =
                    exec.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            Future<Void> cf =
                    exec.submit(
                            () -> {
                                client.handshakeAsClient();
                                return null;
                            });
            ExecutionException ex =
                    assertThrows(ExecutionException.class, () -> cf.get(15, TimeUnit.SECONDS));
            assertTrue(ex.getCause() instanceof TlsException, "ожидался TlsException: " + ex);
            assertEquals(
                    TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                    ((TlsException) ex.getCause()).getAlertCode());
            sf.cancel(true);
        } finally {
            exec.shutdownNow();
        }
    }

    @Test
    @DisplayName("CCS с содержимым 0x02 во время handshake -> TlsException(unexpected_message)")
    void testCcsWithWrongValueRejected() throws Exception {
        assertClientRejectsInjectedCcs(ccsRecord((byte) 0x02));
    }

    @Test
    @DisplayName("CCS с длиной 0 во время handshake -> TlsException(unexpected_message)")
    void testCcsWithEmptyPayloadRejected() throws Exception {
        assertClientRejectsInjectedCcs(ccsRecord());
    }

    @Test
    @DisplayName("CCS с длиной 2 во время handshake -> TlsException(unexpected_message)")
    void testCcsWithTwoBytePayloadRejected() throws Exception {
        assertClientRejectsInjectedCcs(ccsRecord((byte) 0x01, (byte) 0x01));
    }

    @Test
    @DisplayName(
            "CCS первой записью на сервере (до ClientHello) -> TlsException(unexpected_message)")
    void testCcsBeforeClientHelloRejectedOnServer() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        var c2s = new LinkedBlockingQueue<byte[]>();
        c2s.add(ccsRecord((byte) 0x01));
        InMemoryTlsTransport serverTransport =
                new InMemoryTlsTransport(c2s) {
                    @Override
                    public void sendRecord(byte[] record) throws IOException {
                        // ответ не нужен: сервер должен прервать handshake до отправки
                    }
                };
        TlsSession server =
                TlsSession.createServer(
                        serverTransport,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);

        TlsException ex = assertThrows(TlsException.class, server::handshakeAsServer);
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, ex.getAlertCode());
    }

    @Test
    @DisplayName(
            "CCS после handshake в read() -> TlsException(unexpected_message), не IllegalArgumentException")
    void testCcsAfterHandshakeRejectedInRead() throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsSession server =
                TlsSession.createServer(tp.getServerTransport(), cs, bundle.cert, bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(tp.getClientTransport(), cs, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();

        tp.getServerTransport().sendRecord(ccsRecord((byte) 0x01));

        TlsException ex = assertThrows(TlsException.class, client::read);
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, ex.getAlertCode());
    }

    // =======================================================================
    // close_notify
    // =======================================================================

    // =======================================================================
    // CA verify
    // =======================================================================

    @Test
    @DisplayName("handshake с CA verify: самоподписанный сертификат проходит")
    void testHandshakeWithCaVerify() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        tp.getServerTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);
        // Проверяем сертификат сервера его же публичным ключом (self-signed)
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(
                                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                                        TrustAnchors.ofCertificate(bundle.cert))
                                .withoutHostnameVerification(),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);

        assertTrue(client.isHandshakeDone(), "Handshake с CA verify должен пройти");
        exec.shutdown();
        server.close();
        client.close();
    }

    // =======================================================================
    // CertificateVerify
    // =======================================================================

    @Test
    @DisplayName("CertificateVerify с неверной схемой подписи -> ALERT_BAD_CERTIFICATE")
    void testCertificateVerifyWrongScheme() throws Exception {
        TlsSession s =
                TlsSession.createClientWithoutServerAuth(
                        new InMemoryTlsTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        null,
                        null);

        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        // схема 0x070D (512-бит), а ожидается 256-бит
        ByteArrayOutputStream cvBody = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(cvBody, TlsConstants.SIG_GOST_TC26_512_A);
        TlsEncoding.encodeUint16(cvBody, 8);
        cvBody.write(new byte[8]);

        byte[] transcript = new byte[TlsConstants.STREEBOG_256_HASH_LEN];
        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                s.verifyCertificateVerify(
                                        cvBody.toByteArray(), bundle.cert, transcript, true));
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    // -----------------------------------------------------------------------
    // Подмена записи в e2e
    // -----------------------------------------------------------------------

    // =======================================================================
    // Ошибка аутентификации
    // =======================================================================

    @Test
    @DisplayName("Handshake: несовпадение ключа сертификата = ошибка")
    void testHandshakeWithMismatchedKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        // Другой ключ для подписи CertificateVerify
        PrivateKeyParameters wrongKey = KeyGenerator.generateKeyPair(params).getPrivate();

        var tp = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        tp.getServerTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        wrongKey);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(
                        tp.getClientTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        null,
                        null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();

        try {
            cf.get(10, TimeUnit.SECONDS);
            fail("Client handshake с неверным ключом должен провалиться");
        } catch (ExecutionException e) {
            assertTrue(
                    e.getCause() instanceof IOException,
                    "Ожидается IOException: " + e.getCause().getMessage());
            assertTrue(
                    e.getCause() instanceof TlsException,
                    "Ожидается TlsException с кодом алерта: " + e.getCause());
            assertEquals(
                    TlsConstants.ALERT_DECRYPT_ERROR,
                    ((TlsException) e.getCause()).getAlertCode(),
                    "подпись CertificateVerify чужим ключом - decrypt_error");
        }

        // Клиент ещё не включил ключ записи и шлёт alert открытым: сервер обязан увидеть настоящий
        // код клиента и не отвечать alert (на alert пира ответа нет)
        try {
            sf.get(10, TimeUnit.SECONDS);
            fail("Сервер должен получить alert клиента");
        } catch (ExecutionException e) {
            TlsException serverError = (TlsException) e.getCause();
            assertTrue(serverError.isFromPeer(), "Alert пришёл от пира: " + serverError);
            assertEquals(
                    TlsConstants.ALERT_DECRYPT_ERROR,
                    serverError.getAlertCode(),
                    "сервер видит настоящий код клиента");
        }
        exec.shutdown();
        exec.awaitTermination(2, TimeUnit.SECONDS);

        java.util.ArrayList<byte[]> s2cRecords = new java.util.ArrayList<>();
        byte[] r;
        while ((r = tp.getServerToClientQueue().poll()) != null) {
            s2cRecords.add(r);
        }
        assertFalse(
                s2cRecords.stream().anyMatch(rec -> rec[0] == TlsConstants.CT_ALERT),
                "На fatal alert пира сервер ничего не отвечает открытым alert");

        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: SNI передаётся от клиента к серверу")
    void testHandshakeSniRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        String sniHost = "my-server.example.com";
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(
                        params, "20240501120000Z", "21060101120000Z", new String[] {sniHost});
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        tp.getServerTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(
                                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                                        TrustAnchors.ofCertificate(bundle.cert))
                                .withServerHostname(sniHost),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();

        assertTrue(client.isHandshakeDone());
        assertTrue(server.isHandshakeDone());
        assertEquals(
                sniHost, server.getRequestedServerName(), "Сервер должен получить SNI от клиента");
        assertEquals(sniHost, client.getPeerHostname(), "Клиент должен помнить hostname");
        client.write("data".getBytes());
        assertArrayEquals("data".getBytes(), server.read());
        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: IDN host -> A-label SNI, selector и wildcard-сертификат")
    void testHandshakeIdnSniAndWildcard() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsCiphersuite cs = getCsL();
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(
                        params,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"*.xn--e1afmkfd.xn--p1ai"});

        java.util.concurrent.atomic.AtomicReference<String> selectedSni =
                new java.util.concurrent.atomic.AtomicReference<>();
        SniCertificateSelector selector =
                sni -> {
                    selectedSni.set(sni);
                    return new TlsServerCredentials(
                            Collections.singletonList(bundle.cert), bundle.priv, null);
                };

        var tp = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(cs, List.of(bundle.cert), bundle.priv)
                                .withSniSelector(selector),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(cs, TrustAnchors.ofCertificate(bundle.cert))
                                .withServerHostname("www.пример.рф"),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();

        assertEquals(
                "www.xn--e1afmkfd.xn--p1ai",
                server.getRequestedServerName(),
                "В ClientHello должен уйти A-label SNI");
        assertEquals(
                "www.xn--e1afmkfd.xn--p1ai",
                selectedSni.get(),
                "Selector должен получить A-label, а не Unicode");
        assertTrue(client.isHandshakeDone());
        assertTrue(server.isHandshakeDone());
        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: IP-литералы не уходят в SNI")
    void testIpHostnameNoSni() throws Exception {
        assertIpHandshakeWithoutSni("192.168.1.10", "192.168.1.10");
        assertIpHandshakeWithoutSni("::1", "::1");
        assertIpHandshakeWithoutSni("[::1]", "::1");
    }

    private void assertIpHandshakeWithoutSni(String hostname, String sanIp) throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsCiphersuite cs = getCsL();
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(
                        params,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        null,
                        null,
                        new String[] {sanIp});
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(tp.getServerTransport(), cs, bundle.cert, bundle.priv);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(cs, TrustAnchors.ofCertificate(bundle.cert))
                                .withServerHostname(hostname),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();

        assertTrue(client.isHandshakeDone(), "handshake для " + hostname);
        assertTrue(server.isHandshakeDone(), "handshake для " + hostname);
        assertNull(server.getRequestedServerName(), "IP-литерал не должен уходить в SNI");
        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: SNI selector выбирает сертификат по hostname")
    void testHandshakeWithSniCertificateSelector() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsCiphersuite cs = getCsL();
        String multiHost = "multi.example.com";
        String defaultHost = "default.example.com";

        // Два сертификата с разными SAN: один для multi, другой для fallback
        PkixCertTestHelper.CertBundle defaultBundle =
                PkixCertTestHelper.createCertWithKey(
                        params, "20240501120000Z", "21060101120000Z", new String[] {defaultHost});
        PkixCertTestHelper.CertBundle multiBundle =
                PkixCertTestHelper.createCertWithKey(
                        params, "20240501120000Z", "21060101120000Z", new String[] {multiHost});

        // Selector: для multiHost возвращает multi-credentials, для остальных — null (fallback)
        SniCertificateSelector selector =
                sni -> {
                    if (multiHost.equals(sni)) {
                        return new TlsServerCredentials(
                                Collections.singletonList(multiBundle.cert),
                                multiBundle.priv,
                                null);
                    }
                    return null;
                };

        // ====== Client 1: запрашивает multi.example.com ======
        var tp1 = InMemoryTlsTransport.newPair();
        TlsSession server1 =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        cs,
                                        Collections.singletonList(defaultBundle.cert),
                                        defaultBundle.priv)
                                .withSniSelector(selector),
                        tp1.getServerTransport());
        TlsSession client1 =
                TlsSession.createClient(
                        new TlsClientConfig(cs, TrustAnchors.ofCertificate(multiBundle.cert))
                                .withServerHostname(multiHost),
                        tp1.getClientTransport());

        handshakeInParallel(server1, client1);

        assertEquals(
                multiHost,
                server1.getRequestedServerName(),
                "Сервер должен получить SNI от клиента");
        assertNotNull(client1.getPeerCertificates(), "Клиент должен получить сертификат сервера");
        assertTrue(
                client1.getPeerCertificates().get(0).verifyHostname(multiHost),
                "Клиент должен получить сертификат для multi.example.com, а не default");

        client1.close();
        server1.close();

        // ====== Client 2: запрашивает default.example.com (fallback на default-сертификат) ======
        var tp2 = InMemoryTlsTransport.newPair();
        TlsSession server2 =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        cs,
                                        Collections.singletonList(defaultBundle.cert),
                                        defaultBundle.priv)
                                .withSniSelector(selector),
                        tp2.getServerTransport());
        TlsSession client2 =
                TlsSession.createClient(
                        new TlsClientConfig(cs, TrustAnchors.ofCertificate(defaultBundle.cert))
                                .withServerHostname(defaultHost),
                        tp2.getClientTransport());

        handshakeInParallel(server2, client2);

        assertEquals(
                defaultHost,
                server2.getRequestedServerName(),
                "Сервер должен получить SNI от клиента");
        assertNotNull(client2.getPeerCertificates(), "Клиент должен получить сертификат сервера");
        assertTrue(
                client2.getPeerCertificates().get(0).verifyHostname(defaultHost),
                "Клиент должен получить default-сертификат (через fallback)");

        client2.close();
        server2.close();
    }

    // =======================================================================
    // ALPN (RFC 7301) — интеграционные тесты через TlsClientConfig/TlsServerConfig
    // =======================================================================
    //
    // engine-level тесты для ALPN есть в TlsHandshakeEngineTest, но баг
    // «config.alpnProtocols не пропагируется в TlsSession» живёт именно в
    // factory-методах. Эти тесты проверяют полный путь:
    // TlsClientConfig.withAlpnProtocols() -> createClient() -> handshake -> getAlpnProtocol().

    @Test
    @DisplayName("ALPN: согласование h2 через TlsClientConfig/TlsServerConfig")
    void testAlpnViaConfig() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsCiphersuite cs = getCsL();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);

        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(cs, Collections.singletonList(bundle.cert), bundle.priv)
                                .withAlpnProtocols(List.of("h2", "http/1.1")),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(cs, TrustAnchors.ofCertificate(bundle.cert))
                                .withoutHostnameVerification()
                                .withAlpnProtocols(List.of("h2", "http/1.1")),
                        tp.getClientTransport());

        handshakeInParallel(server, client);

        assertEquals(
                "h2",
                server.getAlpnProtocol(),
                "Сервер: ALPN согласован через TlsServerConfig.withAlpnProtocols");
        assertEquals(
                "h2",
                client.getAlpnProtocol(),
                "Клиент: ALPN согласован через TlsClientConfig.withAlpnProtocols");

        server.close();
        client.close();
    }

    @Test
    @DisplayName("ALPN: клиент без ALPN -> getAlpnProtocol null")
    void testAlpnClientWithoutAlpn() throws Exception {
        // Сервер настроен на ALPN, клиент — нет. Сервер не включает ALPN в EE.
        ECParameters params = ECParameters.tc26a256();
        TlsCiphersuite cs = getCsL();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);

        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(cs, Collections.singletonList(bundle.cert), bundle.priv)
                                .withAlpnProtocols(List.of("h2", "http/1.1")),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(cs, TrustAnchors.ofCertificate(bundle.cert))
                                .withoutHostnameVerification(),
                        tp.getClientTransport());

        handshakeInParallel(server, client);

        assertNull(server.getAlpnProtocol(), "Сервер: ALPN не согласован (клиент не предлагал)");
        assertNull(client.getAlpnProtocol(), "Клиент: ALPN не согласован");

        server.close();
        client.close();
    }

    @Test
    @DisplayName(
            "Прерывание рукопожатия закрытием транспорта из другого потока: сессия остановлена владельцем, close() повторно безопасен")
    void testHandshakeAbortedByClosingTransportFromAnotherThread() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        tp.getServerTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);

        ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            // клиента нет: серверный поток ждёт ClientHello в receiveRecord()
            Future<Void> handshake =
                    exec.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });

            // Безопасный способ прервать рукопожатие: закрыть транспорт, не трогая саму сессию
            tp.getServerTransport().close();

            ExecutionException failure =
                    assertThrows(
                            ExecutionException.class,
                            () -> handshake.get(15, TimeUnit.SECONDS),
                            "рукопожатие без пира должно завершиться ошибкой после закрытия транспорта");
            assertTrue(
                    failure.getCause() instanceof TlsException
                            || failure.getCause() instanceof IOException,
                    "ожидалась ошибка ввода-вывода или TLS: " + failure.getCause());

            // Поток-владелец сам остановил сессию и затёр ключи; закрытие после его завершения
            // безопасно
            assertTrue(
                    server.isClosed(), "владелец должен остановить сессию при обрыве транспорта");
            assertDoesNotThrow(
                    server::close, "close() после остановки сессии должен быть безопасен");
            assertDoesNotThrow(server::close, "повторный close() должен быть безопасен");
        } finally {
            TlsSessionConnection.stopHandshakeThreads(exec);
        }
    }

    @Test
    @DisplayName("Handshake: KU без digitalSignature -> ошибка")
    void testHandshakeKuWithoutDigitalSignature() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(
                        params,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x20},
                        null);
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        tp.getServerTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(
                                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                                        TrustAnchors.ofCertificate(bundle.cert))
                                .withoutHostnameVerification(),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();

        try {
            cf.get(10, TimeUnit.SECONDS);
            fail("Клиентский handshake должен провалиться при KU без digitalSignature");
        } catch (ExecutionException e) {
            assertTrue(
                    e.getCause() instanceof TlsException,
                    "Ожидается TlsException: " + e.getCause().getMessage());
        }
        TlsSessionConnection.stopHandshakeThreads(exec, sf);
        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: EKU без serverAuth -> ошибка")
    void testHandshakeEkuWithoutServerAuth() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(
                        params,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x80},
                        new String[] {"1.3.6.1.5.5.7.3.3"});
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        tp.getServerTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(
                                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                                        TrustAnchors.ofCertificate(bundle.cert))
                                .withoutHostnameVerification(),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();

        try {
            cf.get(10, TimeUnit.SECONDS);
            fail("Клиентский handshake должен провалиться при EKU без serverAuth");
        } catch (ExecutionException e) {
            assertTrue(
                    e.getCause() instanceof TlsException,
                    "Ожидается TlsException: " + e.getCause().getMessage());
        }
        TlsSessionConnection.stopHandshakeThreads(exec, sf);
        server.close();
        client.close();
    }

    // =======================================================================
    // Тесты отправки alert
    // =======================================================================

    @Test
    @DisplayName("Неверный ClientHello: decode_error (checkBounds)")
    void testAlertOnTamperedClientHello() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        PkixCertTestHelper.CertBundle bundle = PkixCertTestHelper.createCertWithKey(params);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        tp.getServerTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);

        // Неверный ClientHello: заголовок верный, тело слишком короткое
        byte[] handshakeFrame = new byte[] {0x01, 0x00, 0x00, 0x02, 0x03, 0x03};
        byte[] record = new byte[5 + handshakeFrame.length];
        record[0] = TlsConstants.CT_HANDSHAKE;
        record[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        record[2] = TlsConstants.LEGACY_VERSION_MINOR;
        record[3] = (byte) (handshakeFrame.length >>> 8);
        record[4] = (byte) handshakeFrame.length;
        System.arraycopy(handshakeFrame, 0, record, 5, handshakeFrame.length);
        tp.getClientToServerQueue().add(record);

        ExecutorService exec = Executors.newSingleThreadExecutor();
        Future<Void> sf =
                exec.submit(
                        () -> {
                            server.handshakeAsServer();
                            return null;
                        });

        try {
            sf.get(10, TimeUnit.SECONDS);
            fail("Серверный handshake должен провалиться");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            assertInstanceOf(TlsException.class, cause);
            assertEquals(TlsConstants.ALERT_DECODE_ERROR, ((TlsException) cause).getAlertCode());
        }

        // Проверяем plaintext alert: writerRecord == null, so alert is not encrypted
        byte[] alertRecord = tp.getServerToClientQueue().poll(1, TimeUnit.SECONDS);
        assertNotNull(alertRecord, "Alert record должен быть в s2c");
        assertArrayEquals(
                new byte[] {
                    TlsConstants.CT_ALERT,
                    TlsConstants.LEGACY_VERSION_MAJOR,
                    TlsConstants.LEGACY_VERSION_MINOR,
                    0,
                    2,
                    TlsConstants.ALERT_FATAL,
                    TlsConstants.ALERT_DECODE_ERROR
                },
                alertRecord,
                "Plaintext alert: FATAL + DECODE_ERROR");

        exec.shutdown();
        server.close();
    }

    @Test
    @DisplayName("Успешный handshake: алерты не отправляются")
    void testAlertNotSentOnSuccessfulHandshake() throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());

        TlsSession server =
                TlsSession.createServer(
                        tp.getServerTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(
                        tp.getClientTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        null,
                        null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);

        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();

        assertTrue(client.isHandshakeDone());
        assertTrue(server.isHandshakeDone());

        // Ни в одной очереди не должно быть алертов
        byte[] record;
        while ((record = tp.getClientToServerQueue().poll()) != null) {
            assertNotEquals(
                    TlsConstants.CT_ALERT, record[0] & 0xFF, "c2s не должен содержать алертов");
        }
        while ((record = tp.getServerToClientQueue().poll()) != null) {
            assertNotEquals(
                    TlsConstants.CT_ALERT, record[0] & 0xFF, "s2c не должен содержать алертов");
        }

        server.close();
        client.close();
    }

    // =======================================================================
    // Проверка цепочки сертификатов (checkServerCertificateChain)
    // =======================================================================

    @Test
    @DisplayName("checkServerCertificateChain: валидная цепочка [leaf, rootCA]")
    void testCheckServerCertificateChainValid() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        noopTransport());

        // Не должно бросить исключение
        session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert));
    }

    @Test
    @DisplayName(
            "checkServerCertificateChain: не-CA верхний сертификат подменяет сервер -> BAD_CERTIFICATE")
    void testCheckServerCertificateChainNonCaTopRejected() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle attackerEe =
                createIntermediateNoCA(root, new byte[] {(byte) 0x80});
        PkixCertTestHelper.CertBundle forgedLeaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        attackerEe.priv,
                        attackerEe.cert.getPublicKey(),
                        attackerEe.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"bank.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("bank.example.com"),
                        noopTransport());

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                session.checkServerCertificateChain(
                                        Arrays.asList(forgedLeaf.cert, attackerEe.cert)));
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
        assertTrue(
                ex.getMessage() != null && ex.getMessage().contains("is not a CA"),
                "ожидалась причина NOT_CA, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("checkServerCertificateChain: одиночный leaf, выпущенный якорем -> успех")
    void testCheckServerCertificateChainSingleLeafIssuedByAnchor() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(root);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        noopTransport());

        session.checkServerCertificateChain(Arrays.asList(leaf.cert));
    }

    @Test
    @DisplayName("checkServerCertificateChain: закреплённый промежуточный якорь -> успех")
    void testCheckServerCertificateChainPinnedIntermediate() throws Exception {
        PkixCertTestHelper.CertBundle externalRoot = createRoot();
        PkixCertTestHelper.CertBundle pinnedIntermediate =
                createIntermediate(externalRoot, 0, new byte[] {(byte) 0x04});
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(pinnedIntermediate);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(
                                        getCsL(),
                                        TrustAnchors.ofCertificate(pinnedIntermediate.cert))
                                .withServerHostname("gost.example.com"),
                        noopTransport());

        session.checkServerCertificateChain(Arrays.asList(leaf.cert, pinnedIntermediate.cert));
    }

    @Test
    @DisplayName("checkServerCertificateChain: чужая CA -> ошибка")
    void testCheckServerCertificateChainWrongCA() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        PkixCertTestHelper.CertBundle wrongRoot =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(wrongRoot.cert))
                                .withServerHostname("gost.example.com"),
                        noopTransport());

        TlsException ex =
                assertThrows(
                        TlsException.class,
                        () ->
                                session.checkServerCertificateChain(
                                        Arrays.asList(leaf.cert, root.cert)));
        assertEquals(
                TlsConstants.ALERT_UNKNOWN_CA,
                ex.getAlertCode(),
                "корень цепочки не подписан ни одним доверенным якорем");
    }

    @Test
    @DisplayName("checkServerCertificateChain: OCSP стэпплинг есть -> успех")
    void testCheckServerCertificateChainOcspPresent() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        leaf.cert.setOcspResponse(
                PkixCertTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn));

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com")
                                .withRequireOcspStapling(true),
                        noopTransport());

        session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert));
    }

    @Test
    @DisplayName("checkServerCertificateChain: OCSP отсутствует -> ошибка")
    void testCheckServerCertificateChainOcspMissing() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com")
                                .withRequireOcspStapling(true),
                        noopTransport());

        assertThrows(
                TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert)));
    }

    // =======================================================================
    // Проверка цепочки клиентского сертификата (checkClientCertificateChain, mTLS)
    // =======================================================================

    @Test
    @DisplayName("checkClientCertificateChain: stapled OCSP good -> успех")
    void testCheckClientCertificateChainOcspGood() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"client.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_CLIENT_AUTH},
                        false,
                        null);
        leaf.cert.setOcspResponse(
                PkixCertTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn));

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("client.example.com"),
                        noopTransport());

        session.checkClientCertificateChain(Arrays.asList(leaf.cert, root.cert));
    }

    @Test
    @DisplayName("checkClientCertificateChain: stapled OCSP revoked -> ошибка")
    void testCheckClientCertificateChainOcspRevoked() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"client.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_CLIENT_AUTH},
                        false,
                        null);
        // Отозванный stapled-ответ обязан привести к fail-closed, симметрично серверу
        byte[] revoked =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .issuerDn(root.subjectDn)
                        .revoked("20240601120000Z")
                        .sign(root.priv);
        leaf.cert.setOcspResponse(revoked);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("client.example.com"),
                        noopTransport());

        assertThrows(
                TlsException.class,
                () -> session.checkClientCertificateChain(Arrays.asList(leaf.cert, root.cert)),
                "Отозванный клиентский сертификат должен отклоняться");
    }

    @Test
    @DisplayName("checkClientCertificateChain: без stapled OCSP -> успех (fetch вне скоупа)")
    void testCheckClientCertificateChainNoOcsp() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"client.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_CLIENT_AUTH},
                        false,
                        null);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("client.example.com"),
                        noopTransport());

        session.checkClientCertificateChain(Arrays.asList(leaf.cert, root.cert));
    }

    // =======================================================================
    // Delegated OCSP responder (checkServerCertificateChain)
    // =======================================================================

    @Test
    @DisplayName("checkServerCertificateChain: delegated OCSP responder валиден -> успех")
    void testCheckServerCertificateChainDelegatedOcspGood() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        // Delegated cert: подписан root, EKU=OCSPSigning, KU=digitalSignature
        PkixCertTestHelper.CertBundle dc =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x80},
                        new String[] {"1.3.6.1.5.5.7.3.9"},
                        false,
                        null);
        // OCSP подписан dc.priv, а не root.priv -> первичный путь упадёт
        leaf.cert.setOcspResponse(
                PkixCertTestHelper.buildOcspResponseWithDelegatedCerts(
                        leaf.cert.getSerialNumber(),
                        dc.priv,
                        dc.cert.getPublicKey(),
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "21060101120000Z",
                        new byte[][] {dc.cert.getEncoded()}));

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com")
                                .withRequireOcspStapling(true),
                        noopTransport());

        session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert));
    }

    @Test
    @DisplayName("checkServerCertificateChain: delegated OCSP wrong EKU -> ошибка")
    void testCheckServerCertificateChainDelegatedOcspWrongEku() throws Exception {
        PkixCertTestHelper.CertBundle root =
                PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        // Delegated cert: подписан root, НО EKU=serverAuth вместо OCSPSigning
        PkixCertTestHelper.CertBundle dc =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        null,
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);
        leaf.cert.setOcspResponse(
                PkixCertTestHelper.buildOcspResponseWithDelegatedCerts(
                        leaf.cert.getSerialNumber(),
                        dc.priv,
                        dc.cert.getPublicKey(),
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "21060101120000Z",
                        new byte[][] {dc.cert.getEncoded()}));

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com")
                                .withRequireOcspStapling(true),
                        noopTransport());

        assertThrows(
                TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert)));
    }

    // =======================================================================
    // 3- и 4-сертификатные цепочки (checkServerCertificateChain)
    // =======================================================================

    private static PkixCertTestHelper.CertBundle createRoot() throws Exception {
        return PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
    }

    private static PkixCertTestHelper.CertBundle createIntermediate(
            PkixCertTestHelper.CertBundle root, int pathLen, byte[] kuFlags) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                ECParameters.tc26a256(),
                root.priv,
                root.cert.getPublicKey(),
                root.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                null,
                kuFlags,
                null,
                true,
                pathLen);
    }

    private static PkixCertTestHelper.CertBundle createIntermediateNoCA(
            PkixCertTestHelper.CertBundle root, byte[] kuFlags) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                ECParameters.tc26a256(),
                root.priv,
                root.cert.getPublicKey(),
                root.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                null,
                kuFlags,
                null,
                false,
                null);
    }

    private static PkixCertTestHelper.CertBundle createServerLeaf(
            PkixCertTestHelper.CertBundle issuer) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                ECParameters.tc26a256(),
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                new String[] {"gost.example.com"},
                new byte[] {(byte) 0x80},
                new String[] {GostOids.EXT_SERVER_AUTH},
                false,
                null);
    }

    @Test
    @DisplayName("checkServerCertificateChain: валидная 3-cert цепочка [leaf, intermediate, root]")
    void testCheckServerCertificateChainValid_3Certs() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle intermediate =
                createIntermediate(root, 0, new byte[] {(byte) 0x04});
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(intermediate);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        noopTransport());

        session.checkServerCertificateChain(Arrays.asList(leaf.cert, intermediate.cert, root.cert));

        assertTrue(intermediate.cert.isCA());
        assertTrue(intermediate.cert.isKeyCertSignSet());
        assertEquals(0, intermediate.cert.getPathLen());
    }

    @Test
    @DisplayName("checkServerCertificateChain: OCSP стэпплинг в 3-cert -> успех")
    void testCheckServerCertificateChainOcspPresent_3Certs() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle intermediate =
                createIntermediate(root, 0, new byte[] {(byte) 0x04});
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(intermediate);
        leaf.cert.setOcspResponse(
                PkixCertTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(),
                        intermediate.priv,
                        intermediate.cert.getPublicKey(),
                        intermediate.subjectDn));

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com")
                                .withRequireOcspStapling(true),
                        noopTransport());

        session.checkServerCertificateChain(Arrays.asList(leaf.cert, intermediate.cert, root.cert));
    }

    @Test
    @DisplayName("checkServerCertificateChain: OCSP отсутствует в 3-cert -> ошибка")
    void testCheckServerCertificateChainOcspMissing_3Certs() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle intermediate =
                createIntermediate(root, 0, new byte[] {(byte) 0x04});
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(intermediate);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com")
                                .withRequireOcspStapling(true),
                        noopTransport());

        assertThrows(
                TlsException.class,
                () ->
                        session.checkServerCertificateChain(
                                Arrays.asList(leaf.cert, intermediate.cert, root.cert)));
    }

    @Test
    @DisplayName("проверка цепочки сертификатов: подменённый промежуточный -> ошибка подписи")
    void testCheckServerCertificateChainTamperedIntermediate() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle intermediate =
                createIntermediate(root, 0, new byte[] {(byte) 0x04});
        PkixCertTestHelper.CertBundle leaf = createServerLeaf(intermediate);

        byte[] tamperedDer = intermediate.cert.getEncoded().clone();
        tamperedDer[tamperedDer.length - 1] ^= 0x01;
        GostCertificate tampered = new GostCertificate(tamperedDer);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        noopTransport());

        assertThrows(
                TlsException.class,
                () ->
                        session.checkServerCertificateChain(
                                Arrays.asList(leaf.cert, tampered, root.cert)));
    }

    // =======================================================================
    // Handshake с 3-сертификатной цепочкой сервера
    // =======================================================================

    @Test
    @DisplayName("validateChain: DN mismatch между issuer и subject -> ALERT_BAD_CERTIFICATE")
    void testChainValidationDnMismatch() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        byte[] wrongIssuer = PkixCertTestHelper.buildDN("Wrong Issuer");
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertWithForcedIssuer(
                        ECParameters.tc26a256(),
                        root.priv,
                        wrongIssuer,
                        "Test Leaf",
                        "20240501120000Z",
                        "21060101120000Z");

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        noopTransport());

        assertThrows(
                TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert)));
    }

    // =======================================================================
    // mTLS handshake с аутентификацией клиента
    // =======================================================================

    private static PkixCertTestHelper.CertBundle createClientLeaf(
            PkixCertTestHelper.CertBundle issuer) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                ECParameters.tc26a256(),
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                null,
                new byte[] {(byte) 0x80},
                new String[] {GostOids.EXT_CLIENT_AUTH},
                false,
                null);
    }

    private static PkixCertTestHelper.CertBundle createClientLeafNoEku(
            PkixCertTestHelper.CertBundle issuer) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                ECParameters.tc26a256(),
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "20240501120000Z",
                "21060101120000Z",
                null,
                new byte[] {(byte) 0x80},
                new String[] {"1.3.6.1.5.5.7.3.3"},
                false,
                null);
    }

    private static PkixCertTestHelper.CertBundle createExpiredClientLeaf(
            PkixCertTestHelper.CertBundle issuer) throws Exception {
        return PkixCertTestHelper.createCertSignedBy(
                ECParameters.tc26a256(),
                issuer.priv,
                issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "20010101120000Z",
                "20020101120000Z",
                null,
                new byte[] {(byte) 0x80},
                new String[] {GostOids.EXT_CLIENT_AUTH},
                false,
                null);
    }

    @Test
    @DisplayName("mTLS handshake: базовая проверка (CR, client cert+CV)")
    void testMtlsHandshakeBasic() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle clientLeaf = createClientLeaf(root);
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);

        assertTrue(client.isHandshakeDone(), "mTLS handshake должен пройти");
        exec.shutdown();
        server.close();
        client.close();
    }

    @Test
    @DisplayName("mTLS handshake: истёкший client cert -> ALERT_CERTIFICATE_EXPIRED")
    void testMtlsHandshakeClientCertExpired() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle clientLeaf = createExpiredClientLeaf(root);
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        ExecutionException ex =
                assertThrows(ExecutionException.class, () -> sf.get(15, TimeUnit.SECONDS));
        assertInstanceOf(TlsException.class, ex.getCause());
        assertEquals(
                TlsConstants.ALERT_CERTIFICATE_EXPIRED,
                ((TlsException) ex.getCause()).getAlertCode());
        exec.shutdown();
    }

    @Test
    @DisplayName("mTLS handshake: client cert с другой CA -> ALERT_UNKNOWN_CA")
    void testMtlsHandshakeWrongClientCa() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle wrongRoot = createRoot();
        PkixCertTestHelper.CertBundle clientLeaf = createClientLeaf(wrongRoot);
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        ExecutionException ex =
                assertThrows(ExecutionException.class, () -> sf.get(15, TimeUnit.SECONDS));
        assertInstanceOf(TlsException.class, ex.getCause());
        assertEquals(TlsConstants.ALERT_UNKNOWN_CA, ((TlsException) ex.getCause()).getAlertCode());
        exec.shutdown();
    }

    @Test
    @DisplayName("mTLS handshake: client cert без clientAuth EKU -> ALERT_BAD_CERTIFICATE")
    void testMtlsHandshakeClientEkuMissing() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle clientLeaf = createClientLeafNoEku(root);
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        ExecutionException ex =
                assertThrows(ExecutionException.class, () -> sf.get(15, TimeUnit.SECONDS));
        assertInstanceOf(TlsException.class, ex.getCause());
        assertEquals(
                TlsConstants.ALERT_BAD_CERTIFICATE, ((TlsException) ex.getCause()).getAlertCode());
        exec.shutdown();
    }

    @Test
    @DisplayName("mTLS handshake: client cert с 3-cert цепочкой [leaf, intermediate, root]")
    void testMtlsHandshake3CertClientChain() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle intermediate =
                createIntermediate(root, 0, new byte[] {(byte) 0x04});
        PkixCertTestHelper.CertBundle clientLeaf = createClientLeaf(intermediate);
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(
                                        Arrays.asList(
                                                clientLeaf.cert, intermediate.cert, root.cert))
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);

        assertTrue(client.isHandshakeDone(), "mTLS с 3-cert клиентской цепочкой должен пройти");
        exec.shutdown();
        server.close();
        client.close();
    }

    @Test
    @DisplayName("mTLS handshake: server cert с 3-cert цепочкой + mTLS")
    void testMtlsHandshake3CertServerChain() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle intermediate =
                createIntermediate(root, 0, new byte[] {(byte) 0x04});
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(intermediate);
        PkixCertTestHelper.CertBundle clientLeaf = createClientLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Arrays.asList(
                                                serverLeaf.cert, intermediate.cert, root.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);

        assertTrue(client.isHandshakeDone(), "mTLS с 3-cert серверной цепочкой должен пройти");
        exec.shutdown();
        server.close();
        client.close();
    }

    @Test
    @DisplayName("mTLS backward compat: server не запрашивает mTLS, client имеет сертификат")
    void testHandshakeBackwardCompatNoMtls() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle clientLeaf = createClientLeaf(root);
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);

        assertTrue(client.isHandshakeDone(), "Backward compat handshake должен пройти");
        exec.shutdown();
        server.close();
        client.close();
    }

    @Test
    @DisplayName("mTLS: клиент без сертификата -> пустой certificate_list, сервер reject (need)")
    void testMtlsClientWithoutCert() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();

        // RFC 8446 §4.4.2: клиент без сертификата отправляет пустой certificate_list.
        // Сервер с needClientAuth=true отвергает пустой сертификат.
        cf.get(15, TimeUnit.SECONDS); // клиент завершил отправку пустого Certificate + Finished

        ExecutionException sex =
                assertThrows(ExecutionException.class, () -> sf.get(5, TimeUnit.SECONDS));
        assertInstanceOf(TlsException.class, sex.getCause());
        assertEquals(
                TlsConstants.ALERT_CERTIFICATE_REQUIRED,
                ((TlsException) sex.getCause()).getAlertCode());

        exec.shutdown();
        server.close();
        client.close();
    }

    /**
     * Запускает handshake клиента и сервера параллельно и возвращает ошибку сервера
     * (null, если он завершился успешно). Клиент в этих сценариях всегда завершает свою
     * часть: проверка клиентского сертификата происходит на сервере.
     */
    private static Throwable runMtlsPair(TlsSession server, TlsSession client) throws Exception {
        ExecutorService exec = Executors.newFixedThreadPool(2);
        try {
            Phaser phaser = new Phaser(3);
            Future<Void> cf =
                    exec.submit(
                            () -> {
                                phaser.arriveAndAwaitAdvance();
                                client.handshakeAsClient();
                                return null;
                            });
            Future<Void> sf =
                    exec.submit(
                            () -> {
                                phaser.arriveAndAwaitAdvance();
                                server.handshakeAsServer();
                                return null;
                            });
            phaser.arriveAndAwaitAdvance();
            cf.get(15, TimeUnit.SECONDS);
            try {
                sf.get(15, TimeUnit.SECONDS);
                return null;
            } catch (ExecutionException e) {
                return e.getCause();
            }
        } finally {
            exec.shutdown();
        }
    }

    private static TlsSession wantServer(
            PkixCertTestHelper.CertBundle root,
            PkixCertTestHelper.CertBundle serverLeaf,
            InMemoryTlsTransport.Pair tp) {
        return TlsSession.createServer(
                new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv)
                        .wantClientAuth(TrustAnchors.ofCertificate(root.cert)),
                tp.getServerTransport());
    }

    @Test
    @DisplayName(
            "wantClientAuth: клиент без сертификата -> handshake успешен, hasPeerCertificate() == false")
    void testWantClientAuthWithoutCert() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = wantServer(root, serverLeaf, tp);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        assertNull(runMtlsPair(server, client), "WANT не должен отвергать клиента без сертификата");

        assertTrue(server.isHandshakeDone(), "handshake на сервере должен завершиться");
        assertFalse(
                server.hasPeerCertificate(),
                "Клиент не предъявил сертификат: признак должен быть false");
        server.close();
        client.close();
    }

    @Test
    @DisplayName("wantClientAuth: клиент с валидным сертификатом -> hasPeerCertificate() == true")
    void testWantClientAuthWithValidCert() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle clientLeaf = createClientLeaf(root);
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = wantServer(root, serverLeaf, tp);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        assertNull(runMtlsPair(server, client), "Валидный сертификат должен приниматься");

        assertTrue(server.hasPeerCertificate(), "Сертификат предъявлен и проверен");
        server.close();
        client.close();
    }

    @Test
    @DisplayName("wantClientAuth: предъявленный истёкший сертификат -> ALERT_CERTIFICATE_EXPIRED")
    void testWantClientAuthExpiredCertRejected() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle clientLeaf = createExpiredClientLeaf(root);
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = wantServer(root, serverLeaf, tp);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        Throwable failure = runMtlsPair(server, client);

        assertInstanceOf(
                TlsException.class,
                failure,
                "WANT не должен ослаблять проверку предъявленного сертификата");
        assertEquals(
                TlsConstants.ALERT_CERTIFICATE_EXPIRED, ((TlsException) failure).getAlertCode());
        assertFalse(server.hasPeerCertificate(), "Отвергнутый сертификат не считается принятым");
        server.close();
        client.close();
    }

    @Test
    @DisplayName("needClientAuth: после успешного handshake hasPeerCertificate() == true")
    void testNeedClientAuthHasPeerCertificate() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle clientLeaf = createClientLeaf(root);
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        assertNull(runMtlsPair(server, client), "NEED с валидным сертификатом должен проходить");

        assertTrue(server.hasPeerCertificate(), "Сертификат клиента предъявлен и проверен");
        server.close();
        client.close();
    }

    // =======================================================================
    // NewSessionTicket / PskStore / post-handshake
    // =======================================================================

    @Test
    @DisplayName("NewSessionTicket: обратимость построение -> разбор")
    void testNewSessionTicketRoundtrip() throws Exception {
        byte[] ticketNonce = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] ticket = new byte[] {0x10, 0x20, 0x30, 0x40};

        byte[] body = TlsMessageBuilder.buildNewSessionTicket(7200, 12345, ticketNonce, ticket);
        TlsMessageParser.ParsedNewSessionTicket parsed =
                TlsMessageParser.parseNewSessionTicket(body);

        assertEquals(7200, parsed.ticketLifetime);
        assertEquals(12345, parsed.ticketAgeAdd);
        assertArrayEquals(ticketNonce, parsed.ticketNonce);
        assertArrayEquals(ticket, parsed.ticket);
    }

    @Test
    @DisplayName("PskStore: onTicketReceived с RuntimeException на клиенте — NST не ломает read()")
    void testPskStoreOnTicketReceivedThrowing_ClientSide() throws Exception {
        PskStore throwingStore =
                new PskStore() {
                    @Override
                    public PskEntry get(byte[] ticket) {
                        return null;
                    }

                    @Override
                    public PskEntry getForResumption(PskBinding binding) {
                        return null;
                    }

                    @Override
                    public PskEntry peek(byte[] ticket) {
                        return null;
                    }

                    @Override
                    public void remove(byte[] ticket) {}

                    @Override
                    public int size() {
                        return 0;
                    }

                    @Override
                    public void evictExpired() {}

                    @Override
                    public void clear() {}

                    @Override
                    public void onTicketReceived(PskEntry entry) {
                        throw new RuntimeException("Серверная часть недоступна");
                    }
                };

        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(), Collections.singletonList(bundle.cert), bundle.priv),
                        pair.getServerTransport());

        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(bundle.cert))
                                .withoutHostnameVerification(),
                        pair.getClientTransport());
        // Клиентский store кидает при сохранении NST — это не должно ломать read()
        client.setPskStore(throwingStore);

        ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            Future<Void> sf =
                    exec.submit(
                            () -> {
                                server.handshakeAsServer();
                                return null;
                            });
            client.handshakeAsClient();
            sf.get(15, TimeUnit.SECONDS);

            // Server handshake отправил NST автоматически. Клиент в первом read()
            // обработает NST (вызовет throwingStore.onTicketReceived -> RuntimeException),
            // после чего прочитает application data.
            byte[] payload = "data after NST".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            server.write(payload);
            byte[] data = client.read();
            assertArrayEquals(payload, data);
        } finally {
            exec.shutdown();
            try {
                exec.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
            }
            server.close();
            client.close();
        }
    }

    @Test
    @DisplayName("read: NewSessionTicket -> сохраняется в PskStore")
    void testReadNewSessionTicket() throws Exception {
        TlsTrafficKeys keys = randomTrafficKeys();
        PskStore store = new InMemoryPskStore(100);
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsRecord writer =
                new TlsRecord(keys.getKey(), keys.getIv(), getCsL().getTagLen(), getCsL());
        TlsSession client = TlsSession.createForTest(transport, getCsL(), keys, keys);
        client.setPskStore(store);

        byte[] ticketNonce = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] ticket = new byte[] {0x10, 0x20, 0x30, 0x40};
        byte[] nstBody = TlsMessageBuilder.buildNewSessionTicket(7200, 12345, ticketNonce, ticket);
        byte[] nstFramed =
                new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, nstBody).encode();
        byte[] nstRecord = writer.protect(TlsConstants.CT_HANDSHAKE, nstFramed);

        byte[] appRecord = writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {0x41});

        transport.inject(nstRecord);
        transport.inject(appRecord);

        byte[] result = client.read();
        assertArrayEquals(new byte[] {0x41}, result);

        PskEntry entry = store.get(ticket);
        assertNotNull(entry);
        assertEquals(7200, entry.getTicketLifetime());
        assertEquals(12345, entry.getTicketAgeAdd());
        assertArrayEquals(ticketNonce, entry.getTicketNonce());
    }

    @Test
    @DisplayName("handshake + NewSessionTicket -> ticketAgeAdd случайный (не 0, не константа)")
    void testHandshakeWithNewSessionTicketAgeAddRandom() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);

        long t1 = handshakeAndGetAge(root, serverLeaf);
        long t2 = handshakeAndGetAge(root, serverLeaf);

        assertNotEquals(0, t1);
        assertNotEquals(t1, t2);
    }

    /** Привязка клиента в режиме «цепочка и имя» с одним якорем (как у createClient в тестах). */
    private static PskBinding clientBinding(GostCertificate anchor, String hostname) {
        return PskBindingFactory.forClient(
                hostname,
                true,
                false,
                TrustAnchors.ofCertificate(anchor),
                false,
                false,
                getCsL().getKdfHashAlgorithm());
    }

    private long handshakeAndGetAge(
            PkixCertTestHelper.CertBundle root, PkixCertTestHelper.CertBundle serverLeaf)
            throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        PskStore store = new InMemoryPskStore(100);

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());
        client.setPskStore(store);
        // Сервер выдаёт тикеты только при заданном хранилище
        server.setPskStore(new InMemoryPskStore(100));

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);

        server.close();
        assertThrows(EOFException.class, () -> client.read());
        client.close();
        exec.shutdown();

        assertEquals(1, store.size(), "должен быть ровно один тикет");
        return store.getForResumption(clientBinding(root.cert, "gost.example.com"))
                .getTicketAgeAdd();
    }

    // =======================================================================
    // Обработка алертов в read()
    // =======================================================================

    private static TlsTrafficKeys randomTrafficKeys() {
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(iv);
        return new TlsTrafficKeys(key, iv);
    }

    @Test
    @DisplayName("разбор alert пира: close_notify -> PeerClosedException")
    void testAlertFromPeerCloseNotify() {
        assertInstanceOf(PeerClosedException.class, TlsSession.alertFromPeer(new byte[] {1, 0}));
    }

    @Test
    @DisplayName("разбор alert пира: bad_certificate -> fatal alert пира с кодом 42")
    void testAlertFromPeerFatal() {
        TlsException error =
                assertInstanceOf(TlsException.class, TlsSession.alertFromPeer(new byte[] {2, 42}));
        assertTrue(error.isFromPeer(), "Fatal alert пришёл от пира");
        assertEquals(42, error.getAlertCode());
    }

    @Test
    @DisplayName("разбор alert пира: пустое тело -> unexpected_message (RFC 8446 §5.4)")
    void testAlertFromPeerEmpty() {
        TlsException error =
                assertInstanceOf(TlsException.class, TlsSession.alertFromPeer(new byte[0]));
        assertFalse(error.isFromPeer(), "Нарушение формата найдено локально");
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode());
    }

    @Test
    @DisplayName("разбор alert пира: 1 байт и 3 байта -> decode_error")
    void testAlertFromPeerWrongLength() {
        for (byte[] body : new byte[][] {{1}, {2, 40, 2}}) {
            TlsException error =
                    assertInstanceOf(TlsException.class, TlsSession.alertFromPeer(body));
            assertEquals(
                    TlsConstants.ALERT_DECODE_ERROR,
                    error.getAlertCode(),
                    "Длина " + body.length + " недопустима");
        }
    }

    @Test
    @DisplayName("read: close_notify от пира -> EOFException")
    void testReadCloseNotify() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsSession server = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        TlsRecord clientRecord =
                new TlsRecord(
                        readerKeys.getKey(), readerKeys.getIv(), getCsL().getTagLen(), getCsL());
        byte[] alertRecord =
                clientRecord.protect(
                        TlsConstants.CT_ALERT,
                        new byte[] {TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY});
        transport.inject(alertRecord);

        assertThrows(EOFException.class, server::read);
        assertTrue(server.isClosed());
        assertFalse(server.isHandshakeDone());
        assertThrows(IllegalStateException.class, server::read);
    }

    @Test
    @DisplayName("read: fatal alert от пира -> IOException")
    void testReadFatalAlert() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsSession server = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        TlsRecord clientRecord =
                new TlsRecord(
                        readerKeys.getKey(), readerKeys.getIv(), getCsL().getTagLen(), getCsL());
        byte[] alertRecord =
                clientRecord.protect(
                        TlsConstants.CT_ALERT,
                        new byte[] {TlsConstants.ALERT_FATAL, TlsConstants.ALERT_BAD_CERTIFICATE});
        transport.inject(alertRecord);

        IOException ex = assertThrows(IOException.class, server::read);
        assertTrue(ex.getMessage().contains("42"));
        assertTrue(server.isClosed());
        assertFalse(server.isHandshakeDone());
        assertThrows(IllegalStateException.class, server::read);
    }

    @Test
    @DisplayName("read: user_canceled -> трактуется как fatal")
    void testReadUserCanceled() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsSession server = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        TlsRecord clientRecord =
                new TlsRecord(
                        readerKeys.getKey(), readerKeys.getIv(), getCsL().getTagLen(), getCsL());
        byte[] alertRecord =
                clientRecord.protect(
                        TlsConstants.CT_ALERT, new byte[] {TlsConstants.ALERT_WARNING, (byte) 90});
        transport.inject(alertRecord);

        IOException ex = assertThrows(IOException.class, server::read);
        assertTrue(ex.getMessage().contains("90"));
        assertTrue(server.isClosed());
    }

    // =======================================================================
    // Фрагментация TLS-записей (RFC 8446 §5.1)
    // =======================================================================

    @Test
    @DisplayName("write: данные >16383 -> фрагментируются на несколько записей")
    void testWriteLargeDataFragment() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        LinkedBlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>();
        TlsTransport transport =
                new TlsTransport() {
                    public void sendRecord(byte[] r) {
                        outbound.add(r);
                    }

                    public byte[] receiveRecord() throws IOException {
                        try {
                            return outbound.poll(10, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            throw new IOException(e);
                        }
                    }

                    public void close() {}
                };
        TlsSession session = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        byte[] largeData = new byte[32000];
        CryptoRandom.INSTANCE.nextBytes(largeData);
        session.write(largeData);

        TlsRecord reader =
                new TlsRecord(
                        writerKeys.getKey(), writerKeys.getIv(), getCsL().getTagLen(), getCsL());
        int total = 0;
        int count = 0;
        while (!outbound.isEmpty()) {
            byte[] record = outbound.poll();
            assertNotNull(record);
            TlsParsedRecord parsed = reader.unprotect(record);
            assertEquals(TlsConstants.CT_APPLICATION_DATA, parsed.getContentType());
            total += parsed.getData().length;
            count++;
        }
        assertEquals(32000, total);
        assertEquals(2, count);
    }

    @Test
    @DisplayName("write: данные ≤16383 -> одна запись (регрессия)")
    void testWriteSmallDataNoFragment() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        LinkedBlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>();
        TlsTransport transport =
                new TlsTransport() {
                    public void sendRecord(byte[] r) {
                        outbound.add(r);
                    }

                    public byte[] receiveRecord() throws IOException {
                        try {
                            return outbound.poll(10, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            throw new IOException(e);
                        }
                    }

                    public void close() {}
                };
        TlsSession session = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        session.write(new byte[100]);
        assertEquals(1, outbound.size());
    }

    private static TlsTransport noopTransport() {
        return new TlsTransport() {
            public void sendRecord(byte[] record) {}

            public byte[] receiveRecord() {
                return new byte[0];
            }

            public void close() {}
        };
    }

    private static TlsCiphersuite getCsL() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    // =======================================================================
    // Утилиты для тестов
    // =======================================================================

    // =======================================================================
    // PSK session resumption
    // =======================================================================

    @Test
    @DisplayName("PSK resumption: mTLS-сервер не принимает тикет и не выдаёт новый")
    void testPskResumptionRefusedForMtls() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle clientLeaf = createClientLeaf(root);
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        PskStore clientStore = new InMemoryPskStore(100);
        PskStore serverStore = new InMemoryPskStore(100);

        // 1-й handshake без mTLS — получаем валидный тикет в обоих сторах.
        var tp1 = InMemoryTlsTransport.newPair();
        TlsSession server1 =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp1.getServerTransport());
        TlsSession client1 =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp1.getClientTransport());
        client1.setPskStore(clientStore);
        server1.setPskStore(serverStore);

        ExecutorService exec = Executors.newFixedThreadPool(2);
        Phaser phaser1 = new Phaser(3);
        Future<Void> cf1 =
                exec.submit(
                        () -> {
                            phaser1.arriveAndAwaitAdvance();
                            client1.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf1 =
                exec.submit(
                        () -> {
                            phaser1.arriveAndAwaitAdvance();
                            server1.handshakeAsServer();
                            return null;
                        });
        phaser1.arriveAndAwaitAdvance();
        cf1.get(15, TimeUnit.SECONDS);
        sf1.get(15, TimeUnit.SECONDS);
        server1.close();
        assertThrows(EOFException.class, () -> client1.read());
        assertEquals(1, clientStore.size(), "Клиент должен получить тикет");
        assertEquals(1, serverStore.size(), "Сервер должен сохранить тикет");
        client1.close();

        // 2-й handshake с mTLS и тем же тикетом: PSK должен быть проигнорирован.
        var tp2 = InMemoryTlsTransport.newPair();
        TlsSession server2 =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert)),
                        tp2.getServerTransport());
        TlsSession client2 =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv)
                                .withServerHostname("gost.example.com"),
                        tp2.getClientTransport());
        client2.setPskStore(clientStore);
        server2.setPskStore(serverStore);

        Phaser phaser2 = new Phaser(3);
        Future<Void> cf2 =
                exec.submit(
                        () -> {
                            phaser2.arriveAndAwaitAdvance();
                            client2.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf2 =
                exec.submit(
                        () -> {
                            phaser2.arriveAndAwaitAdvance();
                            server2.handshakeAsServer();
                            return null;
                        });
        phaser2.arriveAndAwaitAdvance();
        cf2.get(15, TimeUnit.SECONDS);
        sf2.get(15, TimeUnit.SECONDS);

        assertTrue(client2.isHandshakeDone());
        assertFalse(client2.wasResumed(), "mTLS не должен возобновляться по PSK");
        assertEquals(1, serverStore.size(), "Тикет не должен потребляться при mTLS");
        assertEquals(1, clientStore.size(), "Сервер не должен выдавать тикет при mTLS");
        assertNotNull(
                server2.getPeerCertificates(), "Сервер должен проверить клиентский сертификат");

        server2.close();
        client2.close();
        exec.shutdown();
    }

    @Test
    @DisplayName("PSK fallback: неизвестный тикет -> полный handshake")
    void testPskFallbackUnknownTicket() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();
        PskStore clientStore = new InMemoryPskStore(100);
        PskStore serverStore = new InMemoryPskStore(100);

        // Добавляем в clientStore тикет, которого нет в serverStore
        byte[] fakeTicket = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(fakeTicket);
        clientStore.onTicketReceived(
                new PskEntry(
                        fakeTicket,
                        86400,
                        CryptoRandom.INSTANCE.nextInt() & 0xFFFFFFFFL,
                        new byte[8],
                        new byte[32],
                        System.currentTimeMillis(),
                        PskBinding.forServer(null),
                        PskEntry.NO_CERTIFICATE_BOUND));

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp.getServerTransport());
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());
        client.setPskStore(clientStore);
        server.setPskStore(serverStore);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);

        assertTrue(client.isHandshakeDone(), "Handshake с PSK fallback должен пройти");
        assertTrue(server.isHandshakeDone());

        // Проверяем передачу данных (полный handshake отработал)
        byte[] testData = new byte[] {0x0A, 0x0B};
        client.write(testData);
        byte[] received = server.read();
        assertArrayEquals(testData, received);

        server.close();
        client.close();
        exec.shutdown();
    }

    @Test
    @DisplayName("PSK resumption: obfuscated_ticket_age на wire = ageMs + ticketAgeAdd")
    void testPskResumptionObfuscatedTicketAgeOnWire() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();
        PskStore clientStore = new InMemoryPskStore(100);
        PskStore serverStore = new InMemoryPskStore(100);

        // 1-й handshake — получаем тикет
        TlsSession server1 =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp.getServerTransport());
        TlsSession client1 =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());
        client1.setPskStore(clientStore);
        server1.setPskStore(serverStore);

        Phaser phaser1 = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(3);
        Future<Void> cf1 =
                exec.submit(
                        () -> {
                            phaser1.arriveAndAwaitAdvance();
                            client1.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf1 =
                exec.submit(
                        () -> {
                            phaser1.arriveAndAwaitAdvance();
                            server1.handshakeAsServer();
                            return null;
                        });
        phaser1.arriveAndAwaitAdvance();
        cf1.get(15, TimeUnit.SECONDS);
        sf1.get(15, TimeUnit.SECONDS);
        assertTrue(client1.isHandshakeDone());
        server1.close();
        assertThrows(EOFException.class, () -> client1.read());
        assertEquals(1, clientStore.size(), "Клиент должен получить NewSessionTicket");

        // Возраст тикета задаётся сдвигом времени выдачи, а не ожиданием: результат не зависит от
        // скорости потоков. Сдвиг меньше допуска сервера на расхождение возраста (60 с)
        PskEntry entry = clientStore.getForResumption(clientBinding(root.cert, "gost.example.com"));
        long ticketAgeAdd = entry.getTicketAgeAdd();
        long ageMs = 30_000;
        clientStore.onTicketReceived(
                new PskEntry(
                        entry.getTicket(),
                        entry.getTicketLifetime(),
                        ticketAgeAdd,
                        entry.getTicketNonce(),
                        entry.getPsk(),
                        entry.getIssueTime() - ageMs,
                        entry.getBinding(),
                        entry.getValidUntil()));

        // 2-й handshake — перехватываем ClientHello из c2s до сервера
        var tp2 = InMemoryTlsTransport.newPair();
        TlsSession client2 =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp2.getClientTransport());
        client2.setPskStore(clientStore);
        TlsSession server2 =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp2.getServerTransport());
        server2.setPskStore(serverStore);

        // Запускаем клиент — он отправит ClientHello и встанет в ожидании ServerHello
        Future<Void> cf2 =
                exec.submit(
                        () -> {
                            client2.handshakeAsClient();
                            return null;
                        });

        // Перехватываем ClientHello без удаления из очереди (peek)
        LinkedBlockingQueue<byte[]> c2s = tp2.getClientToServerQueue();
        byte[] chRecord = null;
        for (int i = 0; i < 100; i++) {
            chRecord = c2s.peek();
            if (chRecord != null) break;
            Thread.sleep(5);
        }
        assertNotNull(chRecord, "ClientHello не появился в c2s очереди");

        // Парсим obfuscatedTicketAge из ClientHello (ad-hoc, без расширения парсера)
        byte[] chBody =
                TlsHandshakeMessage.decode(
                                Arrays.copyOfRange(
                                        chRecord, TlsConstants.RECORD_HEADER_SIZE, chRecord.length))
                        .getBody();
        long wireAge = parseObfuscatedTicketAge(chBody);

        // wireAge = (возраст + ticketAgeAdd) по модулю 2^32 (RFC 8446 §4.2.11): возраст получается
        // вычитанием ticketAgeAdd по тому же модулю. Он не меньше заданного сдвига и превышает его
        // лишь на время, прошедшее с сдвига (допуск 5 с)
        long ageOnWire = (wireAge - ticketAgeAdd) & 0xFFFFFFFFL;
        assertTrue(
                ageOnWire >= ageMs,
                "возраст в obfuscatedTicketAge меньше ожидаемого: " + ageOnWire + " < " + ageMs);
        assertTrue(
                ageOnWire <= ageMs + 5_000,
                "возраст в obfuscatedTicketAge больше ожидаемого: "
                        + ageOnWire
                        + " > "
                        + (ageMs + 5_000));

        // Запускаем сервер, завершаем handshake
        Future<Void> sf2 =
                exec.submit(
                        () -> {
                            server2.handshakeAsServer();
                            return null;
                        });
        cf2.get(15, TimeUnit.SECONDS);
        sf2.get(15, TimeUnit.SECONDS);
        assertTrue(client2.isHandshakeDone());

        server2.close();
        client2.close();
        exec.shutdown();
    }

    @Test
    @DisplayName("PSK с неверным binder -> ALERT_DECRYPT_ERROR, тикет не изъят")
    void testPskInvalidBinderKeepsTicket() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        PskStore serverStore = new InMemoryPskStore(100);

        var tp = InMemoryTlsTransport.newPair();
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());

        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp.getServerTransport());
        server.setPskStore(serverStore);

        byte[] psk = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(psk);
        byte[] ticket = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(ticket);
        long ticketAgeAdd = CryptoRandom.INSTANCE.nextInt() & 0xFFFFFFFFL;
        serverStore.onTicketReceived(
                new PskEntry(
                        ticket,
                        86400,
                        ticketAgeAdd,
                        new byte[8],
                        psk,
                        System.currentTimeMillis(),
                        PskBinding.forServer(null),
                        PskEntry.NO_CERTIFICATE_BOUND));

        ExecutorService exec = Executors.newFixedThreadPool(2);
        Phaser phaser = new Phaser(2);
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            TlsException e =
                                    assertThrows(
                                            TlsException.class,
                                            () -> {
                                                server.handshakeAsServer();
                                            });
                            assertEquals(
                                    TlsConstants.ALERT_DECRYPT_ERROR,
                                    e.getAlertCode(),
                                    "Неверный binder должен давать decrypt_error (RFC 8446 §4.2.11.2)");
                            return null;
                        });

        // Передаём ClientHello с PSK и неверным binder напрямую в очередь клиента
        byte[] ecdhePoint =
                TlsEncoding.encodePoint(
                        KeyGenerator.generateKeyPair(ECParameters.tc26a256()).getPublic());
        TlsMessageBuilder builder =
                new TlsMessageBuilder(
                        getCsL(),
                        List.of(getCsL().getId()),
                        TlsConstants.GRP_GC256A,
                        TlsConstants.SIG_GOST_TC26_A_256,
                        (PrivateKeyParameters) null,
                        (List<GostCertificate>) null,
                        32);
        byte[] chBody = builder.buildClientHelloWithPsk(ecdhePoint, ticket, ticketAgeAdd);
        chBody[chBody.length - 1] ^= 0xFF; // меняем последний байт binder
        byte[] chFramed =
                TlsMessageBuilder.buildPlaintextRecord(
                        TlsConstants.CT_HANDSHAKE,
                        new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, chBody).encode());
        tp.getClientToServerQueue().add(chFramed);

        phaser.arriveAndAwaitAdvance();
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();

        assertEquals(1, serverStore.size(), "Тикет не должен быть изъят при провале binder");
    }

    @Test
    @DisplayName("PSK resumption с HRR: тикет потребляется в CH1, CH2 повторно не изымает")
    void testPskResumptionWithHrr() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        PskStore clientStore = new InMemoryPskStore(100);
        PskStore serverStore = new InMemoryPskStore(100);

        // 1-й handshake (полный) — получаем тикет
        var tp1 = InMemoryTlsTransport.newPair();
        TlsSession server1 =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp1.getServerTransport());
        TlsSession client1 =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp1.getClientTransport());
        client1.setPskStore(clientStore);
        server1.setPskStore(serverStore);

        Phaser phaser1 = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf1 =
                exec.submit(
                        () -> {
                            phaser1.arriveAndAwaitAdvance();
                            client1.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf1 =
                exec.submit(
                        () -> {
                            phaser1.arriveAndAwaitAdvance();
                            server1.handshakeAsServer();
                            return null;
                        });
        phaser1.arriveAndAwaitAdvance();
        cf1.get(15, TimeUnit.SECONDS);
        sf1.get(15, TimeUnit.SECONDS);
        assertTrue(client1.isHandshakeDone());
        server1.close();
        assertThrows(EOFException.class, () -> client1.read());
        assertEquals(1, clientStore.size(), "Клиент получил 1 тикет");

        // 2-й handshake (PSK resumption) с HRR:
        // сервер предпочитает группу, отличную от дефолтной клиентской
        var tp2 = InMemoryTlsTransport.newPair();
        TlsSession server2 =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .withSelectedNamedGroup(TlsConstants.GRP_GC256A),
                        tp2.getServerTransport());
        server2.setPskStore(serverStore);
        TlsSession client2 =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp2.getClientTransport());
        client2.setPskStore(clientStore);

        Phaser phaser2 = new Phaser(3);
        Future<Void> cf2 =
                exec.submit(
                        () -> {
                            phaser2.arriveAndAwaitAdvance();
                            client2.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf2 =
                exec.submit(
                        () -> {
                            phaser2.arriveAndAwaitAdvance();
                            server2.handshakeAsServer();
                            return null;
                        });
        phaser2.arriveAndAwaitAdvance();
        cf2.get(15, TimeUnit.SECONDS);
        sf2.get(15, TimeUnit.SECONDS);
        assertTrue(client2.isHandshakeDone());
        assertTrue(server2.isHandshakeDone());
        assertTrue(server2.wasResumed(), "PSK должен быть принят после CH2 с пересчитанным binder");

        server2.close();
        client2.close();
        exec.shutdown();
    }

    @Test
    @DisplayName("HRR + PSK + mTLS: PSK подавлен, handshake завершается после HelloRetryRequest")
    void testHrrWithPskAndMtls() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        PkixCertTestHelper.CertBundle clientLeaf = createClientLeaf(root);
        PskStore clientStore = new InMemoryPskStore(100);
        PskStore serverStore = new InMemoryPskStore(100);

        // 1-й handshake (полный, без mTLS) — получаем тикет в общих store.
        var tp1 = InMemoryTlsTransport.newPair();
        TlsSession server1 =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp1.getServerTransport());
        TlsSession client1 =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp1.getClientTransport());
        client1.setPskStore(clientStore);
        server1.setPskStore(serverStore);

        ExecutorService exec = Executors.newFixedThreadPool(2);
        runHandshakePair(exec, client1, server1);
        assertTrue(client1.isHandshakeDone());
        assertEquals(1, serverStore.size(), "сервер должен сохранить тикет");
        // Клиент обрабатывает NewSessionTicket в read(), а не в handshake.
        server1.close();
        assertThrows(EOFException.class, client1::read);
        assertEquals(1, clientStore.size(), "клиент должен получить тикет");

        // 2-й handshake: сервер требует mTLS и предпочитает другую группу,
        // поэтому неизбежен HRR. Дефолтная группа клиента — GRP_GC256B,
        // это проверяется ниже по перехваченному CH1.
        var tp2 = InMemoryTlsTransport.newPair();
        CapturingTransport clientTransport = new CapturingTransport(tp2.getClientTransport());
        CountingPskStore countingServerStore = new CountingPskStore(serverStore);
        TlsSession server2 =
                TlsSession.createServer(
                        new TlsServerConfig(
                                        getCsL(),
                                        Collections.singletonList(serverLeaf.cert),
                                        serverLeaf.priv)
                                .needClientAuth(TrustAnchors.ofCertificate(root.cert))
                                .withSelectedNamedGroup(TlsConstants.GRP_GC256A),
                        tp2.getServerTransport());
        server2.setPskStore(countingServerStore);
        TlsSession client2 =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com")
                                .withClientCertificateChain(clientLeaf.cert)
                                .withClientPrivateKey(clientLeaf.priv),
                        clientTransport);
        client2.setPskStore(clientStore);

        runHandshakePair(exec, client2, server2);
        assertTrue(client2.isHandshakeDone());
        assertTrue(server2.isHandshakeDone());
        assertFalse(server2.wasResumed(), "mTLS должен подавлять PSK-возобновление");
        assertEquals(
                1,
                serverStore.size(),
                "тикет не потреблён и новый не выдан, поэтому остаётся один");
        assertNotNull(server2.getPeerCertificates(), "сервер должен получить сертификат клиента");
        assertEquals(1, server2.getPeerCertificates().size());
        assertArrayEquals(
                clientLeaf.cert.getEncoded(),
                server2.getPeerCertificates().get(0).getEncoded(),
                "сервер должен получить именно клиентский сертификат");

        byte[] ch1Record = clientTransport.firstSent();
        assertNotNull(ch1Record, "клиент должен отправить ClientHello");
        assertEquals((int) TlsConstants.CT_HANDSHAKE, ch1Record[0] & 0xFF);
        TlsHandshakeMessage ch1 =
                TlsHandshakeMessage.decode(
                        Arrays.copyOfRange(
                                ch1Record, TlsConstants.RECORD_HEADER_SIZE, ch1Record.length));
        assertEquals((int) TlsConstants.HT_CLIENT_HELLO, ch1.getType() & 0xFF);
        TlsMessageParser.ParsedKeyShare parsedCh =
                TlsMessageParser.parseClientHello(ch1.getBody(), TlsConstants.GRP_GC256B);
        assertEquals(
                TlsConstants.GRP_GC256B,
                parsedCh.actualGroup,
                "клиент должен явно предложить дефолтную группу GC256B");
        assertNotNull(
                TlsMessageParser.parseClientHelloPsk(
                        ch1.getBody(), TlsConstants.STREEBOG_256_HASH_LEN),
                "CH1 должен содержать pre_shared_key: иначе сценарий HRR+PSK не проверяется");
        assertEquals(
                0,
                countingServerStore.peekCalls(),
                "mTLS должен подавлять PSK-lookup: peek не должен вызываться");
        assertEquals(
                0,
                countingServerStore.getCalls(),
                "mTLS не должен потреблять PSK-тикет: get не должен вызываться");
        assertEquals(
                0,
                countingServerStore.getForResumptionCalls(),
                "сервер не должен запрашивать getForResumption");
        assertEquals(0, countingServerStore.removeCalls(), "mTLS не должен удалять PSK-тикет");
        assertEquals(
                0,
                countingServerStore.onTicketReceivedCalls(),
                "mTLS не должен записывать новый PSK-тикет");

        byte[] shRecord = clientTransport.firstReceived();
        assertNotNull(shRecord, "сервер должен ответить на ClientHello");
        assertEquals((int) TlsConstants.CT_HANDSHAKE, shRecord[0] & 0xFF);
        TlsHandshakeMessage sh =
                TlsHandshakeMessage.decode(
                        Arrays.copyOfRange(
                                shRecord, TlsConstants.RECORD_HEADER_SIZE, shRecord.length));
        assertEquals((int) TlsConstants.HT_SERVER_HELLO, sh.getType() & 0xFF);
        TlsMessageParser.ParsedServerHello parsedSh =
                TlsMessageParser.parseServerHello(sh.getBody(), SERVER_RESPONSE_TYPES_SENT);
        assertTrue(
                TlsMessageParser.isHelloRetryRequest(parsedSh),
                "первый ответ сервера должен быть HelloRetryRequest");
        assertEquals(
                TlsConstants.GRP_GC256A,
                parsedSh.requestedGroup,
                "HRR должен запрашивать группу сервера");

        server2.close();
        client2.close();
        exec.shutdown();
    }

    private static void runHandshakePair(ExecutorService exec, TlsSession client, TlsSession server)
            throws Exception {
        Phaser phaser = new Phaser(3);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);
    }

    /**
     * Обёртка транспорта, сохраняющая первую отправленную и первую принятую
     * записи. Нужна для доказательства HRR: клиентский CH1 и ответ сервера.
     */
    private static final class CapturingTransport implements TlsTransport {
        private final TlsTransport delegate;
        private final AtomicReference<byte[]> firstSent = new AtomicReference<>();
        private final AtomicReference<byte[]> firstReceived = new AtomicReference<>();

        CapturingTransport(TlsTransport delegate) {
            this.delegate = delegate;
        }

        @Override
        public void sendRecord(byte[] record) throws IOException {
            firstSent.compareAndSet(null, record.clone());
            delegate.sendRecord(record);
        }

        @Override
        public byte[] receiveRecord() throws IOException {
            byte[] record = delegate.receiveRecord();
            if (record != null) {
                firstReceived.compareAndSet(null, record.clone());
            }
            return record;
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }

        byte[] firstSent() {
            return firstSent.get();
        }

        byte[] firstReceived() {
            return firstReceived.get();
        }
    }

    /**
     * Обёртка PskStore для проверки, что mTLS вообще не обращается к PSK-store.
     * <p>
     * Считаем read- и write-операции: peek/get/remove/onTicketReceived
     * используются серверным движком, getForResumption оставлен как страховка
     * клиентского API. Нулевые счётчики доказывают, что сервер не искал,
     * не потреблял, не удалял и не записывал тикет, а не просто «не возобновил
     * сессию».
     */
    private static final class CountingPskStore implements PskStore {
        private final PskStore delegate;
        private final AtomicInteger getCount = new AtomicInteger();
        private final AtomicInteger peekCount = new AtomicInteger();
        private final AtomicInteger getForResumptionCount = new AtomicInteger();
        private final AtomicInteger removeCount = new AtomicInteger();
        private final AtomicInteger onTicketReceivedCount = new AtomicInteger();

        CountingPskStore(PskStore delegate) {
            this.delegate = delegate;
        }

        @Override
        public PskEntry get(byte[] ticket) {
            getCount.incrementAndGet();
            return delegate.get(ticket);
        }

        @Override
        public PskEntry getForResumption(PskBinding binding) {
            getForResumptionCount.incrementAndGet();
            return delegate.getForResumption(binding);
        }

        @Override
        public void remove(byte[] ticket) {
            removeCount.incrementAndGet();
            delegate.remove(ticket);
        }

        @Override
        public PskEntry peek(byte[] ticket) {
            peekCount.incrementAndGet();
            return delegate.peek(ticket);
        }

        @Override
        public int size() {
            return delegate.size();
        }

        @Override
        public void evictExpired() {
            delegate.evictExpired();
        }

        @Override
        public void clear() {
            delegate.clear();
        }

        @Override
        public void onTicketReceived(PskEntry entry) {
            onTicketReceivedCount.incrementAndGet();
            delegate.onTicketReceived(entry);
        }

        int getCalls() {
            return getCount.get();
        }

        int peekCalls() {
            return peekCount.get();
        }

        int getForResumptionCalls() {
            return getForResumptionCount.get();
        }

        int removeCalls() {
            return removeCount.get();
        }

        int onTicketReceivedCalls() {
            return onTicketReceivedCount.get();
        }
    }

    @Test
    @DisplayName(
            "PSK ticket_age mismatch > допуска: soft-fallback на полный handshake, соединение не рвётся")
    void testPskTicketAgeMismatchFallsBackToFullHandshake() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        PskStore clientStore = new InMemoryPskStore(100);
        PskStore serverStore = new InMemoryPskStore(100);

        byte[] psk = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(psk);
        byte[] ticket = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(ticket);
        byte[] nonce = new byte[8];
        CryptoRandom.INSTANCE.nextBytes(nonce);
        long ticketAgeAdd = CryptoRandom.INSTANCE.nextInt() & 0xFFFFFFFFL;

        // Клиент получает тикет с issueTime=сейчас (age ≈ 0)
        // Сервер получает тот же тикет, но issueTime на 2 минуты в прошлом
        long pastIssueTime = System.currentTimeMillis() - 120_000;
        PskEntry serverEntry =
                new PskEntry(
                        ticket,
                        86400,
                        ticketAgeAdd,
                        nonce,
                        psk,
                        pastIssueTime,
                        PskBinding.forServer(null),
                        PskEntry.NO_CERTIFICATE_BOUND);
        serverStore.onTicketReceived(serverEntry);
        PskEntry clientEntry =
                new PskEntry(
                        ticket,
                        86400,
                        ticketAgeAdd,
                        nonce,
                        psk,
                        System.currentTimeMillis(),
                        PskBinding.forServer(null),
                        PskEntry.NO_CERTIFICATE_BOUND);
        clientStore.onTicketReceived(clientEntry);

        // Сервер ожидает age ≈ 120000ms, клиент шлёт age ≈ 0ms
        // diff > PSK_AGE_TOLERANCE_MS (60s) → soft-fallback на полный handshake
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp.getServerTransport());
        server.setPskStore(serverStore);
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        tp.getClientTransport());
        client.setPskStore(clientStore);

        ExecutorService exec = Executors.newFixedThreadPool(2);
        Phaser phaser = new Phaser(3);
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        sf.get(15, TimeUnit.SECONDS);
        cf.get(15, TimeUnit.SECONDS);

        assertTrue(client.isHandshakeDone(), "Клиент должен завершить рукопожатие");
        assertTrue(server.isHandshakeDone(), "Сервер должен завершить рукопожатие");
        assertFalse(server.wasResumed(), "Сервер НЕ должен принять PSK при расхождении возраста");
        // Тикет изъят при get(), но после полного handshake сервер кладёт новый NST в store

        server.close();
        client.close();
        exec.shutdown();
    }

    @Test
    @DisplayName("Переполнение записи: payloadLen > MAX_CIPHERTEXT_LENGTH -> ALERT_RECORD_OVERFLOW")
    void testRecordOverflowAfterHandshake() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server =
                TlsSession.createServer(
                        tp.getServerTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        bundle.cert,
                        bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(
                        tp.getClientTransport(),
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                        null,
                        null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();

        assertTrue(client.isHandshakeDone());
        assertTrue(server.isHandshakeDone());

        // Inject record with payloadLen=20000 (> MAX_CIPHERTEXT_LENGTH=16640)
        byte[] overflowRecord = new byte[TlsConstants.RECORD_HEADER_SIZE + 20000];
        overflowRecord[0] = TlsConstants.CT_APPLICATION_DATA;
        overflowRecord[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        overflowRecord[2] = TlsConstants.LEGACY_VERSION_MINOR;
        overflowRecord[3] = (byte) (20000 >>> 8);
        overflowRecord[4] = (byte) 20000;

        tp.getServerToClientQueue().add(overflowRecord);

        TlsException ex = assertThrows(TlsException.class, client::read);
        assertEquals(TlsConstants.ALERT_RECORD_OVERFLOW, ex.getAlertCode());
    }

    // =======================================================================
    // MAX_POST_HANDSHAKE (anti-DoS guard)
    // =======================================================================

    // =======================================================================
    // Cipher suite negotiation
    // =======================================================================

    private static InMemoryTlsTransport clientTransportWithServerSuite(
            InMemoryTlsTransport.Pair realPair, int serverSuiteId) {
        return new InMemoryTlsTransport() {
            @Override
            public void sendRecord(byte[] record) throws IOException {
                realPair.getClientToServerQueue().add(record);
            }

            @Override
            public byte[] receiveRecord() throws IOException {
                try {
                    byte[] record = realPair.getServerToClientQueue().poll(1, TimeUnit.SECONDS);
                    if (record != null
                            && record.length > 46
                            && (record[5] & 0xFF) == TlsConstants.HT_SERVER_HELLO) {
                        byte[] modified = record.clone();
                        modified[44] = (byte) (serverSuiteId >>> 8);
                        modified[45] = (byte) serverSuiteId;
                        return modified;
                    }
                    return record;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Прервано", e);
                }
            }

            @Override
            public void close() {}
        };
    }

    private void runHandshakeWithServerSuite(
            PkixCertTestHelper.CertBundle root,
            PkixCertTestHelper.CertBundle serverLeaf,
            int serverSuiteId)
            throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        TlsSession client =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        clientTransportWithServerSuite(tp, serverSuiteId));
        TlsSession server =
                TlsSession.createServer(
                        new TlsServerConfig(
                                getCsL(),
                                Collections.singletonList(serverLeaf.cert),
                                serverLeaf.priv),
                        tp.getServerTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();

        ExecutionException ex =
                assertThrows(ExecutionException.class, () -> cf.get(15, TimeUnit.SECONDS));
        assertInstanceOf(TlsException.class, ex.getCause());
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                ((TlsException) ex.getCause()).getAlertCode());

        try {
            sf.get(5, TimeUnit.SECONDS);
        } catch (Exception ignored) {
        }
        exec.shutdown();
        client.close();
        server.close();
    }

    // 49412 = 0xC104 (Magma, не предлагался клиентом), 65535 = 0xFFFF (набор неизвестен)
    @ParameterizedTest(name = "{0}")
    @CsvSource({"Magma вне offered, 49412", "неизвестный набор, 65535"})
    @DisplayName(
            "handshake: сервер выбирает набор, которого нет в offered -> ALERT_ILLEGAL_PARAMETER")
    void testCipherSuiteNegotiationRejectsNotOffered(String name, int suiteId) throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        runHandshakeWithServerSuite(root, serverLeaf, suiteId);
    }

    @Test
    @DisplayName(
            "проверка цепочки сертификатов: истёкший промежуточный -> ALERT_CERTIFICATE_EXPIRED")
    void testCheckServerCertificateChainExpiredIntermediate() throws Exception {
        PkixCertTestHelper.CertBundle root = createRoot();
        PkixCertTestHelper.CertBundle expiredInt =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20000101000000Z",
                        "20050101000000Z",
                        null,
                        null,
                        null,
                        true,
                        0);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        ECParameters.tc26a256(),
                        expiredInt.priv,
                        expiredInt.cert.getPublicKey(),
                        expiredInt.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        null,
                        null,
                        false,
                        null);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(root.cert))
                                .withServerHostname("gost.example.com"),
                        noopTransport());

        TlsException e =
                assertThrows(
                        TlsException.class,
                        () ->
                                session.checkServerCertificateChain(
                                        Arrays.asList(leaf.cert, expiredInt.cert, root.cert)));
        assertEquals(TlsConstants.ALERT_CERTIFICATE_EXPIRED, e.getAlertCode());
    }

    @Test
    @DisplayName("проверка цепочки: истёкший cert-якорь при n > 1 -> WARNING, не фатально")
    void testCheckServerCertificateChainExpiredRoot() throws Exception {
        var params = ECParameters.tc26a256();
        var rootKp = KeyGenerator.generateKeyPair(params);
        byte[] rootDn = PkixCertTestHelper.buildDN("Expired Root");
        PkixCertTestHelper.CertBundle expiredRoot =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        rootKp.getPrivate(),
                        rootKp.getPublic(),
                        rootDn,
                        "20000101000000Z",
                        "20050101000000Z",
                        null,
                        null,
                        null,
                        true,
                        null);
        PkixCertTestHelper.CertBundle leaf =
                PkixCertTestHelper.createCertSignedBy(
                        params,
                        expiredRoot.priv,
                        expiredRoot.cert.getPublicKey(),
                        expiredRoot.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        new byte[] {(byte) 0x80},
                        new String[] {GostOids.EXT_SERVER_AUTH},
                        false,
                        null);

        TlsSession session =
                TlsSession.createClient(
                        new TlsClientConfig(getCsL(), TrustAnchors.ofCertificate(expiredRoot.cert))
                                .withServerHostname("gost.example.com"),
                        noopTransport());

        // Cert-якорь при n > 1 даёт WARNING: ограничения и срок якоря
        // аутентифицированы, но TLS сохраняет прежнюю семантику цепочки.
        assertDoesNotThrow(
                () ->
                        session.checkServerCertificateChain(
                                Arrays.asList(leaf.cert, expiredRoot.cert)));
    }

    private long parseObfuscatedTicketAge(byte[] body) {
        int pos = 34;
        int sessionIdLen = body[pos] & 0xFF;
        pos += 1 + sessionIdLen;
        int cipherSuitesLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        pos += 2 + cipherSuitesLen;
        int compressionLen = body[pos] & 0xFF;
        pos += 1 + compressionLen;
        int extLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
        pos += 2;
        int extEnd = pos + extLen;
        while (pos < extEnd) {
            int extType = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
            int extDataLen = ((body[pos + 2] & 0xFF) << 8) | (body[pos + 3] & 0xFF);
            pos += 4;
            if (extType == TlsConstants.EXT_PRE_SHARED_KEY) {
                pos += 2;
                int identityLen = ((body[pos] & 0xFF) << 8) | (body[pos + 1] & 0xFF);
                pos += 2 + identityLen;
                return ((long) (body[pos] & 0xFF) << 24)
                        | ((long) (body[pos + 1] & 0xFF) << 16)
                        | ((long) (body[pos + 2] & 0xFF) << 8)
                        | (long) (body[pos + 3] & 0xFF);
            }
            pos += extDataLen;
        }
        throw new AssertionError("PSK extension not found in ClientHello");
    }

    // =======================================================================
    // KeyUpdate (RFC 8446 §4.6.3)
    // =======================================================================

    @Test
    @DisplayName("KeyUpdate not_requested: reader keys обновляются, старые не работают")
    void testKeyUpdateNotRequested() throws Exception {
        TlsCiphersuite cs = getCsL();
        int hashLen = cs.getHashLen();
        int keyLen = cs.getKeyLen();
        int ivLen = cs.getIvLen();
        int tagLen = cs.getTagLen();

        TlsTrafficKeys initialKeys = randomTrafficKeys();
        byte[] serverSecret = new byte[hashLen];
        byte[] clientSecret = new byte[hashLen];
        CryptoRandom.INSTANCE.nextBytes(serverSecret);
        CryptoRandom.INSTANCE.nextBytes(clientSecret);

        LinkedBlockingQueue<byte[]> inbound = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>();
        TlsTransport transport = makeTransport(inbound, outbound);

        TlsSession session = TlsSession.createForTest(transport, cs, initialKeys, initialKeys);
        TlsSession.setAppTrafficSecrets(session, serverSecret, clientSecret, false);

        // Peer record (same keys as session reader)
        TlsRecord peerRecord = new TlsRecord(initialKeys.getKey(), initialKeys.getIv(), tagLen, cs);

        // Compute expected new reader keys
        byte[] newReaderSecret =
                HkdfStreebog.expandLabel(
                        serverSecret, "traffic upd", new byte[0], hashLen, hashLen);
        byte[] newReaderKey =
                HkdfStreebog.expandLabel(newReaderSecret, "key", new byte[0], keyLen, hashLen);
        byte[] newReaderIv =
                HkdfStreebog.expandLabel(newReaderSecret, "iv", new byte[0], ivLen, hashLen);
        TlsRecord newPeerRecord = new TlsRecord(newReaderKey, newReaderIv, tagLen, cs);

        // 1. App data with old keys -> успех
        inbound.add(peerRecord.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {0x41}));
        assertArrayEquals(new byte[] {0x41}, session.read());

        // 2. KeyUpdate(not_requested) с old keys
        byte[] kuBody = new byte[] {0};
        byte[] kuMsg = new TlsHandshakeMessage(TlsConstants.HT_KEY_UPDATE, kuBody).encode();
        inbound.add(peerRecord.protect(TlsConstants.CT_HANDSHAKE, kuMsg));

        // 3. App data с NEW keys -> успех
        inbound.add(newPeerRecord.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {0x43}));
        assertArrayEquals(new byte[] {0x43}, session.read());

        // 4. App data с old keys -> ошибка (readerRecord обновлён), сессия закрывается
        inbound.add(peerRecord.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {0x42}));
        IOException ex = assertThrows(IOException.class, () -> session.read());
        assertTrue(
                ex.getMessage().toLowerCase().contains("auth")
                        || ex.getCause() instanceof AuthenticationException,
                "Ожидается auth error: " + ex.getMessage());
        assertTrue(session.isClosed(), "Сессия должна быть закрыта после ошибки проверки записи");

        TlsUtils.wipeArray(newReaderSecret);
        TlsUtils.wipeArray(newReaderKey);
        TlsUtils.wipeArray(newReaderIv);
        TlsUtils.wipeArray(serverSecret);
        TlsUtils.wipeArray(clientSecret);
        session.close();
    }

    @Test
    @DisplayName("KeyUpdate requested: reader+writer обновляются, ответ отправлен")
    void testKeyUpdateRequested() throws Exception {
        TlsCiphersuite cs = getCsL();
        int hashLen = cs.getHashLen();
        int keyLen = cs.getKeyLen();
        int ivLen = cs.getIvLen();
        int tagLen = cs.getTagLen();

        TlsTrafficKeys initialReaderKeys = randomTrafficKeys();
        TlsTrafficKeys initialWriterKeys = randomTrafficKeys();
        byte[] serverSecret = new byte[hashLen];
        byte[] clientSecret = new byte[hashLen];
        CryptoRandom.INSTANCE.nextBytes(serverSecret);
        CryptoRandom.INSTANCE.nextBytes(clientSecret);

        LinkedBlockingQueue<byte[]> inbound = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>();
        TlsTransport transport = makeTransport(inbound, outbound);

        TlsSession session =
                TlsSession.createForTest(transport, cs, initialReaderKeys, initialWriterKeys);
        TlsSession.setAppTrafficSecrets(session, serverSecret, clientSecret, false);

        // Peer records
        TlsRecord peerReaderRecord =
                new TlsRecord(initialReaderKeys.getKey(), initialReaderKeys.getIv(), tagLen, cs);

        // Compute expected new reader keys
        byte[] newReaderSecret =
                HkdfStreebog.expandLabel(
                        serverSecret, "traffic upd", new byte[0], hashLen, hashLen);
        byte[] newReaderKey =
                HkdfStreebog.expandLabel(newReaderSecret, "key", new byte[0], keyLen, hashLen);
        byte[] newReaderIv =
                HkdfStreebog.expandLabel(newReaderSecret, "iv", new byte[0], ivLen, hashLen);
        TlsRecord newPeerReaderRecord = new TlsRecord(newReaderKey, newReaderIv, tagLen, cs);

        // 1. KeyUpdate(requested) с old keys -> session обновит reader+writer и отправит ответ
        byte[] kuBody = new byte[] {1};
        byte[] kuMsg = new TlsHandshakeMessage(TlsConstants.HT_KEY_UPDATE, kuBody).encode();
        inbound.add(peerReaderRecord.protect(TlsConstants.CT_HANDSHAKE, kuMsg));

        // 2. После KeyUpdate: app data с НОВЫМИ reader keys -> успех
        inbound.add(
                newPeerReaderRecord.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {0x44}));
        assertArrayEquals(new byte[] {0x44}, session.read());

        // 3. Outbound должен содержать ответный KeyUpdate (not_requested)
        assertEquals(1, outbound.size(), "Должен быть 1 ответный KeyUpdate");
        byte[] response = outbound.poll(1, TimeUnit.SECONDS);
        assertNotNull(response);

        // Декодируем ответ СТАРЫМИ writer-ключами — handleKeyUpdate отправила ответ
        // через writerRecord ДО того, как создала новый (п. 2 -> sendEncryptedRecord,
        // затем п. 3 -> writerRecord = new TlsRecord). Если бы обновление writerRecord
        // произошло раньше отправки, пир не смог бы расшифровать ответ — это свойство
        // синхронизации KeyUpdate: отправитель подтверждает приём новых reader-ключей
        // (ответ зашифрован старыми writer-ключами, которые пир уже заменил на новые
        // reader-ключи на своей стороне).
        TlsRecord peerWriterRecord =
                new TlsRecord(initialWriterKeys.getKey(), initialWriterKeys.getIv(), tagLen, cs);
        TlsParsedRecord parsed = peerWriterRecord.unprotect(response);
        assertEquals(TlsConstants.CT_HANDSHAKE, parsed.getContentType());
        TlsHandshakeMessage hm = TlsHandshakeMessage.decode(parsed.getData());
        assertEquals(TlsConstants.HT_KEY_UPDATE, hm.getType());
        assertArrayEquals(new byte[] {0}, hm.getBody(), "Ответ должен быть not_requested");

        TlsUtils.wipeArray(newReaderSecret);
        TlsUtils.wipeArray(newReaderKey);
        TlsUtils.wipeArray(newReaderIv);
        TlsUtils.wipeArray(serverSecret);
        TlsUtils.wipeArray(clientSecret);
        session.close();
    }

    @Test
    @DisplayName("KeyUpdate: неверная длина тела -> TlsException(DECODE_ERROR)")
    void testKeyUpdateInvalidBody() throws Exception {
        TlsCiphersuite cs = getCsL();
        int tagLen = cs.getTagLen();
        TlsTrafficKeys keys = randomTrafficKeys();

        LinkedBlockingQueue<byte[]> inbound = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>();
        TlsTransport transport = makeTransport(inbound, outbound);

        TlsSession session = TlsSession.createForTest(transport, cs, keys, keys);
        TlsSession.setAppTrafficSecrets(session, new byte[32], new byte[32], false);

        TlsRecord peerRecord = new TlsRecord(keys.getKey(), keys.getIv(), tagLen, cs);
        // Body length != 1
        byte[] kuBody = new byte[] {0, 0};
        byte[] kuMsg = new TlsHandshakeMessage(TlsConstants.HT_KEY_UPDATE, kuBody).encode();
        inbound.add(peerRecord.protect(TlsConstants.CT_HANDSHAKE, kuMsg));

        TlsException ex = assertThrows(TlsException.class, () -> session.read());
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
        session.close();
    }

    private static TlsTransport makeTransport(
            LinkedBlockingQueue<byte[]> inbound, LinkedBlockingQueue<byte[]> outbound) {
        return new TlsTransport() {
            @Override
            public void sendRecord(byte[] r) throws IOException {
                outbound.add(r);
            }

            @Override
            public byte[] receiveRecord() throws IOException {
                try {
                    byte[] r = inbound.poll(10, TimeUnit.SECONDS);
                    if (r == null) throw new IOException("Таймаут");
                    return r;
                } catch (InterruptedException e) {
                    throw new IOException(e);
                }
            }

            @Override
            public void close() {}
        };
    }

    /**
     * Запускает client.handshakeAsClient() и server.handshakeAsServer() параллельно.
     * Использует Phaser для синхронизации старта и ExecutorService для распараллеливания.
     * TLS handshake — двусторонний протокол, клиент и сервер обмениваются
     * сообщениями; последовательный запуск не работает из-за блокирующего read().
     */
    private static void handshakeInParallel(TlsSession server, TlsSession client) throws Exception {
        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        try {
            Future<Void> cf =
                    exec.submit(
                            () -> {
                                phaser.arriveAndAwaitAdvance();
                                client.handshakeAsClient();
                                return null;
                            });
            Future<Void> sf =
                    exec.submit(
                            () -> {
                                phaser.arriveAndAwaitAdvance();
                                server.handshakeAsServer();
                                return null;
                            });
            phaser.arriveAndAwaitAdvance();
            cf.get(15, TimeUnit.SECONDS);
            sf.get(15, TimeUnit.SECONDS);
        } finally {
            exec.shutdown();
        }
        assertTrue(client.isHandshakeDone(), "Клиент: handshake завершён");
        assertTrue(server.isHandshakeDone(), "Сервер: handshake завершён");
    }

    @ParameterizedTest(name = "{0} байт -> записей app_data: {1}")
    @CsvSource({"511, 1", "512, 2", "2000, 4"})
    @DisplayName("max_fragment_length=512: согласование и разбиение данных на записи")
    void testMaxFragmentLengthFragmentation(int dataLen, int expectedRecords) throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        var c2s = new LinkedBlockingQueue<byte[]>();
        var s2c = new LinkedBlockingQueue<byte[]>();
        var appDataRecords = new CopyOnWriteArrayList<byte[]>();

        InMemoryTlsTransport clientTransport =
                new InMemoryTlsTransport(s2c) {
                    @Override
                    public void sendRecord(byte[] record) {
                        if ((record[0] & 0xFF) == TlsConstants.CT_APPLICATION_DATA) {
                            appDataRecords.add(record.clone());
                        }
                        c2s.add(record.clone());
                    }
                };
        InMemoryTlsTransport serverTransport =
                new InMemoryTlsTransport(c2s) {
                    @Override
                    public void sendRecord(byte[] record) {
                        s2c.add(record.clone());
                    }
                };

        TlsSession server = TlsSession.createServer(serverTransport, cs, bundle.cert, bundle.priv);
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(clientTransport, cs, null, null);
        client.setMaxFragmentLengthRequest(TlsConstants.MAX_FRAG_LEN_512);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            client.handshakeAsClient();
                            return null;
                        });
        Future<Void> sf =
                exec.submit(
                        () -> {
                            phaser.arriveAndAwaitAdvance();
                            server.handshakeAsServer();
                            return null;
                        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();

        assertEquals(
                TlsConstants.MAX_FRAG_LEN_512,
                client.getMaxFragmentLength(),
                "Клиент: согласован max_fragment_length=512");
        assertEquals(
                TlsConstants.MAX_FRAG_LEN_512,
                server.getMaxFragmentLength(),
                "Сервер: согласован max_fragment_length=512");

        // зашифрованные сообщения рукопожатия тоже идут с внешним типом application_data
        appDataRecords.clear();

        byte[] sent = new byte[dataLen];
        CryptoRandom.INSTANCE.nextBytes(sent);
        client.write(sent);
        byte[] received = new byte[dataLen];
        int off = 0;
        while (off < dataLen) {
            byte[] chunk = server.read();
            System.arraycopy(chunk, 0, received, off, chunk.length);
            off += chunk.length;
        }
        assertArrayEquals(sent, received, "Данные переданы без искажений");

        assertEquals(
                expectedRecords,
                appDataRecords.size(),
                "Число записей app_data при limit=512 и " + dataLen + " байтах");
        int maxAllowedCiphertext =
                TlsUtils.maxFragmentLength(TlsConstants.MAX_FRAG_LEN_512)
                        + 1
                        + 16; // plaintext + inner_type + tag
        for (byte[] rec : appDataRecords) {
            int bodyLen = ((rec[3] & 0xFF) << 8) | (rec[4] & 0xFF);
            assertTrue(
                    bodyLen <= maxAllowedCiphertext,
                    "Запись app_data не превышает лимит: "
                            + bodyLen
                            + " <= "
                            + maxAllowedCiphertext);
        }
    }
}
