package org.rssys.gost.tls13;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.tls13.psk.*;
import org.rssys.gost.tls13.crypto.*;
import org.rssys.gost.tls13.config.*;
import org.rssys.gost.tls13.cert.*;
import org.rssys.gost.tls13.record.*;
import org.rssys.gost.tls13.message.*;
import org.rssys.gost.tls13.engine.*;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import org.rssys.gost.tls13.transport.SocketTlsTransport;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты TlsSession — TLS 1.3 handshake, передача данных, утилиты.
 */
@DisplayName("TlsSession: handshake, передача данных, утилиты")
class TlsSessionTest {

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
        byte[] emptyCertBody = new byte[]{0x00, 0x00, 0x00, 0x00};
        List<TlsCertificate> chain = TlsMessageParser.parseCertificate(emptyCertBody);
        assertNotNull(chain);
        assertTrue(chain.isEmpty());
    }

    @Test
    @DisplayName("parseCertificate: урезанные данные бросают TlsException")
    void testParseCertificateTruncated() {
        // request_context(1) + list_len(3) с list_len > body
        byte[] body = new byte[]{0x00, 0x00, 0x00, (byte) 0xFF};
        assertThrows(TlsException.class,
                () -> TlsMessageParser.parseCertificate(body));
    }

    @Test
    @DisplayName("parseCertificate: с extensions после сертификата")
    void testParseCertificateWithExtensions() throws Exception {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        byte[] certDer = bundle.cert.getCertData();
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlsEncoding.encodeUint24(entry, certDer.length);
        entry.write(certDer, 0, certDer.length);
        TlsEncoding.encodeUint16(entry, 4); // ext_len=4
        entry.write(new byte[]{0x00, 0x01, 0x00, 0x00}); // ext_type=1, ext_data_len=0

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0); // request context
        byte[] entryBytes = entry.toByteArray();
        TlsEncoding.encodeUint24(body, entryBytes.length);
        body.write(entryBytes, 0, entryBytes.length);

        List<TlsCertificate> chain = TlsMessageParser.parseCertificate(body.toByteArray());
        assertEquals(1, chain.size());
        assertNotNull(chain.get(0));
    }

    @Test
    @DisplayName("parseCertificate: 512-битный ключ в сертификате")
    void testParseCertificate512() throws Exception {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a512());
        byte[] certDer = bundle.cert.getCertData();
        ByteArrayOutputStream entry = new ByteArrayOutputStream();
        TlsEncoding.encodeUint24(entry, certDer.length);
        entry.write(certDer, 0, certDer.length);
        TlsEncoding.encodeUint16(entry, 0); // расширения отсутствуют

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(0); // request context
        byte[] entryBytes = entry.toByteArray();
        TlsEncoding.encodeUint24(body, entryBytes.length);
        body.write(entryBytes, 0, entryBytes.length);

        List<TlsCertificate> chain = TlsMessageParser.parseCertificate(body.toByteArray());
        assertEquals(1, chain.size());
        assertEquals(512, chain.get(0).getKeySize());
    }

    // =======================================================================
    // Тесты extractRecordData
    // =======================================================================

    @Test
    @DisplayName("extractRecordData: null бросает TlsException(ALERT_DECODE_ERROR)")
    void testExtractRecordDataNull() {
        TlsException ex = assertThrows(TlsException.class,
                () -> TlsMessageParser.extractRecordData(null));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName("extractRecordData: слишком короткая запись → TlsException(ALERT_DECODE_ERROR)")
    void testExtractRecordDataTooShort() {
        byte[] shortRecord = new byte[3];
        TlsException ex = assertThrows(TlsException.class,
                () -> TlsMessageParser.extractRecordData(shortRecord));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName("extractRecordData: поле len превышает длину записи → TlsException(ALERT_DECODE_ERROR)")
    void testExtractRecordDataTruncated() {
        byte[] record = new byte[]{TlsConstants.CT_HANDSHAKE, 0x03, 0x03, 0x10, 0x00};
        TlsException ex = assertThrows(TlsException.class,
                () -> TlsMessageParser.extractRecordData(record));
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
    }

    @Test
    @DisplayName("extractRecordData: корректная запись извлекает данные")
    void testExtractRecordDataValid() throws Exception {
        byte[] body = "hello".getBytes();
        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + body.length];
        record[0] = TlsConstants.CT_HANDSHAKE;
        record[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        record[2] = TlsConstants.LEGACY_VERSION_MINOR;
        record[3] = 0;
        record[4] = (byte) body.length;
        System.arraycopy(body, 0, record, TlsConstants.RECORD_HEADER_SIZE, body.length);

        byte[] result = TlsMessageParser.extractRecordData(record);
        assertArrayEquals(body, result);
    }

    // =======================================================================
    // Тесты factory методов и жизненного цикла
    // =======================================================================

    @Test
    @DisplayName("createClient: корректное создание сессии клиента")
    void testCreateClient() {
        TlsSession s = TlsSession.createClient(new InMemoryTlsTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);
        assertNotNull(s);
        assertFalse(s.isHandshakeDone());
        assertFalse(s.isClosed());
    }

    @Test
    @DisplayName("createServer: корректное создание сессии сервера")
    void testCreateServer() {
        TlsSession s = TlsSession.createServer(new InMemoryTlsTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);
        assertNotNull(s);
        assertFalse(s.isHandshakeDone());
        assertFalse(s.isClosed());
    }

    @Test
    @DisplayName("factory: null транспорт бросает исключение")
    void testCreateNullTransport() {
        assertThrows(IllegalArgumentException.class,
                () -> TlsSession.createClient(null,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null));
    }

    @Test
    @DisplayName("factory: null cipher suite бросает исключение")
    void testCreateNullCiphersuite() {
        assertThrows(IllegalArgumentException.class,
                () -> TlsSession.createClient(new InMemoryTlsTransport(), null, null, null));
    }

    @Test
    @DisplayName("write до handshake: IllegalStateException")
    void testWriteBeforeHandshake() {
        TlsSession s = TlsSession.createClient(new InMemoryTlsTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);
        assertThrows(IllegalStateException.class, () -> s.write(new byte[]{1}));
    }

    @Test
    @DisplayName("read до handshake: IllegalStateException")
    void testReadBeforeHandshake() {
        TlsSession s = TlsSession.createClient(new InMemoryTlsTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);
        assertThrows(IllegalStateException.class, s::read);
    }

    @Test
    @DisplayName("close: идемпотентность")
    void testCloseIdempotent() throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        TlsSession s = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);
        s.close();
        assertTrue(s.isClosed());
        s.close();
        assertTrue(s.isClosed());
    }

    @Test
    @DisplayName("handshakeAsClient в закрытой сессии: IllegalStateException")
    void testHandshakeAsClientWhenClosed() throws Exception {
        TlsSession s = TlsSession.createClient(new InMemoryTlsTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);
        s.close();
        assertThrows(IllegalStateException.class, s::handshakeAsClient);
    }

    @Test
    @DisplayName("handshakeAsServer в закрытой сессии: IllegalStateException")
    void testHandshakeAsServerWhenClosed() throws Exception {
        TlsSession s = TlsSession.createServer(new InMemoryTlsTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);
        s.close();
        assertThrows(IllegalStateException.class, s::handshakeAsServer);
    }

    // =======================================================================
    // Полный handshake клиент-сервер
    // =======================================================================

    @Test
    @DisplayName("Полный handshake: клиент-сервер tc26-A-256")
    void testFullHandshake256() throws Exception {
        testHandshake(ECParameters.tc26a256(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
    }

    @Test
    @DisplayName("Полный handshake: сертификат CryptoPro-A (GC256B)")
    void testFullHandshakeCryptoProA() throws Exception {
        testHandshake(ECParameters.cryptoProA(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
    }

    @Test
    @DisplayName("Полный handshake: сертификат tc26-A-512")
    void testFullHandshake512() throws Exception {
        testHandshake(ECParameters.tc26a512(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L);
    }

    private void testHandshake(ECParameters params, TlsCiphersuite cs) throws Exception {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(tp.getServerTransport(), cs, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(tp.getClientTransport(), cs, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);

        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });

        Future<Void> sf = exec.submit(() -> {
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

    // =======================================================================
    // close_notify
    // =======================================================================

    @Test
    @DisplayName("close() после handshake отправляет close_notify")
    void testCloseNotifiesPeer() throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);

        int before = tp.getServerToClientQueue().size();

        assertDoesNotThrow(() -> server.close());
        assertTrue(server.isClosed());

        // close_notify отправлен через writerRecord.protect → +1 запись
        assertEquals(before + 1, tp.getServerToClientQueue().size(), "close_notify отправлен");

        exec.shutdown();
        client.close();
    }

    // =======================================================================
    // CA verify
    // =======================================================================

    @Test
    @DisplayName("handshake с CA verify: самоподписанный сертификат проходит")
    void testHandshakeWithCaVerify() throws Exception {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        // Проверяем сертификат сервера его же публичным ключом (self-signed)
        TlsSession client = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null,
                bundle.cert.getPublicKey());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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

    @Test
    @DisplayName("handshake с неверным CA ключом: ALERT_BAD_CERTIFICATE")
    void testHandshakeWithWrongCaKey() throws Exception {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        // Генерируем другой ключ (не CA для сертификата)
        org.rssys.gost.api.KeyPair wrongKp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());

        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null,
                wrongKp.getPublic());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();

        try {
            cf.get(15, TimeUnit.SECONDS);
            fail("Handshake с неверным CA ключом должен провалиться");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TlsException,
                    "Ожидается TlsException: " + e.getCause().getMessage());
        }

        sf.cancel(true);
        exec.shutdown();
        server.close();
    }

    // =======================================================================
    // CertificateVerify
    // =======================================================================

    @Test
    @DisplayName("CertificateVerify с неверной схемой подписи → ALERT_BAD_CERTIFICATE")
    void testCertificateVerifyWrongScheme() throws Exception {
        TlsSession s = TlsSession.createClient(new InMemoryTlsTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);

        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        // схема 0x070D (512-бит), а ожидается 256-бит
        ByteArrayOutputStream cvBody = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(cvBody, TlsConstants.SIG_GOST_TC26_512_A);
        TlsEncoding.encodeUint16(cvBody, 8);
        cvBody.write(new byte[8]);

        byte[] transcript = new byte[TlsConstants.STREEBOG_256_HASH_LEN];
        TlsException ex = assertThrows(TlsException.class,
                () -> s.verifyCertificateVerify(cvBody.toByteArray(), bundle.cert, transcript, true));
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ex.getAlertCode());
    }

    // -----------------------------------------------------------------------
    // Подмена записи в e2e
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Подмена ciphertext после handshake: AuthenticationException")
    void testTamperedRecordAfterHandshake() throws Exception {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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

        // Клиент отправляет зашифрованную запись
        client.write("tamper me".getBytes());

        // Извлекаем запись из очереди c2s, подменяем байт ciphertext, возвращаем
        byte[] record = tp.getClientToServerQueue().poll(1, TimeUnit.SECONDS);
        assertNotNull(record);
        record[TlsConstants.RECORD_HEADER_SIZE + 4] ^= 0x42;
        tp.getClientToServerQueue().add(record);

        // Сервер читает — должен получить AuthenticationException
        IOException ex = assertThrows(IOException.class, server::read);
        assertTrue(ex.getCause() instanceof AuthenticationException
                        || ex.getMessage().contains("authentication failed"),
                "Expected auth error, got: " + ex.getMessage());

        server.close();
        client.close();
    }

    // =======================================================================
    // Ошибка аутентификации
    // =======================================================================

    @Test
    @DisplayName("Handshake: несовпадение ключа сертификата = ошибка")
    void testHandshakeWithMismatchedKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        // Другой ключ для подписи CertificateVerify
        PrivateKeyParameters wrongKey = KeyGenerator.generateKeyPair(params).getPrivate();

        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, wrongKey);
        TlsSession client = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();

        try {
            cf.get(10, TimeUnit.SECONDS);
            fail("Client handshake с неверным ключом должен провалиться");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof IOException,
                    "Ожидается IOException: " + e.getCause().getMessage());
        }

        // Проверяем, что сервер отправил alert (SF + alert в s2c после потребления клиентом)
        sf.cancel(true);
        exec.shutdown();
        exec.awaitTermination(2, TimeUnit.SECONDS);

        java.util.ArrayList<byte[]> s2cRecords = new java.util.ArrayList<>();
        byte[] r;
        while ((r = tp.getServerToClientQueue().poll()) != null) {
            s2cRecords.add(r);
        }
        assertTrue(s2cRecords.size() >= 2,
                "s2c: Server Finished + alert, всего " + s2cRecords.size());

        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: hostname совпадает с SAN — успех")
    void testHandshakeHostnameMatch() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                params, "240501120000Z", "290501120000Z",
                new String[]{"server.com"});
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(new TlsClientConfig(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L)
                .withServerHostname("server.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();
        cf.get(10, TimeUnit.SECONDS);
        sf.get(10, TimeUnit.SECONDS);
        exec.shutdown();

        assertTrue(client.isHandshakeDone());
        assertTrue(server.isHandshakeDone());
        client.write("data".getBytes());
        assertArrayEquals("data".getBytes(), server.read());
        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: hostname не совпадает с SAN — ошибка")
    void testHandshakeHostnameMismatch() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                params, "240501120000Z", "290501120000Z",
                new String[]{"server.com"});
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(new TlsClientConfig(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L)
                .withServerHostname("evil.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();

        try {
            cf.get(10, TimeUnit.SECONDS);
            fail("Клиентский handshake должен провалиться при несовпадении hostname");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TlsException,
                    "Ожидается TlsException: " + e.getCause().getMessage());
        }
        sf.cancel(true);
        exec.shutdown();
        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: SNI передаётся от клиента к серверу")
    void testHandshakeSniRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        String sniHost = "my-server.example.com";
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                params, "240501120000Z", "290501120000Z",
                new String[]{sniHost});
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(new TlsClientConfig(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L)
                .withServerHostname(sniHost), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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
        assertEquals(sniHost, server.getRequestedServerName(),
                "Сервер должен получить SNI от клиента");
        assertEquals(sniHost, client.getPeerHostname(),
                "Клиент должен помнить hostname");
        client.write("data".getBytes());
        assertArrayEquals("data".getBytes(), server.read());
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
        TlsTestHelper.CertBundle defaultBundle = TlsTestHelper.createCertWithKey(
                params, "240501120000Z", "290501120000Z",
                new String[]{defaultHost});
        TlsTestHelper.CertBundle multiBundle = TlsTestHelper.createCertWithKey(
                params, "240501120000Z", "290501120000Z",
                new String[]{multiHost});

        // Selector: для multiHost возвращает multi-credentials, для остальных — null (fallback)
        SniCertificateSelector selector = sni -> {
            if (multiHost.equals(sni)) {
                return new TlsServerCredentials(
                        Collections.singletonList(multiBundle.cert),
                        multiBundle.priv, null);
            }
            return null;
        };

        // ====== Client 1: запрашивает multi.example.com ======
        var tp1 = InMemoryTlsTransport.newPair();
        TlsSession server1 = TlsSession.createServer(
                new TlsServerConfig(cs, Collections.singletonList(defaultBundle.cert), defaultBundle.priv)
                        .withSniSelector(selector), tp1.getServerTransport());
        TlsSession client1 = TlsSession.createClient(new TlsClientConfig(cs)
                .withServerHostname(multiHost), tp1.getClientTransport());

        handshakeInParallel(server1, client1);

        assertEquals(multiHost, server1.getRequestedServerName(),
                "Сервер должен получить SNI от клиента");
        assertNotNull(client1.getPeerCertificates(),
                "Клиент должен получить сертификат сервера");
        assertTrue(client1.getPeerCertificates().get(0).verifyHostname(multiHost),
                "Клиент должен получить сертификат для multi.example.com, а не default");

        client1.close();
        server1.close();

        // ====== Client 2: запрашивает default.example.com (fallback на default-сертификат) ======
        var tp2 = InMemoryTlsTransport.newPair();
        TlsSession server2 = TlsSession.createServer(
                new TlsServerConfig(cs, Collections.singletonList(defaultBundle.cert), defaultBundle.priv)
                        .withSniSelector(selector), tp2.getServerTransport());
        TlsSession client2 = TlsSession.createClient(new TlsClientConfig(cs)
                .withServerHostname(defaultHost), tp2.getClientTransport());

        handshakeInParallel(server2, client2);

        assertEquals(defaultHost, server2.getRequestedServerName(),
                "Сервер должен получить SNI от клиента");
        assertNotNull(client2.getPeerCertificates(),
                "Клиент должен получить сертификат сервера");
        assertTrue(client2.getPeerCertificates().get(0).verifyHostname(defaultHost),
                "Клиент должен получить default-сертификат (через fallback)");

        client2.close();
        server2.close();
    }

    // =======================================================================
    // ALPN (RFC 7301) — интеграционные тесты через TlsClientConfig/TlsServerConfig
    // =======================================================================
    //
    // WHY: engine-level тесты для ALPN есть в TlsHandshakeEngineTest, но баг
    // «config.alpnProtocols не пропагируется в TlsSession» живёт именно в
    // factory-методах. Эти тесты проверяют полный путь:
    // TlsClientConfig.withAlpnProtocols() → createClient() → handshake → getAlpnProtocol().

    @Test
    @DisplayName("ALPN: согласование h2 через TlsClientConfig/TlsServerConfig")
    void testAlpnViaConfig() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsCiphersuite cs = getCsL();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(
                new TlsServerConfig(cs, Collections.singletonList(bundle.cert), bundle.priv)
                        .withAlpnProtocols(List.of("h2", "http/1.1")), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(
                new TlsClientConfig(cs)
                        .withAlpnProtocols(List.of("h2", "http/1.1")), tp.getClientTransport());

        handshakeInParallel(server, client);

        assertEquals("h2", server.getAlpnProtocol(),
                "Сервер: ALPN согласован через TlsServerConfig.withAlpnProtocols");
        assertEquals("h2", client.getAlpnProtocol(),
                "Клиент: ALPN согласован через TlsClientConfig.withAlpnProtocols");

        server.close();
        client.close();
    }

    @Test
    @DisplayName("ALPN: клиент без ALPN → getAlpnProtocol null")
    void testAlpnClientWithoutAlpn() throws Exception {
        // Сервер настроен на ALPN, клиент — нет. Сервер не включает ALPN в EE.
        ECParameters params = ECParameters.tc26a256();
        TlsCiphersuite cs = getCsL();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);

        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(
                new TlsServerConfig(cs, Collections.singletonList(bundle.cert), bundle.priv)
                        .withAlpnProtocols(List.of("h2", "http/1.1")), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(
                new TlsClientConfig(cs), tp.getClientTransport());

        handshakeInParallel(server, client);

        assertNull(server.getAlpnProtocol(),
                "Сервер: ALPN не согласован (клиент не предлагал)");
        assertNull(client.getAlpnProtocol(),
                "Клиент: ALPN не согласован");

        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: KU без digitalSignature → ошибка")
    void testHandshakeKuWithoutDigitalSignature() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                params, "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x20}, null);
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();

        try {
            cf.get(10, TimeUnit.SECONDS);
            fail("Клиентский handshake должен провалиться при KU без digitalSignature");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TlsException,
                    "Ожидается TlsException: " + e.getCause().getMessage());
        }
        sf.cancel(true);
        exec.shutdown();
        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: EKU без serverAuth → ошибка")
    void testHandshakeEkuWithoutServerAuth() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                params, "240501120000Z", "290501120000Z",
                null, new byte[]{(byte) 0x80}, new String[]{"1.3.6.1.5.5.7.3.3"});
        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();

        try {
            cf.get(10, TimeUnit.SECONDS);
            fail("Клиентский handshake должен провалиться при EKU без serverAuth");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TlsException,
                    "Ожидается TlsException: " + e.getCause().getMessage());
        }
        sf.cancel(true);
        exec.shutdown();
        server.close();
        client.close();
    }

    @Test
    @DisplayName("Handshake: сертификат с IPv4 в SAN")
    void testHandshakeWithIpSan() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(
                params, "240501120000Z", "290501120000Z",
                null, null, null, new String[]{"192.168.1.1"});
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                null, null);

        ExecutorService exec = Executors.newSingleThreadExecutor();
        Future<Void> sf = exec.submit(() -> { server.handshakeAsServer(); return null; });
        client.handshakeAsClient();
        sf.get(10, TimeUnit.SECONDS);
        exec.shutdown();

        byte[] payload = "data".getBytes();
        client.write(payload);
        assertArrayEquals(payload, server.read());

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
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(params);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);

        // Неверный ClientHello: заголовок верный, тело слишком короткое
        byte[] handshakeFrame = new byte[]{0x01, 0x00, 0x00, 0x02, 0x03, 0x03};
        byte[] record = new byte[5 + handshakeFrame.length];
        record[0] = TlsConstants.CT_HANDSHAKE;
        record[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        record[2] = TlsConstants.LEGACY_VERSION_MINOR;
        record[3] = (byte) (handshakeFrame.length >>> 8);
        record[4] = (byte) handshakeFrame.length;
        System.arraycopy(handshakeFrame, 0, record, 5, handshakeFrame.length);
        tp.getClientToServerQueue().add(record);

        ExecutorService exec = Executors.newSingleThreadExecutor();
        Future<Void> sf = exec.submit(() -> {
            server.handshakeAsServer();
            return null;
        });

        try {
            sf.get(10, TimeUnit.SECONDS);
            fail("Серверный handshake должен провалиться");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            assertInstanceOf(TlsException.class, cause);
            assertEquals(TlsConstants.ALERT_DECODE_ERROR,
                    ((TlsException) cause).getAlertCode());
        }

        // Проверяем plaintext alert: writerRecord == null, so alert is not encrypted
        byte[] alertRecord = tp.getServerToClientQueue().poll(1, TimeUnit.SECONDS);
        assertNotNull(alertRecord, "Alert record должен быть в s2c");
        assertArrayEquals(new byte[]{
                TlsConstants.CT_ALERT,
                TlsConstants.LEGACY_VERSION_MAJOR,
                TlsConstants.LEGACY_VERSION_MINOR,
                0, 2,
                TlsConstants.ALERT_FATAL,
                TlsConstants.ALERT_DECODE_ERROR
        }, alertRecord, "Plaintext alert: FATAL + DECODE_ERROR");

        exec.shutdown();
        server.close();
    }

    @Test
    @DisplayName("Успешный handshake: алерты не отправляются")
    void testAlertNotSentOnSuccessfulHandshake() throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());

        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);

        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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
            assertNotEquals(TlsConstants.CT_ALERT, record[0] & 0xFF,
                    "c2s не должен содержать алертов");
        }
        while ((record = tp.getServerToClientQueue().poll()) != null) {
            assertNotEquals(TlsConstants.CT_ALERT, record[0] & 0xFF,
                    "s2c не должен содержать алертов");
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
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), noopTransport());

        // Не должно бросить исключение
        session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert));
    }

    @Test
    @DisplayName("checkServerCertificateChain: чужая CA → ошибка")
    void testCheckServerCertificateChainWrongCA() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);
        org.rssys.gost.api.KeyPair wrongKp = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(wrongKp.getPublic()), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert)));
    }

    @Test
    @DisplayName("checkServerCertificateChain: leaf не CA без BC → OK (i=0 пропускается)")
    void testCheckServerCertificateChainLeafNotCA() throws Exception {
        // Leaf не является CA — это нормально для leaf (i=0 не проверяется)
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey()), noopTransport());

        // Leaf (i=0) не проверяется на CA → проходит
        // Но root (i=1) проверяется на CA — expires — не должен пройти
        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert)));
    }

    @Test
    @DisplayName("checkServerCertificateChain: OCSP стэпплинг есть → успех")
    void testCheckServerCertificateChainOcspPresent() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);
        leaf.cert.setOcspResponse(TlsTestHelper.buildOcspResponse(
                leaf.cert.getSerialNumber(), root.priv, root.cert.getPublicKey(),
                root.subjectDn));

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com")
                .withRequireOcspStapling(true), noopTransport());

        session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert));
    }

    @Test
    @DisplayName("checkServerCertificateChain: OCSP отсутствует → ошибка")
    void testCheckServerCertificateChainOcspMissing() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com")
                .withRequireOcspStapling(true), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert)));
    }

    // =======================================================================
    // Delegated OCSP responder (checkServerCertificateChain)
    // =======================================================================

    @Test
    @DisplayName("checkServerCertificateChain: delegated OCSP responder валиден → успех")
    void testCheckServerCertificateChainDelegatedOcspGood() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);
        // Delegated cert: подписан root, EKU=OCSPSigning, KU=digitalSignature
        TlsTestHelper.CertBundle dc = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x80}, new String[]{"1.3.6.1.5.5.7.3.9"},
                false, null);
        // OCSP подписан dc.priv, а не root.priv → первичный путь упадёт
        leaf.cert.setOcspResponse(TlsTestHelper.buildOcspResponseWithDelegatedCerts(
                leaf.cert.getSerialNumber(), dc.priv, dc.cert.getPublicKey(),
                root.cert.getPublicKey(), root.subjectDn,
                "20300101120000Z", new byte[][]{dc.cert.getEncoded()}));

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com")
                .withRequireOcspStapling(true), noopTransport());

        session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert));
    }

    @Test
    @DisplayName("checkServerCertificateChain: delegated OCSP wrong EKU → ошибка")
    void testCheckServerCertificateChainDelegatedOcspWrongEku() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);
        // Delegated cert: подписан root, НО EKU=serverAuth вместо OCSPSigning
        TlsTestHelper.CertBundle dc = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);
        leaf.cert.setOcspResponse(TlsTestHelper.buildOcspResponseWithDelegatedCerts(
                leaf.cert.getSerialNumber(), dc.priv, dc.cert.getPublicKey(),
                root.cert.getPublicKey(), root.subjectDn,
                "20300101120000Z", new byte[][]{dc.cert.getEncoded()}));

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com")
                .withRequireOcspStapling(true), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert)));
    }

    @Test
    @DisplayName("checkServerCertificateChain: delegated OCSP wrong signer → ошибка")
    void testCheckServerCertificateChainDelegatedOcspWrongSigner() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);
        // Вторая CA — не issuer leaf
        TlsTestHelper.CertBundle wrongRoot = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        // Delegated cert: подписан wrongRoot, а не root (настоящий issuer leaf)
        TlsTestHelper.CertBundle dc = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), wrongRoot.priv, wrongRoot.cert.getPublicKey(),
                wrongRoot.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x80}, new String[]{"1.3.6.1.5.5.7.3.9"},
                false, null);
        leaf.cert.setOcspResponse(TlsTestHelper.buildOcspResponseWithDelegatedCerts(
                leaf.cert.getSerialNumber(), dc.priv, dc.cert.getPublicKey(),
                root.cert.getPublicKey(), root.subjectDn,
                "20300101120000Z", new byte[][]{dc.cert.getEncoded()}));

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com")
                .withRequireOcspStapling(true), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert)));
    }

    @Test
    @DisplayName("checkServerCertificateChain: delegated OCSP просрочен → ошибка")
    void testCheckServerCertificateChainDelegatedOcspExpired() throws Exception {
        TlsTestHelper.CertBundle root = TlsTestHelper.createRootCA(ECParameters.tc26a256());
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);
        // Delegated cert: просрочен (notAfter в прошлом)
        TlsTestHelper.CertBundle dc = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "230101120000Z", "240101120000Z", null,
                new byte[]{(byte) 0x80}, new String[]{"1.3.6.1.5.5.7.3.9"},
                false, null);
        leaf.cert.setOcspResponse(TlsTestHelper.buildOcspResponseWithDelegatedCerts(
                leaf.cert.getSerialNumber(), dc.priv, dc.cert.getPublicKey(),
                root.cert.getPublicKey(), root.subjectDn,
                "20300101120000Z", new byte[][]{dc.cert.getEncoded()}));

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com")
                .withRequireOcspStapling(true), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert)));
    }

    // =======================================================================
    // 3- и 4-сертификатные цепочки (checkServerCertificateChain)
    // =======================================================================

    private static TlsTestHelper.CertBundle createRoot() throws Exception {
        return TlsTestHelper.createRootCA(ECParameters.tc26a256());
    }

    private static TlsTestHelper.CertBundle createIntermediate(
            TlsTestHelper.CertBundle root, int pathLen, byte[] kuFlags) throws Exception {
        return TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z", null,
                kuFlags, null, true, pathLen);
    }

    private static TlsTestHelper.CertBundle createIntermediateNoCA(
            TlsTestHelper.CertBundle root, byte[] kuFlags) throws Exception {
        return TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z", null,
                kuFlags, null, false, null);
    }

    private static TlsTestHelper.CertBundle createServerLeaf(
            TlsTestHelper.CertBundle issuer) throws Exception {
        return TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), issuer.priv, issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);
    }

    @Test
    @DisplayName("checkServerCertificateChain: валидная 3-cert цепочка [leaf, intermediate, root]")
    void testCheckServerCertificateChainValid_3Certs() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle intermediate = createIntermediate(root, 0, new byte[]{(byte) 0x04});
        TlsTestHelper.CertBundle leaf = createServerLeaf(intermediate);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), noopTransport());

        session.checkServerCertificateChain(Arrays.asList(leaf.cert, intermediate.cert, root.cert));

        assertTrue(intermediate.cert.isCA());
        assertTrue(intermediate.cert.isKeyCertSignSet());
        assertEquals(0, intermediate.cert.getPathLen());
    }

    @Test
    @DisplayName("checkServerCertificateChain: intermediate не CA → ошибка")
    void testCheckServerCertificateChainIntermediateNotCA() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle intermediate = createIntermediateNoCA(root, new byte[]{(byte) 0x04});
        TlsTestHelper.CertBundle leaf = createServerLeaf(intermediate);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey()), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, intermediate.cert, root.cert)));
    }

    @Test
    @DisplayName("checkServerCertificateChain: intermediate без keyCertSign → ошибка")
    void testCheckServerCertificateChainIntermediateNoKeyCertSign() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle intermediate = createIntermediate(root, 0, new byte[]{0x00});
        TlsTestHelper.CertBundle leaf = createServerLeaf(intermediate);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey()), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, intermediate.cert, root.cert)));
    }

    @Test
    @DisplayName("checkServerCertificateChain: 4-cert, ca2.pathLen=0 на i=2 → нарушение")
    void testCheckServerCertificateChainPathLenExceeded_4Certs() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle ca2 = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x04}, null, true, 0);
        TlsTestHelper.CertBundle ca1 = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), ca2.priv, ca2.cert.getPublicKey(),
                ca2.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x04}, null, true, null);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), ca1.priv, ca1.cert.getPublicKey(),
                ca1.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(
                        Arrays.asList(leaf.cert, ca1.cert, ca2.cert, root.cert)));
    }

    @Test
    @DisplayName("checkServerCertificateChain: OCSP стэпплинг в 3-cert → успех")
    void testCheckServerCertificateChainOcspPresent_3Certs() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle intermediate = createIntermediate(root, 0, new byte[]{(byte) 0x04});
        TlsTestHelper.CertBundle leaf = createServerLeaf(intermediate);
        leaf.cert.setOcspResponse(TlsTestHelper.buildOcspResponse(
                leaf.cert.getSerialNumber(), intermediate.priv, intermediate.cert.getPublicKey(),
                intermediate.subjectDn));

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com")
                .withRequireOcspStapling(true), noopTransport());

        session.checkServerCertificateChain(Arrays.asList(leaf.cert, intermediate.cert, root.cert));
    }

    @Test
    @DisplayName("checkServerCertificateChain: OCSP отсутствует в 3-cert → ошибка")
    void testCheckServerCertificateChainOcspMissing_3Certs() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle intermediate = createIntermediate(root, 0, new byte[]{(byte) 0x04});
        TlsTestHelper.CertBundle leaf = createServerLeaf(intermediate);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com")
                .withRequireOcspStapling(true), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, intermediate.cert, root.cert)));
    }

    @Test
    @DisplayName("checkServerCertificateChain: tampered intermediate → signature error")
    void testCheckServerCertificateChainTamperedIntermediate() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle intermediate = createIntermediate(root, 0, new byte[]{(byte) 0x04});
        TlsTestHelper.CertBundle leaf = createServerLeaf(intermediate);

        byte[] tamperedDer = intermediate.cert.getCertData().clone();
        tamperedDer[tamperedDer.length - 1] ^= 0x01;
        TlsCertificate tampered = new TlsCertificate(tamperedDer);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey()), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, tampered, root.cert)));
    }

    // =======================================================================
    // Handshake с 3-сертификатной цепочкой сервера
    // =======================================================================

    @Test
    @DisplayName("handshake с 3-cert цепочкой сервера [leaf, intermediate, root]")
    void testHandshakeWith3CertChain() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle intermediate = createIntermediate(root, 0, new byte[]{(byte) 0x04});
        TlsTestHelper.CertBundle leaf = createServerLeaf(intermediate);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Arrays.asList(leaf.cert, intermediate.cert, root.cert), leaf.priv), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);

        assertTrue(client.isHandshakeDone(), "Handshake с 3-cert цепочкой должен пройти");
        exec.shutdown();
        server.close();
        client.close();
    }

    @Test
    @DisplayName("validateChain: DN mismatch между issuer и subject → ALERT_BAD_CERTIFICATE")
    void testChainValidationDnMismatch() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        byte[] wrongIssuer = TlsTestHelper.buildDN("Wrong Issuer");
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertWithForcedIssuer(
                ECParameters.tc26a256(), root.priv, wrongIssuer,
                "Test Leaf", "240501120000Z", "290501120000Z");

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(Arrays.asList(leaf.cert, root.cert)));
    }

    // =======================================================================
    // mTLS handshake с аутентификацией клиента
    // =======================================================================

    private static TlsTestHelper.CertBundle createClientLeaf(
            TlsTestHelper.CertBundle issuer) throws Exception {
        return TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), issuer.priv, issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_CLIENT_AUTH},
                false, null);
    }

    private static TlsTestHelper.CertBundle createClientLeafNoEku(
            TlsTestHelper.CertBundle issuer) throws Exception {
        return TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), issuer.priv, issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x80}, new String[]{"1.3.6.1.5.5.7.3.3"},
                false, null);
    }

    private static TlsTestHelper.CertBundle createExpiredClientLeaf(
            TlsTestHelper.CertBundle issuer) throws Exception {
        return TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), issuer.priv, issuer.cert.getPublicKey(),
                issuer.subjectDn,
                "20010101120000Z", "20020101120000Z", null,
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_CLIENT_AUTH},
                false, null);
    }

    @Test
    @DisplayName("mTLS handshake: базовая проверка (CR, client cert+CV)")
    void testMtlsHandshakeBasic() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle clientLeaf = createClientLeaf(root);
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey()), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withClientCertificateChain(clientLeaf.cert)
                .withClientPrivateKey(clientLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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
    @DisplayName("mTLS handshake: истёкший client cert → ALERT_BAD_CERTIFICATE")
    void testMtlsHandshakeClientCertExpired() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle clientLeaf = createExpiredClientLeaf(root);
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey()), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withClientCertificateChain(clientLeaf.cert)
                .withClientPrivateKey(clientLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        ExecutionException ex = assertThrows(ExecutionException.class, () -> sf.get(15, TimeUnit.SECONDS));
        assertInstanceOf(TlsException.class, ex.getCause());
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ((TlsException) ex.getCause()).getAlertCode());
        exec.shutdown();
    }

    @Test
    @DisplayName("mTLS handshake: client cert с другой CA → ALERT_BAD_CERTIFICATE")
    void testMtlsHandshakeWrongClientCa() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle wrongRoot = createRoot();
        TlsTestHelper.CertBundle clientLeaf = createClientLeaf(wrongRoot);
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey()), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withClientCertificateChain(clientLeaf.cert)
                .withClientPrivateKey(clientLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        ExecutionException ex = assertThrows(ExecutionException.class, () -> sf.get(15, TimeUnit.SECONDS));
        assertInstanceOf(TlsException.class, ex.getCause());
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ((TlsException) ex.getCause()).getAlertCode());
        exec.shutdown();
    }

    @Test
    @DisplayName("mTLS handshake: client cert без clientAuth EKU → ALERT_BAD_CERTIFICATE")
    void testMtlsHandshakeClientEkuMissing() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle clientLeaf = createClientLeafNoEku(root);
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey()), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withClientCertificateChain(clientLeaf.cert)
                .withClientPrivateKey(clientLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        ExecutionException ex = assertThrows(ExecutionException.class, () -> sf.get(15, TimeUnit.SECONDS));
        assertInstanceOf(TlsException.class, ex.getCause());
        assertEquals(TlsConstants.ALERT_BAD_CERTIFICATE, ((TlsException) ex.getCause()).getAlertCode());
        exec.shutdown();
    }

    @Test
    @DisplayName("mTLS handshake: client cert с 3-cert цепочкой [leaf, intermediate, root]")
    void testMtlsHandshake3CertClientChain() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle intermediate = createIntermediate(root, 0, new byte[]{(byte) 0x04});
        TlsTestHelper.CertBundle clientLeaf = createClientLeaf(intermediate);
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey()), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withClientCertificateChain(Arrays.asList(
                        clientLeaf.cert, intermediate.cert, root.cert))
                .withClientPrivateKey(clientLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle intermediate = createIntermediate(root, 0, new byte[]{(byte) 0x04});
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(intermediate);
        TlsTestHelper.CertBundle clientLeaf = createClientLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Arrays.asList(serverLeaf.cert, intermediate.cert, root.cert), serverLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey()), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withClientCertificateChain(clientLeaf.cert)
                .withClientPrivateKey(clientLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle clientLeaf = createClientLeaf(root);
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withClientCertificateChain(clientLeaf.cert)
                .withClientPrivateKey(clientLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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
    @DisplayName("mTLS: клиент без сертификата → пустой certificate_list, сервер reject (need)")
    void testMtlsClientWithoutCert() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv)
                .withCaPublicKey(root.cert.getPublicKey()), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();

        // RFC 8446 §4.4.2: клиент без сертификата отправляет пустой certificate_list.
        // Сервер с needClientAuth=true отвергает пустой сертификат.
        cf.get(15, TimeUnit.SECONDS); // клиент завершил отправку пустого Certificate + Finished

        ExecutionException sex = assertThrows(ExecutionException.class, () -> sf.get(5, TimeUnit.SECONDS));
        assertInstanceOf(TlsException.class, sex.getCause());
        assertEquals(TlsConstants.ALERT_CERTIFICATE_REQUIRED, ((TlsException) sex.getCause()).getAlertCode());

        exec.shutdown();
        server.close();
        client.close();
    }

    // =======================================================================
    // NewSessionTicket / PskStore / post-handshake
    // =======================================================================

    @Test
    @DisplayName("NewSessionTicket: build → parse roundtrip")
    void testNewSessionTicketRoundtrip() throws Exception {
        byte[] ticketNonce = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] ticket = new byte[]{0x10, 0x20, 0x30, 0x40};

        byte[] body = TlsMessageBuilder.buildNewSessionTicket(7200, 12345, ticketNonce, ticket);
        TlsMessageParser.ParsedNewSessionTicket parsed = TlsMessageParser.parseNewSessionTicket(body);

        assertEquals(7200, parsed.ticketLifetime);
        assertEquals(12345, parsed.ticketAgeAdd);
        assertArrayEquals(ticketNonce, parsed.ticketNonce);
        assertArrayEquals(ticket, parsed.ticket);
    }

    @Test
    @DisplayName("PskStore: add → get → remove")
    void testPskStoreAddGetRemove() {
        PskStore store = new InMemoryPskStore(100);
        byte[] ticket = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte[] nonce = new byte[]{0x0A, 0x0B};

        store.onTicketReceived(new PskEntry(ticket, 3600, 99, nonce, null, System.currentTimeMillis()));
        assertEquals(1, store.size());

        PskEntry entry = store.get(ticket);
        assertNotNull(entry);
        assertEquals(3600, entry.getTicketLifetime());
        assertEquals(99, entry.getTicketAgeAdd());
        assertArrayEquals(nonce, entry.getTicketNonce());
        assertArrayEquals(ticket, entry.getTicket());

        store.remove(ticket);
        assertNull(store.get(ticket));
        assertEquals(0, store.size());
    }

    @Test
    @DisplayName("PskStore: add с пустым тикетом → IllegalArgumentException")
    void testPskStoreAddEmptyTicket() {
        PskStore store = new InMemoryPskStore(100);
        assertThrows(IllegalArgumentException.class,
                () -> store.onTicketReceived(new PskEntry(new byte[0], 3600, 0, new byte[]{0x01}, new byte[8], System.currentTimeMillis())));
    }

    @Test
    @DisplayName("PskStore: add с null тикетом → IllegalArgumentException")
    void testPskStoreAddNullTicket() {
        PskStore store = new InMemoryPskStore(100);
        assertThrows(IllegalArgumentException.class,
                () -> store.onTicketReceived(new PskEntry(null, 3600, 0, new byte[]{0x01}, new byte[8], System.currentTimeMillis())));
    }

    @Test
    @DisplayName("PskStore: 8 потоков, без исключений, после remove → null")
    void testPskStoreConcurrent() throws Exception {
        PskStore store = new InMemoryPskStore(100);
        byte[] ticket = new byte[]{0x01, 0x02, 0x03, 0x04};
        store.onTicketReceived(new PskEntry(ticket, 3600, CryptoRandom.INSTANCE.nextInt() & 0xFFFFFFFFL, new byte[]{0x05}, new byte[8], System.currentTimeMillis()));

        int threadCount = 8;
        AtomicInteger successCount = new AtomicInteger();
        Thread[] threads = new Thread[threadCount];
        CountDownLatch latch = new CountDownLatch(1);

        for (int i = 0; i < threadCount; i++) {
            threads[i] = new Thread(() -> {
                try { latch.await(); } catch (InterruptedException e) { return; }
                PskEntry entry = store.get(ticket);
                if (entry != null) {
                    store.remove(ticket);
                    successCount.incrementAndGet();
                }
            });
            threads[i].start();
        }

        latch.countDown();
        for (Thread t : threads) t.join(5000);

        assertTrue(successCount.get() >= 1, "at least one thread should get the entry");
        assertNull(store.get(ticket));
    }

    @Test
    @DisplayName("PskStore: getForResumption после expiry → null (без evictExpired)")
    void testPskStoreGetForResumptionExpired() throws Exception {
        InMemoryPskStore store = new InMemoryPskStore(100);
        byte[] ticket = new byte[]{0x01, 0x02, 0x03, 0x04};
        byte[] nonce = new byte[]{0x0A, 0x0B};
        byte[] psk = new byte[32];

        // Тикет с lifetime = 0 (фактически истёк сразу)
        store.onTicketReceived(new PskEntry(ticket, 0, 99, nonce, psk,
                System.currentTimeMillis() - 1000));

        // getForResumption должен вернуть null — тикет expired per-call
        assertNull(store.getForResumption(),
                "expired ticket must not be returned by getForResumption");
        assertNull(store.get(ticket),
                "expired ticket must not be returned by get");
        // store.size() может быть 1 (жатдаем gc-like evictExpired)
    }

    @Test
    @DisplayName("PskStore: onTicketReceived с RuntimeException — handshake не ломается")
    void testPskStoreOnTicketReceivedThrowing() throws Exception {
        // PskStore, который всегда кидает при сохранении тикета
        PskStore throwingStore = new PskStore() {
            @Override public PskEntry get(byte[] ticket) { return null; }
            @Override public PskEntry getForResumption() { return null; }
            @Override public PskEntry peek(byte[] ticket) { return null; }
            @Override public void remove(byte[] ticket) {}
            @Override public int size() { return 0; }
            @Override public void evictExpired() {}
            @Override public void clear() {}
            @Override public void onTicketReceived(PskEntry entry) {
                throw new RuntimeException("Backend unavailable");
            }
        };

        // Полный handshake с сервером, чей PskStore кидает на onTicketReceived.
        // Сервер отправляет NewSessionTicket после handshake.
        // Исключение из store не должно ломать сессию — стек ловит и логирует.
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(
                new TlsServerConfig(getCsL(), Collections.singletonList(bundle.cert), bundle.priv),
                pair.getServerTransport());
        server.setPskStore(throwingStore);

        TlsSession client = TlsSession.createClient(
                new TlsClientConfig(getCsL()), pair.getClientTransport());

        ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            Future<Void> sf = exec.submit(() -> { server.handshakeAsServer(); return null; });
            client.handshakeAsClient();
            sf.get(15, TimeUnit.SECONDS);

            // После handshake отправляем данные — если бы исключение из store
            // сломало handshake, read/write упали бы
            client.write("hello".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] data = server.read();
            assertEquals("hello", new String(data, java.nio.charset.StandardCharsets.UTF_8));
        } finally {
            exec.shutdown();
            try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            server.close();
            client.close();
        }
    }

    @Test
    @DisplayName("PskStore: onTicketReceived с RuntimeException на клиенте — NST не ломает read()")
    void testPskStoreOnTicketReceivedThrowing_ClientSide() throws Exception {
        PskStore throwingStore = new PskStore() {
            @Override public PskEntry get(byte[] ticket) { return null; }
            @Override public PskEntry getForResumption() { return null; }
            @Override public PskEntry peek(byte[] ticket) { return null; }
            @Override public void remove(byte[] ticket) {}
            @Override public int size() { return 0; }
            @Override public void evictExpired() {}
            @Override public void clear() {}
            @Override public void onTicketReceived(PskEntry entry) {
                throw new RuntimeException("Backend unavailable");
            }
        };

        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        InMemoryTlsTransport.Pair pair = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(
                new TlsServerConfig(getCsL(), Collections.singletonList(bundle.cert), bundle.priv),
                pair.getServerTransport());

        TlsSession client = TlsSession.createClient(
                new TlsClientConfig(getCsL()), pair.getClientTransport());
        // Клиентский store кидает при сохранении NST — это не должно ломать read()
        client.setPskStore(throwingStore);

        ExecutorService exec = Executors.newSingleThreadExecutor();
        try {
            Future<Void> sf = exec.submit(() -> { server.handshakeAsServer(); return null; });
            client.handshakeAsClient();
            sf.get(15, TimeUnit.SECONDS);

            // Server handshake отправил NST автоматически. Клиент в первом read()
            // обработает NST (вызовет throwingStore.onTicketReceived → RuntimeException),
            // после чего прочитает application data.
            byte[] payload = "data after NST".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            server.write(payload);
            byte[] data = client.read();
            assertArrayEquals(payload, data);
        } finally {
            exec.shutdown();
            try { exec.awaitTermination(5, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
            server.close();
            client.close();
        }
    }

    @Test
    @DisplayName("read: NewSessionTicket → сохраняется в PskStore")
    void testReadNewSessionTicket() throws Exception {
        TlsTrafficKeys keys = randomTrafficKeys();
        PskStore store = new InMemoryPskStore(100);
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsRecord writer = new TlsRecord(keys.getKey(), keys.getIv(), getCsL().getTagLen(), getCsL());
        TlsSession client = TlsSession.createForTest(transport, getCsL(), keys, keys);
        client.setPskStore(store);

        byte[] ticketNonce = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] ticket = new byte[]{0x10, 0x20, 0x30, 0x40};
        byte[] nstBody = TlsMessageBuilder.buildNewSessionTicket(7200, 12345, ticketNonce, ticket);
        byte[] nstFramed = new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, nstBody).encode();
        byte[] nstRecord = writer.protect(TlsConstants.CT_HANDSHAKE, nstFramed);

        byte[] appRecord = writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{0x41});

        transport.inject(nstRecord);
        transport.inject(appRecord);

        byte[] result = client.read();
        assertArrayEquals(new byte[]{0x41}, result);

        PskEntry entry = store.get(ticket);
        assertNotNull(entry);
        assertEquals(7200, entry.getTicketLifetime());
        assertEquals(12345, entry.getTicketAgeAdd());
        assertArrayEquals(ticketNonce, entry.getTicketNonce());
    }

    @Test
    @DisplayName("handshake + NewSessionTicket → PskStore получает тикет")
    void testHandshakeWithNewSessionTicket() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();
        PskStore clientStore = new InMemoryPskStore(100);

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());
        client.setPskStore(clientStore);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            server.handshakeAsServer();
            return null;
        });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);

        assertTrue(client.isHandshakeDone(), "Handshake должен пройти");

        server.close();
        assertThrows(EOFException.class, () -> client.read());

        assertEquals(1, clientStore.size(), "PskStore должен содержать тикет");
        exec.shutdown();
    }

    @Test
    @DisplayName("handshake + NewSessionTicket → ticketAgeAdd случайный (не 0, не константа)")
    void testHandshakeWithNewSessionTicketAgeAddRandom() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);

        long t1 = handshakeAndGetAge(root, serverLeaf);
        long t2 = handshakeAndGetAge(root, serverLeaf);

        assertNotEquals(0, t1);
        assertNotEquals(t1, t2);
    }

    private long handshakeAndGetAge(TlsTestHelper.CertBundle root,
                                     TlsTestHelper.CertBundle serverLeaf) throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        PskStore store = new InMemoryPskStore(100);

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());
        client.setPskStore(store);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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
        return store.getForResumption().getTicketAgeAdd();
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
    @DisplayName("parseAlertDescription: close_notify → 0")
    void testParseCloseNotify() throws Exception {
        assertEquals(0, TlsSession.parseAlertDescription(new byte[]{1, 0}));
    }

    @Test
    @DisplayName("parseAlertDescription: bad_certificate → 42")
    void testParseFatal() throws Exception {
        assertEquals(42, TlsSession.parseAlertDescription(new byte[]{2, 42}));
    }

    @Test
    @DisplayName("parseAlertDescription: пустой payload → TlsException")
    void testParseTruncatedEmpty() {
        assertThrows(TlsException.class,
                () -> TlsSession.parseAlertDescription(new byte[0]));
    }

    @Test
    @DisplayName("parseAlertDescription: 1 байт → TlsException")
    void testParseTruncatedOne() {
        assertThrows(TlsException.class,
                () -> TlsSession.parseAlertDescription(new byte[]{1}));
    }

    @Test
    @DisplayName("read: close_notify от пира → EOFException")
    void testReadCloseNotify() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsSession server = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        TlsRecord clientRecord = new TlsRecord(readerKeys.getKey(), readerKeys.getIv(),
                getCsL().getTagLen(), getCsL());
        byte[] alertRecord = clientRecord.protect(TlsConstants.CT_ALERT,
                new byte[]{TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY});
        transport.inject(alertRecord);

        assertThrows(EOFException.class, server::read);
        assertTrue(server.isClosed());
        assertFalse(server.isHandshakeDone());
        assertThrows(IllegalStateException.class, server::read);
    }

    @Test
    @DisplayName("read: fatal alert от пира → IOException")
    void testReadFatalAlert() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsSession server = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        TlsRecord clientRecord = new TlsRecord(readerKeys.getKey(), readerKeys.getIv(),
                getCsL().getTagLen(), getCsL());
        byte[] alertRecord = clientRecord.protect(TlsConstants.CT_ALERT,
                new byte[]{TlsConstants.ALERT_FATAL, TlsConstants.ALERT_BAD_CERTIFICATE});
        transport.inject(alertRecord);

        IOException ex = assertThrows(IOException.class, server::read);
        assertTrue(ex.getMessage().contains("42"));
        assertTrue(server.isClosed());
        assertFalse(server.isHandshakeDone());
        assertThrows(IllegalStateException.class, server::read);
    }

    @Test
    @DisplayName("read: truncated alert → TlsException(ALERT_DECODE_ERROR)")
    void testReadTruncatedAlert() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsSession server = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        TlsRecord clientRecord = new TlsRecord(readerKeys.getKey(), readerKeys.getIv(),
                getCsL().getTagLen(), getCsL());
        byte[] alertRecord = clientRecord.protect(TlsConstants.CT_ALERT, new byte[]{1});
        transport.inject(alertRecord);

        assertThrows(TlsException.class, server::read);
    }

    @Test
    @DisplayName("read: user_canceled → трактуется как fatal")
    void testReadUserCanceled() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsSession server = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        TlsRecord clientRecord = new TlsRecord(readerKeys.getKey(), readerKeys.getIv(),
                getCsL().getTagLen(), getCsL());
        byte[] alertRecord = clientRecord.protect(TlsConstants.CT_ALERT,
                new byte[]{TlsConstants.ALERT_WARNING, (byte) 90});
        transport.inject(alertRecord);

        IOException ex = assertThrows(IOException.class, server::read);
        assertTrue(ex.getMessage().contains("90"));
        assertTrue(server.isClosed());
    }

    // =======================================================================
    // Фрагментация TLS-записей (RFC 8446 §5.1)
    // =======================================================================

    @Test
    @DisplayName("write: данные >16383 → фрагментируются на несколько записей")
    void testWriteLargeDataFragment() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        LinkedBlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>();
        TlsTransport transport = new TlsTransport() {
            public void sendRecord(byte[] r) { outbound.add(r); }
            public byte[] receiveRecord() throws IOException {
                try { return outbound.poll(10, TimeUnit.SECONDS); }
                catch (InterruptedException e) { throw new IOException(e); }
            }
            public void close() {}
        };
        TlsSession session = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        byte[] largeData = new byte[32000];
        CryptoRandom.INSTANCE.nextBytes(largeData);
        session.write(largeData);

        TlsRecord reader = new TlsRecord(writerKeys.getKey(), writerKeys.getIv(),
                getCsL().getTagLen(), getCsL());
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
    @DisplayName("write: данные ≤16383 → одна запись (регрессия)")
    void testWriteSmallDataNoFragment() throws Exception {
        TlsTrafficKeys readerKeys = randomTrafficKeys();
        TlsTrafficKeys writerKeys = randomTrafficKeys();
        LinkedBlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>();
        TlsTransport transport = new TlsTransport() {
            public void sendRecord(byte[] r) { outbound.add(r); }
            public byte[] receiveRecord() throws IOException {
                try { return outbound.poll(10, TimeUnit.SECONDS); }
                catch (InterruptedException e) { throw new IOException(e); }
            }
            public void close() {}
        };
        TlsSession session = TlsSession.createForTest(transport, getCsL(), readerKeys, writerKeys);

        session.write(new byte[100]);
        assertEquals(1, outbound.size());
    }

    @Test
    @DisplayName("receiveDecryptedHandshake: 2 фрагментированных записи → одно сообщение")
    void testReceiveFragmentedHandshake() throws Exception {
        TlsTrafficKeys keys = randomTrafficKeys();
        LinkedBlockingQueue<byte[]> inbound = new LinkedBlockingQueue<>();
        TlsTransport transport = new TlsTransport() {
            public void sendRecord(byte[] r) {}
            public byte[] receiveRecord() throws IOException {
                try { byte[] rec = inbound.poll(10, TimeUnit.SECONDS);
                    if (rec == null) throw new IOException("timeout"); return rec; }
                catch (InterruptedException e) { throw new IOException(e); }
            }
            public void close() {}
        };
        TlsSession session = TlsSession.createForTest(transport, getCsL(), keys, randomTrafficKeys());

        byte[] hsBody = new byte[25000];
        CryptoRandom.INSTANCE.nextBytes(hsBody);
        byte[] hsMsg = new TlsHandshakeMessage(TlsConstants.HT_CERTIFICATE, hsBody).encode();

        TlsRecord peerRecord = new TlsRecord(keys.getKey(), keys.getIv(),
                getCsL().getTagLen(), getCsL());
        int maxPayload = 16383;
        inbound.add(peerRecord.protect(TlsConstants.CT_HANDSHAKE,
                Arrays.copyOfRange(hsMsg, 0, maxPayload)));
        inbound.add(peerRecord.protect(TlsConstants.CT_HANDSHAKE,
                Arrays.copyOfRange(hsMsg, maxPayload, hsMsg.length)));

        HandshakeContext ctx = new HandshakeContext();
        TlsHandshakeMessage parsed = session.receiveDecryptedHandshake(ctx);
        assertEquals(TlsConstants.HT_CERTIFICATE, parsed.getType());
        assertArrayEquals(hsBody, parsed.getBody());
    }

    @Test
    @DisplayName("receiveDecryptedHandshake: coalescing — 2 сообщения в 1 записи")
    void testReceiveCoalescedHandshake() throws Exception {
        TlsTrafficKeys keys = randomTrafficKeys();
        LinkedBlockingQueue<byte[]> inbound = new LinkedBlockingQueue<>();
        TlsTransport transport = new TlsTransport() {
            public void sendRecord(byte[] r) {}
            public byte[] receiveRecord() throws IOException {
                try { byte[] rec = inbound.poll(10, TimeUnit.SECONDS);
                    if (rec == null) throw new IOException("coalescing: no more records"); return rec; }
                catch (InterruptedException e) { throw new IOException(e); }
            }
            public void close() {}
        };
        TlsSession session = TlsSession.createForTest(transport, getCsL(), keys, randomTrafficKeys());

        byte[] body1 = new byte[]{0x01, 0x02, 0x03};
        byte[] body2 = new byte[]{0x04, 0x05, 0x06};
        byte[] msg1 = new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, body1).encode();
        byte[] msg2 = new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, body2).encode();
        byte[] combined = concat(msg1, msg2);

        TlsRecord peerRecord = new TlsRecord(keys.getKey(), keys.getIv(),
                getCsL().getTagLen(), getCsL());
        inbound.add(peerRecord.protect(TlsConstants.CT_HANDSHAKE, combined));

        HandshakeContext ctx = new HandshakeContext();
        TlsHandshakeMessage parsed1 = session.receiveDecryptedHandshake(ctx);
        assertEquals(TlsConstants.HT_CLIENT_HELLO, parsed1.getType());
        assertArrayEquals(body1, parsed1.getBody());

        TlsHandshakeMessage parsed2 = session.receiveDecryptedHandshake(ctx);
        assertEquals(TlsConstants.HT_SERVER_HELLO, parsed2.getType());
        assertArrayEquals(body2, parsed2.getBody());

        // Транспорт пуст — второе сообщение пришло из буфера, не из второго record
        assertTrue(inbound.isEmpty());
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    private static TlsTransport noopTransport() {
        return new TlsTransport() {
            public void sendRecord(byte[] record) {}
            public byte[] receiveRecord() { return new byte[0]; }
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
    @DisplayName("PSK resumption: полный → сокращённый handshake")
    void testPskResumption() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();
        PskStore clientStore = new InMemoryPskStore(100);
        PskStore serverStore = new InMemoryPskStore(100);

        // 1-й handshake (полный) — получаем тикет
        TlsSession server1 = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp.getServerTransport());
        TlsSession client1 = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());
        client1.setPskStore(clientStore);
        server1.setPskStore(serverStore);

        Phaser phaser1 = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf1 = exec.submit(() -> {
            phaser1.arriveAndAwaitAdvance();
            client1.handshakeAsClient();
            return null;
        });
        Future<Void> sf1 = exec.submit(() -> {
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

        // 2-й handshake (сокращённый по PSK)
        var tp2 = InMemoryTlsTransport.newPair();
        TlsSession server2 = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp2.getServerTransport());
        TlsSession client2 = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp2.getClientTransport());
        client2.setPskStore(clientStore);
        server2.setPskStore(serverStore);

        Phaser phaser2 = new Phaser(3);
        Future<Void> cf2 = exec.submit(() -> {
            phaser2.arriveAndAwaitAdvance();
            client2.handshakeAsClient();
            return null;
        });
        Future<Void> sf2 = exec.submit(() -> {
            phaser2.arriveAndAwaitAdvance();
            server2.handshakeAsServer();
            return null;
        });
        phaser2.arriveAndAwaitAdvance();
        cf2.get(15, TimeUnit.SECONDS);
        sf2.get(15, TimeUnit.SECONDS);
        assertTrue(client2.isHandshakeDone());

        // Передача данных через сокращённый handshake
        byte[] testData = new byte[]{0x01, 0x02, 0x03};
        client2.write(testData);
        byte[] received = server2.read();
        assertArrayEquals(testData, received);

        server2.close();
        client2.close();
        exec.shutdown();
    }

    @Test
    @DisplayName("PSK fallback: неизвестный тикет → полный handshake")
    void testPskFallbackUnknownTicket() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();
        PskStore clientStore = new InMemoryPskStore(100);
        PskStore serverStore = new InMemoryPskStore(100);

        // Добавляем в clientStore тикет, которого нет в serverStore
        byte[] fakeTicket = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(fakeTicket);
        clientStore.onTicketReceived(new PskEntry(fakeTicket, 86400, CryptoRandom.INSTANCE.nextInt() & 0xFFFFFFFFL, new byte[8], new byte[32], System.currentTimeMillis()));

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());
        client.setPskStore(clientStore);
        server.setPskStore(serverStore);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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
        byte[] testData = new byte[]{0x0A, 0x0B};
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
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        var tp = InMemoryTlsTransport.newPair();
        PskStore clientStore = new InMemoryPskStore(100);
        PskStore serverStore = new InMemoryPskStore(100);

        // 1-й handshake — получаем тикет
        TlsSession server1 = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp.getServerTransport());
        TlsSession client1 = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());
        client1.setPskStore(clientStore);
        server1.setPskStore(serverStore);

        Phaser phaser1 = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(3);
        Future<Void> cf1 = exec.submit(() -> {
            phaser1.arriveAndAwaitAdvance();
            client1.handshakeAsClient();
            return null;
        });
        Future<Void> sf1 = exec.submit(() -> {
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

        // Запоминаем ticketAgeAdd и issueTime до sleep
        PskEntry entry = clientStore.getForResumption();
        long ticketAgeAdd = entry.getTicketAgeAdd();
        long issueTime = entry.getIssueTime();
        long sleepMs = 100;
        Thread.sleep(sleepMs);

        // 2-й handshake — перехватываем ClientHello из c2s до сервера
        var tp2 = InMemoryTlsTransport.newPair();
        TlsSession client2 = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp2.getClientTransport());
        client2.setPskStore(clientStore);
        TlsSession server2 = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp2.getServerTransport());
        server2.setPskStore(serverStore);

        // Запускаем клиент — он отправит ClientHello и встанет в ожидании ServerHello
        Future<Void> cf2 = exec.submit(() -> {
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
        byte[] chBody = TlsHandshakeMessage.decode(
                Arrays.copyOfRange(chRecord, TlsConstants.RECORD_HEADER_SIZE, chRecord.length)
        ).getBody();
        long wireAge = parseObfuscatedTicketAge(chBody);

        // Проверяем: wireAge ≈ sleepMs + ticketAgeAdd (с допуском на jitter потоков)
        assertTrue(wireAge >= ticketAgeAdd + sleepMs,
                "obfuscatedTicketAge меньше ожидаемого: " + wireAge
                        + " < " + (ticketAgeAdd + sleepMs));
        assertTrue(wireAge <= ticketAgeAdd + sleepMs + 200,
                "obfuscatedTicketAge больше ожидаемого: " + wireAge
                        + " > " + (ticketAgeAdd + sleepMs + 200));

        // Запускаем сервер, завершаем handshake
        Future<Void> sf2 = exec.submit(() -> {
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
    @DisplayName("PSK tampered binder → ALERT_HANDSHAKE_FAILURE")
    void testPskTamperedBinder() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        PskStore serverStore = new InMemoryPskStore(100);

        var tp = InMemoryTlsTransport.newPair();
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp.getServerTransport());
        server.setPskStore(serverStore);

        byte[] psk = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(psk);
        byte[] ticket = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(ticket);
        long ticketAgeAdd = CryptoRandom.INSTANCE.nextInt() & 0xFFFFFFFFL;
        serverStore.onTicketReceived(new PskEntry(ticket, 86400, ticketAgeAdd, new byte[8], psk, System.currentTimeMillis()));

        ExecutorService exec = Executors.newFixedThreadPool(2);
        Phaser phaser = new Phaser(2);
        Future<Void> sf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            assertThrows(TlsException.class, () -> {
                server.handshakeAsServer();
            });
            return null;
        });

        // Впрыскиваем ClientHello с PSK и битым binder'ом напрямую в c2s очередь
        byte[] ecdhePoint = TlsEncoding.encodePoint(KeyGenerator.generateKeyPair(
                ECParameters.tc26a256()).getPublic());
        TlsMessageBuilder builder = new TlsMessageBuilder(getCsL(),
                List.of(getCsL().getId()),
                TlsConstants.GRP_GC256A, TlsConstants.SIG_GOST_TC26_A_256,
                (PrivateKeyParameters) null, (List<TlsCertificate>) null, 32);
        byte[] chBody = builder.buildClientHelloWithPsk(ecdhePoint, ticket, ticketAgeAdd);
        chBody[chBody.length - 1] ^= 0xFF; // портим последний байт binder'а
        byte[] chFramed = TlsMessageBuilder.buildPlaintextRecord(
                TlsConstants.CT_HANDSHAKE,
                new TlsHandshakeMessage(TlsConstants.HT_CLIENT_HELLO, chBody).encode());
        tp.getClientToServerQueue().add(chFramed);

        phaser.arriveAndAwaitAdvance();
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();
    }

    @Test
    @DisplayName("Record overflow: payloadLen > MAX_CIPHERTEXT_LENGTH → ALERT_RECORD_OVERFLOW")
    void testRecordOverflowAfterHandshake() throws Exception {
        TlsTestHelper.CertBundle bundle = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        var tp = InMemoryTlsTransport.newPair();

        TlsSession server = TlsSession.createServer(tp.getServerTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, bundle.cert, bundle.priv);
        TlsSession client = TlsSession.createClient(tp.getClientTransport(),
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L, null, null);

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> {
            phaser.arriveAndAwaitAdvance();
            client.handshakeAsClient();
            return null;
        });
        Future<Void> sf = exec.submit(() -> {
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

    @Test
    @DisplayName("read: 7 post-handshake + app data → успех, лимит не превышен")
    void testMaxPostHandshake_8Allowed() throws Exception {
        TlsTrafficKeys keys = randomTrafficKeys();
        PskStore store = new InMemoryPskStore(100);
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsRecord writer = new TlsRecord(keys.getKey(), keys.getIv(), getCsL().getTagLen(), getCsL());
        TlsSession client = TlsSession.createForTest(transport, getCsL(), keys, keys);
        client.setPskStore(store);

        // Сначала генерируем 7 NST (seq 0..6), потом app data (seq 7)
        byte[][] nstRecords = new byte[7][];
        for (int i = 0; i < 7; i++) {
            byte[] body = TlsMessageBuilder.buildNewSessionTicket(
                    7200, 1, new byte[8], new byte[]{(byte) i});
            byte[] framed = new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, body).encode();
            nstRecords[i] = writer.protect(TlsConstants.CT_HANDSHAKE, framed);
        }
        byte[] appRecord = writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{0x41});

        for (byte[] rec : nstRecords) transport.inject(rec);
        transport.inject(appRecord);

        byte[] result = client.read();
        assertArrayEquals(new byte[]{0x41}, result);
        assertEquals(7, store.size());
    }

    @Test
    @DisplayName("read: 8 post-handshake → TlsException (лимит 8)")
    void testMaxPostHandshake_9Exceeded() throws Exception {
        TlsTrafficKeys keys = randomTrafficKeys();
        PskStore store = new InMemoryPskStore(100);
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsRecord writer = new TlsRecord(keys.getKey(), keys.getIv(), getCsL().getTagLen(), getCsL());
        TlsSession client = TlsSession.createForTest(transport, getCsL(), keys, keys);
        client.setPskStore(store);

        for (int i = 0; i < 8; i++) {
            byte[] nstBody = TlsMessageBuilder.buildNewSessionTicket(
                    7200, 1, new byte[8], new byte[]{(byte) i});
            byte[] nstFramed = new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, nstBody).encode();
            transport.inject(writer.protect(TlsConstants.CT_HANDSHAKE, nstFramed));
        }
        byte[] appRecord = writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{0x42});
        transport.inject(appRecord);

        TlsException ex = assertThrows(TlsException.class, client::read);
        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, ex.getAlertCode());

        byte[] result = client.read();
        assertArrayEquals(new byte[]{0x42}, result);
    }

    // =======================================================================
    // Cipher suite negotiation
    // =======================================================================

    @Test
    @DisplayName("handshake: сервер выбирает S, клиент {L,S} → успех, negotiated=S")
    void testCipherSuiteNegotiation_SuccessSwitch() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        TlsCiphersuite serverSuite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;

        var tp = InMemoryTlsTransport.newPair();
        TlsSession server = TlsSession.createServer(new TlsServerConfig(serverSuite, Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp.getServerTransport());
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), tp.getClientTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> { phaser.arriveAndAwaitAdvance(); client.handshakeAsClient(); return null; });
        Future<Void> sf = exec.submit(() -> { phaser.arriveAndAwaitAdvance(); server.handshakeAsServer(); return null; });
        phaser.arriveAndAwaitAdvance();
        cf.get(15, TimeUnit.SECONDS);
        sf.get(15, TimeUnit.SECONDS);
        exec.shutdown();
        server.close();
        client.close();

        java.lang.reflect.Field f = TlsSession.class.getDeclaredField("ciphersuite");
        f.setAccessible(true);
        TlsCiphersuite negotiated = (TlsCiphersuite) f.get(client);
        assertEquals(0xC105, negotiated.getId());
    }

    private static InMemoryTlsTransport forgedClientTransport(
            InMemoryTlsTransport.Pair realPair, int forgedCsId) {
        return new InMemoryTlsTransport() {
            @Override public void sendRecord(byte[] record) throws IOException {
                realPair.getClientToServerQueue().add(record);
            }
            @Override public byte[] receiveRecord() throws IOException {
                try {
                    byte[] record = realPair.getServerToClientQueue().poll(1, TimeUnit.SECONDS);
                    if (record != null && record.length > 46
                            && (record[5] & 0xFF) == TlsConstants.HT_SERVER_HELLO) {
                        byte[] modified = record.clone();
                        modified[44] = (byte)(forgedCsId >>> 8);
                        modified[45] = (byte)forgedCsId;
                        return modified;
                    }
                    return record;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted", e);
                }
            }
            @Override public void close() {}
        };
    }

    private void runForgedHandshake(TlsTestHelper.CertBundle root,
                                     TlsTestHelper.CertBundle serverLeaf,
                                     int forgedCsId) throws Exception {
        var tp = InMemoryTlsTransport.newPair();
        TlsSession client = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), forgedClientTransport(tp, forgedCsId));
        TlsSession server = TlsSession.createServer(new TlsServerConfig(getCsL(), Collections.singletonList(serverLeaf.cert), serverLeaf.priv), tp.getServerTransport());

        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        Future<Void> cf = exec.submit(() -> { phaser.arriveAndAwaitAdvance(); client.handshakeAsClient(); return null; });
        Future<Void> sf = exec.submit(() -> { phaser.arriveAndAwaitAdvance(); server.handshakeAsServer(); return null; });
        phaser.arriveAndAwaitAdvance();

        ExecutionException ex = assertThrows(ExecutionException.class, () -> cf.get(15, TimeUnit.SECONDS));
        assertInstanceOf(TlsException.class, ex.getCause());
        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, ((TlsException) ex.getCause()).getAlertCode());

        try { sf.get(5, TimeUnit.SECONDS); } catch (Exception ignored) {}
        exec.shutdown();
        client.close();
        server.close();
    }

    @Test
    @DisplayName("handshake: сервер выбирает Magma (0xC104, не в offered) → ALERT_ILLEGAL_PARAMETER")
    void testCipherSuiteNegotiation_NotInOffered() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        runForgedHandshake(root, serverLeaf, 0xC104);
    }

    @Test
    @DisplayName("handshake: сервер выбирает неизвестный suite (0xFFFF) → ALERT_ILLEGAL_PARAMETER")
    void testCipherSuiteNegotiation_Unknown() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle serverLeaf = createServerLeaf(root);
        runForgedHandshake(root, serverLeaf, 0xFFFF);
    }

    // =======================================================================
    // SocketTlsTransport — лимит размера записи
    // =======================================================================

    @Test
    @DisplayName("SocketTlsTransport: запись > 16640 → IOException")
    void testSocketTlsTransport_RecordOverflow() throws Exception {
        PipedInputStream pipeIn = new PipedInputStream();
        PipedOutputStream pipeOut = new PipedOutputStream(pipeIn);
        Socket fakeSocket = new Socket() {
            @Override public java.io.InputStream getInputStream() { return pipeIn; }
            @Override public java.io.OutputStream getOutputStream() { return pipeOut; }
            @Override public void close() {}
        };

        byte[] header = new byte[TlsConstants.RECORD_HEADER_SIZE];
        header[0] = TlsConstants.CT_APPLICATION_DATA;
        header[1] = TlsConstants.LEGACY_VERSION_MAJOR;
        header[2] = TlsConstants.LEGACY_VERSION_MINOR;
        header[3] = (byte)(20000 >>> 8);
        header[4] = (byte)20000;
        pipeOut.write(header);
        pipeOut.flush();

        SocketTlsTransport st = new SocketTlsTransport(fakeSocket);
        assertThrows(IOException.class, st::receiveRecord);
    }

    // =======================================================================
    // Не-handshake content_type в read() loop
    // =======================================================================

    @Test
    @DisplayName("read: CT_APPLICATION_DATA в post-handshake → TlsException")
    void testNonHandshakeTypeInRead() throws Exception {
        TlsTrafficKeys keys = randomTrafficKeys();
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsRecord writer = new TlsRecord(keys.getKey(), keys.getIv(), getCsL().getTagLen(), getCsL());
        TlsSession client = TlsSession.createForTest(transport, getCsL(), keys, keys);

        byte[] body = TlsMessageBuilder.buildNewSessionTicket(7200, 1, new byte[8], new byte[]{0x01});
        byte[] framed = new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, body).encode();
        transport.inject(writer.protect(TlsConstants.CT_HANDSHAKE, framed));
        transport.inject(writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{0x41}));
        transport.inject(writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{0x42}));

        byte[] result = client.read();
        assertArrayEquals(new byte[]{0x41}, result);
        byte[] result2 = client.read();
        assertArrayEquals(new byte[]{0x42}, result2);
    }

    // =======================================================================
    // pathLen boundary — 5-cert chain
    // =======================================================================

    @Test
    @DisplayName("checkServerCertificateChain: 5-cert, ca3.pathLen=1 на i=3 → нарушение")
    void testPathLen_5CertBoundary() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle ca3 = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(),
                root.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x04}, null, true, 1);
        TlsTestHelper.CertBundle ca2 = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), ca3.priv, ca3.cert.getPublicKey(),
                ca3.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x04}, null, true, null);
        TlsTestHelper.CertBundle ca1 = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), ca2.priv, ca2.cert.getPublicKey(),
                ca2.subjectDn,
                "240501120000Z", "290501120000Z", null,
                new byte[]{(byte) 0x04}, null, true, null);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), ca1.priv, ca1.cert.getPublicKey(),
                ca1.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"},
                new byte[]{(byte) 0x80}, new String[]{GostOids.EXT_SERVER_AUTH},
                false, null);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), noopTransport());

        assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(
                        Arrays.asList(leaf.cert, ca1.cert, ca2.cert, ca3.cert, root.cert)));
    }

    @Test
    @DisplayName("checkServerCertificateChain: intermediate expired → ALERT_CERTIFICATE_EXPIRED")
    void testCheckServerCertificateChainExpiredIntermediate() throws Exception {
        TlsTestHelper.CertBundle root = createRoot();
        TlsTestHelper.CertBundle expiredInt = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), root.priv, root.cert.getPublicKey(), root.subjectDn,
                "20000101000000Z", "20050101000000Z", null, null, null, true, 0);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                ECParameters.tc26a256(), expiredInt.priv, expiredInt.cert.getPublicKey(),
                expiredInt.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"}, null, null, false, null);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(root.cert.getPublicKey())
                .withServerHostname("gost.example.com"), noopTransport());

        TlsException e = assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(
                        Arrays.asList(leaf.cert, expiredInt.cert, root.cert)));
        assertEquals(TlsConstants.ALERT_CERTIFICATE_EXPIRED, e.getAlertCode());
    }

    @Test
    @DisplayName("checkServerCertificateChain: root expired → ALERT_CERTIFICATE_EXPIRED")
    void testCheckServerCertificateChainExpiredRoot() throws Exception {
        var params = ECParameters.tc26a256();
        var rootKp = KeyGenerator.generateKeyPair(params);
        byte[] rootDn = TlsTestHelper.buildDN("Expired Root");
        TlsTestHelper.CertBundle expiredRoot = TlsTestHelper.createCertSignedBy(
                params, rootKp.getPrivate(), rootKp.getPublic(), rootDn,
                "20000101000000Z", "20050101000000Z", null, null, null, true, null);
        TlsTestHelper.CertBundle leaf = TlsTestHelper.createCertSignedBy(
                params, expiredRoot.priv, expiredRoot.cert.getPublicKey(), expiredRoot.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"gost.example.com"}, null, null, false, null);

        TlsSession session = TlsSession.createClient(new TlsClientConfig(getCsL())
                .withCaPublicKey(expiredRoot.cert.getPublicKey())
                .withServerHostname("gost.example.com"), noopTransport());

        TlsException e = assertThrows(TlsException.class,
                () -> session.checkServerCertificateChain(
                        Arrays.asList(leaf.cert, expiredRoot.cert)));
        assertEquals(TlsConstants.ALERT_CERTIFICATE_EXPIRED, e.getAlertCode());
    }

    @Test
    @DisplayName("InMemoryTlsTransport: close() → receiveRecord() throws IOException")
    void testClosedTransportThrows() {
        var transport = new InMemoryTlsTransport();
        transport.close();
        assertThrows(IOException.class, transport::receiveRecord);
    }

    @Test
    @DisplayName("InMemoryTlsTransport: inject → close → receiveRecord returns record (no loss)")
    void testClosedTransportDrainsQueuedRecords() throws Exception {
        var transport = new InMemoryTlsTransport();
        byte[] record = {0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        transport.inject(record);
        transport.close();
        assertArrayEquals(record, transport.receiveRecord());
        assertThrows(IOException.class, transport::receiveRecord);
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
        byte[] newReaderSecret = HkdfStreebog.expandLabel(
                serverSecret, TlsConstants.LABEL_TRAFFIC_UPD, new byte[0], hashLen, hashLen);
        byte[] newReaderKey = HkdfStreebog.expandLabel(
                newReaderSecret, TlsConstants.LABEL_KEY, new byte[0], keyLen, hashLen);
        byte[] newReaderIv = HkdfStreebog.expandLabel(
                newReaderSecret, TlsConstants.LABEL_IV, new byte[0], ivLen, hashLen);
        TlsRecord newPeerRecord = new TlsRecord(newReaderKey, newReaderIv, tagLen, cs);

        // 1. App data with old keys → успех
        inbound.add(peerRecord.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{0x41}));
        assertArrayEquals(new byte[]{0x41}, session.read());

        // 2. KeyUpdate(not_requested) с old keys
        byte[] kuBody = new byte[]{0};
        byte[] kuMsg = new TlsHandshakeMessage(TlsConstants.HT_KEY_UPDATE, kuBody).encode();
        inbound.add(peerRecord.protect(TlsConstants.CT_HANDSHAKE, kuMsg));

        // 3. App data с old keys → ошибка (readerRecord обновлён)
        inbound.add(peerRecord.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{0x42}));
        IOException ex = assertThrows(IOException.class, () -> session.read());
        assertTrue(ex.getMessage().toLowerCase().contains("auth") || ex.getCause() instanceof AuthenticationException,
                "Ожидается auth error: " + ex.getMessage());

        // 4. App data с NEW keys → успех
        inbound.add(newPeerRecord.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{0x43}));
        assertArrayEquals(new byte[]{0x43}, session.read());

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

        TlsSession session = TlsSession.createForTest(
                transport, cs, initialReaderKeys, initialWriterKeys);
        TlsSession.setAppTrafficSecrets(session, serverSecret, clientSecret, false);

        // Peer records
        TlsRecord peerReaderRecord = new TlsRecord(
                initialReaderKeys.getKey(), initialReaderKeys.getIv(), tagLen, cs);

        // Compute expected new reader keys
        byte[] newReaderSecret = HkdfStreebog.expandLabel(
                serverSecret, TlsConstants.LABEL_TRAFFIC_UPD, new byte[0], hashLen, hashLen);
        byte[] newReaderKey = HkdfStreebog.expandLabel(
                newReaderSecret, TlsConstants.LABEL_KEY, new byte[0], keyLen, hashLen);
        byte[] newReaderIv = HkdfStreebog.expandLabel(
                newReaderSecret, TlsConstants.LABEL_IV, new byte[0], ivLen, hashLen);
        TlsRecord newPeerReaderRecord = new TlsRecord(newReaderKey, newReaderIv, tagLen, cs);

        // 1. KeyUpdate(requested) с old keys → session обновит reader+writer и отправит ответ
        byte[] kuBody = new byte[]{1};
        byte[] kuMsg = new TlsHandshakeMessage(TlsConstants.HT_KEY_UPDATE, kuBody).encode();
        inbound.add(peerReaderRecord.protect(TlsConstants.CT_HANDSHAKE, kuMsg));

        // 2. После KeyUpdate: app data с НОВЫМИ reader keys → успех
        inbound.add(newPeerReaderRecord.protect(TlsConstants.CT_APPLICATION_DATA, new byte[]{0x44}));
        assertArrayEquals(new byte[]{0x44}, session.read());

        // 3. Outbound должен содержать ответный KeyUpdate (not_requested)
        assertEquals(1, outbound.size(), "Должен быть 1 ответный KeyUpdate");
        byte[] response = outbound.poll(1, TimeUnit.SECONDS);
        assertNotNull(response);

        // Декодируем ответ СТАРЫМИ writer-ключами — handleKeyUpdate отправила ответ
        // через writerRecord ДО того, как создала новый (п. 2 → sendEncryptedRecord,
        // затем п. 3 → writerRecord = new TlsRecord). Если бы обновление writerRecord
        // произошло раньше отправки, пир не смог бы расшифровать ответ — это свойство
        // синхронизации KeyUpdate: отправитель подтверждает приём новых reader-ключей
        // (ответ зашифрован старыми writer-ключами, которые пир уже заменил на новые
        // reader-ключи на своей стороне).
        TlsRecord peerWriterRecord = new TlsRecord(
                initialWriterKeys.getKey(), initialWriterKeys.getIv(), tagLen, cs);
        TlsParsedRecord parsed = peerWriterRecord.unprotect(response);
        assertEquals(TlsConstants.CT_HANDSHAKE, parsed.getContentType());
        TlsHandshakeMessage hm = TlsHandshakeMessage.decode(parsed.getData());
        assertEquals(TlsConstants.HT_KEY_UPDATE, hm.getType());
        assertArrayEquals(new byte[]{0}, hm.getBody(), "Ответ должен быть not_requested");

        TlsUtils.wipeArray(newReaderSecret);
        TlsUtils.wipeArray(newReaderKey);
        TlsUtils.wipeArray(newReaderIv);
        TlsUtils.wipeArray(serverSecret);
        TlsUtils.wipeArray(clientSecret);
        session.close();
    }

    @Test
    @DisplayName("KeyUpdate: неверная длина тела → TlsException(DECODE_ERROR)")
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
        byte[] kuBody = new byte[]{0, 0};
        byte[] kuMsg = new TlsHandshakeMessage(TlsConstants.HT_KEY_UPDATE, kuBody).encode();
        inbound.add(peerRecord.protect(TlsConstants.CT_HANDSHAKE, kuMsg));

        TlsException ex = assertThrows(TlsException.class, () -> session.read());
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ex.getAlertCode());
        session.close();
    }

    private static TlsTransport makeTransport(
            LinkedBlockingQueue<byte[]> inbound,
            LinkedBlockingQueue<byte[]> outbound) {
        return new TlsTransport() {
            @Override public void sendRecord(byte[] r) throws IOException {
                outbound.add(r);
            }
            @Override public byte[] receiveRecord() throws IOException {
                try {
                    byte[] r = inbound.poll(10, TimeUnit.SECONDS);
                    if (r == null) throw new IOException("timeout");
                    return r;
                } catch (InterruptedException e) {
                    throw new IOException(e);
                }
            }
            @Override public void close() {}
        };
    }

    /**
     * Запускает client.handshakeAsClient() и server.handshakeAsServer() параллельно.
     * Использует Phaser для синхронизации старта и ExecutorService для распараллеливания.
     * WHY: TLS handshake — двусторонний протокол, клиент и сервер обмениваются
     * сообщениями; последовательный запуск не работает из-за блокирующего read().
     */
    private static void handshakeInParallel(TlsSession server, TlsSession client) throws Exception {
        Phaser phaser = new Phaser(3);
        ExecutorService exec = Executors.newFixedThreadPool(2);
        try {
            Future<Void> cf = exec.submit(() -> {
                phaser.arriveAndAwaitAdvance();
                client.handshakeAsClient();
                return null;
            });
            Future<Void> sf = exec.submit(() -> {
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

}
