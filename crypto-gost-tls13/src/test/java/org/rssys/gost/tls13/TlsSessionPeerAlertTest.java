package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.record.TlsRecord;

/**
 * Alert пира и разбор записей до установки ключей (RFC 8446 §5.1, §5.4, §6).
 *
 * <p>На fatal alert пира ответного alert не отправляется (код пира нельзя отражать обратно), на
 * {@code close_notify} в рукопожатии отправляется ответный {@code close_notify}, а не
 * {@code handshake_failure}. Записи до ключей проверяются по типу и длине, версия записи не
 * проверяется (RFC 8446 §5.1: поле игнорируется).
 */
@DisplayName("TlsSession: alert пира и открытые записи в рукопожатии")
class TlsSessionPeerAlertTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final byte[] CLOSE_NOTIFY_BODY = {
        TlsConstants.ALERT_WARNING, TlsConstants.CLOSE_NOTIFY
    };

    /** Транспорт-заглушка: отдаёт заданные записи, затем обрывает приём; отправленное копит. */
    private static final class ScriptedTransport implements TlsTransport {
        private final ArrayDeque<byte[]> incoming = new ArrayDeque<>();
        final List<byte[]> sent = new ArrayList<>();

        ScriptedTransport(byte[]... records) {
            Collections.addAll(incoming, records);
        }

        @Override
        public void sendRecord(byte[] record) {
            sent.add(record.clone());
        }

        @Override
        public byte[] receiveRecord() throws IOException {
            byte[] record = incoming.poll();
            if (record == null) {
                throw new IOException("scripted transport: no more records");
            }
            return record;
        }

        @Override
        public void close() {}
    }

    private static byte[] plaintextRecord(byte contentType, byte[] body) {
        return TlsMessageBuilder.buildPlaintextRecord(contentType, body);
    }

    private static byte[] fatalAlert(byte description) {
        return plaintextRecord(
                TlsConstants.CT_ALERT, new byte[] {TlsConstants.ALERT_FATAL, description});
    }

    private static TlsSession serverOver(TlsTransport transport) throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        return TlsSession.createServer(transport, SUITE, bundle.cert, bundle.priv);
    }

    private static TlsException handshakeFails(TlsSession server) {
        return assertThrows(TlsException.class, server::handshakeAsServer);
    }

    // ------------------------------------------------------------------ открытая фаза: alert

    @Test
    @DisplayName("fatal alert пира до ключей: исключение от пира, ответного alert нет")
    void plaintextFatalAlertIsNotEchoed() throws Exception {
        ScriptedTransport transport =
                new ScriptedTransport(fatalAlert(TlsConstants.ALERT_HANDSHAKE_FAILURE));
        TlsSession server = serverOver(transport);

        TlsException error = handshakeFails(server);

        assertTrue(error.isFromPeer(), "Alert пришёл от пира");
        assertEquals(TlsConstants.ALERT_HANDSHAKE_FAILURE, error.getAlertCode());
        assertTrue(transport.sent.isEmpty(), "На fatal alert пира ничего не отправляется");
        assertTrue(server.isClosed(), "Сессия должна быть закрыта");
    }

    @Test
    @DisplayName(
            "close_notify пира до ключей: PeerClosedException и ответный close_notify открытым")
    void plaintextCloseNotifyIsAnswered() throws Exception {
        ScriptedTransport transport =
                new ScriptedTransport(plaintextRecord(TlsConstants.CT_ALERT, CLOSE_NOTIFY_BODY));
        TlsSession server = serverOver(transport);

        assertThrows(PeerClosedException.class, server::handshakeAsServer);

        assertEquals(1, transport.sent.size(), "Должен уйти ровно один ответ");
        assertArrayEqualsRecord(
                plaintextRecord(TlsConstants.CT_ALERT, CLOSE_NOTIFY_BODY), transport.sent.get(0));
        assertTrue(server.isClosed(), "Сессия должна быть закрыта");
    }

    @Test
    @DisplayName("обрыв транспорта в рукопожатии: обычная ошибка, не close_notify пира")
    void transportFailureIsNotPeerClose() throws Exception {
        ScriptedTransport transport = new ScriptedTransport();
        TlsSession server = serverOver(transport);

        IOException error = assertThrows(IOException.class, server::handshakeAsServer);

        assertFalse(error instanceof PeerClosedException, "Обрыв не закрытие пиром: " + error);
        assertTrue(server.isClosed());
    }

    // ------------------------------------------------------------------ открытая фаза: записи

    private static void assertArrayEqualsRecord(byte[] expected, byte[] actual) {
        org.junit.jupiter.api.Assertions.assertArrayEquals(
                expected, actual, "Запись на проводе не совпала с ожидаемой");
    }

    private static void assertRejected(byte[] record, byte expectedAlert, String reason)
            throws Exception {
        TlsSession server = serverOver(new ScriptedTransport(record));

        TlsException error = handshakeFails(server);

        assertEquals(expectedAlert, error.getAlertCode(), reason + ": " + error.getMessage());
        assertFalse(error.isFromPeer(), "Нарушение найдено локально");
    }

    @Test
    @DisplayName("открытая запись типа application_data до ключей: unexpected_message")
    void plaintextApplicationDataRejected() throws Exception {
        assertRejected(
                plaintextRecord(TlsConstants.CT_APPLICATION_DATA, new byte[] {1, 2, 3}),
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                "Тип 23 не может быть handshake");
    }

    @Test
    @DisplayName("открытая запись длиннее 2^14: record_overflow")
    void plaintextOverlongRecordRejected() throws Exception {
        byte[] body = new byte[TlsConstants.MAX_PLAINTEXT_LENGTH + 1];
        assertRejected(
                plaintextRecord(TlsConstants.CT_HANDSHAKE, body),
                TlsConstants.ALERT_RECORD_OVERFLOW,
                "Длина больше 2^14");
    }

    @Test
    @DisplayName("пустая открытая handshake-запись: unexpected_message")
    void plaintextEmptyHandshakeRecordRejected() throws Exception {
        assertRejected(
                plaintextRecord(TlsConstants.CT_HANDSHAKE, new byte[0]),
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                "RFC 8446 §5.1: нулевая длина handshake-фрагмента недопустима");
    }

    @Test
    @DisplayName("хвост после объявленной длины открытой записи: decode_error")
    void plaintextTrailingBytesRejected() throws Exception {
        byte[] record = plaintextRecord(TlsConstants.CT_HANDSHAKE, new byte[] {1, 0, 0, 0});
        byte[] withTrail = java.util.Arrays.copyOf(record, record.length + 2);
        assertRejected(withTrail, TlsConstants.ALERT_DECODE_ERROR, "Хвост за записью");
    }

    @Test
    @DisplayName("пустая открытая alert-запись: unexpected_message")
    void plaintextEmptyAlertRejected() throws Exception {
        assertRejected(
                plaintextRecord(TlsConstants.CT_ALERT, new byte[0]),
                TlsConstants.ALERT_UNEXPECTED_MESSAGE,
                "RFC 8446 §5.4: пустой alert недопустим");
    }

    @Test
    @DisplayName("alert из одного байта: decode_error")
    void plaintextOneByteAlertRejected() throws Exception {
        assertRejected(
                plaintextRecord(TlsConstants.CT_ALERT, new byte[] {TlsConstants.ALERT_FATAL}),
                TlsConstants.ALERT_DECODE_ERROR,
                "Усечённый alert");
    }

    @Test
    @DisplayName("три байта в alert-записи (склейка): decode_error")
    void plaintextCoalescedAlertRejected() throws Exception {
        assertRejected(
                plaintextRecord(
                        TlsConstants.CT_ALERT,
                        new byte[] {TlsConstants.ALERT_FATAL, 40, TlsConstants.ALERT_FATAL}),
                TlsConstants.ALERT_DECODE_ERROR,
                "RFC 8446 §5.1: несколько alert в одной записи недопустимы");
    }

    @Test
    @DisplayName("версия открытой записи не проверяется: ClientHello с 0x0301 принят")
    void plaintextRecordVersionIsIgnored() throws Exception {
        ScriptedTransport clientTransport = new ScriptedTransport();
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(clientTransport, SUITE, null, null);
        assertThrows(IOException.class, client::handshakeAsClient);
        byte[] clientHello = clientTransport.sent.get(0).clone();
        // Совместимый заголовок первого ClientHello (RFC 8446 §5.1): версия 0x0301
        clientHello[1] = 0x03;
        clientHello[2] = 0x01;
        ScriptedTransport serverTransport = new ScriptedTransport(clientHello);
        TlsSession server = serverOver(serverTransport);

        assertThrows(IOException.class, server::handshakeAsServer);

        assertFalse(
                serverTransport.sent.isEmpty() || isFatalAlertRecord(serverTransport.sent.get(0)),
                "Сервер должен принять ClientHello и начать ответ, а не отвергнуть версию записи");
    }

    @Test
    @DisplayName(
            "лишний байт после ClientHello в той же записи: unexpected_message (граница записи)")
    void bytesAfterClientHelloInSameRecordAreRejected() throws Exception {
        ScriptedTransport clientTransport = new ScriptedTransport();
        TlsSession client =
                TlsSession.createClientWithoutServerAuth(clientTransport, SUITE, null, null);
        assertThrows(IOException.class, client::handshakeAsClient);
        byte[] clientHello = clientTransport.sent.get(0);
        // Запись удлиняется на один байт: сообщение ClientHello заканчивается раньше конца записи.
        // RFC 8446 §5.1: перед сменой ключа чтения сообщения обязаны заканчиваться на границе
        // записи, а после ClientHello сервер переходит на ключи рукопожатия
        byte[] withStray = java.util.Arrays.copyOf(clientHello, clientHello.length + 1);
        int bodyLength = clientHello.length - TlsConstants.RECORD_HEADER_SIZE + 1;
        withStray[3] = (byte) (bodyLength >>> 8);
        withStray[4] = (byte) bodyLength;
        TlsSession server = serverOver(new ScriptedTransport(withStray));

        TlsException error = handshakeFails(server);

        assertEquals(
                TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode(), error.getMessage());
    }

    private static boolean isFatalAlertRecord(byte[] record) {
        return record[0] == TlsConstants.CT_ALERT && record[5] == TlsConstants.ALERT_FATAL;
    }

    // ------------------------------------------------------------------ зашифрованная фаза

    // ------------------------------------------------------------------ после рукопожатия

    @Test
    @DisplayName(
            "read(): close_notify пира - PeerClosedException, fatal alert пира - от пира с кодом")
    void readReportsPeerAlertKinds() throws Exception {
        TlsSessionConnection closing = TlsSessionConnection.establish(SUITE);
        closing.client().close();
        assertThrows(PeerClosedException.class, closing.server()::read);

        TlsSessionConnection failing = TlsSessionConnection.establish(SUITE);
        failing.client().write(new byte[] {1});
        byte[] record = failing.transports().getClientToServerQueue().poll(1, TimeUnit.SECONDS);
        record[TlsConstants.RECORD_HEADER_SIZE + 4] ^= 0x42;
        failing.transports().getClientToServerQueue().add(record);
        assertThrows(TlsException.class, failing.server()::read);

        TlsException peerAlert = assertThrows(TlsException.class, failing.client()::read);
        assertTrue(peerAlert.isFromPeer(), "Fatal alert пришёл от пира");
        assertEquals(TlsConstants.ALERT_BAD_RECORD_MAC, peerAlert.getAlertCode());
    }

    private static TlsRecord writerOf(TlsSession session) throws Exception {
        java.lang.reflect.Field field = TlsSession.class.getDeclaredField("writerRecord");
        field.setAccessible(true);
        return (TlsRecord) field.get(session);
    }

    private static void assertReadRejects(byte contentType, byte[] body, byte expectedAlert)
            throws Exception {
        TlsSessionConnection connection = TlsSessionConnection.establish(SUITE);
        byte[] record = writerOf(connection.client()).protect(contentType, body);
        connection.transports().getClientToServerQueue().add(record);

        TlsException error = assertThrows(TlsException.class, connection.server()::read);

        assertEquals(expectedAlert, error.getAlertCode(), error.getMessage());
        assertTrue(connection.server().isClosed());
    }

    @Test
    @DisplayName("read(): пустая зашифрованная handshake-запись - unexpected_message")
    void readRejectsEmptyHandshakeRecord() throws Exception {
        assertReadRejects(
                TlsConstants.CT_HANDSHAKE, new byte[0], TlsConstants.ALERT_UNEXPECTED_MESSAGE);
    }

    @Test
    @DisplayName("read(): пустая зашифрованная alert-запись - unexpected_message")
    void readRejectsEmptyAlertRecord() throws Exception {
        assertReadRejects(
                TlsConstants.CT_ALERT, new byte[0], TlsConstants.ALERT_UNEXPECTED_MESSAGE);
    }

    @Test
    @DisplayName("read(): alert из одного байта - decode_error")
    void readRejectsOneByteAlert() throws Exception {
        assertReadRejects(
                TlsConstants.CT_ALERT,
                new byte[] {TlsConstants.ALERT_FATAL},
                TlsConstants.ALERT_DECODE_ERROR);
    }
}
