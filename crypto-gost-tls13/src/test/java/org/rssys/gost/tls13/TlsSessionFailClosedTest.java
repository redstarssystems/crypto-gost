package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import org.rssys.gost.util.AuthenticationException;

/**
 * Сессия закрывается на первой же ошибке (RFC 8446 §5.2, §6.2): подделанная или повреждённая
 * запись, сбой транспорта, исчерпание SNMAX и неудачное рукопожатие не оставляют «живую» сессию
 * с рабочим {@code write()}.
 */
@DisplayName("TlsSession: закрытие сессии при ошибке (fail-closed)")
class TlsSessionFailClosedTest {

    private static final TlsCiphersuite SUITE_L =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final TlsCiphersuite SUITE_S =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;

    private static TlsSessionConnection connect(TlsCiphersuite suite) throws Exception {
        return TlsSessionConnection.establish(suite);
    }

    private static byte[] takeClientRecord(TlsSessionConnection connection) throws Exception {
        byte[] record = connection.transports().getClientToServerQueue().poll(1, TimeUnit.SECONDS);
        assertNotNull(record, "Клиент должен был отправить запись");
        return record;
    }

    private static byte[] flipCiphertextByte(byte[] record) {
        byte[] forged = record.clone();
        forged[TlsConstants.RECORD_HEADER_SIZE + 4] ^= 0x42;
        return forged;
    }

    private static Object readField(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    @Test
    @DisplayName("подмена записи на лету: чтение закрывает сессию, пир получает bad_record_mac")
    void tamperedRecordClosesSessionAndSendsBadRecordMac() throws Exception {
        TlsSessionConnection connection = connect(SUITE_L);
        connection.client().write("подмена".getBytes(StandardCharsets.UTF_8));
        byte[] forged = flipCiphertextByte(takeClientRecord(connection));
        connection.transports().getClientToServerQueue().add(forged);

        TlsException failure = assertThrows(TlsException.class, connection.server()::read);

        assertTrue(
                failure.getCause() instanceof AuthenticationException,
                "причина отказа: ошибка проверки подлинности записи");
        assertTrue(connection.server().isClosed(), "Сессия сервера должна быть закрыта");
        assertThrows(IllegalStateException.class, connection.server()::read);
        assertThrows(
                IllegalStateException.class,
                () -> connection.server().write(new byte[] {1}),
                "Запись в закрытую сессию должна быть отвергнута");
        TlsException peerAlert = assertThrows(TlsException.class, connection.client()::read);
        assertTrue(peerAlert.isFromPeer(), "Fatal alert пришёл от пира");
        assertEquals(
                TlsConstants.ALERT_BAD_RECORD_MAC,
                peerAlert.getAlertCode(),
                "Пир должен получить bad_record_mac (20)");
    }

    @Test
    @DisplayName("вставка лишней записи: номер не растёт, но сессия закрывается на первой попытке")
    void injectedRecordClosesSession() throws Exception {
        TlsSessionConnection connection = connect(SUITE_L);
        connection.client().write("подлинная".getBytes(StandardCharsets.UTF_8));
        byte[] genuine = takeClientRecord(connection);
        // Лишняя запись идёт перед подлинной: seqNum при ошибке не растёт, и подлинная запись с тем
        // же номером читалась бы дальше, а атакующий мог бы подбирать тег на одном номере
        connection.transports().getClientToServerQueue().add(flipCiphertextByte(genuine));
        connection.transports().getClientToServerQueue().add(genuine);

        assertThrows(TlsException.class, connection.server()::read);

        assertTrue(connection.server().isClosed(), "Сессия должна закрыться на первой подделке");
        assertThrows(
                IllegalStateException.class,
                connection.server()::read,
                "Подлинная запись после подделки не должна читаться");
    }

    @Test
    @DisplayName("fatal alert пира: сессия закрыта, движок с секретами уничтожен")
    void fatalAlertFromPeerDestroysEngine() throws Exception {
        TlsSessionConnection connection = connect(SUITE_L);
        connection.client().write("x".getBytes(StandardCharsets.UTF_8));
        connection
                .transports()
                .getClientToServerQueue()
                .add(flipCiphertextByte(takeClientRecord(connection)));
        assertThrows(TlsException.class, connection.server()::read);

        assertThrows(IOException.class, connection.client()::read);

        assertTrue(connection.client().isClosed(), "Сессия клиента должна быть закрыта");
        assertNull(
                readField(connection.client(), "engine"),
                "Движок с секретами должен быть уничтожен после fatal alert");
    }

    @Test
    @DisplayName("сбой транспорта при чтении: сессия закрывается без alert")
    void transportFailureInReadStopsSession() throws Exception {
        TlsSessionConnection connection = connect(SUITE_L);
        connection.transports().getClientTransport().close();

        assertThrows(IOException.class, connection.server()::read);

        assertTrue(connection.server().isClosed(), "Сессия должна закрыться при сбое транспорта");
    }

    @Test
    @DisplayName("сбой транспорта при записи: сессия закрывается")
    void transportFailureInWriteStopsSession() throws Exception {
        TlsSessionConnection connection = connect(SUITE_L);
        connection.transports().getClientTransport().close();

        assertThrows(IOException.class, () -> connection.client().write(new byte[] {1}));

        assertTrue(connection.client().isClosed(), "Сессия должна закрыться при сбое транспорта");
    }

    @Test
    @DisplayName("сбой транспорта при KeyUpdate: сессия закрывается")
    void transportFailureInKeyUpdateStopsSession() throws Exception {
        TlsSessionConnection connection = connect(SUITE_L);
        connection.transports().getClientTransport().close();

        assertThrows(IOException.class, () -> connection.client().initiateKeyUpdate(false));

        assertTrue(
                connection.client().isClosed(),
                "Движок ждёт подтверждения новых ключей, сессия должна закрыться");
    }

    @Test
    @DisplayName("исчерпание SNMAX при записи: сессия закрывается")
    void snmaxExhaustionStopsSession() throws Exception {
        TlsSessionConnection connection = connect(SUITE_S);
        TlsRecord writer = (TlsRecord) readField(connection.client(), "writerRecord");
        // Остаётся ровно одна запись: первая проходит, вторая упирается в SNMAX
        writer.setSequenceNumber(SUITE_S.getSnmax() - 1);
        connection.client().write(new byte[] {1});

        assertThrows(IllegalStateException.class, () -> connection.client().write(new byte[] {2}));

        assertTrue(connection.client().isClosed(), "Сессия должна закрыться при исчерпании SNMAX");
    }

    @Test
    @DisplayName("повреждённый заголовок записи: TlsException с decode_error, сессия закрыта")
    void malformedRecordGivesTlsException() throws Exception {
        // Длина полезной нагрузки 5 меньше тега 16: до исправления летел IllegalArgumentException
        byte[] payloadTooSmall = {
            TlsConstants.CT_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5
        };
        TlsSessionConnection connection = connect(SUITE_L);
        connection.transports().getClientToServerQueue().add(payloadTooSmall);

        TlsException error = assertThrows(TlsException.class, connection.server()::read);

        assertEquals(TlsConstants.ALERT_DECODE_ERROR, error.getAlertCode());
        assertTrue(connection.server().isClosed(), "Сессия должна быть закрыта");
    }

    @Test
    @DisplayName("неверная версия в заголовке записи: TlsException с decode_error")
    void invalidRecordVersionGivesTlsException() throws Exception {
        byte[] record = new byte[TlsConstants.RECORD_HEADER_SIZE + 32];
        record[0] = TlsConstants.CT_APPLICATION_DATA;
        record[1] = 0x03;
        record[2] = 0x01;
        record[4] = 32;
        TlsSessionConnection connection = connect(SUITE_L);
        connection.transports().getClientToServerQueue().add(record);

        TlsException error = assertThrows(TlsException.class, connection.server()::read);

        assertEquals(TlsConstants.ALERT_DECODE_ERROR, error.getAlertCode());
    }

    @Test
    @DisplayName("повторное рукопожатие после успешного: IllegalStateException")
    void secondHandshakeAfterSuccessIsRejected() throws Exception {
        TlsSessionConnection connection = connect(SUITE_L);

        assertThrows(IllegalStateException.class, connection.client()::handshakeAsClient);
        assertThrows(IllegalStateException.class, connection.server()::handshakeAsServer);
    }

    @Test
    @DisplayName("неудачное рукопожатие закрывает сессию, повтор запрещён")
    void failedHandshakeClosesSession() throws Exception {
        PkixCertTestHelper.CertBundle bundle =
                PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
        var transports = InMemoryTlsTransport.newPair();
        TlsSession server =
                TlsSession.createServer(
                        transports.getServerTransport(), SUITE_L, bundle.cert, bundle.priv);
        // ClientHello с пустым телом: сервер отвергает его с decode_error
        transports
                .getClientToServerQueue()
                .add(
                        new byte[] {
                            TlsConstants.CT_HANDSHAKE,
                            0x03,
                            0x03,
                            0x00,
                            0x04,
                            0x01,
                            0x00,
                            0x00,
                            0x00
                        });

        assertThrows(TlsException.class, server::handshakeAsServer);

        assertTrue(server.isClosed(), "Сессия должна быть закрыта после ошибки рукопожатия");
        assertThrows(IllegalStateException.class, server::handshakeAsServer);
    }

    @Test
    @DisplayName("закрытие сессии затирает буфер открытого текста")
    void closeWipesPlaintextBuffer() throws Exception {
        TlsSessionConnection connection = connect(SUITE_L);
        byte[] secret = "секретные данные приложения".getBytes(StandardCharsets.UTF_8);
        connection.client().write(secret);
        assertArrayEquals(secret, connection.server().read());

        connection.server().close();

        assertNull(
                readField(connection.server(), "engine"),
                "Движок с секретами должен быть уничтожен при закрытии");
        ByteBuffer plainBuffer = (ByteBuffer) readField(connection.server(), "sessionPlainBuf");
        for (byte b : plainBuffer.array()) {
            assertEquals(0, b, "Буфер открытого текста должен быть затёрт при закрытии");
        }
    }
}
