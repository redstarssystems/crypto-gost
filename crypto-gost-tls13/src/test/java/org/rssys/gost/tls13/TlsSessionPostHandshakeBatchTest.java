package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.tls13.crypto.HkdfStreebog;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.util.CryptoRandom;

/**
 * Несколько post-handshake сообщений в одной записи и фрагменты одного сообщения (RFC 8446 §5.1):
 * сообщения разбираются все до приёма следующей записи, запись другого типа не перемежается с
 * незавершённым сообщением, KeyUpdate замыкает свою запись.
 */
@DisplayName("TlsSession.read(): несколько post-handshake сообщений в одной записи")
class TlsSessionPostHandshakeBatchTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final byte[] APP_DATA = {0x41, 0x42};

    /** Сессия-клиент с известными ключами и «пиром», который пишет записи теми же ключами. */
    private static final class Peer {
        final LinkedBlockingQueue<byte[]> inbound = new LinkedBlockingQueue<>();
        final LinkedBlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>();
        final PskStore store = new InMemoryPskStore(100);
        final TlsSession session;
        final TlsRecord writer;
        final byte[] serverSecret = new byte[SUITE.getHashLen()];
        final byte[] clientSecret = new byte[SUITE.getHashLen()];

        Peer() {
            byte[] key = new byte[TlsConstants.KUZNYECHIK_KEY_SIZE];
            byte[] iv = new byte[TlsConstants.MGM_IV_SIZE];
            CryptoRandom.INSTANCE.nextBytes(key);
            CryptoRandom.INSTANCE.nextBytes(iv);
            CryptoRandom.INSTANCE.nextBytes(serverSecret);
            CryptoRandom.INSTANCE.nextBytes(clientSecret);
            TlsTrafficKeys keys = new TlsTrafficKeys(key.clone(), iv.clone());
            session =
                    TlsSession.createForTest(
                            transport(), SUITE, keys, new TlsTrafficKeys(key.clone(), iv.clone()));
            TlsSession.setAppTrafficSecrets(session, serverSecret, clientSecret, false);
            session.setPskStore(store);
            writer = new TlsRecord(key, iv, SUITE.getTagLen(), SUITE);
        }

        private TlsTransport transport() {
            return new TlsTransport() {
                @Override
                public void sendRecord(byte[] record) {
                    outbound.add(record);
                }

                @Override
                public byte[] receiveRecord() throws IOException {
                    try {
                        byte[] record = inbound.poll(5, TimeUnit.SECONDS);
                        if (record == null) throw new IOException("Таймаут приёма в тесте");
                        return record;
                    } catch (InterruptedException e) {
                        throw new IOException(e);
                    }
                }

                @Override
                public void close() {}
            };
        }

        /** Ключи пира после его KeyUpdate: «traffic upd» от секрета сервера (RFC 8446 §7.2). */
        TlsRecord writerAfterKeyUpdate() {
            int hashLen = SUITE.getHashLen();
            byte[] secret =
                    HkdfStreebog.expandLabel(
                            serverSecret, "traffic upd", new byte[0], hashLen, hashLen);
            byte[] key =
                    HkdfStreebog.expandLabel(
                            secret, "key", new byte[0], SUITE.getKeyLen(), hashLen);
            byte[] iv =
                    HkdfStreebog.expandLabel(secret, "iv", new byte[0], SUITE.getIvLen(), hashLen);
            return new TlsRecord(key, iv, SUITE.getTagLen(), SUITE);
        }
    }

    private static byte[] ticket(int index) {
        byte[] body =
                TlsMessageBuilder.buildNewSessionTicket(
                        7200, 1, new byte[8], new byte[] {(byte) index});
        return new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, body).encode();
    }

    private static byte[] keyUpdate(boolean requested) {
        return new TlsHandshakeMessage(
                        TlsConstants.HT_KEY_UPDATE, new byte[] {(byte) (requested ? 1 : 0)})
                .encode();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.write(part, 0, part.length);
        return out.toByteArray();
    }

    @Test
    @DisplayName("два NewSessionTicket в одной записи: оба обработаны до приёма следующей записи")
    void twoTicketsInOneRecordAreBothProcessed() throws Exception {
        Peer peer = new Peer();
        peer.inbound.add(
                peer.writer.protect(TlsConstants.CT_HANDSHAKE, concat(ticket(1), ticket(2))));
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_APPLICATION_DATA, APP_DATA));

        assertArrayEquals(APP_DATA, peer.session.read());

        assertEquals(2, peer.store.size(), "Оба тикета записи должны быть приняты");
    }

    @Test
    @DisplayName(
            "NST и KeyUpdate с запросом в одной записи: ответ уходит сразу, обмен идёт на новых ключах")
    void ticketAndKeyUpdateInOneRecord() throws Exception {
        Peer peer = new Peer();
        peer.inbound.add(
                peer.writer.protect(TlsConstants.CT_HANDSHAKE, concat(ticket(1), keyUpdate(true))));
        // Пир сменил ключ записи вместе с KeyUpdate: данные приложения идут уже на новых ключах
        peer.inbound.add(
                peer.writerAfterKeyUpdate().protect(TlsConstants.CT_APPLICATION_DATA, APP_DATA));

        assertArrayEquals(APP_DATA, peer.session.read());

        assertEquals(1, peer.store.size(), "Тикет перед KeyUpdate должен быть принят");
        assertFalse(peer.outbound.isEmpty(), "Ответный KeyUpdate должен быть отправлен");
    }

    @ParameterizedTest(name = "request_update = {0}")
    @ValueSource(ints = {2, 0x7F, 0x80, 0xFF})
    @DisplayName("KeyUpdate: request_update вне {0, 1} -> illegal_parameter и закрытие сессии")
    void keyUpdateWithInvalidRequestUpdateIsRejected(int value) throws Exception {
        Peer peer = new Peer();
        byte[] frame =
                new TlsHandshakeMessage(TlsConstants.HT_KEY_UPDATE, new byte[] {(byte) value})
                        .encode();
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_HANDSHAKE, frame));

        TlsException error = assertThrows(TlsException.class, peer.session::read);

        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                error.getAlertCode(),
                "Недопустимое значение request_update должно давать illegal_parameter");
        assertTrue(peer.session.isClosed(), "Сессия должна быть закрыта");
    }

    @Test
    @DisplayName("девять сообщений в одной записи: превышен лимит сообщений за read()")
    void tooManyMessagesInOneRecordIsRejected() throws Exception {
        Peer peer = new Peer();
        byte[][] tickets = new byte[TlsConstants.MAX_POST_HANDSHAKE + 1][];
        for (int i = 0; i < tickets.length; i++) tickets[i] = ticket(i);
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_HANDSHAKE, concat(tickets)));

        TlsException error = assertThrows(TlsException.class, peer.session::read);

        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode());
        assertTrue(peer.session.isClosed(), "Сессия должна быть закрыта");
    }

    @Test
    @DisplayName("восемь сообщений в одной записи принимаются (предел включительно)")
    void maximumMessagesInOneRecordAreAccepted() throws Exception {
        Peer peer = new Peer();
        byte[][] tickets = new byte[TlsConstants.MAX_POST_HANDSHAKE][];
        for (int i = 0; i < tickets.length; i++) tickets[i] = ticket(i);
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_HANDSHAKE, concat(tickets)));
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_APPLICATION_DATA, APP_DATA));

        assertArrayEquals(APP_DATA, peer.session.read());

        assertEquals(TlsConstants.MAX_POST_HANDSHAKE, peer.store.size());
    }

    @Test
    @DisplayName("запись данных между фрагментами одного сообщения: unexpected_message")
    void applicationDataBetweenMessageFragmentsIsRejected() throws Exception {
        Peer peer = new Peer();
        byte[] frame = ticket(1);
        // Первая запись несёт только начало сообщения, сообщение ещё не завершено
        peer.inbound.add(
                peer.writer.protect(
                        TlsConstants.CT_HANDSHAKE, Arrays.copyOf(frame, frame.length - 2)));
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_APPLICATION_DATA, APP_DATA));

        TlsException error = assertThrows(TlsException.class, peer.session::read);

        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode());
        assertTrue(peer.session.isClosed(), "Сессия должна быть закрыта");
    }

    @Test
    @DisplayName("сообщение, разбитое на две записи подряд, собирается")
    void messageSplitAcrossTwoRecordsIsAssembled() throws Exception {
        Peer peer = new Peer();
        byte[] frame = ticket(1);
        peer.inbound.add(
                peer.writer.protect(
                        TlsConstants.CT_HANDSHAKE, Arrays.copyOf(frame, frame.length - 2)));
        peer.inbound.add(
                peer.writer.protect(
                        TlsConstants.CT_HANDSHAKE,
                        Arrays.copyOfRange(frame, frame.length - 2, frame.length)));
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_APPLICATION_DATA, APP_DATA));

        assertArrayEquals(APP_DATA, peer.session.read());

        assertEquals(1, peer.store.size());
    }

    @Test
    @DisplayName("KeyUpdate не последним сообщением записи: unexpected_message (RFC 8446 §5.1)")
    void keyUpdateMustEndItsRecord() throws Exception {
        Peer peer = new Peer();
        peer.inbound.add(
                peer.writer.protect(
                        TlsConstants.CT_HANDSHAKE, concat(keyUpdate(false), ticket(1))));

        TlsException error = assertThrows(TlsException.class, peer.session::read);

        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode());
        assertTrue(peer.session.isClosed(), "Сессия должна быть закрыта");
    }

    @Test
    @DisplayName("два KeyUpdate в одной записи: первый не на границе записи, unexpected_message")
    void twoKeyUpdatesInOneRecordAreRejected() throws Exception {
        Peer peer = new Peer();
        peer.inbound.add(
                peer.writer.protect(
                        TlsConstants.CT_HANDSHAKE, concat(keyUpdate(false), keyUpdate(false))));

        TlsException error = assertThrows(TlsException.class, peer.session::read);

        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode());
    }

    @Test
    @DisplayName(
            "пять NST и KeyUpdate в одной записи, затем данные: лимит не мешает дойти до данных")
    void fiveTicketsAndKeyUpdateThenApplicationData() throws Exception {
        Peer peer = new Peer();
        byte[][] messages = new byte[TlsConstants.MAX_TICKETS_TO_SEND + 1][];
        for (int i = 0; i < TlsConstants.MAX_TICKETS_TO_SEND; i++) messages[i] = ticket(i);
        messages[TlsConstants.MAX_TICKETS_TO_SEND] = keyUpdate(true);
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_HANDSHAKE, concat(messages)));
        peer.inbound.add(
                peer.writerAfterKeyUpdate().protect(TlsConstants.CT_APPLICATION_DATA, APP_DATA));

        assertArrayEquals(APP_DATA, peer.session.read());

        assertEquals(TlsConstants.MAX_TICKETS_TO_SEND, peer.store.size());
    }

    @Test
    @DisplayName(
            "alert посреди незавершённого сообщения разбирается первым (осознанное отступление)")
    void alertBetweenMessageFragmentsIsReportedFirst() throws Exception {
        Peer peer = new Peer();
        byte[] frame = ticket(1);
        peer.inbound.add(
                peer.writer.protect(
                        TlsConstants.CT_HANDSHAKE, Arrays.copyOf(frame, frame.length - 2)));
        peer.inbound.add(
                peer.writer.protect(
                        TlsConstants.CT_ALERT,
                        new byte[] {
                            TlsConstants.ALERT_FATAL, TlsConstants.ALERT_HANDSHAKE_FAILURE
                        }));

        TlsException error = assertThrows(TlsException.class, peer.session::read);

        assertTrue(error.isFromPeer(), "Пользователь должен увидеть настоящую причину");
        assertEquals(TlsConstants.ALERT_HANDSHAKE_FAILURE, error.getAlertCode());
    }

    @Test
    @DisplayName("заголовок служебного сообщения крупнее предела: отказ до накопления тела")
    void oversizedPostHandshakeMessageIsRejectedByHeader() throws Exception {
        Peer peer = new Peer();
        int declared = TlsConstants.MAX_POST_HANDSHAKE_MESSAGE_SIZE;
        // Тело на один байт больше предельного: сообщение режется на мелкие записи, но отказ
        // наступает уже по заголовку, когда он собран
        byte[] header = {
            TlsConstants.HT_NEW_SESSION_TICKET,
            (byte) (declared >>> 16),
            (byte) (declared >>> 8),
            (byte) declared
        };
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_HANDSHAKE, header));

        TlsException error = assertThrows(TlsException.class, peer.session::read);

        assertEquals(TlsConstants.ALERT_DECODE_ERROR, error.getAlertCode());
        assertTrue(peer.session.isClosed(), "Сессия должна быть закрыта");
    }

    @Test
    @DisplayName("предел размера служебного сообщения покрывает самый большой NewSessionTicket")
    void postHandshakeSizeLimitCoversLargestTicket() {
        // lifetime, age_add, nonce (1 + 255), ticket (2 + 65535), расширения (2 + 65535), заголовок
        int largest = 4 + 4 + 4 + 1 + 255 + 2 + 65535 + 2 + 65535;
        assertEquals(largest, TlsConstants.MAX_POST_HANDSHAKE_MESSAGE_SIZE);
        assertTrue(
                TlsConstants.MAX_POST_HANDSHAKE_MESSAGE_SIZE
                        < TlsConstants.MAX_HANDSHAKE_MESSAGE_SIZE,
                "Для служебных сообщений предел должен быть меньше общего");
    }

    private static byte[][] split(byte[] frame, int pieces) {
        byte[][] result = new byte[pieces][];
        int base = frame.length / pieces;
        int offset = 0;
        for (int i = 0; i < pieces; i++) {
            int length = i == pieces - 1 ? frame.length - offset : base;
            result[i] = Arrays.copyOfRange(frame, offset, offset + length);
            offset += length;
        }
        return result;
    }

    @Test
    @DisplayName("восемь сообщений по одному на запись, затем данные: данные читаются")
    void eightMessagesInSeparateRecordsThenApplicationData() throws Exception {
        Peer peer = new Peer();
        for (int i = 0; i < TlsConstants.MAX_POST_HANDSHAKE; i++) {
            peer.inbound.add(peer.writer.protect(TlsConstants.CT_HANDSHAKE, ticket(i)));
        }
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_APPLICATION_DATA, APP_DATA));

        assertArrayEquals(APP_DATA, peer.session.read());

        assertEquals(TlsConstants.MAX_POST_HANDSHAKE, peer.store.size());
    }

    @Test
    @DisplayName("девятое сообщение в отдельной записи: unexpected_message")
    void ninthMessageInSeparateRecordIsRejected() throws Exception {
        Peer peer = new Peer();
        for (int i = 0; i < TlsConstants.MAX_POST_HANDSHAKE + 1; i++) {
            peer.inbound.add(peer.writer.protect(TlsConstants.CT_HANDSHAKE, ticket(i)));
        }

        TlsException error = assertThrows(TlsException.class, peer.session::read);

        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode());
        assertTrue(peer.session.isClosed());
    }

    @Test
    @DisplayName("крупный тикет, разрезанный на десять записей, собирается")
    void largeTicketSplitAcrossManyRecordsIsAssembled() throws Exception {
        Peer peer = new Peer();
        byte[] body =
                TlsMessageBuilder.buildNewSessionTicket(7200, 1, new byte[8], new byte[60_000]);
        byte[] frame = new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, body).encode();
        for (byte[] piece : split(frame, 10)) {
            peer.inbound.add(peer.writer.protect(TlsConstants.CT_HANDSHAKE, piece));
        }
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_APPLICATION_DATA, APP_DATA));

        assertArrayEquals(APP_DATA, peer.session.read());

        assertEquals(1, peer.store.size(), "Тикет, превышающий восемь записей, должен собраться");
    }

    @Test
    @DisplayName("бюджет записей: восемь сообщений по девять записей, затем данные - читаются")
    void fullRecordBudgetThenApplicationData() throws Exception {
        Peer peer = new Peer();
        int perMessage = TlsConstants.MAX_POST_HANDSHAKE_RECORDS / TlsConstants.MAX_POST_HANDSHAKE;
        for (int message = 0; message < TlsConstants.MAX_POST_HANDSHAKE; message++) {
            for (byte[] piece : split(ticket(message), perMessage)) {
                peer.inbound.add(peer.writer.protect(TlsConstants.CT_HANDSHAKE, piece));
            }
        }
        peer.inbound.add(peer.writer.protect(TlsConstants.CT_APPLICATION_DATA, APP_DATA));

        assertArrayEquals(APP_DATA, peer.session.read());

        assertEquals(TlsConstants.MAX_POST_HANDSHAKE, peer.store.size());
    }

    @Test
    @DisplayName("бюджет записей исчерпан: следующая handshake-запись даёт unexpected_message")
    void recordBudgetExhaustionIsRejected() throws Exception {
        Peer peer = new Peer();
        // Одно сообщение режется на крошечные записи: на одну больше бюджета
        byte[] frame =
                new TlsHandshakeMessage(
                                TlsConstants.HT_NEW_SESSION_TICKET,
                                TlsMessageBuilder.buildNewSessionTicket(
                                        7200, 1, new byte[8], new byte[200]))
                        .encode();
        int records = TlsConstants.MAX_POST_HANDSHAKE_RECORDS + 1;
        assertTrue(frame.length >= records, "Сообщение должно резаться на такое число записей");
        for (byte[] piece : split(frame, records)) {
            peer.inbound.add(peer.writer.protect(TlsConstants.CT_HANDSHAKE, piece));
        }

        TlsException error = assertThrows(TlsException.class, peer.session::read);

        assertEquals(TlsConstants.ALERT_UNEXPECTED_MESSAGE, error.getAlertCode());
        assertTrue(peer.session.isClosed());
    }

    @Test
    @DisplayName("бюджет записей выведен из пределов сообщений и вмещает наибольшее сообщение")
    void recordBudgetIsDerivedFromMessageLimits() {
        int recordsPerLargestMessage =
                (TlsConstants.MAX_POST_HANDSHAKE_MESSAGE_SIZE
                                + TlsConstants.MAX_PLAINTEXT_LENGTH
                                - 1)
                        / TlsConstants.MAX_PLAINTEXT_LENGTH;
        assertEquals(
                TlsConstants.MAX_POST_HANDSHAKE * recordsPerLargestMessage,
                TlsConstants.MAX_POST_HANDSHAKE_RECORDS);
        assertTrue(
                recordsPerLargestMessage >= 9,
                "Наибольшее служебное сообщение не помещается в восемь записей");
    }
}
