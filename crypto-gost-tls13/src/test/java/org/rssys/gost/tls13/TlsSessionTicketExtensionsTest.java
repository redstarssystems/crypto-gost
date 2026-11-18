package org.rssys.gost.tls13;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.engine.TlsHandshakeMessage;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.record.TlsRecord;
import org.rssys.gost.tls13.record.TlsTrafficKeys;
import org.rssys.gost.tls13.transport.InMemoryTlsTransport;
import org.rssys.gost.util.CryptoRandom;

/**
 * Блок расширений NewSessionTicket в {@code TlsSession}: ошибка приходит после рукопожатия, поэтому
 * обязана закрывать установленное соединение, а не только бросать исключение разборщика.
 */
@DisplayName("TlsSession: расширения NewSessionTicket")
class TlsSessionTicketExtensionsTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

    /** lifetime(4) || age_add(4) || nonce(1+8) || ticket(2+3), без блока расширений. */
    private static byte[] ticketWithoutExtensionBlock() {
        return new byte[] {
            0x00, 0x00, 0x1C, 0x20, 0x01, 0x02, 0x03, 0x04, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0x00,
            0x03, 0x0A, 0x0B, 0x0C
        };
    }

    private static byte[] withExtensionBlock(byte[] extensions) {
        byte[] ticket = ticketWithoutExtensionBlock();
        byte[] body = new byte[ticket.length + 2 + extensions.length];
        System.arraycopy(ticket, 0, body, 0, ticket.length);
        body[ticket.length] = (byte) (extensions.length >>> 8);
        body[ticket.length + 1] = (byte) extensions.length;
        System.arraycopy(extensions, 0, body, ticket.length + 2, extensions.length);
        return body;
    }

    /** Клиентская сессия получает NewSessionTicket с заданным телом, затем запись данных. */
    private static TlsSession sessionAfterTicket(byte[] ticketBody) throws Exception {
        return sessionAfterTicket(ticketBody, true);
    }

    /** То же, но хранилище PSK задаётся флагом: разбор NST от него зависеть не должен. */
    private static TlsSession sessionAfterTicket(byte[] ticketBody, boolean withPskStore)
            throws Exception {
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(iv);
        TlsTrafficKeys keys = new TlsTrafficKeys(key, iv);
        TlsRecord writer = new TlsRecord(keys.getKey(), keys.getIv(), SUITE.getTagLen(), SUITE);
        InMemoryTlsTransport transport = new InMemoryTlsTransport();
        TlsSession client = TlsSession.createForTest(transport, SUITE, keys, keys);
        if (withPskStore) {
            client.setPskStore(new InMemoryPskStore(100));
        }
        byte[] framed =
                new TlsHandshakeMessage(TlsConstants.HT_NEW_SESSION_TICKET, ticketBody).encode();
        transport.inject(writer.protect(TlsConstants.CT_HANDSHAKE, framed, 0, framed.length));
        transport.inject(writer.protect(TlsConstants.CT_APPLICATION_DATA, new byte[] {0x41}));
        return client;
    }

    @Test
    @DisplayName("NewSessionTicket без блока расширений: decode_error и закрытие соединения")
    void ticketWithoutExtensionBlockClosesSession() throws Exception {
        TlsSession client = sessionAfterTicket(ticketWithoutExtensionBlock());
        Exception thrown = assertThrows(Exception.class, client::read);
        assertTrue(thrown instanceof TlsException, "ожидалось TlsException, получено " + thrown);
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ((TlsException) thrown).getAlertCode());
        assertTrue(client.isClosed(), "соединение с прикладными данными должно быть закрыто");
    }

    @Test
    @DisplayName("NewSessionTicket с key_share: illegal_parameter и закрытие соединения")
    void ticketWithForeignExtensionClosesSession() throws Exception {
        byte[] keyShare = {0x00, 0x33, 0x00, 0x02, 0x00, 0x23};
        TlsSession client = sessionAfterTicket(withExtensionBlock(keyShare));
        Exception thrown = assertThrows(Exception.class, client::read);
        assertTrue(thrown instanceof TlsException, "ожидалось TlsException, получено " + thrown);
        assertEquals(TlsConstants.ALERT_ILLEGAL_PARAMETER, ((TlsException) thrown).getAlertCode());
        assertTrue(client.isClosed(), "соединение с прикладными данными должно быть закрыто");
    }

    @Test
    @DisplayName("NewSessionTicket с пустым блоком расширений: соединение продолжает работать")
    void ticketWithEmptyExtensionBlockKeepsSessionAlive() throws Exception {
        TlsSession client = sessionAfterTicket(withExtensionBlock(new byte[0]));
        assertArrayEquals(new byte[] {0x41}, client.read(), "после тикета читаются данные");
    }

    @Test
    @DisplayName("Без хранилища PSK искажённый NewSessionTicket тоже закрывает соединение")
    void malformedTicketClosesSessionWithoutPskStore() throws Exception {
        TlsSession client = sessionAfterTicket(ticketWithoutExtensionBlock(), false);
        Exception thrown = assertThrows(Exception.class, client::read);
        assertTrue(thrown instanceof TlsException, "ожидалось TlsException, получено " + thrown);
        assertEquals(TlsConstants.ALERT_DECODE_ERROR, ((TlsException) thrown).getAlertCode());
        assertTrue(client.isClosed(), "строгость не должна зависеть от наличия хранилища");
    }

    @Test
    @DisplayName("Без хранилища PSK корректный NewSessionTicket не мешает чтению данных")
    void validTicketWithoutPskStoreKeepsSessionAlive() throws Exception {
        TlsSession client = sessionAfterTicket(withExtensionBlock(new byte[0]), false);
        assertArrayEquals(new byte[] {0x41}, client.read());
    }
}
