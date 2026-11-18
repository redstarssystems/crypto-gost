package org.rssys.gost.jsse.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.util.CryptoRandom;

/**
 * Клиент не сохраняет тикет, который не поместится в расширение {@code pre_shared_key}: предъявленный
 * в ClientHello он вышел бы с переполненными длинами, и пир ответил бы {@code decode_error}.
 */
@DisplayName("GostSSLSessionContext: тикет, не помещающийся в ClientHello, не сохраняется")
class GostSSLSessionContextTicketLimitTest {

    private static final TlsCiphersuite SUITE =
            TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    private static final int HASH_LEN = 32;
    private static final PskBinding BINDING = new PskBinding("test.example", "test-id");

    private static int savedTickets(int ticketLength) throws Exception {
        GostSSLSessionContext context = new GostSSLSessionContext(SUITE);
        byte[] rms = new byte[HASH_LEN];
        CryptoRandom.INSTANCE.nextBytes(rms);
        byte[] ticket = new byte[ticketLength];
        CryptoRandom.INSTANCE.nextBytes(ticket);
        byte[] nstBody = TlsMessageBuilder.buildNewSessionTicket(3600, 0, new byte[8], ticket);

        context.saveNewSessionTicket(
                "test.example",
                443,
                rms,
                TlsMessageParser.parseNewSessionTicket(nstBody),
                BINDING,
                PskEntry.NO_CERTIFICATE_BOUND);

        return context.getPskStore().size();
    }

    @Test
    @DisplayName("Тикет наибольшей допустимой длины сохраняется, на байт длиннее - нет")
    void ticketLongerThanExtensionLimitIsNotSaved() throws Exception {
        int limit = TlsPskHelper.maxIdentityLength(HASH_LEN);

        assertEquals(1, savedTickets(limit), "тикет длиной " + limit + " байт помещается");
        assertEquals(0, savedTickets(limit + 1), "тикет длиннее предела предъявить нельзя");
    }
}
