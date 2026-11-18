package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.List;
import java.util.logging.Level;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.util.CryptoRandom;

/**
 * Возобновление по PSK через HelloRetryRequest: решение сервера по PSK принимается в первом
 * ClientHello и переносится во второй без пересмотра (RFC 8446 §4.1.2, §4.2.11), а binder
 * второго ClientHello считается по RFC 8446 §4.2.11.2.
 */
@DisplayName("TlsHandshakeEngine: PSK после HelloRetryRequest")
class TlsHandshakeEnginePskAfterHrrTest {

    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;
    // Клиент стартует с группы, которой сервер не предпочитает: рукопожатие идёт через HRR
    private static final int CLIENT_GROUP = TlsConstants.GRP_GC256A;
    private static final int SERVER_GROUP = TlsConstants.GRP_GC256B;
    // Допуск проверки возраста тикета заведомо превышен
    private static final long WRONG_OBFUSCATED_AGE = 0x40000000L;

    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
    }

    private static TlsCiphersuite cs() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    private static byte[] random(int length) {
        byte[] bytes = new byte[length];
        CryptoRandom.INSTANCE.nextBytes(bytes);
        return bytes;
    }

    private static TlsHandshakeEngine client() {
        return new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.CLIENT,
                cs(),
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        CLIENT_GROUP,
                        SIG_SCHEME,
                        null,
                        null,
                        HASH_LEN),
                ECParameters.tc26a256(),
                CLIENT_GROUP,
                SIG_SCHEME,
                HASH_LEN,
                null,
                false,
                null);
    }

    private static TlsHandshakeEngine server() {
        return new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER,
                cs(),
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        SERVER_GROUP,
                        SIG_SCHEME,
                        serverCert.priv,
                        List.of(serverCert.cert),
                        HASH_LEN),
                ECParameters.cryptoProA(),
                SERVER_GROUP,
                SIG_SCHEME,
                HASH_LEN,
                null,
                false,
                null);
    }

    private static TlsHandshakeEngine clientWithPsk(byte[] psk, byte[] identity, long age) {
        TlsHandshakeEngine client = client();
        client.setPsk(psk, identity, age);
        return client;
    }

    private static TlsHandshakeEngine serverWithStore(PskStore store) {
        TlsHandshakeEngine server = server();
        server.setServerPskStore(store);
        return server;
    }

    private static PskStore storeWith(byte[] ticket, byte[] psk) {
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
        return store;
    }

    /** Хранилище, у которого {@code get} всегда пуст: моделирует гонку peek -> get. */
    private static final class LosingRaceStore implements PskStore {
        private final PskStore delegate;

        LosingRaceStore(PskStore delegate) {
            this.delegate = delegate;
        }

        @Override
        public PskEntry get(byte[] ticket) {
            return null;
        }

        @Override
        public PskEntry getForResumption(PskBinding binding) {
            return delegate.getForResumption(binding);
        }

        @Override
        public void remove(byte[] ticket) {
            delegate.remove(ticket);
        }

        @Override
        public PskEntry peek(byte[] ticket) {
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
            delegate.onTicketReceived(entry);
        }
    }

    /** Содержимое закрытого поля pskKey: после отказа в PSK оно обязано быть обнулено. */
    private static byte[] pskKeyOf(TlsHandshakeEngine engine) throws Exception {
        Field field = TlsHandshakeEngine.class.getDeclaredField("pskKey");
        field.setAccessible(true);
        return (byte[]) field.get(engine);
    }

    /** Клиент -> CH1, сервер -> HRR; возвращает HRR. */
    private static byte[] runUntilHrr(TlsHandshakeEngine client, TlsHandshakeEngine server)
            throws Exception {
        server.receive(client.start());
        server.acknowledgeReadKeyChange();
        byte[] hrr = HandshakeOutputs.nextMessage(server);
        assertNotNull(hrr, "сервер должен ответить HelloRetryRequest");
        assertNull(HandshakeOutputs.nextMessage(server), "после HRR очередь сервера пуста");
        return hrr;
    }

    private static byte[] clientSecondHello(TlsHandshakeEngine client, byte[] hrr)
            throws Exception {
        client.receive(hrr);
        client.acknowledgeReadKeyChange();
        byte[] ch2 = HandshakeOutputs.nextMessage(client);
        assertNotNull(ch2, "клиент должен прислать второй ClientHello");
        return ch2;
    }

    @Test
    @DisplayName("валидный тикет и HRR: PSK принят, рукопожатие завершается на обеих сторонах")
    void validTicketResumesThroughHrr() throws Exception {
        byte[] psk = random(HASH_LEN);
        byte[] ticket = random(32);
        PskStore store = storeWith(ticket, psk);
        TlsHandshakeEngine client = clientWithPsk(psk, ticket, 0);
        TlsHandshakeEngine server = serverWithStore(store);

        byte[] hrr = runUntilHrr(client, server);
        server.receive(clientSecondHello(client, hrr));
        server.acknowledgeReadKeyChange();

        assertTrue(server.isPskAccepted(), "PSK должен быть принят во втором ClientHello");
        assertNull(store.peek(ticket), "тикет должен быть потреблён однократно");

        byte[] serverHello = HandshakeOutputs.nextMessage(server);
        byte[] encryptedExtensions = HandshakeOutputs.nextMessage(server);
        byte[] serverFinished = HandshakeOutputs.nextMessage(server);
        assertNull(
                HandshakeOutputs.nextMessage(server), "при PSK сертификатов в полёте сервера нет");
        client.receive(serverHello);
        client.acknowledgeReadKeyChange();
        client.receive(encryptedExtensions);
        client.acknowledgeReadKeyChange();
        client.receive(serverFinished);
        client.acknowledgeReadKeyChange();
        assertTrue(client.isPskAccepted(), "клиент должен увидеть принятый PSK");
        server.receive(HandshakeOutputs.nextMessage(client));
        server.acknowledgeReadKeyChange();
        assertTrue(server.isDone(), "сервер должен завершить рукопожатие");
    }

    @Test
    @DisplayName("тикет с неверным возрастом и HRR: полное рукопожатие, PSK не принимается")
    void staleAgeTicketIsNotAcceptedAfterHrr() throws Exception {
        byte[] psk = random(HASH_LEN);
        byte[] ticket = random(32);
        TlsHandshakeEngine client = clientWithPsk(psk, ticket, WRONG_OBFUSCATED_AGE);
        TlsHandshakeEngine server = serverWithStore(storeWith(ticket, psk));

        byte[] hrr = runUntilHrr(client, server);
        server.receive(clientSecondHello(client, hrr));
        server.acknowledgeReadKeyChange();

        assertFalse(
                server.isPskAccepted(),
                "тикет, отвергнутый в первом ClientHello, не должен приниматься во втором");
        assertNotNull(
                HandshakeOutputs.nextMessage(server),
                "сервер должен продолжить полным рукопожатием");
        assertNull(pskKeyOf(server), "отвергнутый PSK должен быть затёрт");
    }

    @Test
    @DisplayName("неизвестная identity в CH1 и тот же PSK в CH2: полное рукопожатие без обрыва")
    void unknownIdentityRepeatedInSecondHelloIsIgnored() throws Exception {
        byte[] psk = random(HASH_LEN);
        TlsHandshakeEngine client = clientWithPsk(psk, random(32), 0);
        TlsHandshakeEngine server = serverWithStore(new InMemoryPskStore(10));

        byte[] hrr = runUntilHrr(client, server);
        server.receive(clientSecondHello(client, hrr));
        server.acknowledgeReadKeyChange();

        assertFalse(server.isPskAccepted(), "неизвестный тикет не должен приниматься");
        assertNotNull(
                HandshakeOutputs.nextMessage(server),
                "сервер должен продолжить полным рукопожатием");
    }

    @Test
    @DisplayName("гонка peek -> get в CH1: PSK не принимается и во втором ClientHello")
    void lostRaceInFirstHelloIsNotAcceptedInSecond() throws Exception {
        byte[] psk = random(HASH_LEN);
        byte[] ticket = random(32);
        TlsHandshakeEngine client = clientWithPsk(psk, ticket, 0);
        TlsHandshakeEngine server = serverWithStore(new LosingRaceStore(storeWith(ticket, psk)));

        byte[] hrr = runUntilHrr(client, server);
        server.receive(clientSecondHello(client, hrr));
        server.acknowledgeReadKeyChange();

        assertFalse(
                server.isPskAccepted(),
                "тикет, потерянный в гонке, не должен приниматься во втором ClientHello");
        assertNotNull(
                HandshakeOutputs.nextMessage(server),
                "сервер должен продолжить полным рукопожатием");
    }

    @Test
    @DisplayName("CH2 с другой identity: illegal_parameter")
    void differentIdentityInSecondHelloIsRejected() throws Exception {
        byte[] psk = random(HASH_LEN);
        byte[] ticket = random(32);
        TlsHandshakeEngine server = serverWithStore(storeWith(ticket, psk));
        byte[] hrr = runUntilHrr(clientWithPsk(psk, ticket, 0), server);

        // Второй ClientHello строит другой клиент: его PSK и identity не совпадают с CH1
        TlsHandshakeEngine impostor = clientWithPsk(psk, random(32), 0);
        impostor.start();
        byte[] foreignCh2 = clientSecondHello(impostor, hrr);

        TlsException ex = assertThrows(TlsException.class, () -> server.receive(foreignCh2));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                ex.getAlertCode(),
                "смена identity между ClientHello должна давать illegal_parameter");
        assertNull(pskKeyOf(server), "PSK должен быть затёрт перед отказом");
    }

    @Test
    @DisplayName("PSK только в CH2 при явном setServerPsk: illegal_parameter")
    void pskAppearingOnlyInSecondHelloIsRejected() throws Exception {
        byte[] psk = random(HASH_LEN);
        TlsHandshakeEngine server = server();
        server.setServerPsk(psk);
        byte[] hrr = runUntilHrr(client(), server);

        TlsHandshakeEngine lateClient = clientWithPsk(psk, random(32), 0);
        lateClient.start();
        byte[] ch2WithPsk = clientSecondHello(lateClient, hrr);

        TlsException ex = assertThrows(TlsException.class, () -> server.receive(ch2WithPsk));
        assertEquals(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                ex.getAlertCode(),
                "PSK, которого не было в CH1, не должен появляться в CH2");
        assertNull(pskKeyOf(server), "PSK должен быть затёрт перед отказом");
    }

    @Test
    @DisplayName("CH2 без pre_shared_key после принятого PSK в CH1: полное рукопожатие")
    void secondHelloWithoutPskFallsBackToFullHandshake() throws Exception {
        byte[] psk = random(HASH_LEN);
        byte[] ticket = random(32);
        TlsHandshakeEngine server = serverWithStore(storeWith(ticket, psk));
        byte[] hrr = runUntilHrr(clientWithPsk(psk, ticket, 0), server);

        TlsHandshakeEngine plainClient = client();
        plainClient.start();
        server.receive(clientSecondHello(plainClient, hrr));
        server.acknowledgeReadKeyChange();

        assertFalse(server.isPskAccepted(), "без pre_shared_key в CH2 PSK принят быть не может");
        assertNull(pskKeyOf(server), "PSK должен быть затёрт");
    }

    @Test
    @DisplayName("неверный binder в CH2: decrypt_error и затёртый pskKey")
    void wrongBinderInSecondHelloGivesDecryptError() throws Exception {
        byte[] psk = random(HASH_LEN);
        byte[] ticket = random(32);
        TlsHandshakeEngine client = clientWithPsk(psk, ticket, 0);
        TlsHandshakeEngine server = serverWithStore(storeWith(ticket, psk));

        byte[] ch2 = clientSecondHello(client, runUntilHrr(client, server));
        ch2[ch2.length - 1] ^= 1;

        try (LogCapture log = LogCapture.start(LogCapture.TLS13)) {
            TlsException ex = assertThrows(TlsException.class, () -> server.receive(ch2));
            assertEquals(
                    TlsConstants.ALERT_DECRYPT_ERROR,
                    ex.getAlertCode(),
                    "неверный binder должен давать decrypt_error (RFC 8446 §6.2)");
            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "отказ по данным пира не даёт WARNING");
        }
        assertNull(pskKeyOf(server), "PSK должен быть затёрт после неверного binder");
    }

    @Test
    @DisplayName("неверный binder в CH1: decrypt_error и затёртый pskKey")
    void wrongBinderInFirstHelloGivesDecryptError() throws Exception {
        byte[] psk = random(HASH_LEN);
        byte[] ticket = random(32);
        TlsHandshakeEngine server = serverWithStore(storeWith(ticket, psk));
        byte[] ch1 = clientWithPsk(psk, ticket, 0).start();
        ch1[ch1.length - 1] ^= 1;

        TlsException ex = assertThrows(TlsException.class, () -> server.receive(ch1));
        assertEquals(
                TlsConstants.ALERT_DECRYPT_ERROR,
                ex.getAlertCode(),
                "неверный binder должен давать decrypt_error (RFC 8446 §6.2)");
        assertNull(pskKeyOf(server), "PSK должен быть затёрт после неверного binder");
    }

    @Test
    @DisplayName("префикс транскрипта: message_hash || HRR, CH2 не добавлен, копия независима")
    void transcriptPrefixIsMessageHashPlusHrr() {
        HandshakeContext context = new HandshakeContext(HASH_LEN);
        byte[] ch1 = random(100);
        byte[] hrr = random(40);
        byte[] ch1Hash;
        context.addToTranscript(ch1);
        ch1Hash = context.transcriptHash();
        context.replaceTranscriptWithMessageHash();
        context.addToTranscript(hrr);

        byte[] prefix = context.transcriptPrefix();

        assertEquals(4 + HASH_LEN + hrr.length, prefix.length, "длина префикса");
        assertEquals(TlsConstants.HT_MESSAGE_HASH, prefix[0], "тип message_hash");
        assertEquals(HASH_LEN, prefix[3] & 0xFF, "длина message_hash");
        byte[] embeddedHash = java.util.Arrays.copyOfRange(prefix, 4, 4 + HASH_LEN);
        assertArrayEquals(ch1Hash, embeddedHash, "внутри message_hash лежит Hash(CH1)");
        assertArrayEquals(
                hrr,
                java.util.Arrays.copyOfRange(prefix, 4 + HASH_LEN, prefix.length),
                "после message_hash следует полный кадр HRR");

        byte[] hashBefore = context.transcriptHash();
        java.util.Arrays.fill(prefix, (byte) 0);
        assertArrayEquals(
                hashBefore,
                context.transcriptHash(),
                "затирание копии не должно менять транскрипт");
    }
}
