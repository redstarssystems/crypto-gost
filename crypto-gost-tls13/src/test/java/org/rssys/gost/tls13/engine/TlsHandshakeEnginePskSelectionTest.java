package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.LogCapture;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.PskClientHelloFixture;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.crypto.HkdfStreebog;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageParser;
import org.rssys.gost.tls13.psk.InMemoryPskStore;
import org.rssys.gost.tls13.psk.PskBinding;
import org.rssys.gost.tls13.psk.PskEntry;
import org.rssys.gost.tls13.psk.PskStore;
import org.rssys.gost.tls13.psk.TlsPskHelper;
import org.rssys.gost.util.CryptoRandom;

/**
 * Строгий разбор {@code pre_shared_key} на сервере и проверка {@code selected_identity} на клиенте
 * (RFC 8446 §4.2.9, §4.2.11): структура, выбор среди нескольких identity, предел просмотра
 * хранилища, перенос выбора из первого ClientHello во второй после HelloRetryRequest.
 */
@DisplayName("TlsHandshakeEngine: выбор PSK среди нескольких identity и строгий разбор")
class TlsHandshakeEnginePskSelectionTest {

    /** Типы расширений ClientHello, на которые тест якобы получает ответ в ServerHello. */
    private static final Set<Integer> SERVER_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_SUPPORTED_VERSIONS,
                    TlsConstants.EXT_KEY_SHARE,
                    TlsConstants.EXT_PRE_SHARED_KEY);

    private static final int HASH_LEN = 32;
    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    // Клиент начинает с GC256A; сервер, предпочитающий GC256B, отвечает HelloRetryRequest
    private static final int CLIENT_GROUP = TlsConstants.GRP_GC256A;
    private static final int HRR_SERVER_GROUP = TlsConstants.GRP_GC256B;
    private static final int UNKNOWN_EXTENSION = 0x4A4A;

    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() {
        serverCert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
    }

    /** Тикет и PSK, которыми клиент и сервер владеют вместе. */
    record Known(byte[] ticket, byte[] psk) {}

    static Known known(int n) {
        return new Known(sequence(0x10 * n), sequence(0xA0 + n));
    }

    private static byte[] sequence(int base) {
        byte[] data = new byte[HASH_LEN];
        for (int i = 0; i < HASH_LEN; i++) {
            data[i] = (byte) (base + i);
        }
        return data;
    }

    private static byte[] randomTicket() {
        byte[] ticket = new byte[HASH_LEN];
        CryptoRandom.INSTANCE.nextBytes(ticket);
        return ticket;
    }

    private static TlsCiphersuite suite() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    static InMemoryPskStore storeWith(Known... entries) {
        InMemoryPskStore store = new InMemoryPskStore(100);
        for (Known k : entries) {
            store.onTicketReceived(entry(k, System.currentTimeMillis()));
        }
        return store;
    }

    private static PskEntry entry(Known k, long issueTime) {
        return entry(k, issueTime, 3600);
    }

    private static PskEntry entry(Known k, long issueTime, long lifetimeSeconds) {
        return new PskEntry(
                k.ticket(),
                lifetimeSeconds,
                0,
                new byte[8],
                k.psk(),
                issueTime,
                PskBinding.forServer(null),
                PskEntry.NO_CERTIFICATE_BOUND);
    }

    private static TlsHandshakeEngine server(PskStore store, int group, ECParameters params) {
        TlsHandshakeEngine server =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.SERVER,
                        suite(),
                        new TlsMessageBuilder(
                                suite(),
                                List.of(suite().getId()),
                                group,
                                SIG_SCHEME,
                                serverCert.priv,
                                List.of(serverCert.cert),
                                HASH_LEN),
                        params,
                        group,
                        SIG_SCHEME,
                        HASH_LEN,
                        null,
                        false,
                        null);
        server.setServerPskStore(store);
        return server;
    }

    static TlsHandshakeEngine server(PskStore store) {
        return server(store, CLIENT_GROUP, ECParameters.tc26a256());
    }

    private static TlsHandshakeEngine hrrServer(PskStore store) {
        return server(store, HRR_SERVER_GROUP, ECParameters.cryptoProA());
    }

    private static TlsHandshakeEngine client(Known psk) {
        TlsHandshakeEngine client =
                new TlsHandshakeEngine(
                        TlsHandshakeEngine.Role.CLIENT,
                        suite(),
                        new TlsMessageBuilder(
                                suite(),
                                List.of(suite().getId()),
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
        if (psk != null) {
            client.setPsk(psk.psk(), psk.ticket(), 0);
        }
        return client;
    }

    /** Основа для конструктора: кадр штатного клиента с одной identity. */
    private static byte[] baseFrame() throws Exception {
        return client(known(0)).start();
    }

    static PskClientHelloFixture fixtureWith(Known... identities) throws Exception {
        PskClientHelloFixture fixture = new PskClientHelloFixture(baseFrame());
        for (Known k : identities) {
            fixture.identity(k.ticket(), 0, k.psk());
        }
        return fixture;
    }

    /** Identity, о которой сервер не знает: случайный тикет и произвольный PSK. */
    static Known stranger() {
        return new Known(randomTicket(), sequence(0x77));
    }

    static TlsException receiveRejected(TlsHandshakeEngine server, byte[] frame) {
        return assertThrows(
                TlsException.class, () -> server.receive(frame), "ClientHello должен отвергаться");
    }

    static void assertAlert(byte expected, TlsException ex) {
        assertEquals(expected, ex.getAlertCode(), "код алерта: " + ex.getMessage());
    }

    private static int selectedIdentityOf(TlsHandshakeEngine server) throws Exception {
        byte[] serverHello = HandshakeOutputs.nextMessage(server);
        assertNotNull(serverHello, "сервер должен прислать ServerHello");
        return TlsMessageParser.parseServerHello(
                        TlsHandshakeMessage.decode(serverHello).getBody(),
                        SERVER_RESPONSE_TYPES_SENT)
                .selectedPskIdentity;
    }

    @Test
    @DisplayName("legacy_version ServerHello не 0x0303: принятый PSK клиент по-прежнему видит")
    void legacyVersionDoesNotHidePsk() throws Exception {
        // RFC 8446 §4.2.1: при наличии supported_versions legacy_version игнорируется. Раньше
        // selected_identity искался проходом, который при чужой версии считал расширений нет, и
        // клиент уходил в полное рукопожатие. На живом сервере проверить нельзя (транскрипты
        // разойдутся на Finished), поэтому проверяется только решение клиента о режиме
        Known k = known(1);
        TlsHandshakeEngine client = client(k);
        TlsHandshakeEngine server = server(storeWith(k));
        server.receive(client.start());
        byte[] serverHello = HandshakeOutputs.nextMessage(server);
        // handshake-заголовок(4) || legacy_version(2)
        serverHello[4] = 0x03;
        serverHello[5] = 0x01;

        client.receive(serverHello);

        assertTrue(client.isPskAccepted(), "PSK принят сервером и должен быть виден клиенту");
    }

    // ========================================================================
    // Структура расширений
    // ========================================================================

    @Test
    @DisplayName("pre_shared_key без psk_key_exchange_modes: missing_extension")
    void missingKeyExchangeModesIsRejected() throws Exception {
        Known a = known(1);
        byte[] frame = fixtureWith(a).withoutModes().build();

        assertAlert(
                TlsConstants.ALERT_MISSING_EXTENSION, receiveRejected(server(storeWith(a)), frame));
    }

    @Test
    @DisplayName("Режимы без psk_dhe_ke: PSK не выбирается, полное рукопожатие без обрыва")
    void modesWithoutDheKeFallBackToFullHandshake() throws Exception {
        Known a = known(1);
        InMemoryPskStore store = storeWith(a);
        byte[] frame = fixtureWith(a).modes((byte) 1, (byte) 0).build();
        TlsHandshakeEngine server = server(store);

        server.receive(frame);

        assertFalse(server.isPskAccepted(), "без psk_dhe_ke PSK принят быть не может");
        assertNotNull(store.peek(a.ticket()), "тикет не должен быть потреблён");
    }

    @Test
    @DisplayName("Битый psk_key_exchange_modes: decode_error")
    void malformedKeyExchangeModesIsRejected() throws Exception {
        Known a = known(1);
        // заявленная длина списка 5, байт один
        byte[] frame = fixtureWith(a).modes((byte) 5, (byte) 1).build();

        assertAlert(TlsConstants.ALERT_DECODE_ERROR, receiveRejected(server(storeWith(a)), frame));
    }

    @Test
    @DisplayName("pre_shared_key не последним расширением: illegal_parameter")
    void pskNotLastIsRejected() throws Exception {
        Known a = known(1);
        byte[] frame = fixtureWith(a).extensionAfterPsk(UNKNOWN_EXTENSION, new byte[] {1}).build();

        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER, receiveRejected(server(storeWith(a)), frame));
    }

    @Test
    @DisplayName("Binder на один меньше или больше числа identity: illegal_parameter")
    void binderCountMismatchIsRejected() throws Exception {
        Known a = known(1);
        Known b = known(2);
        for (int delta : new int[] {-1, 1}) {
            byte[] frame = fixtureWith(a, b).binderCountDelta(delta).build();
            assertAlert(
                    TlsConstants.ALERT_ILLEGAL_PARAMETER,
                    receiveRejected(server(storeWith(a, b)), frame));
        }
    }

    @Test
    @DisplayName(
            "Длина binder: 31 байт - decode_error (opaque<32..255>), 33 байта - illegal_parameter")
    void binderLengthIsChecked() throws Exception {
        Known a = known(1);
        assertAlert(
                TlsConstants.ALERT_DECODE_ERROR,
                receiveRejected(server(storeWith(a)), fixtureWith(a).binderLength(0, 31).build()));
        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                receiveRejected(server(storeWith(a)), fixtureWith(a).binderLength(0, 33).build()));
    }

    @Test
    @DisplayName(
            "Binder неверной длины у identity за пределом просмотра: illegal_parameter, а не «не смотрели»")
    void binderLengthIsCheckedBeyondTheScanLimit() throws Exception {
        Known a = known(1);
        PskClientHelloFixture fixture = fixtureWith(a);
        for (int i = 0; i < 6; i++) {
            fixture.identity(randomTicket(), 0, sequence(0x77));
        }
        // identity 6 (седьмая) за пределом MAX_PSK_IDENTITIES: её binder в 33 байта
        byte[] frame = fixture.binderLength(6, 33).build();

        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER, receiveRejected(server(storeWith(a)), frame));
    }

    @Test
    @DisplayName("Искажённая длина вектора binders или лишние байты после него: decode_error")
    void malformedBindersVectorIsRejected() throws Exception {
        Known a = known(1);
        for (int delta : new int[] {-1, 1}) {
            assertAlert(
                    TlsConstants.ALERT_DECODE_ERROR,
                    receiveRejected(
                            server(storeWith(a)),
                            fixtureWith(a).bindersLengthDelta(delta).build()));
        }
        assertAlert(
                TlsConstants.ALERT_DECODE_ERROR,
                receiveRejected(
                        server(storeWith(a)),
                        fixtureWith(a).garbageAfterBinders(new byte[] {0, 0}).build()));
    }

    @Test
    @DisplayName("Байты после блока расширений ClientHello: decode_error")
    void dataAfterExtensionsIsRejected() throws Exception {
        Known a = known(1);
        byte[] frame = fixtureWith(a).build();
        byte[] withTail = java.util.Arrays.copyOf(frame, frame.length + 1);
        int bodyLength = withTail.length - 4;
        withTail[1] = (byte) (bodyLength >>> 16);
        withTail[2] = (byte) (bodyLength >>> 8);
        withTail[3] = (byte) bodyLength;

        assertAlert(
                TlsConstants.ALERT_DECODE_ERROR, receiveRejected(server(storeWith(a)), withTail));
    }

    @Test
    @DisplayName(
            "Повтор pre_shared_key, psk_key_exchange_modes и произвольного расширения: illegal_parameter")
    void duplicateExtensionsAreRejected() throws Exception {
        Known a = known(1);
        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                receiveRejected(server(storeWith(a)), fixtureWith(a).duplicatePsk().build()));
        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                receiveRejected(server(storeWith(a)), fixtureWith(a).duplicateModes().build()));
        // повтор типа, который уже есть в основе ClientHello (supported_versions), и без PSK вовсе
        byte[] withoutPsk =
                new PskClientHelloFixture(client(null).start())
                        .withoutPskExtension()
                        .extensionBeforePsk(
                                TlsConstants.EXT_SUPPORTED_VERSIONS, new byte[] {2, 3, 4})
                        .build();
        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                receiveRejected(server(new InMemoryPskStore(10)), withoutPsk));
    }

    // ========================================================================
    // Выбор среди нескольких identity
    // ========================================================================

    @Test
    @DisplayName(
            "Выбирается первая известная, не первая в списке: selected_identity равен её номеру")
    void firstKnownIdentityIsSelected() throws Exception {
        Known b = known(2);
        Known c = known(3);
        InMemoryPskStore store = storeWith(b, c);
        PskClientHelloFixture fixture =
                fixtureWith(stranger(), b, c); // номера: 0 - чужая, 1 - b, 2 - c
        TlsHandshakeEngine server = server(store);

        server.receive(fixture.build());

        assertTrue(server.isPskAccepted(), "известная identity должна быть выбрана");
        assertEquals(1, selectedIdentityOf(server), "selected_identity - номер b в списке клиента");
        assertNull(store.peek(b.ticket()), "выбранный тикет потреблён");
        assertNotNull(store.peek(c.ticket()), "вторая известная identity не трогается");
    }

    @Test
    @DisplayName("Нет известных identity: полное рукопожатие без обрыва")
    void noKnownIdentityFallsBackToFullHandshake() throws Exception {
        TlsHandshakeEngine server = server(new InMemoryPskStore(10));

        server.receive(fixtureWith(stranger(), stranger()).build());

        assertFalse(server.isPskAccepted(), "неизвестные identity игнорируются");
        assertNotNull(
                HandshakeOutputs.nextMessage(server), "сервер продолжает полным рукопожатием");
    }

    @Test
    @DisplayName("Предел просмотра: известная identity на 5-м месте выбрана, на 6-м и дальше - нет")
    void scanLimitBoundsStoreLookups() throws Exception {
        int limit = TlsConstants.MAX_PSK_IDENTITIES;
        Known target = known(4);
        for (int position : new int[] {limit - 1, limit, limit + 6}) {
            PskClientHelloFixture fixture = fixtureWith();
            for (int i = 0; i < 17; i++) {
                if (i == position) {
                    fixture.identity(target.ticket(), 0, target.psk());
                } else {
                    Known other = stranger();
                    fixture.identity(other.ticket(), 0, other.psk());
                }
            }
            TlsHandshakeEngine server = server(storeWith(target));

            server.receive(fixture.build());

            if (position < limit) {
                assertTrue(server.isPskAccepted(), "известная на месте " + position + " выбрана");
                assertEquals(position, selectedIdentityOf(server), "selected_identity");
            } else {
                assertFalse(
                        server.isPskAccepted(),
                        "известная на месте " + position + " за пределом просмотра: PSK не выбран");
                assertNotNull(HandshakeOutputs.nextMessage(server), "соединение не обрывается");
            }
        }
    }

    @Test
    @DisplayName(
            "Выбранная не прошла проверку возраста: полное рукопожатие, вторая известная не пробуется")
    void rejectedByAgeDoesNotTryNextIdentity() throws Exception {
        Known first = known(1);
        Known second = known(2);
        InMemoryPskStore store = new InMemoryPskStore(100);
        // первый выпущен сутки назад при сроке жизни в неделю: тикет известен и не просрочен,
        // но возраст в ClientHello (0) расходится с ожидаемым на сутки
        store.onTicketReceived(
                entry(first, System.currentTimeMillis() - 24L * 3600 * 1000, 7L * 24 * 3600));
        store.onTicketReceived(entry(second, System.currentTimeMillis()));
        TlsHandshakeEngine server = server(store);

        try (LogCapture log = LogCapture.start(LogCapture.TLS13)) {
            server.receive(fixtureWith(first, second).build());

            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "возраст билета данные пира: WARNING не нужен");
            assertTrue(
                    log.messages(Level.FINE).stream()
                            .anyMatch(m -> m.contains("ticket age mismatch")),
                    "причина отказа PSK на DEBUG: " + log.messages(Level.FINE));
            assertTrue(
                    log.messages(Level.FINE).stream()
                            .anyMatch(
                                    m ->
                                            m.contains(
                                                    "PSK offered: 2 identity(ies), accepted=false")),
                    "итог поиска PSK на DEBUG: " + log.messages(Level.FINE));
        }

        assertFalse(server.isPskAccepted(), "отказ по возрасту ведёт к полному рукопожатию");
        assertNotNull(
                store.peek(second.ticket()),
                "к следующей identity сервер не переходит: её тикет не потреблён");
    }

    @Test
    @DisplayName("Неверный binder выбранной: decrypt_error, вторая известная не пробуется")
    void wrongBinderOfSelectedGivesDecryptError() throws Exception {
        Known first = known(1);
        Known second = known(2);
        InMemoryPskStore store = storeWith(first, second);
        // binder первой посчитан по чужому PSK
        PskClientHelloFixture fixture = fixtureWith().identity(first.ticket(), 0, sequence(0x55));
        fixture.identity(second.ticket(), 0, second.psk());

        try (LogCapture log = LogCapture.start(LogCapture.TLS13)) {
            assertAlert(
                    TlsConstants.ALERT_DECRYPT_ERROR,
                    receiveRejected(server(store), fixture.build()));
            // Причина целиком в исключении и в alert: запись в журнале её не дублирует
            assertEquals(
                    List.of(),
                    log.messagesAtOrAbove(Level.WARNING),
                    "отказ по данным пира не даёт WARNING");
        }
        assertNotNull(store.peek(first.ticket()), "тикет с неверным binder остаётся в хранилище");
        assertNotNull(store.peek(second.ticket()), "вторая identity не потреблена");
    }

    @Test
    @DisplayName("isOrderedSubsetOf: повреждённый снимок даёт false, а не исключение")
    void corruptedSnapshotIsNotASubset() throws Exception {
        Known a = known(1);
        byte[] frame = fixtureWith(a).build();
        byte[] body = java.util.Arrays.copyOfRange(frame, 4, frame.length);
        TlsMessageParser.ParsedClientPsk psk = TlsMessageParser.parseClientHelloPsk(body, HASH_LEN);

        byte[] snapshot = psk.identitiesSnapshot();
        assertTrue(psk.isOrderedSubsetOf(snapshot), "собственный снимок содержит identity");
        // заявленная длина записи выходит за массив
        byte[] truncated = java.util.Arrays.copyOf(snapshot, snapshot.length - 1);
        assertFalse(
                psk.isOrderedSubsetOf(truncated), "усечённый снимок не может содержать identity");
        assertFalse(psk.isOrderedSubsetOf(new byte[] {0x7F, (byte) 0xFF, 1}), "длина за пределом");
        assertFalse(psk.isOrderedSubsetOf(new byte[0]), "пустой снимок не содержит identity");
    }

    // ========================================================================
    // Второй ClientHello после HelloRetryRequest
    // ========================================================================

    /** Состояние рукопожатия после HelloRetryRequest: нужно для сборки второго ClientHello. */
    private record AfterHrr(TlsHandshakeEngine server, byte[] prefix, byte[] baseSecondHello) {}

    private static AfterHrr hrrAfter(InMemoryPskStore store, byte[] firstHello) throws Exception {
        TlsHandshakeEngine server = hrrServer(store);
        server.receive(firstHello);
        byte[] hrr = HandshakeOutputs.nextMessage(server);
        assertNotNull(hrr, "сервер должен ответить HelloRetryRequest");

        // Основа второго ClientHello: штатный клиент, прошедший свой HRR
        TlsHandshakeEngine client = client(known(0));
        client.start();
        client.receive(hrr);
        byte[] baseSecond = HandshakeOutputs.nextMessage(client);

        byte[] prefix = new byte[4 + HASH_LEN + hrr.length];
        prefix[0] = TlsConstants.HT_MESSAGE_HASH;
        prefix[3] = (byte) HASH_LEN;
        org.rssys.gost.digest.Digest digest = HkdfStreebog.newDigest(HASH_LEN);
        digest.update(firstHello, 0, firstHello.length);
        digest.doFinal(prefix, 4);
        System.arraycopy(hrr, 0, prefix, 4 + HASH_LEN, hrr.length);
        return new AfterHrr(server, prefix, baseSecond);
    }

    private static byte[] secondHello(AfterHrr state, Known... identities) {
        PskClientHelloFixture fixture =
                new PskClientHelloFixture(state.baseSecondHello()).afterHrr(state.prefix());
        for (Known k : identities) {
            fixture.identity(k.ticket(), 0, k.psk());
        }
        return fixture.build();
    }

    @Test
    @DisplayName("CH1 [A,B], выбрана B: CH2 [B] - возобновление, selected_identity = 0")
    void secondHelloWithOnlySelectedKeepsPsk() throws Exception {
        Known a = stranger();
        Known b = known(2);
        AfterHrr state = hrrAfter(storeWith(b), fixtureWith(a, b).build());

        state.server().receive(secondHello(state, b));

        assertTrue(state.server().isPskAccepted(), "PSK принят");
        assertEquals(0, selectedIdentityOf(state.server()), "индекс в CH2 после удаления A");
    }

    @Test
    @DisplayName("CH1 [A,B], выбрана B: CH2 [A,B] - возобновление, selected_identity = 1")
    void secondHelloWithSameListKeepsPsk() throws Exception {
        Known a = stranger();
        Known b = known(2);
        AfterHrr state = hrrAfter(storeWith(b), fixtureWith(a, b).build());

        state.server().receive(secondHello(state, a, b));

        assertTrue(state.server().isPskAccepted(), "PSK принят");
        assertEquals(1, selectedIdentityOf(state.server()), "индекс B в CH2");
    }

    @Test
    @DisplayName("CH1 [A,B], выбрана B: CH2 [A] - полное рукопожатие, B не подставляется")
    void secondHelloWithoutSelectedFallsBack() throws Exception {
        Known a = stranger();
        Known b = known(2);
        AfterHrr state = hrrAfter(storeWith(b), fixtureWith(a, b).build());

        state.server().receive(secondHello(state, a));

        assertFalse(
                state.server().isPskAccepted(), "принятая identity удалена: PSK не используется");
        assertNotNull(state.server().poll(), "рукопожатие продолжается полным");
    }

    @Test
    @DisplayName("CH2 с добавленной identity: illegal_parameter")
    void secondHelloWithAddedIdentityIsRejected() throws Exception {
        Known a = stranger();
        Known b = known(2);
        AfterHrr state = hrrAfter(storeWith(b), fixtureWith(a, b).build());

        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                receiveRejected(state.server(), secondHello(state, a, stranger())));
    }

    @Test
    @DisplayName("CH2 с изменённым порядком identity: illegal_parameter")
    void secondHelloWithReorderedIdentitiesIsRejected() throws Exception {
        Known a = stranger();
        Known b = known(2);
        Known c = stranger();
        AfterHrr state = hrrAfter(storeWith(b), fixtureWith(a, b, c).build());

        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                receiveRejected(state.server(), secondHello(state, c, b, a)));
    }

    @Test
    @DisplayName(
            "Известная identity на 6-м месте в CH1 не становится выбранной, когда CH2 убрал первые пять")
    void identityBeyondScanLimitIsNotSelectedInSecondHello() throws Exception {
        Known target = known(6);
        PskClientHelloFixture first = fixtureWith();
        List<Known> all = new ArrayList<>();
        for (int i = 0; i < TlsConstants.MAX_PSK_IDENTITIES; i++) {
            all.add(stranger());
        }
        all.add(target);
        for (Known k : all) {
            first.identity(k.ticket(), 0, k.psk());
        }
        InMemoryPskStore store = storeWith(target);
        AfterHrr state = hrrAfter(store, first.build());

        // CH2 удаляет первые пять: известная identity оказывается первой в списке
        state.server().receive(secondHello(state, target));

        assertFalse(
                state.server().isPskAccepted(),
                "за пределом просмотра в CH1 identity не выбрана, и в CH2 её выбирать нельзя");
        assertNotNull(store.peek(target.ticket()), "тикет не потреблён");
    }

    @Test
    @DisplayName("setPsk отвергает пустую, отсутствующую и не помещающуюся в расширение identity")
    void setPskRejectsInvalidIdentity() {
        TlsHandshakeEngine client = client(null);
        byte[] psk = sequence(0xA0);
        int limit = TlsPskHelper.maxIdentityLength(HASH_LEN);

        for (byte[] identity : new byte[][] {null, new byte[0], new byte[limit + 1]}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> client.setPsk(psk, identity, 0),
                    "identity вне 1.."
                            + limit
                            + " байт должна отвергаться сразу, не в рукопожатии");
        }
        client.setPsk(psk, new byte[limit], 0);
        client.setPsk(psk, new byte[1], 0);
    }

    @Test
    @DisplayName("Граница identity: 65492 байта при Стрибоге-256, на 1 больше не помещается")
    void identityLimitFollowsExtensionSize() {
        assertEquals(65_492, TlsPskHelper.maxIdentityLength(32), "65535 - 11 - 32");
        assertEquals(65_460, TlsPskHelper.maxIdentityLength(64), "65535 - 11 - 64");
    }

    @Test
    @DisplayName(
            "Identity предельной длины не помещается с другими расширениями: ClientHello без PSK")
    void maximalIdentityWithdrawsPskOffer() throws Exception {
        TlsHandshakeEngine client = client(null);
        // сама identity проходит грубую проверку setPsk, но вместе с остальными расширениями
        // блок длиннее 65535: клиент не должен падать, а обязан идти полным рукопожатием
        client.setPsk(sequence(0xA0), new byte[TlsPskHelper.maxIdentityLength(HASH_LEN)], 0);

        byte[] frame = client.start();

        assertTrue(client.isPskOfferWithdrawn(), "предложение PSK должно быть снято");
        assertNull(
                TlsMessageParser.parseClientHelloPsk(
                        TlsHandshakeMessage.decode(frame).getBody(), HASH_LEN),
                "в ClientHello не должно быть pre_shared_key");
    }

    @Test
    @DisplayName("Обычная identity: предложение PSK не снимается")
    void ordinaryIdentityIsNotWithdrawn() throws Exception {
        TlsHandshakeEngine client = client(known(1));

        client.start();

        assertFalse(client.isPskOfferWithdrawn(), "тикет нормальной длины предъявляется");
    }

    // ========================================================================
    // Гонка: запись забрана параллельным соединением между peek и чтением ключа
    // ========================================================================

    /** Хранилище, у которого peek отдаёт запись, уже затёртую параллельным get(). */
    private static final class RacingStore implements PskStore {
        private final InMemoryPskStore delegate;
        private final byte[] racedTicket;

        RacingStore(InMemoryPskStore delegate, byte[] racedTicket) {
            this.delegate = delegate;
            this.racedTicket = racedTicket.clone();
        }

        @Override
        public PskEntry peek(byte[] ticket) {
            PskEntry entry = delegate.peek(ticket);
            if (entry != null && java.util.Arrays.equals(ticket, racedTicket)) {
                entry.destroy(); // другой поток успел забрать тикет и стереть ключ
            }
            return entry;
        }

        @Override
        public PskEntry get(byte[] ticket) {
            return delegate.get(ticket);
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

    @Test
    @DisplayName("Запись затёрта параллельным соединением: полное рукопожатие, а не обрыв")
    void entryErasedByConcurrentConnectionFallsBackToFullHandshake() throws Exception {
        Known raced = known(1);
        TlsHandshakeEngine server = server(new RacingStore(storeWith(raced), raced.ticket()));

        server.receive(fixtureWith(raced).build());

        assertFalse(server.isPskAccepted(), "ключа уже нет: PSK не принят");
        assertNotNull(
                HandshakeOutputs.nextMessage(server),
                "сервер продолжает полным рукопожатием, без исключения");
    }

    @Test
    @DisplayName("Первая запись затёрта параллельным соединением: берётся следующая известная")
    void erasedEntryIsSkippedInFavourOfNextKnown() throws Exception {
        Known raced = known(1);
        Known next = known(2);
        TlsHandshakeEngine server = server(new RacingStore(storeWith(raced, next), raced.ticket()));

        server.receive(fixtureWith(raced, next).build());

        assertTrue(server.isPskAccepted(), "следующая известная identity должна быть выбрана");
        assertEquals(1, selectedIdentityOf(server), "selected_identity - номер второй identity");
    }

    // ========================================================================
    // Клиент: selected_identity и неожиданные расширения в ServerHello
    // ========================================================================

    /** ServerHello штатного сервера с нужным ответом по PSK; рукопожатие начато клиентом. */
    private static byte[] serverHelloFor(int selectedPsk) throws Exception {
        TlsMessageBuilder builder =
                new TlsMessageBuilder(
                        suite(),
                        List.of(suite().getId()),
                        CLIENT_GROUP,
                        SIG_SCHEME,
                        serverCert.priv,
                        List.of(serverCert.cert),
                        HASH_LEN);
        byte[] point =
                TlsEncoding.encodePoint(
                        KeyGenerator.generateKeyPair(ECParameters.tc26a256()).getPublic());
        return new TlsHandshakeMessage(
                        TlsConstants.HT_SERVER_HELLO,
                        builder.buildServerHello(point, selectedPsk, CLIENT_GROUP))
                .encode();
    }

    /** Подменяет данные последнего расширения ServerHello (pre_shared_key) произвольными байтами. */
    private static byte[] withPskExtensionData(byte[] shFrame, byte[] data, boolean duplicate) {
        int oldExtensionSize = 4 + 2;
        byte[] body = java.util.Arrays.copyOfRange(shFrame, 4, shFrame.length - oldExtensionSize);
        int pos = 2 + TlsConstants.RANDOM_LENGTH;
        pos += 1 + (body[pos] & 0xFF) + 3;
        int extLengthPos = pos;
        byte[] extension = new byte[4 + data.length];
        extension[0] = (byte) (TlsConstants.EXT_PRE_SHARED_KEY >>> 8);
        extension[1] = (byte) TlsConstants.EXT_PRE_SHARED_KEY;
        extension[2] = (byte) (data.length >>> 8);
        extension[3] = (byte) data.length;
        System.arraycopy(data, 0, extension, 4, data.length);
        int copies = duplicate ? 2 : 1;
        byte[] newBody = new byte[body.length + extension.length * copies];
        System.arraycopy(body, 0, newBody, 0, body.length);
        for (int i = 0; i < copies; i++) {
            System.arraycopy(
                    extension, 0, newBody, body.length + i * extension.length, extension.length);
        }
        int extensionsLength =
                (((newBody[extLengthPos] & 0xFF) << 8) | (newBody[extLengthPos + 1] & 0xFF))
                        - oldExtensionSize
                        + extension.length * copies;
        newBody[extLengthPos] = (byte) (extensionsLength >>> 8);
        newBody[extLengthPos + 1] = (byte) extensionsLength;
        return new TlsHandshakeMessage(TlsConstants.HT_SERVER_HELLO, newBody).encode();
    }

    @Test
    @DisplayName("Клиент: selected_identity = 0 принимается, PSK принят")
    void clientAcceptsOfferedIdentity() throws Exception {
        TlsHandshakeEngine client = client(known(1));
        client.start();

        client.receive(serverHelloFor(0));

        assertTrue(client.isPskAccepted(), "выбор предложенной identity принимается");
    }

    @Test
    @DisplayName("Клиент: selected_identity за пределами предложенных: illegal_parameter")
    void clientRejectsSelectedIdentityOutOfRange() throws Exception {
        TlsHandshakeEngine client = client(known(1));
        client.start();
        byte[] serverHello = serverHelloFor(1);

        assertAlert(TlsConstants.ALERT_ILLEGAL_PARAMETER, receiveRejected(client, serverHello));
    }

    @Test
    @DisplayName(
            "Клиент: pre_shared_key в ServerHello, когда PSK не предлагался: unsupported_extension")
    void clientRejectsUnsolicitedPsk() throws Exception {
        TlsHandshakeEngine client = client(null);
        client.start();

        assertAlert(
                TlsConstants.ALERT_UNSUPPORTED_EXTENSION,
                receiveRejected(client, serverHelloFor(0)));
    }

    @Test
    @DisplayName("Клиент: selected_identity не из двух байт: decode_error")
    void clientRejectsMalformedSelectedIdentity() throws Exception {
        TlsHandshakeEngine client = client(known(1));
        client.start();
        byte[] malformed = withPskExtensionData(serverHelloFor(0), new byte[] {0, 0, 0}, false);

        assertAlert(TlsConstants.ALERT_DECODE_ERROR, receiveRejected(client, malformed));
    }

    @Test
    @DisplayName("Клиент: повтор pre_shared_key в ServerHello: illegal_parameter")
    void clientRejectsDuplicatePskInServerHello() throws Exception {
        TlsHandshakeEngine client = client(known(1));
        client.start();
        byte[] duplicated = withPskExtensionData(serverHelloFor(0), new byte[] {0, 0}, true);

        assertAlert(TlsConstants.ALERT_ILLEGAL_PARAMETER, receiveRejected(client, duplicated));
    }
}
