package org.rssys.gost.tls13.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.tls13.TlsException;
import org.rssys.gost.tls13.message.TlsEncoding;
import org.rssys.gost.tls13.message.TlsMessageBuilder;
import org.rssys.gost.tls13.message.TlsMessageBuilderTestAccess;
import org.rssys.gost.tls13.message.TlsMessageParser;

/**
 * Выбор группы сервером по всем записям key_share (RFC 8446 §4.1.4, §4.2.8): HRR никогда не
 * запрашивает группу, уже присланную клиентом; приемлемая группа из key_share принимается без
 * HRR; CH2 после HRR обязан содержать ровно одну запись с запрошенной группой.
 */
@DisplayName("TlsHandshakeEngine: выбор группы по key_share и HelloRetryRequest")
class TlsHandshakeEngineGroupSelectionTest {

    /** Типы расширений ClientHello, на которые тест якобы получает ответ в ServerHello. */
    private static final Set<Integer> SERVER_RESPONSE_TYPES_SENT =
            Set.of(
                    TlsConstants.EXT_SUPPORTED_VERSIONS,
                    TlsConstants.EXT_KEY_SHARE,
                    TlsConstants.EXT_PRE_SHARED_KEY);

    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;
    private static final int GREASE = 0xAAAA;
    private static final int[] ALL_GROUPS = {
        TlsConstants.GRP_GC256A,
        TlsConstants.GRP_GC256B,
        TlsConstants.GRP_GC256C,
        TlsConstants.GRP_GC256D,
        TlsConstants.GRP_GC512A,
        TlsConstants.GRP_GC512B,
        TlsConstants.GRP_GC512C
    };

    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
    }

    private static TlsCiphersuite cs() {
        return TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
    }

    private static TlsHandshakeEngine server(int preferredGroup) {
        return new TlsHandshakeEngine(
                TlsHandshakeEngine.Role.SERVER,
                cs(),
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        preferredGroup,
                        SIG_SCHEME,
                        serverCert.priv,
                        List.of(serverCert.cert),
                        HASH_LEN),
                TlsCiphersuite.namedGroupToParams(preferredGroup),
                preferredGroup,
                SIG_SCHEME,
                HASH_LEN,
                null,
                false,
                null);
    }

    /** Точка ECDHE для реальной группы; для GREASE - произвольные байты (сервер её не читает). */
    private static byte[] point(int group) throws Exception {
        if (group == GREASE) {
            return new byte[64];
        }
        return TlsEncoding.encodePoint(
                KeyGenerator.generateKeyPair(TlsCiphersuite.namedGroupToParams(group)).getPublic());
    }

    private static Map<Integer, byte[]> shares(int... groups) throws Exception {
        Map<Integer, byte[]> m = new LinkedHashMap<>();
        for (int g : groups) {
            m.put(g, point(g));
        }
        return m;
    }

    /** Кадр ClientHello: список supported_groups и записи key_share заданы тестом. */
    private static byte[] clientHello(int[] supportedGroups, Map<Integer, byte[]> keyShares)
            throws Exception {
        TlsMessageBuilder b =
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        TlsConstants.GRP_GC256A,
                        SIG_SCHEME,
                        null,
                        null,
                        HASH_LEN);
        if (supportedGroups != null) {
            TlsMessageBuilderTestAccess.setSupportedGroups(b, supportedGroups);
        }
        return new TlsHandshakeMessage(
                        TlsConstants.HT_CLIENT_HELLO, b.buildClientHello(keyShares, "localhost"))
                .encode();
    }

    /** Кадр ClientHello, у которого последняя запись key_share повреждена (длина ключа). */
    private static byte[] clientHelloWithBrokenTrailingEntry(
            int[] supportedGroups, Map<Integer, byte[]> keyShares) throws Exception {
        TlsMessageBuilder b =
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        TlsConstants.GRP_GC256A,
                        SIG_SCHEME,
                        null,
                        null,
                        HASH_LEN);
        TlsMessageBuilderTestAccess.setSupportedGroups(b, supportedGroups);
        byte[] body = b.buildClientHello(keyShares, "localhost");
        return new TlsHandshakeMessage(
                        TlsConstants.HT_CLIENT_HELLO,
                        TlsMessageBuilderTestAccess.corruptLastKeyShareEntry(body))
                .encode();
    }

    private static byte[] clientHelloWithoutKeyShare(int[] supportedGroups) throws Exception {
        TlsMessageBuilder b =
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        TlsConstants.GRP_GC256A,
                        SIG_SCHEME,
                        null,
                        null,
                        HASH_LEN);
        TlsMessageBuilderTestAccess.setSupportedGroups(b, supportedGroups);
        TlsMessageBuilderTestAccess.omitKeyShare(b);
        return new TlsHandshakeMessage(
                        TlsConstants.HT_CLIENT_HELLO, b.buildClientHello(shares(), "localhost"))
                .encode();
    }

    private static TlsMessageParser.ParsedServerHello reply(TlsHandshakeEngine server)
            throws Exception {
        byte[] frame = HandshakeOutputs.nextMessage(server);
        assertNotNull(frame, "сервер обязан ответить ServerHello или HRR");
        return TlsMessageParser.parseServerHello(
                TlsHandshakeMessage.decode(frame).getBody(), SERVER_RESPONSE_TYPES_SENT);
    }

    private static void assertAlert(byte expected, TlsHandshakeEngine server, byte[] frame) {
        TlsException ex = assertThrows(TlsException.class, () -> server.receive(frame));
        assertEquals(expected, ex.getAlertCode());
    }

    @Test
    @DisplayName("Клиент только GC256B, сервер предпочитает GC512C: без HRR, принята GC256B")
    void clientGroupAcceptedWithoutHrr() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC512C);

        s.receive(
                clientHello(new int[] {TlsConstants.GRP_GC256B}, shares(TlsConstants.GRP_GC256B)));

        TlsMessageParser.ParsedServerHello sh = reply(s);
        assertFalse(TlsMessageParser.isHelloRetryRequest(sh), "HRR не нужен");
        assertEquals(TlsConstants.GRP_GC256B, sh.actualGroup);
    }

    @Test
    @DisplayName(
            "Клиент [GC256B, GC512C], key_share GC256B, сервер предпочитает GC512C: HRR на GC512C")
    void hrrToServerPreferenceWhenClientSupportsIt() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC512C);

        s.receive(
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C},
                        shares(TlsConstants.GRP_GC256B)));

        TlsMessageParser.ParsedServerHello hrr = reply(s);
        assertTrue(TlsMessageParser.isHelloRetryRequest(hrr));
        assertEquals(TlsConstants.GRP_GC512C, hrr.requestedGroup);
    }

    @Test
    @DisplayName("key_share [GREASE, GC512C]: GREASE пропущена, принята GC512C без HRR")
    void greaseEntrySkipped() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);

        s.receive(
                clientHello(
                        new int[] {GREASE, TlsConstants.GRP_GC512C},
                        shares(GREASE, TlsConstants.GRP_GC512C)));

        TlsMessageParser.ParsedServerHello sh = reply(s);
        assertFalse(TlsMessageParser.isHelloRetryRequest(sh));
        assertEquals(TlsConstants.GRP_GC512C, sh.actualGroup);
    }

    @Test
    @DisplayName("key_share только [GREASE]: HRR на поддерживаемую группу, не из key_share")
    void hrrToGroupOutsideKeyShare() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);

        s.receive(clientHello(new int[] {GREASE, TlsConstants.GRP_GC512C}, shares(GREASE)));

        TlsMessageParser.ParsedServerHello hrr = reply(s);
        assertTrue(TlsMessageParser.isHelloRetryRequest(hrr));
        assertEquals(TlsConstants.GRP_GC512C, hrr.requestedGroup);
    }

    @Test
    @DisplayName("Предпочтительная группа сервера есть среди key_share: принимается она")
    void serverPreferenceInKeyShareWins() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);

        s.receive(
                clientHello(ALL_GROUPS, shares(TlsConstants.GRP_GC256A, TlsConstants.GRP_GC256B)));

        TlsMessageParser.ParsedServerHello sh = reply(s);
        assertFalse(TlsMessageParser.isHelloRetryRequest(sh));
        assertEquals(TlsConstants.GRP_GC256B, sh.actualGroup);
    }

    @Test
    @DisplayName("Общей группы нет: handshake_failure")
    void noCommonGroup() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);

        assertAlert(
                TlsConstants.ALERT_HANDSHAKE_FAILURE,
                s,
                clientHello(new int[] {GREASE}, shares(GREASE)));
    }

    @Test
    @DisplayName("CH1 без расширения key_share: missing_extension")
    void ch1WithoutKeyShareIsMissingExtension() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);

        assertAlert(
                TlsConstants.ALERT_MISSING_EXTENSION,
                s,
                clientHelloWithoutKeyShare(new int[] {TlsConstants.GRP_GC256B}));
    }

    // ----- Пустой client_shares в CH1: запрос выбора группы (RFC 8446 §4.2.8) -----

    @Test
    @DisplayName(
            "CH1 с пустым key_share, сервер предпочитает GC512C из supported_groups: HRR на нее")
    void emptyKeyShareGetsHrrToServerPreference() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC512C);

        s.receive(
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C}, shares()));

        TlsMessageParser.ParsedServerHello hrr = reply(s);
        assertTrue(TlsMessageParser.isHelloRetryRequest(hrr), "пустой key_share - это запрос HRR");
        assertEquals(TlsConstants.GRP_GC512C, hrr.requestedGroup);
    }

    @Test
    @DisplayName("CH1 с пустым key_share, предпочтения сервера нет у клиента: HRR на первую общую")
    void emptyKeyShareGetsHrrToFirstCommonGroup() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC512C);

        // GREASE неизвестна серверу и пропускается, GC256B - первая общая
        s.receive(clientHello(new int[] {GREASE, TlsConstants.GRP_GC256B}, shares()));

        TlsMessageParser.ParsedServerHello hrr = reply(s);
        assertTrue(TlsMessageParser.isHelloRetryRequest(hrr));
        assertEquals(TlsConstants.GRP_GC256B, hrr.requestedGroup);
    }

    @Test
    @DisplayName("CH1 с пустым key_share и без общих групп: handshake_failure")
    void emptyKeyShareWithoutCommonGroupFails() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);

        assertAlert(
                TlsConstants.ALERT_HANDSHAKE_FAILURE, s, clientHello(new int[] {GREASE}, shares()));
    }

    @Test
    @DisplayName("CH1 с пустым key_share и без supported_groups: missing_extension (RFC 8446 §9.2)")
    void emptyKeyShareWithoutSupportedGroupsIsMissingExtension() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);
        TlsMessageBuilder b =
                new TlsMessageBuilder(
                        cs(),
                        List.of(cs().getId()),
                        TlsConstants.GRP_GC256A,
                        SIG_SCHEME,
                        null,
                        null,
                        HASH_LEN);
        TlsMessageBuilderTestAccess.omitSupportedGroups(b);

        assertAlert(
                TlsConstants.ALERT_MISSING_EXTENSION,
                s,
                new TlsHandshakeMessage(
                                TlsConstants.HT_CLIENT_HELLO,
                                b.buildClientHello(shares(), "localhost"))
                        .encode());
    }

    @Test
    @DisplayName("Пустой CH1 -> HRR -> CH2 с одной записью запрошенной группы -> ServerHello")
    void emptyKeyShareFullRoundTrip() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC512C);
        int[] groups = {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C};

        s.receive(clientHello(groups, shares()));
        TlsMessageParser.ParsedServerHello hrr = reply(s);
        assertTrue(TlsMessageParser.isHelloRetryRequest(hrr));
        s.receive(clientHello(groups, shares(hrr.requestedGroup)));

        TlsMessageParser.ParsedServerHello sh = reply(s);
        assertFalse(TlsMessageParser.isHelloRetryRequest(sh), "второй HRR недопустим");
        assertEquals(TlsConstants.GRP_GC512C, sh.actualGroup);
    }

    // ----- CH2 после HRR -----

    /** Сервер, уже отправивший HRR на GC512C (клиент предложил только GC256B с key_share). */
    private static TlsHandshakeEngine serverAfterHrrToGc512c() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC512C);
        s.receive(
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C},
                        shares(TlsConstants.GRP_GC256B)));
        assertTrue(TlsMessageParser.isHelloRetryRequest(reply(s)));
        return s;
    }

    @Test
    @DisplayName("CH2 с одной записью запрошенной группы принимается")
    void ch2WithRequestedGroupAccepted() throws Exception {
        TlsHandshakeEngine s = serverAfterHrrToGc512c();

        s.receive(
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C},
                        shares(TlsConstants.GRP_GC512C)));

        TlsMessageParser.ParsedServerHello sh = reply(s);
        assertFalse(TlsMessageParser.isHelloRetryRequest(sh));
        assertEquals(TlsConstants.GRP_GC512C, sh.actualGroup);
    }

    @Test
    @DisplayName("CH2 без расширения key_share -> illegal_parameter")
    void ch2WithoutKeyShareRejected() throws Exception {
        TlsHandshakeEngine s = serverAfterHrrToGc512c();

        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                s,
                clientHelloWithoutKeyShare(
                        new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C}));
    }

    @Test
    @DisplayName("CH2 с пустым списком key_share -> illegal_parameter")
    void ch2WithEmptyKeyShareRejected() throws Exception {
        TlsHandshakeEngine s = serverAfterHrrToGc512c();

        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                s,
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C}, shares()));
    }

    @Test
    @DisplayName("CH2 с двумя записями (одна - запрошенная) -> illegal_parameter")
    void ch2WithTwoEntriesRejected() throws Exception {
        TlsHandshakeEngine s = serverAfterHrrToGc512c();

        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                s,
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C},
                        shares(TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C)));
    }

    @Test
    @DisplayName("CH2 с группой, отличной от запрошенной -> illegal_parameter")
    void ch2WithOtherGroupRejected() throws Exception {
        TlsHandshakeEngine s = serverAfterHrrToGc512c();

        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                s,
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C},
                        shares(TlsConstants.GRP_GC256B)));
    }

    @Test
    @DisplayName("CH2: запрошенная группа первой, затем лишняя запись -> illegal_parameter")
    void ch2WithRequestedGroupFirstAndExtraEntryRejected() throws Exception {
        TlsHandshakeEngine s = serverAfterHrrToGc512c();

        assertAlert(
                TlsConstants.ALERT_ILLEGAL_PARAMETER,
                s,
                clientHello(
                        new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC512C},
                        shares(TlsConstants.GRP_GC512C, TlsConstants.GRP_GC256B)));
    }

    @Test
    @DisplayName("CH1 с битой хвостовой записью key_share -> decode_error")
    void ch1WithBrokenTrailingEntryRejected() throws Exception {
        TlsHandshakeEngine s = server(TlsConstants.GRP_GC256B);

        assertAlert(
                TlsConstants.ALERT_DECODE_ERROR,
                s,
                clientHelloWithBrokenTrailingEntry(
                        new int[] {TlsConstants.GRP_GC256B, TlsConstants.GRP_GC256A},
                        shares(TlsConstants.GRP_GC256B, TlsConstants.GRP_GC256A)));
    }
}
