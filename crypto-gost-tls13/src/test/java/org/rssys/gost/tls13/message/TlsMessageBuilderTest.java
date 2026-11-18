package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("TlsMessageBuilder — сборка handshake-сообщений")
class TlsMessageBuilderTest {

    private static final int NAMED_GROUP = TlsConstants.GRP_GC256A;
    private static final int SIG_SCHEME = TlsConstants.SIG_GOST_TC26_A_256;
    private static final int HASH_LEN = 32;

    private static TlsMessageBuilder builder() {
        return new TlsMessageBuilder(
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                List.of(TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L.getId()),
                NAMED_GROUP,
                SIG_SCHEME,
                null,
                null,
                HASH_LEN);
    }

    @Test
    @DisplayName("HRR: legacy_session_id отражается в теле HRR (RFC 8446 §4.1.3)")
    void testHrrEchoesSessionId() throws Exception {
        byte[] sid = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(sid);

        TlsMessageBuilder mb = builder();
        mb.setClientSessionId(sid);
        byte[] hrrBody =
                mb.buildHelloRetryRequest(
                        NAMED_GROUP,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L.getId());

        // Body layout: legacy_version(2) + random(32) + session_id_len(1) + session_id(N) + ...
        int sidLen = hrrBody[34] & 0xFF;
        assertEquals(sid.length, sidLen, "session_id_len должен совпадать");
        byte[] echoedSid = new byte[sidLen];
        System.arraycopy(hrrBody, 35, echoedSid, 0, sidLen);
        assertArrayEquals(sid, echoedSid, "session_id должен быть скопирован в HRR");
    }

    @Test
    @DisplayName("HRR: без session_id поле session_id_len = 0")
    void testHrrWithoutSessionId() throws Exception {
        TlsMessageBuilder mb = builder();
        byte[] hrrBody =
                mb.buildHelloRetryRequest(
                        NAMED_GROUP,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L.getId());

        int sidLen = hrrBody[34] & 0xFF;
        assertEquals(0, sidLen, "Без вызова setClientSessionId session_id_len должен быть 0");
    }

    @Test
    @DisplayName("HRR: setClientSessionId(null) эквивалентен отсутствию session_id")
    void testHrrNullSessionId() throws Exception {
        TlsMessageBuilder mb = builder();
        mb.setClientSessionId(null);
        byte[] hrrBody =
                mb.buildHelloRetryRequest(
                        NAMED_GROUP,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L.getId());

        int sidLen = hrrBody[34] & 0xFF;
        assertEquals(0, sidLen, "setClientSessionId(null) -> длина session_id = 0");
    }

    @Test
    @DisplayName("HRR: setClientSessionId(пустой массив) эквивалентен null")
    void testHrrEmptySessionId() throws Exception {
        TlsMessageBuilder mb = builder();
        mb.setClientSessionId(new byte[0]);
        byte[] hrrBody =
                mb.buildHelloRetryRequest(
                        NAMED_GROUP,
                        TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L.getId());

        int sidLen = hrrBody[34] & 0xFF;
        assertEquals(0, sidLen, "setClientSessionId([]) -> длина session_id = 0");
    }

    // ---- согласование набора шифров с учётом длины хеша ----

    private static byte[] clientHelloOfferingSuite() throws Exception {
        byte[] share =
                TlsEncoding.encodePoint(
                        KeyGenerator.generateKeyPair(TlsCiphersuite.namedGroupToParams(NAMED_GROUP))
                                .getPublic());
        return builder().buildClientHello(Map.of(NAMED_GROUP, share), "localhost");
    }

    @Test
    @DisplayName("согласование: набор с длиной хеша движка выбирается")
    void negotiationPicksSuiteOfRequiredHashLength() throws Exception {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        assertSame(
                suite,
                builder().negotiateCiphersuite(clientHelloOfferingSuite(), suite, HASH_LEN),
                "Набор клиента совпал с длиной хеша движка");
    }

    @Test
    @DisplayName(
            "согласование: набор с другой длиной хеша не выбирается ни как предпочтительный, ни из списка")
    void negotiationSkipsSuiteOfOtherHashLength() throws Exception {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;

        assertNull(
                builder()
                        .negotiateCiphersuite(
                                clientHelloOfferingSuite(),
                                suite,
                                TlsConstants.STREEBOG_512_HASH_LEN),
                "Единственный предложенный набор с хешем 32 не подходит движку с хешем 64: "
                        + "пересечения нет, обрыв остаётся за вызывающим (handshake_failure)");
        assertNull(
                builder()
                        .negotiateCiphersuite(
                                clientHelloOfferingSuite(),
                                null,
                                TlsConstants.STREEBOG_512_HASH_LEN),
                "Без предпочтительного набора список сервера тоже фильтруется по длине хеша");
    }

    @Test
    @DisplayName("согласование: неизвестный ID набора в списке сервера пропускается, без NPE")
    void negotiationSkipsUnknownSuiteId() throws Exception {
        TlsCiphersuite suite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsMessageBuilder withUnknownId =
                new TlsMessageBuilder(
                        suite,
                        List.of(0xFFFF, suite.getId()),
                        NAMED_GROUP,
                        SIG_SCHEME,
                        null,
                        null,
                        HASH_LEN);

        assertSame(
                suite,
                withUnknownId.negotiateCiphersuite(clientHelloOfferingSuite(), null, HASH_LEN),
                "Неизвестный ID пропущен, следующий известный набор выбран");

        TlsMessageBuilder onlyUnknownId =
                new TlsMessageBuilder(
                        suite, List.of(0xFFFF), NAMED_GROUP, SIG_SCHEME, null, null, HASH_LEN);
        assertNull(
                onlyUnknownId.negotiateCiphersuite(clientHelloOfferingSuite(), null, HASH_LEN),
                "Только неизвестный ID: пересечения нет, результат null (handshake_failure)");
    }

    @Test
    @DisplayName("согласование: предпочтительный набор вне списка разрешённых не выбирается")
    void negotiationIgnoresPreferredSuiteOutsideAllowedList() throws Exception {
        TlsCiphersuite longSuite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsCiphersuite shortSuite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;
        // Клиент предлагает оба набора, у сервера разрешён только короткий
        byte[] hello = clientHelloOffering(List.of(longSuite.getId(), shortSuite.getId()));
        TlsMessageBuilder allowedShortOnly = serverBuilderAllowing(List.of(shortSuite.getId()));

        assertSame(
                shortSuite,
                allowedShortOnly.negotiateCiphersuite(hello, longSuite, HASH_LEN),
                "предпочтительный длинный набор не разрешён: должен быть выбран разрешённый");
    }

    @Test
    @DisplayName("согласование: клиент предлагает только неразрешённый предпочтительный - null")
    void negotiationWithOnlyDisallowedPreferredSuiteFails() throws Exception {
        TlsCiphersuite longSuite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        TlsCiphersuite shortSuite = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_S;
        byte[] hello = clientHelloOffering(List.of(longSuite.getId()));
        TlsMessageBuilder allowedShortOnly = serverBuilderAllowing(List.of(shortSuite.getId()));

        assertNull(
                allowedShortOnly.negotiateCiphersuite(hello, longSuite, HASH_LEN),
                "пересечения с разрешёнными наборами нет: handshake_failure на стороне вызывающего");
    }

    private static byte[] clientHelloOffering(List<Integer> suiteIds) throws Exception {
        byte[] share =
                TlsEncoding.encodePoint(
                        KeyGenerator.generateKeyPair(TlsCiphersuite.namedGroupToParams(NAMED_GROUP))
                                .getPublic());
        return serverBuilderAllowing(suiteIds)
                .buildClientHello(Map.of(NAMED_GROUP, share), "localhost");
    }

    private static TlsMessageBuilder serverBuilderAllowing(List<Integer> suiteIds) {
        return new TlsMessageBuilder(
                TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L,
                suiteIds,
                NAMED_GROUP,
                SIG_SCHEME,
                null,
                null,
                HASH_LEN);
    }
}
