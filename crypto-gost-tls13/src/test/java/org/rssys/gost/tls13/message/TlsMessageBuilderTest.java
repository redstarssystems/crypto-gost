package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
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
}
