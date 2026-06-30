package org.rssys.gost.pkix.tsp;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.util.CryptoRandom;

@DisplayName("TspRequestBuilder: построение TimeStampReq")
class TspRequestBuilderTest {

    @Test
    @DisplayName("Успешная сборка минимального запроса")
    void buildMinimalRequest() {
        byte[] hash = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(hash);
        byte[] req = TspRequestBuilder.create().messageImprint(hash, GostOids.DIGEST_256).build();
        assertTrue(req.length > 0);
    }

    @Test
    @DisplayName("Сборка с reqPolicy и certReq")
    void buildWithPolicyAndCertReq() {
        byte[] hash = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(hash);
        byte[] req =
                TspRequestBuilder.create()
                        .messageImprint(hash, GostOids.DIGEST_256)
                        .reqPolicy("1.3.6.1.4.1.4146.1.2.1")
                        .certReq(true)
                        .build();
        assertTrue(req.length > 0);
    }

    @Test
    @DisplayName("Cборка с заданным nonce")
    void buildWithNonce() {
        byte[] hash = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(hash);
        byte[] req =
                TspRequestBuilder.create()
                        .messageImprint(hash, GostOids.DIGEST_256)
                        .nonce(BigInteger.valueOf(1234567890))
                        .build();
        assertTrue(req.length > 0);
    }

    @Test
    @DisplayName("Авто-генерация nonce, если не задан явно")
    void autoGenerateNonce() {
        byte[] hash = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(hash);
        byte[] req1 = TspRequestBuilder.create().messageImprint(hash, GostOids.DIGEST_256).build();
        byte[] req2 = TspRequestBuilder.create().messageImprint(hash, GostOids.DIGEST_256).build();
        assertNotNull(req1);
        assertNotNull(req2);
        // Разные nonce → разный DER
        boolean differ = false;
        if (req1.length == req2.length) {
            for (int i = 0; i < req1.length; i++) {
                if (req1[i] != req2[i]) {
                    differ = true;
                    break;
                }
            }
        } else {
            differ = true;
        }
        assertTrue(differ, "Two builds without explicit nonce should produce different DER");
    }

    @Test
    @DisplayName("Сборка падает без messageImprint")
    void failsWithoutMessageImprint() {
        assertThrows(NullPointerException.class, () -> TspRequestBuilder.create().build());
    }

    @Test
    @DisplayName("Сборка с 512-битным хэшем")
    void build512() {
        byte[] hash = new byte[64];
        CryptoRandom.INSTANCE.nextBytes(hash);
        byte[] req = TspRequestBuilder.create().messageImprint(hash, GostOids.DIGEST_512).build();
        assertTrue(req.length > 0);
    }
}
