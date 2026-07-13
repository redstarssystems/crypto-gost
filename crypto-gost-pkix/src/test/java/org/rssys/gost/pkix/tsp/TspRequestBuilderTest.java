package org.rssys.gost.pkix.tsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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

    @Test
    @DisplayName("Повторный build() на одном билдере даёт разные nonce (anti-replay)")
    void nonceDiffersBetweenBuildsOnSameBuilder() {
        byte[] hash = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(hash);
        TspRequestBuilder builder =
                TspRequestBuilder.create().messageImprint(hash, GostOids.DIGEST_256);

        builder.build();
        BigInteger first = builder.getNonce();
        builder.build();
        BigInteger second = builder.getNonce();

        assertNotNull(first, "nonce первой сборки не null");
        assertNotNull(second, "nonce второй сборки не null");
        assertNotEquals(
                first,
                second,
                "два build() на одном билдере не должны переиспользовать nonce (защита от replay)");
    }

    @Test
    @DisplayName("getNonce() до build() бросает IllegalStateException")
    void getNonceBeforeBuildThrows() {
        byte[] hash = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(hash);
        TspRequestBuilder builder =
                TspRequestBuilder.create().messageImprint(hash, GostOids.DIGEST_256);
        assertThrows(
                IllegalStateException.class,
                builder::getNonce,
                "getNonce() до build() должен бросать исключение (нет pre-build peek)");
    }

    @Test
    @DisplayName("Явно заданный nonce переиспользуется между build() намеренно")
    void explicitNoncePreservedAcrossBuilds() {
        byte[] hash = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(hash);
        BigInteger explicit = BigInteger.valueOf(424242);
        TspRequestBuilder builder =
                TspRequestBuilder.create()
                        .messageImprint(hash, GostOids.DIGEST_256)
                        .nonce(explicit);

        builder.build();
        assertEquals(explicit, builder.getNonce(), "явный nonce сохраняется после build()");
        builder.build();
        assertEquals(
                explicit,
                builder.getNonce(),
                "явный nonce не регенерируется — это осознанный выбор вызывающего");
    }

    @Test
    @DisplayName("Opt-out nonce(null): getNonce() после build() возвращает null")
    void optOutNonceReturnsNull() {
        byte[] hash = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(hash);
        TspRequestBuilder builder =
                TspRequestBuilder.create().messageImprint(hash, GostOids.DIGEST_256).nonce(null);
        builder.build();
        assertNull(builder.getNonce(), "явный opt-out nonce(null) -> getNonce() возвращает null");
    }
}
