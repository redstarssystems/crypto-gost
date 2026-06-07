package org.rssys.gost.jca.spi;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Fuzz-тесты для {@link GostKeyFactorySpi}.
 * <p>
 * Публичный JCA entry point: {@code KeyFactory.getInstance("ECGOST3410-2012")}.
 * Любой вызов generatePublic(X509EncodedKeySpec) или generatePrivate(PKCS8EncodedKeySpec)
 * с произвольными байтами запускает цепочку:
 * GostKeyFactorySpi → GostDerCodec.decodePublicKey/decodePrivateKey → DerCodec.parseSequenceContents.
 * <p>
 * Весь путь через наш код (AGENTS.md — запрет на SunJCE/JDK). Если фаззер находит
 * баг — это баг нашей DER-инфраструктуры, не JDK.
 * <p>
 * ПОЧЕМУ ловим только InvalidKeySpecException: GostKeyFactorySpi оборачивает
 * все RuntimeExceptions из GostDerCodec/DerCodec в InvalidKeySpecException.
 * Если AIOOBE/NPE не будут перехвачены — они дойдут до Jazzer как баг.
 * InvalidKeySpecException — единственная ожидаемая реакция на битый DER.
 */
class GostKeyFactorySpiFuzzTest {

    private static final KeyFactory KEY_FACTORY;

    static {
        try {
            KEY_FACTORY = KeyFactory.getInstance("ECGOST3410-2012");
        } catch (Exception e) {
            throw new RuntimeException("Failed to get KeyFactory instance", e);
        }
    }

    /**
     * Fuzz-тест для engineGeneratePublic: битый DER SubjectPublicKeyInfo.
     * Путь: X509EncodedKeySpec → GostDerCodec.decodePublicKey → DerCodec.parseSequenceContents.
     * <p>
     * ПОЧЕМУ не ловим RuntimeException: если AIOOBE/NPE не перехвачен
     * GostKeyFactorySpi — Jazzer должен его увидеть как баг. Если перехвачен
     * завернут в InvalidKeySpecException — это ожидаемая реакция.
     */
    @FuzzTest
    void fuzzGeneratePublic(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        X509EncodedKeySpec spec = new X509EncodedKeySpec(input);
        try {
            KEY_FACTORY.generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            // Ожидаемо на битом DER
        }
    }

    /**
     * Fuzz-тест для engineGeneratePrivate: битый DER PrivateKeyInfo.
     * <p>
     * Аналогично fuzzGeneratePublic — только InvalidKeySpecException
     * ловится как ожидаемая реакция.
     */
    @FuzzTest
    void fuzzGeneratePrivate(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        if (input.length == 0) return;
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(input);
        try {
            KEY_FACTORY.generatePrivate(spec);
        } catch (InvalidKeySpecException e) {
            // Ожидаемо на битом DER
        }
    }
}
