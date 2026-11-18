package org.rssys.gost.jca.spi;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.rssys.gost.JcaTestSupport;

/**
 * Fuzz-тесты для {@link GostKeyFactorySpi}.
 * <p>
 * Публичный JCA entry point: {@code KeyFactory.getInstance("ECGOST3410-2012")}.
 * Любой вызов generatePublic(X509EncodedKeySpec) или generatePrivate(PKCS8EncodedKeySpec)
 * с произвольными байтами запускает цепочку:
 * GostKeyFactorySpi -> GostDerCodec.decodePublicKey/decodePrivateKey -> DerCodec.parseSequenceContents.
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
        // Статические поля ниже создаются при загрузке класса, раньше жизненного цикла JUnit и
        // раньше запуска под Jazzer: провайдер должен быть зарегистрирован уже здесь
        JcaTestSupport.ensureProvider();
        try {
            KEY_FACTORY = KeyFactory.getInstance("ECGOST3410-2012");
        } catch (Exception e) {
            throw new RuntimeException("Failed to get KeyFactory instance", e);
        }
    }

    /**
     * Fuzz-тест для engineGeneratePublic: битый DER SubjectPublicKeyInfo.
     * Путь: X509EncodedKeySpec -> GostDerCodec.decodePublicKey -> DerCodec.parseSequenceContents.
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

    /**
     * Targeted: SPKI с валидным GOST-заголовком, но случайными координатами точки.
     * Фикс 0.6.1: ECPoint.isValidPublicKey() для защиты от invalid-curve attack.
     * <p>
     * Случайные байты в fuzzGeneratePublic практически никогда не формируют
     * валидный SPKI с правильным OID кривой — isValidPublicKey не вызывается.
     * Этот targeted-тест строит валидный SPKI-заголовок (OID кривой TC26A-256),
     * но координаты точки — случайные (шанс попасть на кривую ничтожен),
     * что гарантирует вызов isValidPublicKey и ожидаемый InvalidKeySpecException.
     * <p>
     * ПОЧЕМУ именно SPKI, а не прямой ECPoint.isValidPublicKey():
     * тест через JCA entry point проверяет весь стек — GostDerCodec ->
     * ECPoint -> isValidPublicKey — а не только изолированный метод.
     */
    @FuzzTest
    void fuzzGeneratePublicWithCraftedPoint(FuzzedDataProvider data) {
        byte[] xy = data.consumeBytes(64);
        if (xy.length != 64) return;
        byte[] spki = buildGostSpki(xy);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(spki);
        try {
            KEY_FACTORY.generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            // Ожидаемо: точка не на кривой -> isValidPublicKey -> reject
        }
    }

    /**
     * Строит SubjectPublicKeyInfo DER для GOST TC26A-256 с указанными X/Y (32+32 байт).
     * Точка задаётся в uncompressed-формате (0x04 || X || Y).
     */
    private static byte[] buildGostSpki(byte[] xy) {
        byte[] algOid = {0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01};
        byte[] paramOid = {0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01};
        // AlgorithmIdentifier SEQUENCE
        byte[] algSeq = new byte[2 + 2 + algOid.length + 2 + paramOid.length];
        int pos = 0;
        algSeq[pos++] = 0x30;
        algSeq[pos++] = (byte) (2 + algOid.length + 2 + paramOid.length);
        algSeq[pos++] = 0x06;
        algSeq[pos++] = (byte) algOid.length;
        System.arraycopy(algOid, 0, algSeq, pos, algOid.length);
        pos += algOid.length;
        algSeq[pos++] = 0x06;
        algSeq[pos++] = (byte) paramOid.length;
        System.arraycopy(paramOid, 0, algSeq, pos, paramOid.length);
        // BIT STRING (0x00 unused + 0x04 marker + 64 bytes X/Y = 66)
        byte[] bitString = new byte[66];
        bitString[0] = 0x00;
        bitString[1] = 0x04;
        System.arraycopy(xy, 0, bitString, 2, 64);
        // Outer SEQUENCE
        byte[] spki = new byte[2 + algSeq.length + 2 + bitString.length];
        spki[0] = 0x30;
        spki[1] = (byte) (algSeq.length + 2 + bitString.length);
        System.arraycopy(algSeq, 0, spki, 2, algSeq.length);
        spki[2 + algSeq.length] = 0x03;
        spki[2 + algSeq.length + 1] = (byte) bitString.length;
        System.arraycopy(bitString, 0, spki, 2 + algSeq.length + 2, bitString.length);
        return spki;
    }
}
