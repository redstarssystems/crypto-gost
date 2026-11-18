package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.SignedDerTestSupport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.NonceMode;

/**
 * Проверка самого помощника {@link SignedDerTestSupport}: тесты, которые на него опираются,
 * не должны проходить тривиально и не должны маскировать расхождения.
 */
@DisplayName("SignedDerTestSupport: сравнение с нормализацией значения подписи")
class SignedDerTestSupportTest {

    private static byte[] tbs(ECParameters params, KeyPair keyPair, String subject) {
        byte[] subjectDn = GostDnParser.encodeDn(subject);
        return GostCertificateBuilder.create(params, subjectDn)
                .publicKey(keyPair.getPublic())
                .notBefore("20240501120000Z")
                .notAfter("21060101120000Z")
                .issuerDn(subjectDn)
                .serial(BigInteger.ONE)
                .buildTbs();
    }

    @Test
    @DisplayName(
            "Один TBS, подписанный дважды в гибридном режиме: DER различаются, нормализованные равны")
    void hedgedSignaturesDifferOnlyInSignatureValue() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair keyPair = KeyGenerator.generateKeyPair(params);
        byte[] tbs = tbs(params, keyPair, "CN=Helper");
        GostSigner hedged = GostSigner.of(keyPair.getPrivate(), NonceMode.HEDGED);

        byte[] first = GostCertificateBuilder.sign(tbs, hedged).getEncoded();
        byte[] second = GostCertificateBuilder.sign(tbs, hedged).getEncoded();

        assertFalse(Arrays.equals(first, second), "гибридные подписи одного TBS совпали");
        SignedDerTestSupport.assertSameExceptSignature("один TBS", first, second);
    }

    @Test
    @DisplayName("Разные TBS остаются различимыми после нормализации")
    void differentTbsStayDistinguishable() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair keyPair = KeyGenerator.generateKeyPair(params);
        GostSigner signer = GostSigner.of(keyPair.getPrivate(), NonceMode.DETERMINISTIC);

        byte[] first =
                GostCertificateBuilder.sign(tbs(params, keyPair, "CN=One"), signer).getEncoded();
        byte[] second =
                GostCertificateBuilder.sign(tbs(params, keyPair, "CN=Two"), signer).getEncoded();

        assertThrows(
                AssertionError.class,
                () -> SignedDerTestSupport.assertSameExceptSignature("разные TBS", first, second),
                "расхождение в подписанной части обязано быть видно");
    }

    @Test
    @DisplayName("Байты открытого ключа в SubjectPublicKeyInfo не обнуляются")
    void publicKeyBytesAreNotZeroed() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair keyOne = KeyGenerator.generateKeyPair(params);
        KeyPair keyTwo = KeyGenerator.generateKeyPair(params);
        GostSigner signerOne = GostSigner.of(keyOne.getPrivate(), NonceMode.DETERMINISTIC);

        // Один подписант, разные открытые ключи субъекта: различие только в SPKI
        byte[] first =
                GostCertificateBuilder.sign(tbs(params, keyOne, "CN=Same"), signerOne).getEncoded();
        byte[] second =
                GostCertificateBuilder.sign(tbs(params, keyTwo, "CN=Same"), signerOne).getEncoded();

        assertThrows(
                AssertionError.class,
                () -> SignedDerTestSupport.assertSameExceptSignature("разные ключи", first, second),
                "различие в открытом ключе субъекта обнулено вместе с подписью");
    }

    @Test
    @DisplayName("Значение подписи реально обнуляется, остальное сохраняется")
    void onlySignatureValueIsZeroed() {
        ECParameters params = ECParameters.tc26a256();
        KeyPair keyPair = KeyGenerator.generateKeyPair(params);
        byte[] der =
                GostCertificateBuilder.sign(
                                tbs(params, keyPair, "CN=Zero"),
                                GostSigner.of(keyPair.getPrivate(), NonceMode.DETERMINISTIC))
                        .getEncoded();

        byte[] zeroed = SignedDerTestSupport.withZeroedSignatures(der);

        assertTrue(zeroed.length == der.length, "длина изменилась");
        int differing = 0;
        for (int i = 0; i < der.length; i++) {
            if (der[i] != zeroed[i]) {
                differing++;
            }
        }
        // Подпись 64 байта (s || r): обнулены именно они, и только они
        assertTrue(differing > 32 && differing <= 64, "изменено " + differing + " байт");
        assertArrayEquals(
                Arrays.copyOf(der, der.length - 70),
                Arrays.copyOf(zeroed, zeroed.length - 70),
                "изменилась не только подпись");
        assertNotEquals(der.length, 0);
    }

    @Test
    @DisplayName("DER без подписи ГОСТ отвергается, а не сравнивается как есть")
    void objectWithoutSignatureFails() {
        assertThrows(
                AssertionError.class,
                () -> SignedDerTestSupport.withZeroedSignatures(new byte[] {0x30, 0x00}),
                "объект без подписи обязан давать ошибку, иначе тест прошёл бы тривиально");
    }
}
