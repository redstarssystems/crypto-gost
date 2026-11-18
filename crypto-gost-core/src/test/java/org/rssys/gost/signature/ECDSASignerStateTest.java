package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.digest.Streebog256;

/**
 * Явное состояние {@link ECDSASigner}: до {@code init}, после {@code destroy()} и в неверном
 * режиме вместо {@link NullPointerException} из недоинициализированных полей - понятный
 * {@link IllegalStateException}. Тип исключения мало: проверяется текст каждого состояния, иначе
 * снятие одной проверки подменялось бы другой с тем же типом.
 */
@DisplayName("ECDSASigner: явное состояние (init, режим, destroy)")
class ECDSASignerStateTest {

    private static final byte[] HASH = new byte[32];

    private static PrivateKeyParameters priv;
    private static PublicKeyParameters pub;

    @BeforeAll
    static void setUp() {
        HASH[0] = 0x42;
        KeyPair keys = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        priv = keys.getPrivate();
        pub = keys.getPublic();
    }

    private static ECDSASigner newSigner() {
        return new ECDSASigner(Streebog256::new);
    }

    private static void assertState(Runnable call, String expectedMessage, String why) {
        IllegalStateException ex = assertThrows(IllegalStateException.class, call::run, why);
        assertEquals(expectedMessage, ex.getMessage(), why);
    }

    @Test
    @DisplayName("До init обе операции -> IllegalStateException «is not initialized»")
    void beforeInit() {
        ECDSASigner signer = newSigner();

        assertState(
                () -> signer.generateSignature(HASH),
                "ECDSASigner is not initialized",
                "подпись до init");
        assertState(
                () -> signer.verifySignature(HASH, BigInteger.ONE, BigInteger.ONE),
                "ECDSASigner is not initialized",
                "проверка до init");
    }

    @Test
    @DisplayName("Режим подписи: проверка -> ISE, режим проверки: подпись -> ISE")
    void wrongMode() {
        ECDSASigner signing = newSigner();
        signing.init(true, priv);
        assertState(
                () -> signing.verifySignature(HASH, BigInteger.ONE, BigInteger.ONE),
                "ECDSASigner is initialized for signing, not for verification",
                "проверка в режиме подписи");

        ECDSASigner verifying = newSigner();
        verifying.init(false, pub);
        assertState(
                () -> verifying.generateSignature(HASH),
                "ECDSASigner is initialized for verification, not for signing",
                "подпись в режиме проверки");
    }

    @Test
    @DisplayName("Неудачный init оставляет подписанта не инициализированным; повторный init лечит")
    void failedInitLeavesUninitialized() {
        ECDSASigner signer = newSigner();
        signer.init(true, priv);

        // Неверный тип параметров для режима подписи
        assertThrows(IllegalArgumentException.class, () -> signer.init(true, pub));

        assertState(
                () -> signer.generateSignature(HASH),
                "ECDSASigner is not initialized",
                "после неудачного init подпись по старому ключу недопустима");
        assertState(
                () -> signer.verifySignature(HASH, BigInteger.ONE, BigInteger.ONE),
                "ECDSASigner is not initialized",
                "после неудачного init проверка недопустима");

        signer.init(true, priv);
        assertNotNull(signer.generateSignature(HASH), "успешный повторный init возвращает подпись");
    }

    @Test
    @DisplayName(
            "Неудачный init для проверки (неверный тип параметров) оставляет не инициализированным")
    void failedVerificationInitLeavesUninitialized() {
        ECDSASigner signer = newSigner();
        signer.init(false, pub);

        assertThrows(IllegalArgumentException.class, () -> signer.init(false, priv));

        assertState(
                () -> signer.verifySignature(HASH, BigInteger.ONE, BigInteger.ONE),
                "ECDSASigner is not initialized",
                "после неудачного init проверка недопустима");
    }

    @Test
    @DisplayName("После destroy обе операции и init -> ISE «has been destroyed»")
    void afterDestroy() {
        ECDSASigner signer = newSigner();
        signer.init(true, priv);
        signer.destroy();

        assertTrue(signer.isDestroyed());
        assertState(
                () -> signer.generateSignature(HASH),
                "ECDSASigner has been destroyed",
                "подпись после destroy");
        assertState(
                () -> signer.verifySignature(HASH, BigInteger.ONE, BigInteger.ONE),
                "ECDSASigner has been destroyed",
                "проверка после destroy");
        assertState(() -> signer.init(true, priv), "ECDSASigner has been destroyed", "init");
    }

    @Test
    @DisplayName("Обычные подпись и проверка, смена режима повторным init работают как раньше")
    void normalOperationUnchanged() {
        ECDSASigner signer = newSigner();
        signer.init(true, priv);
        BigInteger[] signature = signer.generateSignature(HASH);

        signer.init(false, pub);
        assertTrue(
                signer.verifySignature(HASH, signature[0], signature[1]),
                "подпись должна проверяться после смены режима");
        byte[] other = HASH.clone();
        other[1] ^= 1;
        assertFalse(signer.verifySignature(other, signature[0], signature[1]));
    }

    @Test
    @DisplayName("DigestSigner: init(true) и verify с действительной подписью -> ISE от подписанта")
    void digestSignerWrongMode() {
        byte[] message = "message".getBytes(StandardCharsets.UTF_8);
        // Действительная подпись нужна, чтобы отказ шёл от requireReady, а не от проверки
        // диапазона r и s, возвращающей false
        DigestSigner producer = new DigestSigner(newSigner(), new Streebog256());
        producer.init(true, priv);
        producer.update(message, 0, message.length);
        byte[] validSignature = producer.sign();

        DigestSigner signingOnly = new DigestSigner(newSigner(), new Streebog256());
        signingOnly.init(true, priv);
        signingOnly.update(message, 0, message.length);

        IllegalStateException ex =
                assertThrows(
                        IllegalStateException.class,
                        () -> signingOnly.verify(validSignature),
                        "проверка в режиме подписи должна отказывать понятно");
        assertEquals(
                "ECDSASigner is initialized for signing, not for verification", ex.getMessage());
    }
}
