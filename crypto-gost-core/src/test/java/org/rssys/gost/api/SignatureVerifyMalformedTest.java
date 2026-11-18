package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.signature.ECParameters;

@DisplayName("Signature.verify и verifyHash: подпись неверной длины не принимается и не бросает")
class SignatureVerifyMalformedTest {

    private static final byte[] MESSAGE = "message".getBytes(StandardCharsets.UTF_8);

    static Stream<ECParameters> curves() {
        return Stream.of(ECParameters.cryptoProA(), ECParameters.tc26a512());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("verify на подписи неверной длины, пустой и null возвращает false")
    void verifyReturnsFalseOnMalformedLength(ECParameters params) {
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        try {
            byte[] good = Signature.sign(MESSAGE, pair.getPrivate());

            assertFalse(
                    Signature.verify(
                            MESSAGE, Arrays.copyOf(good, good.length + 1), pair.getPublic()));
            assertFalse(
                    Signature.verify(
                            MESSAGE, Arrays.copyOf(good, good.length - 1), pair.getPublic()));
            assertFalse(
                    Signature.verify(MESSAGE, new byte[3], pair.getPublic()), "подпись в 3 байта");
            assertFalse(Signature.verify(MESSAGE, new byte[0], pair.getPublic()), "пустая подпись");
            assertFalse(Signature.verify(MESSAGE, null, pair.getPublic()), "подпись null");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("verifyHash на подписи неверной длины, пустой и null возвращает false")
    void verifyHashReturnsFalseOnMalformedLength(ECParameters params) {
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        try {
            byte[] hash = new byte[params.hlen];
            byte[] good = Signature.signHash(hash, pair.getPrivate());

            assertFalse(
                    Signature.verifyHash(
                            hash, Arrays.copyOf(good, good.length + 1), pair.getPublic()));
            assertFalse(
                    Signature.verifyHash(
                            hash, Arrays.copyOf(good, good.length - 1), pair.getPublic()));
            assertFalse(
                    Signature.verifyHash(hash, new byte[0], pair.getPublic()), "пустая подпись");
            assertFalse(Signature.verifyHash(hash, null, pair.getPublic()), "подпись null");
            assertTrue(Signature.verifyHash(hash, good, pair.getPublic()), "верная подпись");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName(
            "После отказа по длине следующая проверка верной подписи проходит: состояние не залипло")
    void verifyAfterMalformedCallStillWorks(ECParameters params) {
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        try {
            byte[] good = Signature.sign(MESSAGE, pair.getPrivate());

            assertFalse(Signature.verify(MESSAGE, new byte[3], pair.getPublic()));
            assertTrue(Signature.verify(MESSAGE, good, pair.getPublic()), "верная подпись");
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Неверная длина хэша по-прежнему даёт исключение: это ошибка вызывающего")
    void wrongHashLengthStillThrows(ECParameters params) {
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        try {
            byte[] good = Signature.sign(MESSAGE, pair.getPrivate());
            assertThrows(
                    IllegalArgumentException.class,
                    () -> Signature.verifyHash(new byte[5], good, pair.getPublic()),
                    "хэш неверной длины");
        } finally {
            pair.getPrivate().destroy();
        }
    }
}
