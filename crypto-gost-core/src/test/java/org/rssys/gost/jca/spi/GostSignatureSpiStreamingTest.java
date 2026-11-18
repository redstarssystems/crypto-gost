package org.rssys.gost.jca.spi;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.StreebogStateProbe;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostECPrivateKey;
import org.rssys.gost.jca.key.GostECPublicKey;

/**
 * Потоковое хэширование и сброс состояния {@link GostSignatureSpi}, а также стандартное
 * исключение {@link GostKeyGeneratorSpi}.
 */
@DisplayName("GostSignatureSpi: потоковое хэширование и состояние после ошибок")
@ExtendWith(JcaTestSupport.class)
class GostSignatureSpiStreamingTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final byte[] MESSAGE_ONE = "первое сообщение".getBytes(StandardCharsets.UTF_8);
    private static final byte[] MESSAGE_TWO = "второе сообщение".getBytes(StandardCharsets.UTF_8);

    static Stream<Arguments> curves() {
        return Stream.of(
                Arguments.of("ECGOST3410-2012-256", "cryptopro-A", 32),
                Arguments.of("ECGOST3410-2012-512", "tc26-gost-A-512", 64));
    }

    private static KeyPair newKeyPair(String curveName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ECGOST3410-2012", PROVIDER);
        generator.initialize(new ECGenParameterSpec(curveName));
        return generator.generateKeyPair();
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static byte[] streebog(byte[] message, int hlen) {
        byte[] hash = new byte[hlen];
        if (hlen == 32) {
            Streebog256 digest = new Streebog256();
            digest.update(message, 0, message.length);
            digest.doFinal(hash, 0);
        } else {
            Streebog512 digest = new Streebog512();
            digest.update(message, 0, message.length);
            digest.doFinal(hash, 0);
        }
        return hash;
    }

    /**
     * Экземпляр JCA-подписи в детерминированном режиме: тесты сравнивают байты подписи с подписью
     * готового хэша, а в вероятностном режиме совпадать им нечему.
     */
    private static Signature deterministicSignature(String algorithm) throws Exception {
        Signature signature = Signature.getInstance(algorithm, PROVIDER);
        signature.setParameter(
                new org.rssys.gost.jca.spec.GostSignatureParameterSpec(
                        org.rssys.gost.signature.NonceMode.DETERMINISTIC));
        return signature;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Потоковая подпись равна подписи готового хэша Стрибога")
    void streamingSignEqualsSignHash(String algorithm, String curve, int hlen) throws Exception {
        KeyPair pair = newKeyPair(curve);
        byte[] message = concat(MESSAGE_ONE, MESSAGE_TWO);

        Signature signer = deterministicSignature(algorithm);
        signer.initSign(pair.getPrivate());
        signer.update(message);
        byte[] viaJca = signer.sign();

        byte[] viaApi =
                org.rssys.gost.api.Signature.signHash(
                        streebog(message, hlen),
                        ((GostECPrivateKey) pair.getPrivate()).toPrivateKeyParameters(),
                        org.rssys.gost.signature.NonceMode.DETERMINISTIC);

        // подпись детерминирована (RFC 6979): совпасть должны байты, а не только корректность
        assertArrayEquals(viaApi, viaJca, "подпись JCA не совпала с подписью хэша Стрибога");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Дробление update по 1, 7 и 64 байта даёт ту же подпись, что один вызов")
    void chunkedUpdatesGiveSameSignature(String algorithm, String curve, int hlen)
            throws Exception {
        KeyPair pair = newKeyPair(curve);
        byte[] message = new byte[300];
        for (int i = 0; i < message.length; i++) {
            message[i] = (byte) (i * 31 + 7);
        }

        Signature whole = deterministicSignature(algorithm);
        whole.initSign(pair.getPrivate());
        whole.update(message);
        byte[] expected = whole.sign();

        for (int chunk : new int[] {1, 7, 64}) {
            Signature chunked = deterministicSignature(algorithm);
            chunked.initSign(pair.getPrivate());
            for (int offset = 0; offset < message.length; offset += chunk) {
                chunked.update(message, offset, Math.min(chunk, message.length - offset));
            }
            assertArrayEquals(
                    expected, chunked.sign(), "дробление по " + chunk + " байт изменило подпись");
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("verify: после исключения данные неудавшегося вызова не склеиваются со следующим")
    void failedVerifyDoesNotLeakMessageIntoNextCall(String algorithm, String curve, int hlen)
            throws Exception {
        KeyPair pair = newKeyPair(curve);
        byte[] concatenated = concat(MESSAGE_ONE, MESSAGE_TWO);

        Signature signer = deterministicSignature(algorithm);
        signer.initSign(pair.getPrivate());
        signer.update(concatenated);
        byte[] signatureOverConcatenation = signer.sign();
        signer.update(MESSAGE_TWO);
        byte[] signatureOverSecond = signer.sign();

        Signature verifier = deterministicSignature(algorithm);
        verifier.initVerify(pair.getPublic());
        verifier.update(MESSAGE_ONE);
        // подпись неверной длины даёт исключение до сравнения с хэшем
        assertThrows(SignatureException.class, () -> verifier.verify(new byte[5]));

        verifier.update(MESSAGE_TWO);
        assertFalse(
                verifier.verify(signatureOverConcatenation),
                "подпись над M1||M2 принята: сообщение прошлого вызова осталось в состоянии");

        verifier.update(MESSAGE_TWO);
        assertTrue(
                verifier.verify(signatureOverSecond),
                "верная подпись M2 отвергнута после ошибки предыдущего вызова");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("sign: после исключения следующее сообщение подписывается без хвоста прежнего")
    void failedSignDoesNotLeakMessageIntoNextCall(String algorithm, String curve, int hlen)
            throws Exception {
        KeyPair brokenPair = newKeyPair(curve);
        KeyPair workingPair = newKeyPair(curve);

        Signature signer = deterministicSignature(algorithm);
        signer.initSign(brokenPair.getPrivate());
        signer.update(MESSAGE_ONE);
        // уничтоженный ключ: подпись обязана упасть
        ((GostECPrivateKey) brokenPair.getPrivate()).destroy();
        assertThrows(SignatureException.class, signer::sign);

        signer.initSign(workingPair.getPrivate());
        signer.update(MESSAGE_TWO);
        byte[] actual = signer.sign();

        byte[] expected =
                org.rssys.gost.api.Signature.signHash(
                        streebog(MESSAGE_TWO, hlen),
                        ((GostECPrivateKey) workingPair.getPrivate()).toPrivateKeyParameters(),
                        org.rssys.gost.signature.NonceMode.DETERMINISTIC);
        assertArrayEquals(expected, actual, "в подпись попал хвост сообщения неудавшегося вызова");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("Объект повторно используется после успешной подписи и проверки")
    void reusableAfterSuccess(String algorithm, String curve, int hlen) throws Exception {
        KeyPair pair = newKeyPair(curve);

        Signature signer = deterministicSignature(algorithm);
        signer.initSign(pair.getPrivate());
        signer.update(MESSAGE_ONE);
        byte[] first = signer.sign();
        signer.update(MESSAGE_TWO);
        byte[] second = signer.sign();

        Signature verifier = deterministicSignature(algorithm);
        verifier.initVerify(pair.getPublic());
        verifier.update(MESSAGE_ONE);
        assertTrue(verifier.verify(first), "первая подпись не прошла проверку");
        verifier.update(MESSAGE_TWO);
        assertTrue(verifier.verify(second), "вторая подпись не прошла проверку");
        verifier.update(MESSAGE_TWO);
        assertFalse(verifier.verify(first), "чужая подпись принята");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("update(byte), ByteBuffer и длины на границе блока дают подпись хэша Стрибога")
    void allUpdatePathsAndBlockBoundariesMatchSignHash(String algorithm, String curve, int hlen)
            throws Exception {
        KeyPair pair = newKeyPair(curve);
        var privateParameters = ((GostECPrivateKey) pair.getPrivate()).toPrivateKeyParameters();

        for (int length : new int[] {0, 1, 63, 64, 65, 127, 128, 129}) {
            byte[] message = new byte[length];
            for (int i = 0; i < length; i++) {
                message[i] = (byte) (i * 13 + 5);
            }
            byte[] expected =
                    org.rssys.gost.api.Signature.signHash(
                            streebog(message, hlen),
                            privateParameters,
                            org.rssys.gost.signature.NonceMode.DETERMINISTIC);

            Signature byteWise = deterministicSignature(algorithm);
            byteWise.initSign(pair.getPrivate());
            for (byte value : message) {
                byteWise.update(value);
            }
            assertArrayEquals(expected, byteWise.sign(), "update(byte), длина " + length);

            Signature heap = deterministicSignature(algorithm);
            heap.initSign(pair.getPrivate());
            heap.update(ByteBuffer.wrap(message));
            assertArrayEquals(expected, heap.sign(), "heap ByteBuffer, длина " + length);

            Signature direct = deterministicSignature(algorithm);
            direct.initSign(pair.getPrivate());
            direct.update(ByteBuffer.allocateDirect(length).put(message).flip());
            assertArrayEquals(expected, direct.sign(), "direct ByteBuffer, длина " + length);
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("После sign и verify рабочие буферы Стрибога нулевые, включая хвост сообщения")
    void digestWorkBuffersWipedAfterSignAndVerify(String algorithm, String curve, int hlen)
            throws Exception {
        KeyPair pair = newKeyPair(curve);
        GostSignatureSpi spi = newSpi(hlen);
        spi.engineInitSign((GostECPrivateKey) pair.getPrivate());
        byte[] tail = new byte[30];
        java.util.Arrays.fill(tail, (byte) 0x5A);
        spi.engineUpdate(tail, 0, tail.length);
        byte[] signature = spi.engineSign();
        assertAllWorkBuffersZero(spi);

        spi.engineInitVerify((GostECPublicKey) pair.getPublic());
        spi.engineUpdate(tail, 0, tail.length);
        assertTrue(spi.engineVerify(signature), "подпись не прошла проверку");
        assertAllWorkBuffersZero(spi);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("curves")
    @DisplayName("После ошибки sign и verify рабочие буферы Стрибога тоже нулевые")
    void digestWorkBuffersWipedAfterFailure(String algorithm, String curve, int hlen)
            throws Exception {
        KeyPair pair = newKeyPair(curve);
        byte[] tail = new byte[30];
        java.util.Arrays.fill(tail, (byte) 0x5A);

        // прямой вызов SPI без повторной initSign: через Signature сброс делает инициализация
        // и скрыл бы отсутствие finally в engineSign
        GostSignatureSpi signer = newSpi(hlen);
        signer.engineInitSign((GostECPrivateKey) pair.getPrivate());
        signer.engineUpdate(tail, 0, tail.length);
        ((GostECPrivateKey) pair.getPrivate()).destroy();
        assertThrows(SignatureException.class, signer::engineSign);
        assertAllWorkBuffersZero(signer);

        KeyPair other = newKeyPair(curve);
        GostSignatureSpi verifier = newSpi(hlen);
        verifier.engineInitVerify((GostECPublicKey) other.getPublic());
        verifier.engineUpdate(tail, 0, tail.length);
        assertThrows(SignatureException.class, () -> verifier.engineVerify(new byte[5]));
        assertAllWorkBuffersZero(verifier);
    }

    private static GostSignatureSpi newSpi(int hlen) {
        return hlen == 32
                ? new GostSignatureSpi.Ecgost3410_256Spi()
                : new GostSignatureSpi.Ecgost3410_512Spi();
    }

    private static void assertAllWorkBuffersZero(GostSignatureSpi spi) throws Exception {
        Field digestField = GostSignatureSpi.class.getDeclaredField("digest");
        digestField.setAccessible(true);
        StreebogStateProbe.assertWipedLikeFresh(digestField.get(spi));
    }

    @Test
    @DisplayName("Повторная инициализация сбрасывает недоделанное сообщение")
    void reinitializationDropsPendingMessage() throws Exception {
        KeyPair pair = newKeyPair("cryptopro-A");

        Signature verifier = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        verifier.initVerify(pair.getPublic());
        verifier.update(MESSAGE_ONE);
        verifier.initVerify(pair.getPublic());

        Signature signer = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        signer.initSign(pair.getPrivate());
        signer.update(MESSAGE_TWO);
        byte[] signature = signer.sign();

        verifier.update(MESSAGE_TWO);
        assertTrue(verifier.verify(signature), "после initVerify старое сообщение не сброшено");
    }

    @Test
    @DisplayName("update без инициализации отвергается")
    void updateWithoutInitializationRejected() throws Exception {
        Signature signature = Signature.getInstance("ECGOST3410-2012-256", PROVIDER);
        assertThrows(SignatureException.class, () -> signature.update(MESSAGE_ONE));
    }

    @Test
    @DisplayName("Прямой вызов engineUpdate с неверными границами отвергается")
    void engineUpdateChecksBounds() throws Exception {
        KeyPair pair = newKeyPair("cryptopro-A");
        GostSignatureSpi.Ecgost3410_256Spi spi = new GostSignatureSpi.Ecgost3410_256Spi();
        spi.engineInitVerify((GostECPublicKey) pair.getPublic());

        assertThrows(IndexOutOfBoundsException.class, () -> spi.engineUpdate(new byte[4], 2, 10));
        assertDoesNotThrow(() -> spi.engineUpdate(new byte[4], 1, 3));
    }

    @Test
    @DisplayName("KeyGenerator.init(128) бросает java.security.InvalidParameterException")
    void keyGeneratorRejectsWrongSizeWithStandardException() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("Kuznyechik", PROVIDER);

        assertThrows(InvalidParameterException.class, () -> generator.init(128));
        assertDoesNotThrow(() -> generator.init(256));
    }
}
