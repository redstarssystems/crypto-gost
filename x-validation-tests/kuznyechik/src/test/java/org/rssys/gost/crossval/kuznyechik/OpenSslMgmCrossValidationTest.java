package org.rssys.gost.crossval.kuznyechik;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.rssys.gost.api.MgmCipher;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.crossval.util.CrossValUtils;
import org.rssys.gost.crossval.util.OpenSslChecker;
import org.rssys.gost.jca.RssysGostProvider;
import org.rssys.gost.jca.key.GostSecretKey;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

import java.io.ByteArrayOutputStream;
import java.security.Security;
import java.util.Arrays;
import java.util.stream.Stream;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * Кросс-валидация Кузнечика-MGM (RFC 9058) с OpenSSL (gost-engine, провайдер gostprov).
 * <p>
 * До этого MGM проверялся только векторами RFC 9058 и внутри TLS (AAD из 5 байт заголовка).
 * Здесь сверяются JCA {@code Kuznyechik/MGM/NoPadding} и {@link MgmCipher#sealWithIcn} с OpenSSL
 * на длинах AAD и открытого текста вокруг границ блока: пустой AAD, неполный блок, ровно блок,
 * блок с хвостом, несколько блоков. Эталон - C-хелпер на EVP API ({@link MgmToolRunner}); он
 * принимает AAD целиком, поэтому дробление {@code updateAAD} и {@code update} проверяется только
 * на нашей стороне против одного вызова OpenSSL.
 */
class OpenSslMgmCrossValidationTest {

    private static final String PROVIDER = RssysGostProvider.PROVIDER_NAME;
    private static final String TRANSFORMATION = "Kuznyechik/MGM/NoPadding";
    private static final int KEY_LEN = 32;
    private static final int ICN_LEN = 16;
    private static final int TAG_LEN = 16;
    private static final int[] AAD_SIZES = {0, 1, 15, 16, 17, 41, 100};
    private static final int[] PLAINTEXT_SIZES = {0, 1, 16, 17, 67};
    private static final int[] CHUNK_SIZES = {1, 7, 16};

    @BeforeAll
    static void prepare() throws Exception {
        OpenSslChecker.assumeOpenSslAvailable();
        OpenSslChecker.assumeKuznyechikCipher();
        MgmToolRunner.prepare();
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new RssysGostProvider());
        }
    }

    @AfterAll
    static void cleanup() {
        MgmToolRunner.cleanup();
    }

    /** Все сочетания длин, кроме пары пустых данных: её MGM отвергает (RFC 9058 §6). */
    static Stream<Arguments> matrix() {
        Stream.Builder<Arguments> builder = Stream.builder();
        for (int aadSize : AAD_SIZES) {
            for (int plaintextSize : PLAINTEXT_SIZES) {
                if (aadSize != 0 || plaintextSize != 0) {
                    builder.add(Arguments.of(aadSize, plaintextSize));
                }
            }
        }
        return builder.build();
    }

    @ParameterizedTest(name = "AAD {0} байт, открытый текст {1} байт")
    @MethodSource("matrix")
    @DisplayName("JCA и MgmCipher совпадают с OpenSSL байт в байт и расшифровывают его данные")
    void matchesOpenSslInBothDirections(int aadSize, int plaintextSize) throws Exception {
        Sample sample = Sample.random(aadSize, plaintextSize);
        byte[] expected = MgmToolRunner.seal(sample.key, sample.icn, sample.aad, sample.plaintext);
        assertEquals(
                plaintextSize + TAG_LEN, expected.length, "Длина ответа OpenSSL: данные и тег");

        // Наше шифрование совпадает с эталоном
        byte[] jcaSealed = jcaSeal(sample, Cipher.ENCRYPT_MODE, sample.plaintext, 0);
        assertArrayEquals(
                expected,
                jcaSealed,
                () ->
                        "JCA не совпал с OpenSSL: "
                                + CrossValUtils.diffContext(expected, jcaSealed)
                                + " "
                                + sample.context());

        byte[] packet =
                MgmCipher.sealWithIcn(
                        sample.plaintext, new SymmetricKey(sample.key), sample.icn, sample.aad);
        assertArrayEquals(
                CrossValUtils.concat(sample.icn, expected),
                packet,
                () -> "MgmCipher.sealWithIcn не совпал с OpenSSL: " + sample.context());

        // OpenSSL принимает наш шифртекст
        MgmToolRunner.Outcome openedByOpenSsl =
                MgmToolRunner.open(sample.key, sample.icn, sample.aad, jcaSealed);
        assertEquals(
                0,
                openedByOpenSsl.exitCode(),
                () -> "OpenSSL отверг наш пакет: " + sample.context());
        assertArrayEquals(
                sample.plaintext,
                openedByOpenSsl.output(),
                () -> "OpenSSL расшифровал наш пакет иначе: " + sample.context());

        // Мы принимаем шифртекст OpenSSL
        assertArrayEquals(
                sample.plaintext,
                jcaSeal(sample, Cipher.DECRYPT_MODE, expected, 0),
                () -> "JCA не расшифровал данные OpenSSL: " + sample.context());
        assertArrayEquals(
                sample.plaintext,
                MgmCipher.open(
                        CrossValUtils.concat(sample.icn, expected),
                        new SymmetricKey(sample.key),
                        sample.aad),
                () -> "MgmCipher.open не расшифровал данные OpenSSL: " + sample.context());
    }

    @ParameterizedTest(name = "AAD {0} байт, открытый текст {1} байт")
    @MethodSource("matrix")
    @DisplayName("Дробление updateAAD и update не меняет результат (эталон - один вызов OpenSSL)")
    void chunkedInputMatchesOpenSsl(int aadSize, int plaintextSize) throws Exception {
        Sample sample = Sample.random(aadSize, plaintextSize);
        byte[] expected = MgmToolRunner.seal(sample.key, sample.icn, sample.aad, sample.plaintext);

        for (int chunk : CHUNK_SIZES) {
            byte[] sealed = jcaSeal(sample, Cipher.ENCRYPT_MODE, sample.plaintext, chunk);
            assertArrayEquals(
                    expected,
                    sealed,
                    () ->
                            "Шифрование порциями по "
                                    + chunk
                                    + " байт не совпало с OpenSSL: "
                                    + CrossValUtils.diffContext(expected, sealed)
                                    + " "
                                    + sample.context());
            byte[] opened = jcaSeal(sample, Cipher.DECRYPT_MODE, expected, chunk);
            assertArrayEquals(
                    sample.plaintext,
                    opened,
                    () ->
                            "Расшифрование порциями по "
                                    + chunk
                                    + " байт не совпало: "
                                    + sample.context());
        }
    }

    @ParameterizedTest(name = "AAD {0} байт, открытый текст {1} байт")
    @MethodSource("tamperingCases")
    @DisplayName("Искажение тега, шифртекста или AAD отвергается и нами, и OpenSSL")
    void tamperingIsRejectedByBothSides(int aadSize, int plaintextSize) throws Exception {
        Sample sample = Sample.random(aadSize, plaintextSize);
        byte[] sealed = MgmToolRunner.seal(sample.key, sample.icn, sample.aad, sample.plaintext);
        int tagStart = sealed.length - TAG_LEN;

        // Без этого тест остался бы зелёным и при регрессии «отвергаем всё»
        assertAccepted(sample, sealed, sample.aad);

        assertRejected(sample, flipBit(sealed, sealed.length - 1), sample.aad, "бит тега");
        assertRejected(sample, flipBit(sealed, tagStart), sample.aad, "первый бит тега");
        assertRejected(sample, zeroTag(sealed), sample.aad, "нулевой тег");
        if (plaintextSize > 0) {
            assertRejected(sample, flipBit(sealed, 0), sample.aad, "бит шифртекста");
        }
        if (aadSize > 0) {
            assertRejected(sample, sealed, flipBit(sample.aad, aadSize - 1), "бит AAD");
        }
    }

    static Stream<Arguments> tamperingCases() {
        return Stream.of(
                Arguments.of(17, 17),
                Arguments.of(0, 16),
                Arguments.of(16, 0),
                Arguments.of(41, 67));
    }

    @Test
    @DisplayName(
            "Посылка RFC 9058 §6: при пустых P и A тег не зависит от ICN, и мы такое отвергаем")
    void emptyMessageHasConstantTagAndIsRejectedByLibrary() throws Exception {
        byte[] key = new byte[KEY_LEN];
        CryptoRandom.INSTANCE.nextBytes(key);
        byte[] firstIcn = newIcn();
        byte[] secondIcn = newIcn();
        byte[] none = new byte[0];

        byte[] firstTag = MgmToolRunner.seal(key, firstIcn, none, none);
        byte[] secondTag = MgmToolRunner.seal(key, secondIcn, none, none);
        assertArrayEquals(
                firstTag,
                secondTag,
                "Тег пустого сообщения у OpenSSL не должен зависеть от ICN: иначе довод RFC 9058 §6"
                    + " неверен");

        // Тег пустого сообщения равен E_K(0): это и делает его константой для ключа
        Kuznyechik blockCipher = new Kuznyechik();
        blockCipher.init(true, new SymmetricKey(key));
        byte[] zeroBlockEncrypted = new byte[Kuznyechik.BLOCK_SIZE];
        blockCipher.processBlock(new byte[Kuznyechik.BLOCK_SIZE], 0, zeroBlockEncrypted, 0);
        blockCipher.destroy();
        assertArrayEquals(
                zeroBlockEncrypted, firstTag, "Тег пустого сообщения должен быть равен E_K(0)");

        assertThrows(
                IllegalArgumentException.class,
                () -> MgmCipher.sealWithIcn(none, new SymmetricKey(key), firstIcn, none),
                "MgmCipher обязан отвергать пустые данные без AAD");
        Sample sample = new Sample(key, firstIcn, none, none);
        assertThrows(
                IllegalArgumentException.class,
                () -> jcaSeal(sample, Cipher.ENCRYPT_MODE, none, 0),
                "JCA обязан отвергать пустые данные без AAD");
    }

    private static void assertAccepted(Sample sample, byte[] sealed, byte[] aad) throws Exception {
        MgmToolRunner.Outcome outcome = MgmToolRunner.open(sample.key, sample.icn, aad, sealed);
        assertEquals(
                0,
                outcome.exitCode(),
                () -> "OpenSSL отверг неискажённый пакет: " + outcome.diagnostics());
        assertArrayEquals(
                sample.plaintext,
                jcaSeal(sample, Cipher.DECRYPT_MODE, sealed, 0),
                "JCA не принял неискажённый пакет");
    }

    private static void assertRejected(Sample sample, byte[] sealed, byte[] aad, String what)
            throws Exception {
        MgmToolRunner.Outcome outcome = MgmToolRunner.open(sample.key, sample.icn, aad, sealed);
        assertEquals(
                MgmToolRunner.EXIT_BAD_TAG,
                outcome.exitCode(),
                () -> "OpenSSL должен отказать по тегу (" + what + "): " + outcome.diagnostics());

        Sample tampered = new Sample(sample.key, sample.icn, aad, sample.plaintext);
        assertThrows(
                AEADBadTagException.class,
                () -> jcaSeal(tampered, Cipher.DECRYPT_MODE, sealed, 0),
                "JCA должен отвергать: " + what);
        assertThrows(
                AuthenticationException.class,
                () ->
                        MgmCipher.open(
                                CrossValUtils.concat(sample.icn, sealed),
                                new SymmetricKey(sample.key),
                                aad),
                "MgmCipher должен отвергать: " + what);
    }

    /**
     * Прогоняет данные через JCA-шифр. {@code chunk} - размер порции для {@code updateAAD} и
     * {@code update}; 0 означает один вызов.
     */
    private static byte[] jcaSeal(Sample sample, int mode, byte[] input, int chunk)
            throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(
                mode,
                new GostSecretKey("Kuznyechik", new SymmetricKey(sample.key)),
                new IvParameterSpec(sample.icn));
        if (sample.aad.length > 0) {
            if (chunk == 0) {
                cipher.updateAAD(sample.aad);
            } else {
                for (int offset = 0; offset < sample.aad.length; offset += chunk) {
                    cipher.updateAAD(
                            sample.aad, offset, Math.min(chunk, sample.aad.length - offset));
                }
            }
        }
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        int offset = 0;
        if (chunk != 0) {
            while (input.length - offset > chunk) {
                byte[] part = cipher.update(input, offset, chunk);
                if (part != null) {
                    result.write(part);
                }
                offset += chunk;
            }
        }
        result.write(cipher.doFinal(input, offset, input.length - offset));
        return result.toByteArray();
    }

    private static byte[] flipBit(byte[] data, int index) {
        byte[] copy = Arrays.copyOf(data, data.length);
        copy[index] ^= 0x01;
        return copy;
    }

    private static byte[] zeroTag(byte[] sealed) {
        byte[] copy = Arrays.copyOf(sealed, sealed.length);
        Arrays.fill(copy, copy.length - TAG_LEN, copy.length, (byte) 0);
        return copy;
    }

    /** ICN со старшим битом 0: иначе библиотека отвергает его до сравнения (RFC 9058 §3). */
    private static byte[] newIcn() {
        byte[] icn = new byte[ICN_LEN];
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7f;
        return icn;
    }

    /** Один случай: ключ, ICN, AAD и открытый текст. */
    private record Sample(byte[] key, byte[] icn, byte[] aad, byte[] plaintext) {

        static Sample random(int aadSize, int plaintextSize) {
            byte[] key = new byte[KEY_LEN];
            CryptoRandom.INSTANCE.nextBytes(key);
            byte[] aad = new byte[aadSize];
            CryptoRandom.INSTANCE.nextBytes(aad);
            byte[] plaintext = new byte[plaintextSize];
            CryptoRandom.INSTANCE.nextBytes(plaintext);
            return new Sample(key, newIcn(), aad, plaintext);
        }

        /** Входные данные для воспроизведения расхождения вручную. */
        String context() {
            return "key="
                    + CrossValUtils.toHex(key)
                    + " icn="
                    + CrossValUtils.toHex(icn)
                    + " aad="
                    + CrossValUtils.toHex(aad)
                    + " pt="
                    + CrossValUtils.toHex(plaintext);
        }
    }
}
