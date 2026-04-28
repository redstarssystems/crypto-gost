package org.rssys.gost;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.mode.Cfb;
import org.rssys.gost.mac.Cmac;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты реализации ГОСТ Р 34.12-2015 (Кузнечик) и ГОСТ Р 34.13-2015 (CFB, CMAC).
 *
 * Все эталонные значения взяты из текстов стандартов:
 *   - ГОСТ Р 34.12-2015, приложение А (страница 25)
 *   - ГОСТ Р 34.13-2015, раздел А (страницы 29–30)
 *
 * Те же векторы используются в тестах проекта redpass (crypto_test.clj).
 */
@DisplayName("GOST Crypto Tests")
class CryptoTest {

    // -----------------------------------------------------------------------
    // Эталонные векторы ГОСТ Р 34.12-2015 / ГОСТ Р 34.13-2015
    // -----------------------------------------------------------------------

    /** Ключ шифрования (256 бит) — стр. 25 ГОСТ Р 34.12-2015 */
    private static final String KEY_HEX =
        "8899aabbccddeeff0011223344556677" +
        "fedcba98765432100123456789abcdef";

    /** Синхропосылка (IV, 256 бит) — стр. 29 ГОСТ Р 34.13-2015 */
    private static final String IV_HEX =
        "1234567890abcef0a1b2c3d4e5f00112" +
        "23344556677889901213141516171819";

    /** Открытый текст (64 байта, 4 блока) — стр. 25 ГОСТ Р 34.12-2015 */
    private static final String PLAIN_HEX =
        "1122334455667700ffeeddccbbaa9988" +
        "00112233445566778899aabbcceeff0a" +
        "112233445566778899aabbcceeff0a00" +
        "2233445566778899aabbcceeff0a0011";

    /** Эталон ECB-шифрования первого блока — стр. 25 ГОСТ Р 34.12-2015 */
    private static final String ECB_CIPHER_BLOCK1_HEX =
        "7f679d90bebc24305a468d42b9d4edcd";

    /** Эталон CFB128-шифрования 4 блоков — стр. 29 ГОСТ Р 34.13-2015 */
    private static final String CFB_CIPHER_HEX =
        "81800a59b1842b24ff1f795e897abd95" +
        "ed5b47a7048cfab48fb521369d9326bf" +
        "79f2a8eb5cc68d38842d264e97a238b5" +
        "4ffebecd4e922de6c75bd9dd44fbf4d1";

    /**
     * Эталон CMAC-8 (усечённый до 8 байт) — стр. 30 ГОСТ Р 34.13-2015.
     * Используется в redpass (cmac-size = 8).
     */
    private static final String CMAC_8_HEX = "336f4d296059fbe3";

    /**
     * Эталон CMAC-16 (полный тег, 16 байт).
     * Вычислен через эталонную реализацию BouncyCastle 1.83.
     */
    private static final String CMAC_16_HEX = "336f4d296059fbe34ddeb35b37749c67";

    // -----------------------------------------------------------------------
    // Вспомогательные методы
    // -----------------------------------------------------------------------

    static byte[] hex(String s) {
        s = s.replaceAll("\\s", "");
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xFF));
        return sb.toString();
    }

    static byte[] key()   { return hex(KEY_HEX); }
    static byte[] iv()    { return hex(IV_HEX); }
    static byte[] plain() { return hex(PLAIN_HEX); }

    // -----------------------------------------------------------------------
    // 1. Kuznyechik — режим ECB
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Кузнечик ECB: шифрование первого блока")
    void testKuznyechikECBEncrypt() {
        Kuznyechik engine = new Kuznyechik();
        engine.init(true, new SymmetricKey(key()));

        byte[] plain  = Arrays.copyOf(plain(), 16); // первый блок
        byte[] cipher = new byte[16];
        engine.processBlock(plain, 0, cipher, 0);

        assertEquals(ECB_CIPHER_BLOCK1_HEX, hex(cipher),
            "ECB-шифрование первого блока должно совпадать с эталоном ГОСТ Р 34.12-2015");
    }

    @Test
    @DisplayName("Кузнечик ECB: расшифрование первого блока")
    void testKuznyechikECBDecrypt() {
        Kuznyechik engine = new Kuznyechik();
        engine.init(false, new SymmetricKey(key()));

        byte[] cipher    = hex(ECB_CIPHER_BLOCK1_HEX);
        byte[] decrypted = new byte[16];
        engine.processBlock(cipher, 0, decrypted, 0);

        assertEquals(hex(Arrays.copyOf(plain(), 16)), hex(decrypted),
            "ECB-расшифрование должно восстановить исходный первый блок");
    }

    @Test
    @DisplayName("Кузнечик ECB: encrypt(decrypt(x)) == x")
    void testKuznyechikECBRoundtrip() {
        Kuznyechik enc = new Kuznyechik();
        Kuznyechik dec = new Kuznyechik();
        enc.init(true,  new SymmetricKey(key()));
        dec.init(false, new SymmetricKey(key()));

        byte[] original  = Arrays.copyOf(plain(), 16);
        byte[] cipher    = new byte[16];
        byte[] recovered = new byte[16];
        enc.processBlock(original, 0, cipher,    0);
        dec.processBlock(cipher,   0, recovered, 0);

        assertArrayEquals(original, recovered,
            "Кузнечик ECB: encrypt → decrypt должен вернуть исходный блок");
    }

    // -----------------------------------------------------------------------
    // 2. Cfb — режим CFB128
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CFB128: шифрование 4 блоков по эталону ГОСТ Р 34.13-2015")
    void testCFB128Encrypt() {
        Cfb cipher = new Cfb(new Kuznyechik(), 128);
        cipher.init(true, new ParametersWithIV(new SymmetricKey(key()), iv()));

        byte[] plain  = plain();
        byte[] result = new byte[plain.length];
        cipher.processBytes(plain, 0, plain.length, result, 0);

        assertEquals(CFB_CIPHER_HEX, hex(result),
            "CFB128-шифрование должно совпадать с эталоном ГОСТ Р 34.13-2015, стр. 29");
    }

    @Test
    @DisplayName("CFB128: расшифрование 4 блоков по эталону ГОСТ Р 34.13-2015")
    void testCFB128Decrypt() {
        Cfb cipher = new Cfb(new Kuznyechik(), 128);
        cipher.init(false, new ParametersWithIV(new SymmetricKey(key()), iv()));

        byte[] ciphertext = hex(CFB_CIPHER_HEX);
        byte[] result     = new byte[ciphertext.length];
        cipher.processBytes(ciphertext, 0, ciphertext.length, result, 0);

        assertEquals(PLAIN_HEX, hex(result),
            "CFB128-расшифрование должно восстановить открытый текст");
    }

    @Test
    @DisplayName("CFB128: encrypt(decrypt(x)) == x для произвольных данных")
    void testCFB128Roundtrip() {
        byte[] original = "Проверка Кузнечик CFB128 2015".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        Cfb enc = new Cfb(new Kuznyechik(), 128);
        Cfb dec = new Cfb(new Kuznyechik(), 128);
        enc.init(true,  new ParametersWithIV(new SymmetricKey(key()), iv()));
        dec.init(false, new ParametersWithIV(new SymmetricKey(key()), iv()));

        byte[] encrypted = new byte[original.length];
        byte[] recovered = new byte[original.length];
        enc.processBytes(original,  0, original.length,  encrypted, 0);
        dec.processBytes(encrypted, 0, encrypted.length, recovered, 0);

        assertArrayEquals(original, recovered,
            "CFB128 roundtrip должен вернуть исходные данные");
    }

    @Test
    @DisplayName("CFB128: шифрование данных меньше блока (5 байт)")
    void testCFB128ShortData() {
        byte[] original = "hello".getBytes();

        Cfb enc = new Cfb(new Kuznyechik(), 128);
        Cfb dec = new Cfb(new Kuznyechik(), 128);
        enc.init(true,  new ParametersWithIV(new SymmetricKey(key()), iv()));
        dec.init(false, new ParametersWithIV(new SymmetricKey(key()), iv()));

        byte[] encrypted = new byte[original.length];
        byte[] recovered = new byte[original.length];
        enc.processBytes(original,  0, original.length,  encrypted, 0);
        dec.processBytes(encrypted, 0, encrypted.length, recovered, 0);

        assertArrayEquals(original, recovered,
            "CFB128 должен корректно работать с данными меньше одного блока");
    }

    @Test
    @DisplayName("CFB128: reset() восстанавливает начальное состояние")
    void testCFB128Reset() {
        Cfb cipher = new Cfb(new Kuznyechik(), 128);
        cipher.init(true, new ParametersWithIV(new SymmetricKey(key()), iv()));

        byte[] plain    = plain();
        byte[] result1  = new byte[plain.length];
        byte[] result2  = new byte[plain.length];

        cipher.processBytes(plain, 0, plain.length, result1, 0);
        cipher.reset();
        cipher.processBytes(plain, 0, plain.length, result2, 0);

        assertArrayEquals(result1, result2,
            "После reset() шифрование должно давать тот же результат");
    }

    // -----------------------------------------------------------------------
    // 3. Cmac — имитозащита ГОСТ Р 34.13-2015
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CMAC-8: усечённый тег 8 байт — эталон ГОСТ Р 34.13-2015, стр. 30")
    void testCMAC8() {
        Cmac cmac = new Cmac(new Kuznyechik(), 64); // 64 бит = 8 байт
        cmac.init(new SymmetricKey(key()));

        byte[] plain = plain();
        cmac.update(plain, 0, plain.length);

        byte[] result = new byte[8];
        cmac.doFinal(result, 0);

        assertEquals(CMAC_8_HEX, hex(result),
            "CMAC-8 должен совпадать с эталоном ГОСТ Р 34.13-2015, стр. 30");
    }

    @Test
    @DisplayName("CMAC-16: полный тег 16 байт")
    void testCMAC16() {
        Cmac cmac = new Cmac(new Kuznyechik()); // 128 бит = 16 байт
        cmac.init(new SymmetricKey(key()));

        byte[] plain = plain();
        cmac.update(plain, 0, plain.length);

        byte[] result = new byte[16];
        cmac.doFinal(result, 0);

        assertEquals(CMAC_16_HEX, hex(result),
            "CMAC-16 должен совпадать с эталонным значением");
    }

    @Test
    @DisplayName("CMAC-8: первые 8 байт CMAC-16 совпадают с CMAC-8")
    void testCMAC8IsPrefixOfCMAC16() {
        Cmac cmac8  = new Cmac(new Kuznyechik(), 64);
        Cmac cmac16 = new Cmac(new Kuznyechik());
        cmac8.init(new SymmetricKey(key()));
        cmac16.init(new SymmetricKey(key()));

        byte[] plain = plain();
        cmac8.update(plain,  0, plain.length);
        cmac16.update(plain, 0, plain.length);

        byte[] out8  = new byte[8];
        byte[] out16 = new byte[16];
        cmac8.doFinal(out8,   0);
        cmac16.doFinal(out16, 0);

        assertArrayEquals(out8, Arrays.copyOf(out16, 8),
            "CMAC-8 должен быть равен первым 8 байтам CMAC-16");
    }

    @Test
    @DisplayName("CMAC: побайтовое update эквивалентно пакетному update")
    void testCMACByteByByteEquivalent() {
        byte[] plain = plain();

        Cmac bulk   = new Cmac(new Kuznyechik());
        Cmac oneByte = new Cmac(new Kuznyechik());
        bulk.init(new SymmetricKey(key()));
        oneByte.init(new SymmetricKey(key()));

        bulk.update(plain, 0, plain.length);
        for (byte b : plain) oneByte.update(b);

        byte[] out1 = new byte[16];
        byte[] out2 = new byte[16];
        bulk.doFinal(out1, 0);
        oneByte.doFinal(out2, 0);

        assertArrayEquals(out1, out2,
            "Побайтовый update должен давать тот же результат, что и пакетный");
    }

    @Test
    @DisplayName("CMAC: reset() позволяет повторно вычислить тот же MAC")
    void testCMACReset() {
        Cmac cmac = new Cmac(new Kuznyechik(), 64);
        cmac.init(new SymmetricKey(key()));

        byte[] plain = plain();
        byte[] out1  = new byte[8];
        byte[] out2  = new byte[8];

        cmac.update(plain, 0, plain.length);
        cmac.doFinal(out1, 0);

        // doFinal сам вызывает reset(), поэтому сразу обновляем снова
        cmac.update(plain, 0, plain.length);
        cmac.doFinal(out2, 0);

        assertArrayEquals(out1, out2, "CMAC после reset() должен давать тот же результат");
        assertEquals(CMAC_8_HEX, hex(out1));
    }

    @Test
    @DisplayName("CMAC: разные ключи дают разные теги")
    void testCMACDifferentKeys() {
        byte[] key2 = hex(KEY_HEX.replace("8899", "0011"));
        byte[] plain = plain();

        Cmac cmac1 = new Cmac(new Kuznyechik());
        Cmac cmac2 = new Cmac(new Kuznyechik());
        cmac1.init(new SymmetricKey(key()));
        cmac2.init(new SymmetricKey(key2));

        cmac1.update(plain, 0, plain.length);
        cmac2.update(plain, 0, plain.length);

        byte[] out1 = new byte[16];
        byte[] out2 = new byte[16];
        cmac1.doFinal(out1, 0);
        cmac2.doFinal(out2, 0);

        assertFalse(Arrays.equals(out1, out2),
            "Разные ключи должны давать разные теги");
    }

    // -----------------------------------------------------------------------
    // 4. CMAC: граничные случаи
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CMAC: пустое сообщение — не бросает, длина тега верна")
    void testCMACEmptyMessage() {
        Cmac cmac = new Cmac(new Kuznyechik());
        cmac.init(new SymmetricKey(key()));
        cmac.update(new byte[0], 0, 0);
        byte[] result = new byte[16];
        cmac.doFinal(result, 0);

        assertEquals(16, result.length);
        // Результат не должен состоять из одних нулей
        boolean allZero = true;
        for (byte b : result) {
            if (b != 0) { allZero = false; break; }
        }
        assertFalse(allZero, "CMAC пустого сообщения не должен состоять из одних нулей");
    }

    @Test
    @DisplayName("CMAC: пустое и непустое сообщение дают разные теги")
    void testCMACEmptyDiffersFromNonEmpty() {
        Cmac cmac1 = new Cmac(new Kuznyechik());
        Cmac cmac2 = new Cmac(new Kuznyechik());
        SymmetricKey k = new SymmetricKey(key());
        cmac1.init(k);
        cmac2.init(k);

        // Пустое сообщение
        byte[] out1 = new byte[16];
        cmac1.doFinal(out1, 0);

        // Непустое сообщение
        byte[] out2 = new byte[16];
        cmac2.update(plain(), 0, plain().length);
        cmac2.doFinal(out2, 0);

        assertFalse(Arrays.equals(out1, out2),
            "CMAC пустого и непустого сообщения должны отличаться");
    }

    // -----------------------------------------------------------------------
    // 5. Совместная работа CFB + CMAC
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CFB+CMAC: обнаружение подмены байта в шифртексте")
    void testCFBCMACTamperDetection() {
        byte[] plain = plain();

        // Шифруем
        Cfb enc = new Cfb(new Kuznyechik(), 128);
        enc.init(true, new ParametersWithIV(new SymmetricKey(key()), iv()));
        byte[] ciphertext = new byte[plain.length];
        enc.processBytes(plain, 0, plain.length, ciphertext, 0);

        // Вычисляем CMAC от открытого текста
        Cmac cmac = new Cmac(new Kuznyechik(), 64);
        cmac.init(new SymmetricKey(key()));
        cmac.update(plain, 0, plain.length);
        byte[] expectedTag = new byte[8];
        cmac.doFinal(expectedTag, 0);

        // Портим байт в шифртексте
        byte[] tampered = ciphertext.clone();
        tampered[5] ^= 0x01;

        // Расшифровываем испорченный шифртекст
        Cfb dec = new Cfb(new Kuznyechik(), 128);
        dec.init(false, new ParametersWithIV(new SymmetricKey(key()), iv()));
        byte[] recovered = new byte[tampered.length];
        dec.processBytes(tampered, 0, tampered.length, recovered, 0);

        // CMAC от расшифрованных (испорченных) данных должен отличаться
        Cmac cmac2 = new Cmac(new Kuznyechik(), 64);
        cmac2.init(new SymmetricKey(key()));
        cmac2.update(recovered, 0, recovered.length);
        byte[] actualTag = new byte[8];
        cmac2.doFinal(actualTag, 0);

        assertFalse(Arrays.equals(expectedTag, actualTag),
            "Подмена байта в шифртексте должна изменить CMAC расшифрованных данных");
    }

    @Test
    @DisplayName("CFB+CMAC: корректные данные проходят проверку целостности")
    void testCFBCMACIntegrityOK() {
        byte[] plain = "Секретное сообщение для проверки".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // Вычисляем CMAC от открытого текста перед шифрованием
        Cmac cmacEnc = new Cmac(new Kuznyechik(), 64);
        cmacEnc.init(new SymmetricKey(key()));
        cmacEnc.update(plain, 0, plain.length);
        byte[] sentTag = new byte[8];
        cmacEnc.doFinal(sentTag, 0);

        // Шифруем
        Cfb enc = new Cfb(new Kuznyechik(), 128);
        enc.init(true, new ParametersWithIV(new SymmetricKey(key()), iv()));
        byte[] ciphertext = new byte[plain.length];
        enc.processBytes(plain, 0, plain.length, ciphertext, 0);

        // Расшифровываем
        Cfb dec = new Cfb(new Kuznyechik(), 128);
        dec.init(false, new ParametersWithIV(new SymmetricKey(key()), iv()));
        byte[] recovered = new byte[ciphertext.length];
        dec.processBytes(ciphertext, 0, ciphertext.length, recovered, 0);

        // Проверяем CMAC
        Cmac cmacDec = new Cmac(new Kuznyechik(), 64);
        cmacDec.init(new SymmetricKey(key()));
        cmacDec.update(recovered, 0, recovered.length);
        byte[] receivedTag = new byte[8];
        cmacDec.doFinal(receivedTag, 0);

        assertArrayEquals(sentTag, receivedTag, "CMAC должен совпасть — данные не повреждены");
        assertArrayEquals(plain, recovered, "Расшифрованный текст должен совпасть с исходным");
    }

    // -----------------------------------------------------------------------
    // 5. Граничные случаи
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("GOST3412: ошибка при неверной длине ключа")
    void testInvalidKeyLength() {
        Kuznyechik engine = new Kuznyechik();
        assertThrows(IllegalArgumentException.class,
            () -> engine.init(true, new SymmetricKey(new byte[16])),
            "Ключ длиной отличной от 32 байт должен вызывать IllegalArgumentException");
    }

    @Test
    @DisplayName("GOST3412: ошибка при обработке без инициализации")
    void testProcessBlockWithoutInit() {
        Kuznyechik engine = new Kuznyechik();
        assertThrows(IllegalStateException.class,
            () -> engine.processBlock(new byte[16], 0, new byte[16], 0),
            "Вызов processBlock без init должен вызывать IllegalStateException");
    }

    @Test
    @DisplayName("CFB: ошибка при IV короче размера блока")
    void testCFBShortIV() {
        Cfb cipher = new Cfb(new Kuznyechik(), 128);
        byte[] shortIV = new byte[8]; // меньше 16 байт
        assertThrows(IllegalArgumentException.class,
            () -> cipher.init(true, new ParametersWithIV(new SymmetricKey(key()), shortIV)),
            "IV короче блока должен вызывать IllegalArgumentException");
    }

    @Test
    @DisplayName("Название алгоритма CFB128")
    void testAlgorithmName() {
        Cfb cipher = new Cfb(new Kuznyechik(), 128);
        cipher.init(true, new ParametersWithIV(new SymmetricKey(key()), iv()));
        assertEquals("GOST3412-2015/CFB128", cipher.getAlgorithmName(),
            "Название алгоритма должно быть GOST3412-2015/CFB128");
    }

    @Test
    @DisplayName("Кузнечик: getBlockSize() == 16")
    void testBlockSize() {
        Kuznyechik engine = new Kuznyechik();
        assertEquals(16, engine.getBlockSize());
    }
}
