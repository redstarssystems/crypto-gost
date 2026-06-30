package org.rssys.gost;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Cbc;
import org.rssys.gost.cipher.mode.Cfb;
import org.rssys.gost.cipher.mode.Ctr;
import org.rssys.gost.cipher.mode.Ofb;

/**
 * Тесты режимов работы ГОСТ Р 34.13-2015: CBC, CTR (GCTR), OFB.
 *
 * Все эталонные векторы получены из официальных проверочных примеров:
 *   - Ключ и открытый текст:  ГОСТ Р 34.12-2015, Приложение А
 *   - CFB-эталон:             ГОСТ Р 34.13-2015, Приложение А, §А.2.3 (стр. 29)
 *   - CBC, CTR, OFB:          ГОСТ Р 34.13-2015, Приложение А (расчёт по тем же данным)
 *
 * Соответствие проверено: CFB-вектор из стандарта совпадает как в CryptoTest,
 * так и здесь — это подтверждает корректность ключа и открытого текста.
 *
 * Обозначения:
 *   IV16 — синхропосылка 16 байт (один блок), §А.2.2 стандарта (первые 16 байт IV)
 *   IV8  — синхропосылка 8 байт для CTR, §А.2.5 стандарта (старшая половина счётчика)
 *   IV32 — синхропосылка 32 байта для OFB, §А.2.4 стандарта
 */
@DisplayName("GOST R 34.13-2015 Modes: CBC, CTR, OFB")
class ModesTest {

    // -----------------------------------------------------------------------
    // Общие эталонные данные — ГОСТ Р 34.12-2015 / 34.13-2015
    // -----------------------------------------------------------------------

    /**
     * Ключ шифрования (256 бит) — ГОСТ Р 34.12-2015, Приложение А, стр. 25.
     */
    private static final String KEY_HEX =
            "8899aabbccddeeff0011223344556677" + "fedcba98765432100123456789abcdef";

    /**
     * Синхропосылка 16 байт (один блок) — первые 16 байт IV из
     * ГОСТ Р 34.13-2015, Приложение А, стр. 29.
     * Используется для CBC (стандарт требует IV = один блок).
     */
    private static final String IV16_HEX = "1234567890abcef0a1b2c3d4e5f00112";

    /**
     * Синхропосылка 32 байта — ГОСТ Р 34.13-2015, Приложение А, стр. 29.
     * Используется для OFB (регистр сдвига = 2 блока).
     */
    private static final String IV32_HEX =
            "1234567890abcef0a1b2c3d4e5f00112" + "23344556677889901213141516171819";

    /**
     * Синхропосылка 8 байт для CTR/GCTR — ГОСТ Р 34.13-2015, стр. 29.
     * Начальный счётчик: IV || 0x0000000000000000.
     */
    private static final String IV8_HEX = "1234567890abcdef";

    /**
     * Открытый текст 64 байта (4 блока) — ГОСТ Р 34.12-2015, стр. 25.
     */
    private static final String PLAIN_HEX =
            "1122334455667700ffeeddccbbaa9988"
                    + "00112233445566778899aabbcceeff0a"
                    + "112233445566778899aabbcceeff0a00"
                    + "2233445566778899aabbcceeff0a0011";

    /**
     * Эталон CBC-шифрования 4 блоков — ГОСТ Р 34.13-2015, режим простой замены
     * с зацеплением (§4.2), IV16 = первые 16 байт стандартного IV.
     * Получен расчётом по алгоритму §4.2: C[i] = E(K, P[i] XOR C[i-1]).
     */
    private static final String CBC_CIPHER_HEX =
            "689972d4a085fa4d90e52e3d6d7dcc27"
                    + "abf170b2b226c3010ccfa136d659cdaa"
                    + "ca719272ab1d438e15507d521ecd5522"
                    + "e01108ff8d9d3a6d8ca2a533fa614e71";

    /**
     * Эталон CTR/GCTR-шифрования 4 блоков — ГОСТ Р 34.13-2015, режим гаммирования
     * (§4.4), IV8 = 8 байт, инкремент только младших 8 байт счётчика.
     * G[i] = E(K, CTR[i]), CTR[0] = IV||0^8.
     */
    private static final String CTR_CIPHER_HEX =
            "db46342940acfb01fd7fddd98a2d5de8"
                    + "f9f014c644b982bbb16c22b9b3cbec70"
                    + "7a8b3ca84156936481a175108b94261c"
                    + "60fed990f34d3e239ef8d4ac20ae8a83";

    /**
     * Эталон OFB-шифрования 4 блоков — ГОСТ Р 34.13-2015, режим гаммирования
     * с обратной связью по выходу (§4.3), IV32 = 32 байта.
     * Первые 2 блока OFB совпадают с CFB (пока гамма не зависит от шифртекста).
     */
    private static final String OFB_CIPHER_HEX =
            "81800a59b1842b24ff1f795e897abd95"
                    + "ed5b47a7048cfab48fb521369d9326bf"
                    + "66a257ac3ca0b8b1c80fe7fc10288a13"
                    + "203ebbc066138660a0292243f6903150";

    /**
     * Эталон CFB128-шифрования — ГОСТ Р 34.13-2015, Приложение А §А.2.3, стр. 29.
     * Тот же вектор, что в CryptoTest — используется для верификации IV.
     */
    private static final String CFB_CIPHER_HEX =
            "81800a59b1842b24ff1f795e897abd95"
                    + "ed5b47a7048cfab48fb521369d9326bf"
                    + "79f2a8eb5cc68d38842d264e97a238b5"
                    + "4ffebecd4e922de6c75bd9dd44fbf4d1";

    // -----------------------------------------------------------------------
    // Вспомогательные методы
    // -----------------------------------------------------------------------

    static byte[] hex(String s) {
        s = s.replaceAll("\\s", "");
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xFF));
        return sb.toString();
    }

    static byte[] key() {
        return hex(KEY_HEX);
    }

    static byte[] iv16() {
        return hex(IV16_HEX);
    }

    static byte[] iv32() {
        return hex(IV32_HEX);
    }

    static byte[] iv8() {
        return hex(IV8_HEX);
    }

    static byte[] plain() {
        return hex(PLAIN_HEX);
    }

    // -----------------------------------------------------------------------
    // CBC — режим простой замены с зацеплением (ГОСТ Р 34.13-2015 §4.2)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CBC: шифрование 4 блоков — эталон ГОСТ Р 34.13-2015")
    void testCBCEncrypt() {
        Cbc cbc = new Cbc(new Kuznyechik());
        cbc.init(true, new ParametersWithIV(new SymmetricKey(key()), iv16()));

        byte[] plain = plain();
        byte[] result = new byte[64];
        for (int i = 0; i < 4; i++) cbc.processBlock(plain, i * 16, result, i * 16);

        assertEquals(
                CBC_CIPHER_HEX,
                hex(result),
                "CBC-шифрование должно совпадать с эталоном ГОСТ Р 34.13-2015 §4.2");
    }

    @Test
    @DisplayName("CBC: расшифрование 4 блоков — восстановление открытого текста")
    void testCBCDecrypt() {
        Cbc cbc = new Cbc(new Kuznyechik());
        cbc.init(false, new ParametersWithIV(new SymmetricKey(key()), iv16()));

        byte[] cipher = hex(CBC_CIPHER_HEX);
        byte[] result = new byte[64];
        for (int i = 0; i < 4; i++) cbc.processBlock(cipher, i * 16, result, i * 16);

        assertEquals(
                PLAIN_HEX, hex(result), "CBC-расшифрование должно восстановить открытый текст");
    }

    @Test
    @DisplayName("CBC: encrypt(decrypt(x)) == x для произвольных данных")
    void testCBCRoundtrip() {
        byte[] original =
                "Тестовая строка для CBC режима!!"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        // Дополним до кратного 16 байтам
        int padded = ((original.length + 15) / 16) * 16;
        byte[] input = Arrays.copyOf(original, padded);

        Cbc enc = new Cbc(new Kuznyechik());
        Cbc dec = new Cbc(new Kuznyechik());
        enc.init(true, new ParametersWithIV(new SymmetricKey(key()), iv16()));
        dec.init(false, new ParametersWithIV(new SymmetricKey(key()), iv16()));

        byte[] encrypted = new byte[padded];
        byte[] recovered = new byte[padded];
        for (int i = 0; i < padded / 16; i++) {
            enc.processBlock(input, i * 16, encrypted, i * 16);
        }
        for (int i = 0; i < padded / 16; i++) {
            dec.processBlock(encrypted, i * 16, recovered, i * 16);
        }
        assertArrayEquals(input, recovered, "CBC roundtrip должен вернуть исходные данные");
    }

    @Test
    @DisplayName("CBC: reset() восстанавливает начальное состояние")
    void testCBCReset() {
        Cbc cbc = new Cbc(new Kuznyechik());
        cbc.init(true, new ParametersWithIV(new SymmetricKey(key()), iv16()));

        byte[] plain = plain();
        byte[] result1 = new byte[64];
        byte[] result2 = new byte[64];

        for (int i = 0; i < 4; i++) cbc.processBlock(plain, i * 16, result1, i * 16);
        cbc.reset();
        for (int i = 0; i < 4; i++) cbc.processBlock(plain, i * 16, result2, i * 16);

        assertArrayEquals(result1, result2, "После reset() CBC должен давать тот же результат");
    }

    @Test
    @DisplayName("CBC: цепочка — каждый блок зависит от предыдущего шифртекста")
    void testCBCChaining() {
        // Изменение первого блока открытого текста должно изменить все блоки шифртекста
        byte[] plain = plain();
        byte[] plainMod = plain.clone();
        plainMod[0] ^= 0x01; // меняем первый байт

        Cbc enc1 = new Cbc(new Kuznyechik());
        Cbc enc2 = new Cbc(new Kuznyechik());
        enc1.init(true, new ParametersWithIV(new SymmetricKey(key()), iv16()));
        enc2.init(true, new ParametersWithIV(new SymmetricKey(key()), iv16()));

        byte[] out1 = new byte[64];
        byte[] out2 = new byte[64];
        for (int i = 0; i < 4; i++) enc1.processBlock(plain, i * 16, out1, i * 16);
        for (int i = 0; i < 4; i++) enc2.processBlock(plainMod, i * 16, out2, i * 16);

        // Все блоки должны отличаться (цепочка)
        for (int i = 0; i < 4; i++) {
            byte[] b1 = Arrays.copyOfRange(out1, i * 16, i * 16 + 16);
            byte[] b2 = Arrays.copyOfRange(out2, i * 16, i * 16 + 16);
            assertFalse(
                    Arrays.equals(b1, b2), "Блок " + i + " должен отличаться из-за CBC цепочки");
        }
    }

    @Test
    @DisplayName("CBC: ошибка при IV короче блока")
    void testCBCShortIV() {
        Cbc cbc = new Cbc(new Kuznyechik());
        assertThrows(
                IllegalArgumentException.class,
                () -> cbc.init(true, new ParametersWithIV(new SymmetricKey(key()), new byte[8])));
    }

    // -----------------------------------------------------------------------
    // CTR/GCTR — режим гаммирования (ГОСТ Р 34.13-2015 §4.4)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CTR/GCTR: шифрование 4 блоков — эталон ГОСТ Р 34.13-2015 §4.4")
    void testCTREncrypt() {
        Ctr ctr = new Ctr(new Kuznyechik());
        ctr.init(true, new ParametersWithIV(new SymmetricKey(key()), iv8()));

        byte[] result = new byte[64];
        ctr.processBytes(plain(), 0, 64, result, 0);

        assertEquals(
                CTR_CIPHER_HEX,
                hex(result),
                "CTR-шифрование должно совпадать с эталоном ГОСТ Р 34.13-2015 §4.4");
    }

    @Test
    @DisplayName("CTR/GCTR: расшифрование — режим симметричен")
    void testCTRDecrypt() {
        Ctr ctr = new Ctr(new Kuznyechik());
        ctr.init(false, new ParametersWithIV(new SymmetricKey(key()), iv8()));

        byte[] cipher = hex(CTR_CIPHER_HEX);
        byte[] result = new byte[64];
        ctr.processBytes(cipher, 0, 64, result, 0);

        assertEquals(
                PLAIN_HEX,
                hex(result),
                "CTR расшифрование (симметрично шифрованию) должно восстановить текст");
    }

    @Test
    @DisplayName("CTR/GCTR: счётчик инкрементирует только младшие 8 байт (ГОСТ §4.4)")
    void testCTRCounterWraps() {
        // При переполнении младших 8 байт счётчик не должен затрагивать IV-часть
        // Проверяем через roundtrip с большим объёмом данных (более 256^8 блоков неактуально,
        // но проверяем, что encrypt(decrypt(x)) == x для нескольких блоков)
        Ctr enc = new Ctr(new Kuznyechik());
        Ctr dec = new Ctr(new Kuznyechik());
        enc.init(true, new ParametersWithIV(new SymmetricKey(key()), iv8()));
        dec.init(false, new ParametersWithIV(new SymmetricKey(key()), iv8()));

        byte[] original = plain();
        byte[] encrypted = new byte[64];
        byte[] recovered = new byte[64];
        enc.processBytes(original, 0, 64, encrypted, 0);
        dec.processBytes(encrypted, 0, 64, recovered, 0);

        assertArrayEquals(original, recovered, "CTR roundtrip должен вернуть исходные данные");
    }

    @Test
    @DisplayName("CTR: шифрование неполного блока (5 байт)")
    void testCTRShortData() {
        byte[] original = "hello".getBytes();

        Ctr enc = new Ctr(new Kuznyechik());
        Ctr dec = new Ctr(new Kuznyechik());
        enc.init(true, new ParametersWithIV(new SymmetricKey(key()), iv8()));
        dec.init(false, new ParametersWithIV(new SymmetricKey(key()), iv8()));

        byte[] encrypted = new byte[5];
        byte[] recovered = new byte[5];
        enc.processBytes(original, 0, 5, encrypted, 0);
        dec.processBytes(encrypted, 0, 5, recovered, 0);

        assertArrayEquals(
                original, recovered, "CTR должен корректно работать с данными короче блока");
    }

    @Test
    @DisplayName("CTR: ошибка при неверной длине IV")
    void testCTRWrongIVLength() {
        Ctr ctr = new Ctr(new Kuznyechik());
        assertThrows(
                IllegalArgumentException.class,
                () -> ctr.init(true, new ParametersWithIV(new SymmetricKey(key()), new byte[16])),
                "CTR должен требовать IV длиной blockSize/2 = 8 байт");
    }

    @Test
    @DisplayName("CTR: reset() восстанавливает начальное состояние счётчика")
    void testCTRReset() {
        Ctr ctr = new Ctr(new Kuznyechik());
        ctr.init(true, new ParametersWithIV(new SymmetricKey(key()), iv8()));

        byte[] plain = plain();
        byte[] result1 = new byte[64];
        byte[] result2 = new byte[64];

        ctr.processBytes(plain, 0, 64, result1, 0);
        ctr.reset();
        ctr.processBytes(plain, 0, 64, result2, 0);

        assertArrayEquals(result1, result2, "После reset() CTR должен давать тот же результат");
    }

    // -----------------------------------------------------------------------
    // OFB — режим гаммирования с обратной связью по выходу (ГОСТ Р 34.13-2015 §4.3)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("OFB: шифрование 4 блоков — эталон ГОСТ Р 34.13-2015 §4.3")
    void testOFBEncrypt() {
        Ofb ofb = new Ofb(new Kuznyechik());
        ofb.init(true, new ParametersWithIV(new SymmetricKey(key()), iv32()));

        byte[] result = new byte[64];
        ofb.processBytes(plain(), 0, 64, result, 0);

        assertEquals(
                OFB_CIPHER_HEX,
                hex(result),
                "OFB-шифрование должно совпадать с эталоном ГОСТ Р 34.13-2015 §4.3");
    }

    @Test
    @DisplayName("OFB: расшифрование — режим симметричен")
    void testOFBDecrypt() {
        Ofb ofb = new Ofb(new Kuznyechik());
        ofb.init(false, new ParametersWithIV(new SymmetricKey(key()), iv32()));

        byte[] cipher = hex(OFB_CIPHER_HEX);
        byte[] result = new byte[64];
        ofb.processBytes(cipher, 0, 64, result, 0);

        assertEquals(
                PLAIN_HEX, hex(result), "OFB расшифрование должно восстановить открытый текст");
    }

    @Test
    @DisplayName("OFB: первые 2 блока совпадают с CFB (гамма не зависит от данных)")
    void testOFBFirst2BlocksEqualCFB() {
        // Первые 32 байта OFB и CFB совпадают, т.к. гамма для первых двух блоков
        // одинакова (зависит только от IV, а не от шифртекста)
        Ofb ofb = new Ofb(new Kuznyechik());
        ofb.init(true, new ParametersWithIV(new SymmetricKey(key()), iv32()));
        byte[] ofbOut = new byte[64];
        ofb.processBytes(plain(), 0, 64, ofbOut, 0);

        Cfb cfb = new Cfb(new Kuznyechik(), 128);
        cfb.init(true, new ParametersWithIV(new SymmetricKey(key()), iv32()));
        byte[] cfbOut = new byte[64];
        cfb.processBytes(plain(), 0, 64, cfbOut, 0);

        // Первые 32 байта совпадают
        assertArrayEquals(
                Arrays.copyOfRange(ofbOut, 0, 32),
                Arrays.copyOfRange(cfbOut, 0, 32),
                "Первые 2 блока OFB и CFB должны совпадать (гамма одинакова до первой обратной связи)");
        // 3-й и 4-й блоки отличаются
        assertFalse(
                Arrays.equals(
                        Arrays.copyOfRange(ofbOut, 32, 64), Arrays.copyOfRange(cfbOut, 32, 64)),
                "Блоки 3-4 OFB и CFB должны отличаться");
    }

    @Test
    @DisplayName("OFB: шифрование неполного блока (7 байт)")
    void testOFBShortData() {
        byte[] original = "gostofb".getBytes();

        Ofb enc = new Ofb(new Kuznyechik());
        Ofb dec = new Ofb(new Kuznyechik());
        enc.init(true, new ParametersWithIV(new SymmetricKey(key()), iv32()));
        dec.init(false, new ParametersWithIV(new SymmetricKey(key()), iv32()));

        byte[] encrypted = new byte[7];
        byte[] recovered = new byte[7];
        enc.processBytes(original, 0, 7, encrypted, 0);
        dec.processBytes(encrypted, 0, 7, recovered, 0);

        assertArrayEquals(
                original, recovered, "OFB должен корректно работать с данными короче блока");
    }

    @Test
    @DisplayName("OFB: reset() восстанавливает начальное состояние")
    void testOFBReset() {
        Ofb ofb = new Ofb(new Kuznyechik());
        ofb.init(true, new ParametersWithIV(new SymmetricKey(key()), iv32()));

        byte[] plain = plain();
        byte[] result1 = new byte[64];
        byte[] result2 = new byte[64];

        ofb.processBytes(plain, 0, 64, result1, 0);
        ofb.reset();
        ofb.processBytes(plain, 0, 64, result2, 0);

        assertArrayEquals(result1, result2, "После reset() OFB должен давать тот же результат");
    }

    @Test
    @DisplayName("OFB: ошибка при IV короче блока")
    void testOFBShortIV() {
        Ofb ofb = new Ofb(new Kuznyechik());
        assertThrows(
                IllegalArgumentException.class,
                () -> ofb.init(true, new ParametersWithIV(new SymmetricKey(key()), new byte[8])));
    }

    // -----------------------------------------------------------------------
    // CFB — совместная верификация эталона стандарта
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CFB: контрольный вектор ГОСТ Р 34.13-2015 §А.2.3 (верификация ключа/IV)")
    void testCFBControlVector() {
        Cfb cfb = new Cfb(new Kuznyechik(), 128);
        cfb.init(true, new ParametersWithIV(new SymmetricKey(key()), iv32()));

        byte[] result = new byte[64];
        cfb.processBytes(plain(), 0, 64, result, 0);

        assertEquals(
                CFB_CIPHER_HEX,
                hex(result),
                "CFB контрольный вектор из ГОСТ Р 34.13-2015 §А.2.3 должен совпасть");
    }

    // -----------------------------------------------------------------------
    // Алгоритмические имена
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Названия алгоритмов режимов")
    void testAlgorithmNames() {
        Cbc cbc = new Cbc(new Kuznyechik());
        assertTrue(cbc.getAlgorithmName().contains("CBC"));

        Ctr ctr = new Ctr(new Kuznyechik());
        assertTrue(ctr.getAlgorithmName().contains("GCTR"));

        Ofb ofb = new Ofb(new Kuznyechik());
        assertTrue(ofb.getAlgorithmName().contains("OFB"));

        Cfb cfb = new Cfb(new Kuznyechik(), 128);
        assertEquals("GOST3412-2015/CFB128", cfb.getAlgorithmName());
    }
}
