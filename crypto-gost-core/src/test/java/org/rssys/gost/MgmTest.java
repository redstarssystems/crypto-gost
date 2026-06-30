package org.rssys.gost;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.cipher.mode.Mgm;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * Тесты Mgm — низкоуровневая реализация.
 * <p>
 * Тестовые векторы: RFC 9058 Appendix A.1 (Кузнечик, примеры 1 и 2).
 * <p>
 * Примечание по ICN:
 * RFC 9058 §3 определяет ICN ∈ V_{n-1} — (n-1)-битная строка.
 * Для Кузнечика n=128, ICN = 127 бит, хранится в 16 байтах с нулём в старшем бите.
 * Конструкция «0^1 || ICN» означает использовать ICN как есть (MSB=0 уже установлен).
 * Конструкция «1^1 || ICN» означает выставить старший бит в 1.
 */
@DisplayName("MGM — RFC 9058 тестовые векторы (Кузнечик)")
class MgmTest {

    // -----------------------------------------------------------------------
    // RFC 9058 A.1.1 — Кузнечик, пример 1
    // -----------------------------------------------------------------------

    // Ключ K (32 байта) — RFC 9058 A.1.1
    private static final byte[] K1 =
            h("8899AABBCCDDEEFF00112233445566" + "77FEDCBA98765432100123456789AB" + "CDEF");

    // ICN (16 байт) — RFC 9058 A.1.1; MSB = 0 (0x11 = 0b00010001 -> ok)
    private static final byte[] ICN1 = h("1122334455667700FFEEDDCCBBAA9988");

    // AAD (41 байт) — RFC 9058 A.1.1
    // 00000: 02 02 02 02 02 02 02 02  01 01 01 01 01 01 01 01
    // 00010: 04 04 04 04 04 04 04 04  03 03 03 03 03 03 03 03
    // 00020: EA 05 05 05 05 05 05 05 05
    private static final byte[] AAD1 =
            h(
                    "0202020202020202"
                            + "0101010101010101"
                            + "0404040404040404"
                            + "0303030303030303"
                            + "EA0505050505050505");

    // Plaintext (67 байт) — RFC 9058 A.1.1
    private static final byte[] PT1 =
            h(
                    "1122334455667700"
                            + "FFEEDDCCBBAA9988"
                            + "0011223344556677"
                            + "8899AABBCCEEFF0A"
                            + "1122334455667788"
                            + "99AABBCCEEFF0A00"
                            + "2233445566778899"
                            + "AABBCCEEFF0A0011"
                            + "AABBCC");

    // Шифртекст C (67 байт) — RFC 9058 A.1.1
    private static final byte[] CT1 =
            h(
                    "A9757B8147956E90"
                            + "55B8A33DE89F42FC"
                            + "8075D2212BF9FD5B"
                            + "D3F7069AADC16B39"
                            + "497AB15915A6BA85"
                            + "936B5D0EA9F6851C"
                            + "C60C14D4D3F883D0"
                            + "AB944206"
                            + "95C76DEB"
                            + "2C7552");

    // Тег T (16 байт) — RFC 9058 A.1.1
    private static final byte[] TAG1 = h("CF5D656F40C34F5C46E8BB0E29FCDB4C");

    @Test
    @DisplayName("RFC 9058 A.1.1: шифртекст совпадает с эталоном")
    void testRfc9058Example1Ciphertext() {
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(new SymmetricKey(K1), ICN1));
        mgm.updateAAD(AAD1, 0, AAD1.length);
        byte[] ct = new byte[PT1.length];
        mgm.processBytes(PT1, 0, PT1.length, ct, 0);
        assertArrayEquals(CT1, ct, "Шифртекст должен совпадать с RFC 9058 A.1.1");
    }

    @Test
    @DisplayName("RFC 9058 A.1.1: тег совпадает с эталоном")
    void testRfc9058Example1Tag() {
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(new SymmetricKey(K1), ICN1));
        mgm.updateAAD(AAD1, 0, AAD1.length);
        byte[] ct = new byte[PT1.length];
        mgm.processBytes(PT1, 0, PT1.length, ct, 0);
        byte[] tag = new byte[16];
        mgm.finishEncryption(tag, 0);
        assertArrayEquals(TAG1, tag, "Тег должен совпадать с RFC 9058 A.1.1");
    }

    @Test
    @DisplayName("RFC 9058 A.1.1: расшифрование и верификация тега")
    void testRfc9058Example1Decryption() throws AuthenticationException {
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(false, new ParametersWithIV(new SymmetricKey(K1), ICN1));
        mgm.updateAAD(AAD1, 0, AAD1.length);
        byte[] pt = new byte[CT1.length];
        mgm.processBytes(CT1, 0, CT1.length, pt, 0);
        assertDoesNotThrow(() -> mgm.finishDecryption(TAG1, 0));
        assertArrayEquals(PT1, pt, "Открытый текст должен совпасть с оригиналом RFC 9058 A.1.1");
    }

    // -----------------------------------------------------------------------
    // RFC 9058 A.1.2 — Кузнечик, пример 2 (пустой plaintext)
    // -----------------------------------------------------------------------

    private static final byte[] K2 =
            h("99AABBCCDDEEFF001122334455667" + "7FEDCBA98765432100123456789AB" + "CDEF88");

    // ICN2 (16 байт) — RFC 9058 A.1.2; MSB = 0 (0x11 = 0b00010001 -> ok)
    private static final byte[] ICN2 = h("1122334455667700FFEEDDCCBBAA9988");

    // AAD (16 байт) — RFC 9058 A.1.2
    private static final byte[] AAD2 = h("01010101010101010101010101010101");

    // Тег T (16 байт) — RFC 9058 A.1.2
    private static final byte[] TAG2 = h("7901E9EA2085CD247ED249695F9F8A85");

    @Test
    @DisplayName("RFC 9058 A.1.2: тег для пустого plaintext совпадает с эталоном")
    void testRfc9058Example2Tag() {
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(new SymmetricKey(K2), ICN2));
        mgm.updateAAD(AAD2, 0, AAD2.length);
        byte[] tag = new byte[16];
        mgm.finishEncryption(tag, 0);
        assertArrayEquals(TAG2, tag, "Тег для пустого PT должен совпадать с RFC 9058 A.1.2");
    }

    @Test
    @DisplayName("RFC 9058 A.1.2: верификация тега для пустого plaintext")
    void testRfc9058Example2Verify() {
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(false, new ParametersWithIV(new SymmetricKey(K2), ICN2));
        mgm.updateAAD(AAD2, 0, AAD2.length);
        assertDoesNotThrow(() -> mgm.finishDecryption(TAG2, 0));
    }

    // -----------------------------------------------------------------------
    // Тесты GF(2^128) умножения
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("gf128Mul: X * 0 = 0")
    void testGf128MulByZero() {
        byte[] x16 = h("8899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899");
        byte[] x = java.util.Arrays.copyOf(x16, 16);
        byte[] zero = new byte[16];
        assertArrayEquals(zero, Mgm.gf128Mul(x, zero));
    }

    @Test
    @DisplayName("gf128Mul: коммутативность X*Y == Y*X")
    void testGf128MulCommutative() {
        byte[] xFull = h("8899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");
        byte[] yFull = h("FFEEDDCCBBAA998877665544332211000F0E0D0C0B0A090807060504030201FF");
        byte[] x = java.util.Arrays.copyOf(xFull, 16);
        byte[] y = java.util.Arrays.copyOf(yFull, 16);
        byte[] xy = Mgm.gf128Mul(java.util.Arrays.copyOf(x, 16), java.util.Arrays.copyOf(y, 16));
        byte[] yx = Mgm.gf128Mul(java.util.Arrays.copyOf(y, 16), java.util.Arrays.copyOf(x, 16));
        assertArrayEquals(xy, yx, "GF(2^128) умножение должно быть коммутативным");
    }

    @Test
    @DisplayName("gf128Mul: X * X вычисляется детерминированно")
    void testGf128MulSquareDeterministic() {
        byte[] xFull = h("8899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788");
        byte[] x = java.util.Arrays.copyOf(xFull, 16);
        byte[] sq1 = Mgm.gf128Mul(java.util.Arrays.copyOf(x, 16), java.util.Arrays.copyOf(x, 16));
        byte[] sq2 = Mgm.gf128Mul(java.util.Arrays.copyOf(x, 16), java.util.Arrays.copyOf(x, 16));
        assertArrayEquals(sq1, sq2, "X^2 должен быть детерминированным");
    }

    @Test
    @DisplayName("gf128Mul: нейтральный элемент — X * 1 = X")
    void testGf128MulByOne() {
        byte[] x = java.util.Arrays.copyOf(h("8899AABBCCDDEEFF0011223344556677"), 16);
        byte[] one = new byte[16];
        one[15] = 1; // w^0 = 1 в big-endian
        assertArrayEquals(
                x, Mgm.gf128Mul(java.util.Arrays.copyOf(x, 16), one), "X * 1 должен равняться X");
    }

    @Test
    @DisplayName("gf128Mul: дистрибутивность X*(Y^Z) == X*Y ^ X*Z")
    void testGf128MulDistributive() {
        byte[] x = java.util.Arrays.copyOf(h("8899AABBCCDDEEFF0011223344556677"), 16);
        byte[] y = java.util.Arrays.copyOf(h("FFEEDDCCBBAA99887766554433221100"), 16);
        byte[] z = java.util.Arrays.copyOf(h("0F0E0D0C0B0A09080706050403020100"), 16);
        byte[] yz = new byte[16];
        for (int i = 0; i < 16; i++) yz[i] = (byte) (y[i] ^ z[i]);
        byte[] lhs = Mgm.gf128Mul(java.util.Arrays.copyOf(x, 16), yz);
        byte[] xy = Mgm.gf128Mul(java.util.Arrays.copyOf(x, 16), java.util.Arrays.copyOf(y, 16));
        byte[] xz = Mgm.gf128Mul(java.util.Arrays.copyOf(x, 16), java.util.Arrays.copyOf(z, 16));
        byte[] rhs = new byte[16];
        for (int i = 0; i < 16; i++) rhs[i] = (byte) (xy[i] ^ xz[i]);
        assertArrayEquals(lhs, rhs, "GF(2^128) должен быть дистрибутивен: X*(Y^Z) == X*Y ^ X*Z");
    }

    // -----------------------------------------------------------------------
    // Roundtrip-тесты
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Roundtrip с AAD: encrypt + decrypt восстанавливает данные")
    void testRoundtrip() throws AuthenticationException {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] aad = "ассоциированные данные".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] data = "тест MGM Кузнечик".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F; // MSB = 0
        SymmetricKey kp = new SymmetricKey(key);

        Mgm enc = new Mgm(new Kuznyechik());
        enc.init(true, new ParametersWithIV(kp, icn));
        enc.updateAAD(aad, 0, aad.length);
        byte[] ct = new byte[data.length];
        enc.processBytes(data, 0, data.length, ct, 0);
        byte[] tag = new byte[16];
        enc.finishEncryption(tag, 0);

        Mgm dec = new Mgm(new Kuznyechik());
        dec.init(false, new ParametersWithIV(kp, icn));
        dec.updateAAD(aad, 0, aad.length);
        byte[] pt = new byte[ct.length];
        dec.processBytes(ct, 0, ct.length, pt, 0);
        dec.finishDecryption(tag, 0);

        assertArrayEquals(data, pt);
    }

    @Test
    @DisplayName("Roundtrip без AAD: корректно работает")
    void testRoundtripNoAad() throws AuthenticationException {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] data = new byte[64];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        Mgm enc = new Mgm(new Kuznyechik());
        enc.init(true, new ParametersWithIV(kp, icn));
        byte[] ct = new byte[data.length];
        enc.processBytes(data, 0, data.length, ct, 0);
        byte[] tag = new byte[16];
        enc.finishEncryption(tag, 0);

        Mgm dec = new Mgm(new Kuznyechik());
        dec.init(false, new ParametersWithIV(kp, icn));
        byte[] pt = new byte[ct.length];
        dec.processBytes(ct, 0, ct.length, pt, 0);
        dec.finishDecryption(tag, 0);
        assertArrayEquals(data, pt);
    }

    @Test
    @DisplayName("Неверный тег: finishDecryption бросает AuthenticationException")
    void testInvalidTag() {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] data = "данные".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        SymmetricKey kp = new SymmetricKey(key);

        Mgm enc = new Mgm(new Kuznyechik());
        enc.init(true, new ParametersWithIV(kp, icn));
        byte[] ct = new byte[data.length];
        enc.processBytes(data, 0, data.length, ct, 0);
        byte[] tag = new byte[16];
        enc.finishEncryption(tag, 0);
        tag[0] ^= 0xFF;

        Mgm dec = new Mgm(new Kuznyechik());
        dec.init(false, new ParametersWithIV(kp, icn));
        byte[] pt = new byte[ct.length];
        dec.processBytes(ct, 0, ct.length, pt, 0);
        assertThrows(AuthenticationException.class, () -> dec.finishDecryption(tag, 0));
    }

    @Test
    @DisplayName("reset(): повторное шифрование даёт тот же результат")
    void testReset() {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(kp, icn));

        byte[] ct1 = new byte[data.length];
        byte[] tag1 = new byte[16];
        mgm.processBytes(data, 0, data.length, ct1, 0);
        mgm.finishEncryption(tag1, 0);

        //        mgm.reset();

        mgm.init(true, new ParametersWithIV(kp, icn));
        byte[] ct2 = new byte[data.length];
        byte[] tag2 = new byte[16];
        mgm.processBytes(data, 0, data.length, ct2, 0);
        mgm.finishEncryption(tag2, 0);

        assertArrayEquals(ct1, ct2, "После reset шифртекст должен совпасть");
        assertArrayEquals(tag1, tag2, "После reset тег должен совпасть");
    }

    // -----------------------------------------------------------------------
    // Тесты reinitICN
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("reinitICN: encrypt с тем же ICN даёт тот же CT+tag что init")
    void reinitICN_sameIcn_matchesInit() {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(kp, icn));

        byte[] ct1 = new byte[data.length];
        byte[] tag1 = new byte[16];
        mgm.processBytes(data, 0, data.length, ct1, 0);
        mgm.finishEncryption(tag1, 0);

        // reinitICN с тем же ICN — переинициализация счётчиков
        mgm.reinitICN(icn);
        byte[] ct2 = new byte[data.length];
        byte[] tag2 = new byte[16];
        mgm.processBytes(data, 0, data.length, ct2, 0);
        mgm.finishEncryption(tag2, 0);

        assertArrayEquals(ct1, ct2, "CT должен совпасть после reinitICN с тем же ICN");
        assertArrayEquals(tag1, tag2, "Tag должен совпасть после reinitICN с тем же ICN");
    }

    @Test
    @DisplayName("reinitICN: другой ICN -> другой шифртекст")
    void reinitICN_differentIcn_producesDifferentOutput() {
        byte[] key = new byte[32];
        byte[] icn1 = new byte[16];
        byte[] icn2 = new byte[16];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn1);
        icn1[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(icn2);
        icn2[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(kp, icn1));

        byte[] ct = new byte[data.length];
        byte[] tag = new byte[16];
        mgm.processBytes(data, 0, data.length, ct, 0);
        mgm.finishEncryption(tag, 0);

        mgm.reinitICN(icn2);
        byte[] ctDiff = new byte[data.length];
        byte[] tagDiff = new byte[16];
        mgm.processBytes(data, 0, data.length, ctDiff, 0);
        mgm.finishEncryption(tagDiff, 0);

        assertFalse(java.util.Arrays.equals(ct, ctDiff), "Другой ICN должен дать другой шифртекст");
        assertFalse(java.util.Arrays.equals(tag, tagDiff), "Другой ICN должен дать другой тег");
    }

    @Test
    @DisplayName("reinitICN: расшифрование работает после reinitICN")
    void reinitICN_decrypt_roundtrip() throws AuthenticationException {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        // Шифруем init-ом
        Mgm enc = new Mgm(new Kuznyechik());
        enc.init(true, new ParametersWithIV(kp, icn));
        byte[] ct = new byte[data.length];
        byte[] tag = new byte[16];
        enc.processBytes(data, 0, data.length, ct, 0);
        enc.finishEncryption(tag, 0);

        // Расшифровываем через init + reinitICN
        Mgm dec = new Mgm(new Kuznyechik());
        dec.init(false, new ParametersWithIV(kp, icn));
        dec.reinitICN(icn);
        byte[] pt = new byte[ct.length];
        dec.processBytes(ct, 0, ct.length, pt, 0);
        dec.finishDecryption(tag, 0);

        assertArrayEquals(data, pt, "Расшифрование после reinitICN должно восстановить PT");
    }

    @Test
    @DisplayName("reinitICN после finishEncryption: новый encrypt работает")
    void reinitICN_afterFinishEncryption() throws AuthenticationException {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(kp, icn));

        byte[] ct1 = new byte[data.length];
        byte[] tag1 = new byte[16];
        mgm.processBytes(data, 0, data.length, ct1, 0);
        mgm.finishEncryption(tag1, 0);

        // finishEncryption поставил finished=true.
        // reinitICN должен сбросить finished в false.
        mgm.reinitICN(icn);
        byte[] ct2 = new byte[data.length];
        byte[] tag2 = new byte[16];
        mgm.processBytes(data, 0, data.length, ct2, 0);
        mgm.finishEncryption(tag2, 0);

        assertArrayEquals(ct1, ct2, "Повторный encrypt после reinitICN должен работать");
    }

    @Test
    @DisplayName("reinitICN после finishDecryption: decrypt + подмена тега ловится")
    void reinitICN_afterFinishDecryption() throws AuthenticationException {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        // Шифруем init-ом
        Mgm enc = new Mgm(new Kuznyechik());
        enc.init(true, new ParametersWithIV(kp, icn));
        byte[] ct = new byte[data.length];
        byte[] tag = new byte[16];
        enc.processBytes(data, 0, data.length, ct, 0);
        enc.finishEncryption(tag, 0);

        // Один Mgm — decrypt, finishDecryption, reinitICN, повторный decrypt
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(false, new ParametersWithIV(kp, icn));

        byte[] pt1 = new byte[ct.length];
        mgm.processBytes(ct, 0, ct.length, pt1, 0);
        mgm.finishDecryption(tag, 0);
        assertArrayEquals(data, pt1, "Первый decrypt должен работать");

        // finishDecryption поставил finished=true, sum/aadBitLen/ctBitLen заполнены.
        // reinitICN должен сбросить ВСЁ per-message состояние.
        mgm.reinitICN(icn);

        // Повторный decrypt с правильным тегом — должен работать
        byte[] pt2 = new byte[ct.length];
        mgm.processBytes(ct, 0, ct.length, pt2, 0);
        mgm.finishDecryption(tag, 0);
        assertArrayEquals(data, pt2, "Повторный decrypt после reinitICN должен работать");

        // Сброс и повторный decrypt с ПОДМЕНЁННЫМ тегом — AuthenticationException
        // Это доказывает что sum/aadBitLen/ctBitLen реально сброшены, а не просто
        // не мешают decrypt-у (иначе подмена tag-а могла бы пройти молча).
        mgm.reinitICN(icn);
        byte[] pt3 = new byte[ct.length];
        mgm.processBytes(ct, 0, ct.length, pt3, 0);
        byte[] tampered = tag.clone();
        tampered[0] ^= 0xFF;
        assertThrows(
                AuthenticationException.class,
                () -> mgm.finishDecryption(tampered, 0),
                "Подменённый тег после reinitICN должен вызывать AuthenticationException");
    }

    @Test
    @DisplayName("reinitICN после failed decrypt: hot path TLS при повреждённой записи")
    void reinitICN_afterFailedDecrypt() throws AuthenticationException {
        // Hot path TLS: Mgm переиспользуется через reinitICN на каждую запись.
        // Если запись повреждена (тег не совпал), следующий reinitICN должен
        // восстановить состояние для корректной обработки следующей записи.
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        // Шифруем — получаем эталонный CT+tag
        Mgm enc = new Mgm(new Kuznyechik());
        enc.init(true, new ParametersWithIV(kp, icn));
        byte[] ct = new byte[data.length];
        byte[] tag = new byte[16];
        enc.processBytes(data, 0, data.length, ct, 0);
        enc.finishEncryption(tag, 0);

        // dec1 — первая запись, повреждённый тег -> fail
        Mgm dec = new Mgm(new Kuznyechik());
        dec.init(false, new ParametersWithIV(kp, icn));
        byte[] pt1 = new byte[ct.length];
        dec.processBytes(ct, 0, ct.length, pt1, 0);
        byte[] badTag = tag.clone();
        badTag[0] ^= 0xFF;
        assertThrows(
                AuthenticationException.class,
                () -> dec.finishDecryption(badTag, 0),
                "Повреждённый тег должен вызывать AuthenticationException");

        // reinitICN с тем же ICN — эмуляция следующей записи в TLS
        dec.reinitICN(icn);
        byte[] pt2 = new byte[ct.length];
        dec.processBytes(ct, 0, ct.length, pt2, 0);
        dec.finishDecryption(tag, 0);
        assertArrayEquals(
                data, pt2, "После reinitICN после failed decrypt расшифрование должно работать");
    }

    @Test
    @DisplayName("reinitICN: множественные последовательные вызовы")
    void reinitICN_multipleCalls() throws AuthenticationException {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        Mgm enc = new Mgm(new Kuznyechik());
        enc.init(true, new ParametersWithIV(kp, icn));
        byte[] ct = new byte[data.length];
        byte[] tag = new byte[16];

        for (int i = 0; i < 5; i++) {
            enc.reinitICN(icn);
            enc.processBytes(data, 0, data.length, ct, 0);
            enc.finishEncryption(tag, 0);
        }

        Mgm dec = new Mgm(new Kuznyechik());
        dec.init(false, new ParametersWithIV(kp, icn));
        for (int i = 0; i < 5; i++) {
            dec.reinitICN(icn);
            byte[] pt = new byte[ct.length];
            dec.processBytes(ct, 0, ct.length, pt, 0);
            dec.finishDecryption(tag, 0);
            assertArrayEquals(data, pt, "Множественный reinitICN roundtrip на итерации " + i);
        }
    }

    @Test
    @DisplayName("reinitICN без init: IllegalStateException")
    void reinitICN_withoutInit_throws() {
        Mgm mgm = new Mgm(new Kuznyechik());
        byte[] icn = new byte[16];
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        assertThrows(
                IllegalStateException.class,
                () -> mgm.reinitICN(icn),
                "reinitICN без init должен бросать IllegalStateException");
    }

    @Test
    @DisplayName("reinitICN с ICN неверной длины: IllegalArgumentException")
    void reinitICN_wrongLength_throws() {
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(new SymmetricKey(K1), ICN1));
        byte[] shortIcn = new byte[8];
        assertThrows(
                IllegalArgumentException.class,
                () -> mgm.reinitICN(shortIcn),
                "reinitICN с ICN длины 8 должен бросать IllegalArgumentException");
    }

    @Test
    @DisplayName("reinitICN с ICN с MSB=1: IllegalArgumentException")
    void reinitICN_msbSet_throws() {
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(new SymmetricKey(K1), ICN1));
        byte[] badIcn = new byte[16];
        badIcn[0] = (byte) 0x80;
        assertThrows(
                IllegalArgumentException.class,
                () -> mgm.reinitICN(badIcn),
                "reinitICN с MSB=1 должен бросать IllegalArgumentException");
    }

    // -----------------------------------------------------------------------
    // Множественные updateAAD()
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("updateAAD(5) + updateAAD(3) совпадает с updateAAD(8)")
    void testMultipleUpdateAadMixed() throws AuthenticationException {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] aad = new byte[8];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(aad);
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        // Один вызов updateAAD(8)
        Mgm enc1 = new Mgm(new Kuznyechik());
        enc1.init(true, new ParametersWithIV(kp, icn));
        enc1.updateAAD(aad, 0, aad.length);
        byte[] ct1 = new byte[data.length];
        byte[] tag1 = new byte[16];
        enc1.processBytes(data, 0, data.length, ct1, 0);
        enc1.finishEncryption(tag1, 0);

        // Два вызова: updateAAD(5) + updateAAD(3)
        Mgm enc2 = new Mgm(new Kuznyechik());
        enc2.init(true, new ParametersWithIV(kp, icn));
        enc2.updateAAD(aad, 0, 5);
        enc2.updateAAD(aad, 5, 3);
        byte[] ct2 = new byte[data.length];
        byte[] tag2 = new byte[16];
        enc2.processBytes(data, 0, data.length, ct2, 0);
        enc2.finishEncryption(tag2, 0);

        assertArrayEquals(ct1, ct2, "CT должен совпасть при разбиении AAD");
        assertArrayEquals(tag1, tag2, "Tag должен совпасть при разбиении AAD");
    }

    @Test
    @DisplayName("updateAAD(16) + updateAAD(16) совпадает с updateAAD(32)")
    void testMultipleUpdateAadBlockAligned() throws AuthenticationException {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] aad = new byte[32];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(aad);
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        Mgm enc1 = new Mgm(new Kuznyechik());
        enc1.init(true, new ParametersWithIV(kp, icn));
        enc1.updateAAD(aad, 0, aad.length);
        byte[] ct1 = new byte[data.length];
        byte[] tag1 = new byte[16];
        enc1.processBytes(data, 0, data.length, ct1, 0);
        enc1.finishEncryption(tag1, 0);

        Mgm enc2 = new Mgm(new Kuznyechik());
        enc2.init(true, new ParametersWithIV(kp, icn));
        enc2.updateAAD(aad, 0, 16);
        enc2.updateAAD(aad, 16, 16);
        byte[] ct2 = new byte[data.length];
        byte[] tag2 = new byte[16];
        enc2.processBytes(data, 0, data.length, ct2, 0);
        enc2.finishEncryption(tag2, 0);

        assertArrayEquals(ct1, ct2, "CT должен совпасть при поблочном разбиении AAD");
        assertArrayEquals(tag1, tag2, "Tag должен совпасть при поблочном разбиении AAD");
    }

    @Test
    @DisplayName("updateAAD(33) разбитый на 4 куска совпадает с одним вызовом")
    void testMultipleUpdateAadManyChunks() throws AuthenticationException {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] aad = new byte[33];
        byte[] data = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(aad);
        CryptoRandom.INSTANCE.nextBytes(data);
        SymmetricKey kp = new SymmetricKey(key);

        Mgm enc1 = new Mgm(new Kuznyechik());
        enc1.init(true, new ParametersWithIV(kp, icn));
        enc1.updateAAD(aad, 0, aad.length);
        byte[] ct1 = new byte[data.length];
        byte[] tag1 = new byte[16];
        enc1.processBytes(data, 0, data.length, ct1, 0);
        enc1.finishEncryption(tag1, 0);

        Mgm enc2 = new Mgm(new Kuznyechik());
        enc2.init(true, new ParametersWithIV(kp, icn));
        enc2.updateAAD(aad, 0, 7);
        enc2.updateAAD(aad, 7, 7);
        enc2.updateAAD(aad, 14, 7);
        enc2.updateAAD(aad, 21, 12);
        byte[] ct2 = new byte[data.length];
        byte[] tag2 = new byte[16];
        enc2.processBytes(data, 0, data.length, ct2, 0);
        enc2.finishEncryption(tag2, 0);

        assertArrayEquals(ct1, ct2, "CT должен совпасть при разбиении 33 байт AAD на 4 куска");
        assertArrayEquals(tag1, tag2, "Tag должен совпасть при разбиении 33 байт AAD на 4 куска");
    }

    @Test
    @DisplayName("updateAAD(5) + finishEncryption (AAD-only) корректен")
    void testMultipleUpdateAadAadOnly() throws AuthenticationException {
        byte[] key = new byte[32];
        byte[] icn = new byte[16];
        byte[] aad = new byte[5];
        CryptoRandom.INSTANCE.nextBytes(key);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(aad);
        SymmetricKey kp = new SymmetricKey(key);

        // Один вызов updateAAD(5) — без processBytes
        Mgm enc = new Mgm(new Kuznyechik());
        enc.init(true, new ParametersWithIV(kp, icn));
        enc.updateAAD(aad, 0, aad.length);
        byte[] tag = new byte[16];
        enc.finishEncryption(tag, 0);

        // Верификация — должен расшифроваться с тем же AAD
        Mgm dec = new Mgm(new Kuznyechik());
        dec.init(false, new ParametersWithIV(kp, icn));
        dec.updateAAD(aad, 0, aad.length);
        dec.finishDecryption(tag, 0);
    }

    @Test
    @DisplayName("updateAAD после processBytes: IllegalStateException")
    void testUpdateAadAfterProcessBytes() {
        Mgm mgm = new Mgm(new Kuznyechik());
        mgm.init(true, new ParametersWithIV(new SymmetricKey(K1), ICN1));
        mgm.processBytes(new byte[0], 0, 0, new byte[0], 0);
        assertThrows(
                IllegalStateException.class,
                () -> mgm.updateAAD(new byte[1], 0, 1),
                "updateAAD после processBytes должен бросать IllegalStateException");
    }

    // -----------------------------------------------------------------------
    // Вспомогательный метод
    // -----------------------------------------------------------------------

    private static byte[] h(String hex) {
        hex = hex.replaceAll("\\s+", "");
        byte[] r = new byte[hex.length() / 2];
        for (int i = 0; i < r.length; i++) {
            r[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return r;
    }
}
