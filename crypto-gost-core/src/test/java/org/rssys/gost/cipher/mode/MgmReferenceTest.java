package org.rssys.gost.cipher.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * Независимый эталон MGM (RFC 9058 §3-§4): умножение в GF(2¹²⁸) «по битам» и расчёт тега по
 * определению. Рабочий {@link Mgm} считает то же самое на длинных словах и без выделений, поэтому
 * совпадение тега на случайных входах проверяет арифметику поля независимо от векторов RFC.
 */
@DisplayName("MGM: эталонное умножение в GF(2^128) и тег по определению")
class MgmReferenceTest {

    private static final int BLOCK = 16;
    private static final HexFormat HEX = HexFormat.of();

    /** Умножение в GF(2¹²⁸) с полиномом w¹²⁸+w⁷+w²+w+1, байты big-endian (RFC 9058 §3). */
    private static byte[] gf128Mul(byte[] x, byte[] y) {
        byte[] result = new byte[BLOCK];
        byte[] v = y.clone();
        // Биты X от w⁰ (младший бит последнего байта) к w¹²⁷
        for (int bit = 0; bit < 128; bit++) {
            if (((x[BLOCK - 1 - bit / 8] >>> (bit % 8)) & 1) != 0) {
                for (int i = 0; i < BLOCK; i++) {
                    result[i] ^= v[i];
                }
            }
            boolean carry = (v[0] & 0x80) != 0;
            for (int i = 0; i < BLOCK - 1; i++) {
                v[i] = (byte) ((v[i] << 1) | ((v[i + 1] & 0xFF) >>> 7));
            }
            v[BLOCK - 1] = (byte) (v[BLOCK - 1] << 1);
            if (carry) {
                v[BLOCK - 1] ^= (byte) 0x87;
            }
        }
        return result;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] r = new byte[BLOCK];
        for (int i = 0; i < BLOCK; i++) {
            r[i] = (byte) (a[i] ^ b[i]);
        }
        return r;
    }

    private static byte[] block(String hex) {
        return HEX.parseHex(hex);
    }

    @Test
    @DisplayName("X * 0 = 0")
    void multiplyByZero() {
        byte[] x = block("8899AABBCCDDEEFF0011223344556677");
        assertArrayEquals(new byte[BLOCK], gf128Mul(x, new byte[BLOCK]));
    }

    @Test
    @DisplayName("X * 1 = X: единица поля - младший бит последнего байта")
    void multiplyByOne() {
        byte[] x = block("8899AABBCCDDEEFF0011223344556677");
        byte[] one = new byte[BLOCK];
        one[BLOCK - 1] = 1;
        assertArrayEquals(x, gf128Mul(x, one), "X * 1 должен равняться X");
    }

    @Test
    @DisplayName("Коммутативность: X * Y = Y * X")
    void multiplicationIsCommutative() {
        byte[] x = block("8899AABBCCDDEEFF0011223344556677");
        byte[] y = block("FFEEDDCCBBAA99887766554433221100");
        assertArrayEquals(gf128Mul(x, y), gf128Mul(y, x), "умножение должно быть коммутативным");
    }

    @Test
    @DisplayName("Дистрибутивность: X * (Y xor Z) = X * Y xor X * Z")
    void multiplicationIsDistributive() {
        byte[] x = block("8899AABBCCDDEEFF0011223344556677");
        byte[] y = block("FFEEDDCCBBAA99887766554433221100");
        byte[] z = block("0F0E0D0C0B0A09080706050403020100");
        assertArrayEquals(
                gf128Mul(x, xor(y, z)),
                xor(gf128Mul(x, y), gf128Mul(x, z)),
                "умножение должно быть дистрибутивно относительно сложения");
    }

    @Test
    @DisplayName("Эталонный тег воспроизводит вектор RFC 9058 A.1.1")
    void referenceReproducesRfcVector() {
        byte[] key = block("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF");
        byte[] icn = block("1122334455667700FFEEDDCCBBAA9988");
        byte[] aad =
                block(
                        "0202020202020202010101010101010104040404040404040303030303030303EA0505050505050505");
        byte[] cipherText =
                block(
                        "A9757B8147956E9055B8A33DE89F42FC8075D2212BF9FD5BD3F7069AADC16B39"
                                + "497AB15915A6BA85936B5D0EA9F6851CC60C14D4D3F883D0AB94420695C76DEB2C7552");
        assertArrayEquals(
                block("CF5D656F40C34F5C46E8BB0E29FCDB4C"),
                referenceTag(key, icn, aad, cipherText),
                "эталон должен давать тег из RFC 9058 A.1.1");
    }

    @Test
    @DisplayName("Тег Mgm совпадает с тегом, посчитанным по определению, на случайных входах")
    void tagMatchesDefinition() {
        for (int round = 0; round < 40; round++) {
            byte[] key = new byte[Kuznyechik.KEY_SIZE];
            byte[] icn = new byte[BLOCK];
            byte[] aad = new byte[CryptoRandom.INSTANCE.nextInt(0, 60)];
            byte[] plain = new byte[CryptoRandom.INSTANCE.nextInt(aad.length == 0 ? 1 : 0, 80)];
            CryptoRandom.INSTANCE.nextBytes(key);
            CryptoRandom.INSTANCE.nextBytes(icn);
            CryptoRandom.INSTANCE.nextBytes(aad);
            CryptoRandom.INSTANCE.nextBytes(plain);
            icn[0] &= 0x7F; // ICN - 127 бит, старший бит нулевой

            Mgm mgm = new Mgm(new Kuznyechik());
            mgm.init(true, new ParametersWithIV(new SymmetricKey(key), icn));
            mgm.updateAAD(aad, 0, aad.length);
            byte[] cipherText = new byte[plain.length];
            mgm.processBytes(plain, 0, plain.length, cipherText, 0);
            byte[] tag = new byte[BLOCK];
            mgm.finishEncryption(tag, 0);

            assertArrayEquals(
                    referenceTag(key, icn, aad, cipherText),
                    tag,
                    "тег Mgm расходится с эталоном: aad=" + aad.length + ", ct=" + plain.length);
        }
    }

    /** Тег по RFC 9058 §4: сумма H_i ⊗ блок по AAD, шифртексту и блоку длин, затем E_K. */
    private static byte[] referenceTag(byte[] key, byte[] icn, byte[] aad, byte[] cipherText) {
        Kuznyechik cipher = new Kuznyechik();
        cipher.init(true, new SymmetricKey(key));
        // Z1 = E_K(1 || ICN): старший бит блока выставляется в 1 (Y1 = E_K(0 || ICN) нужен гамме,
        // для тега не используется)
        byte[] zInput = icn.clone();
        zInput[0] |= (byte) 0x80;
        byte[] z = encrypt(cipher, zInput);
        byte[] sum = new byte[BLOCK];
        sum = foldBlocks(cipher, z, sum, aad);
        sum = foldBlocks(cipher, z, sum, cipherText);
        byte[] lengths =
                ByteBuffer.allocate(BLOCK)
                        .putLong(aad.length * 8L)
                        .putLong(cipherText.length * 8L)
                        .array();
        sum = xor(sum, gf128Mul(encrypt(cipher, z), lengths));
        return encrypt(cipher, sum);
    }

    /** Добавляет в сумму H_i ⊗ блок для каждого блока данных; последний дополняется нулями. */
    private static byte[] foldBlocks(Kuznyechik cipher, byte[] z, byte[] sum, byte[] data) {
        byte[] acc = sum;
        for (int off = 0; off < data.length; off += BLOCK) {
            byte[] chunk = Arrays.copyOfRange(data, off, off + BLOCK);
            acc = xor(acc, gf128Mul(encrypt(cipher, z), chunk));
            incrementLeftHalf(z);
        }
        return acc;
    }

    private static byte[] encrypt(Kuznyechik cipher, byte[] in) {
        byte[] out = new byte[BLOCK];
        cipher.processBlock(in, 0, out, 0);
        return out;
    }

    /** incr_l: левая половина блока как число big-endian по модулю 2⁶⁴. */
    private static void incrementLeftHalf(byte[] z) {
        for (int i = BLOCK / 2 - 1; i >= 0; i--) {
            if (++z[i] != 0) {
                return;
            }
        }
    }
}
