package org.rssys.gost.mac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.SymmetricKey;

/**
 * Сверка {@link Cmac} с независимой простой реализацией CMAC (NIST SP 800-38B / RFC 4493 §2.3) на
 * случайных ключах и сообщениях разной длины.
 *
 * <p>Известные тестовые векторы дают один ключ, и у него перенос при удвоении подключа всегда
 * одинаков, поэтому ветвь «старший бит равен 0» и ветвь «равен 1» вместе они не покрывают. Здесь
 * ключи случайные (с фиксированным зерном), а в эталоне перенос обрабатывается обычным
 * ветвлением: это безопасно только в тесте.</p>
 */
@DisplayName("Cmac: сверка с независимой реализацией на случайных ключах")
class CmacReferenceTest {

    private static final int BLOCK = 16;
    private static final int R_128 = 0x87;

    private static byte[] encryptBlock(Kuznyechik cipher, byte[] block) {
        byte[] out = new byte[BLOCK];
        cipher.processBlock(block, 0, out, 0);
        return out;
    }

    /** Удвоение в GF(2^128) с обычным ветвлением по старшему биту. */
    private static byte[] doubled(byte[] in) {
        byte[] out = new byte[BLOCK];
        int carry = 0;
        for (int i = BLOCK - 1; i >= 0; i--) {
            int b = in[i] & 0xFF;
            out[i] = (byte) ((b << 1) | carry);
            carry = b >>> 7;
        }
        if ((in[0] & 0x80) != 0) {
            out[BLOCK - 1] ^= (byte) R_128;
        }
        return out;
    }

    private static byte[] referenceCmac(byte[] key, byte[] message) {
        Kuznyechik cipher = new Kuznyechik();
        cipher.init(true, new SymmetricKey(key));
        byte[] k1 = doubled(encryptBlock(cipher, new byte[BLOCK]));
        byte[] k2 = doubled(k1);

        int blocks = Math.max(1, (message.length + BLOCK - 1) / BLOCK);
        boolean complete = message.length > 0 && message.length % BLOCK == 0;
        byte[] state = new byte[BLOCK];
        for (int i = 0; i < blocks; i++) {
            byte[] block = new byte[BLOCK];
            int from = i * BLOCK;
            int len = Math.min(BLOCK, Math.max(0, message.length - from));
            System.arraycopy(message, from, block, 0, len);
            if (i == blocks - 1) {
                byte[] subkey = k1;
                if (!complete) {
                    block[len] = (byte) 0x80; // дополнение 10...0
                    subkey = k2;
                }
                for (int j = 0; j < BLOCK; j++) {
                    block[j] ^= subkey[j];
                }
            }
            for (int j = 0; j < BLOCK; j++) {
                state[j] ^= block[j];
            }
            state = encryptBlock(cipher, state);
        }
        return state;
    }

    private static byte[] cmac(byte[] key, byte[] message) {
        Cmac cmac = new Cmac(new Kuznyechik());
        cmac.init(new SymmetricKey(key));
        cmac.update(message, 0, message.length);
        byte[] out = new byte[BLOCK];
        cmac.doFinal(out, 0);
        return out;
    }

    @Test
    @DisplayName("Случайные ключи и длины 0..65 байт совпадают с эталонной реализацией")
    void matchesReferenceOnRandomKeys() {
        Random random = new Random(0x34131L);
        int subkeysWithClearedHighBit = 0;
        int subkeysWithSetHighBit = 0;
        for (int k = 0; k < 64; k++) {
            byte[] key = new byte[32];
            random.nextBytes(key);
            Kuznyechik cipher = new Kuznyechik();
            cipher.init(true, new SymmetricKey(key));
            byte[] l = encryptBlock(cipher, new byte[BLOCK]);
            if ((l[0] & 0x80) == 0) {
                subkeysWithClearedHighBit++;
            } else {
                subkeysWithSetHighBit++;
            }
            if ((doubled(l)[0] & 0x80) == 0) {
                subkeysWithClearedHighBit++;
            } else {
                subkeysWithSetHighBit++;
            }
            for (int length = 0; length <= 65; length++) {
                byte[] message = new byte[length];
                random.nextBytes(message);
                assertArrayEquals(
                        referenceCmac(key, message),
                        cmac(key, message),
                        "ключ " + k + ", длина " + length + ": CMAC должен совпасть с эталоном");
            }
        }
        // Оба значения старшего бита подключей встретились: иначе тест не отличил бы маску
        // от безусловного XOR (и от его отсутствия)
        assertTrue(
                subkeysWithClearedHighBit > 0 && subkeysWithSetHighBit > 0, "обе ветви удвоения");
    }

    @Test
    @DisplayName("Эталон и Cmac дают разные теги для разных сообщений (проверка самой сверки)")
    void referenceIsSensitive() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 7);
        byte[] a = new byte[20];
        byte[] b = a.clone();
        b[19] ^= 1;

        assertFalse(
                Arrays.equals(referenceCmac(key, a), referenceCmac(key, b)),
                "эталон должен различать сообщения");
        assertFalse(Arrays.equals(cmac(key, a), cmac(key, b)), "Cmac должен различать сообщения");
    }
}
