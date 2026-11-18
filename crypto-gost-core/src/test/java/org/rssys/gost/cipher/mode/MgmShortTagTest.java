package org.rssys.gost.cipher.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;
import org.rssys.gost.util.CryptoRandom;

/**
 * Тег MGM короче блока (RFC 9058: MSB_S, S от 8 до 16 байт): запись пишет ровно {@code tagSize}
 * байт и это префикс полного тега, проверка принимает верный короткий тег, отвергает любой
 * изменённый байт и не смотрит на то, что лежит в буфере после тега.
 */
@DisplayName("Mgm: короткие теги (8-16 байт)")
class MgmShortTagTest {

    private static final int AAD_LENGTH = 21;
    private static final int TEXT_LENGTH = 37;

    private static Mgm start(
            boolean encrypt, int tagSize, SymmetricKey key, byte[] icn, byte[] aad) {
        Mgm mgm = new Mgm(new Kuznyechik(), tagSize);
        mgm.init(encrypt, new ParametersWithIV(key, icn));
        mgm.updateAAD(aad, 0, aad.length);
        return mgm;
    }

    @Test
    @DisplayName("Запись: ровно tagSize байт, это префикс полного тега, соседние байты целы")
    void shortTagIsPrefixOfFullTagAndTouchesNothingElse() {
        byte[] keyBytes = new byte[32];
        byte[] icn = new byte[16];
        byte[] aad = new byte[AAD_LENGTH];
        byte[] text = new byte[TEXT_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(keyBytes);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(aad);
        CryptoRandom.INSTANCE.nextBytes(text);
        SymmetricKey key = new SymmetricKey(keyBytes);

        Mgm full = start(true, 16, key, icn, aad);
        byte[] cipherText = new byte[TEXT_LENGTH];
        full.processBytes(text, 0, TEXT_LENGTH, cipherText, 0);
        byte[] fullTag = new byte[16];
        full.finishEncryption(fullTag, 0);

        for (int tagSize = 8; tagSize <= 16; tagSize++) {
            Mgm mgm = start(true, tagSize, key, icn, aad);
            mgm.processBytes(text, 0, TEXT_LENGTH, new byte[TEXT_LENGTH], 0);
            byte[] out = new byte[3 + 16 + 3];
            Arrays.fill(out, (byte) 0x5A);
            assertEquals(
                    tagSize,
                    mgm.finishEncryption(out, 3),
                    "возвращаемый размер, tagSize " + tagSize);

            assertArrayEquals(
                    Arrays.copyOf(fullTag, tagSize),
                    Arrays.copyOfRange(out, 3, 3 + tagSize),
                    "тег должен быть префиксом полного, tagSize " + tagSize);
            for (int i = 0; i < out.length; i++) {
                if (i < 3 || i >= 3 + tagSize) {
                    assertEquals(
                            (byte) 0x5A,
                            out[i],
                            "байт " + i + " вне тега изменён, tagSize " + tagSize);
                }
            }
        }
    }

    @Test
    @DisplayName("После проверки вычисленный тег не остаётся в рабочих полях шифра")
    void computedTagIsNotLeftInCipher() throws AuthenticationException {
        byte[] keyBytes = new byte[32];
        byte[] icn = new byte[16];
        byte[] aad = new byte[AAD_LENGTH];
        byte[] text = new byte[TEXT_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(keyBytes);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(aad);
        CryptoRandom.INSTANCE.nextBytes(text);
        SymmetricKey key = new SymmetricKey(keyBytes);

        Mgm enc = start(true, 16, key, icn, aad);
        byte[] cipherText = new byte[TEXT_LENGTH];
        enc.processBytes(text, 0, TEXT_LENGTH, cipherText, 0);
        byte[] tag = new byte[16];
        enc.finishEncryption(tag, 0);

        byte[] broken = tag.clone();
        broken[0] ^= 0x01;
        for (byte[] given : new byte[][] {tag, broken}) {
            Kuznyechik kuznyechik = new Kuznyechik();
            Mgm dec = new Mgm(kuznyechik, 16);
            dec.init(false, new ParametersWithIV(key, icn));
            dec.updateAAD(aad, 0, aad.length);
            dec.processBytes(cipherText, 0, TEXT_LENGTH, new byte[TEXT_LENGTH], 0);
            try {
                dec.finishDecryption(given, 0);
            } catch (AuthenticationException expected) {
                // для испорченного тега отказ ожидаем, важно состояние шифра после него
            }
            assertEquals(0L, kuznyechik.getEncBufHi(), "старшее слово вычисленного тега осталось");
            assertEquals(0L, kuznyechik.getEncBufLo(), "младшее слово вычисленного тега осталось");
        }
    }

    @Test
    @DisplayName("Проверка: верный короткий тег принимается, любой изменённый байт отвергается")
    void shortTagVerificationDetectsEveryByte() {
        byte[] keyBytes = new byte[32];
        byte[] icn = new byte[16];
        byte[] aad = new byte[AAD_LENGTH];
        byte[] text = new byte[TEXT_LENGTH];
        CryptoRandom.INSTANCE.nextBytes(keyBytes);
        CryptoRandom.INSTANCE.nextBytes(icn);
        icn[0] &= 0x7F;
        CryptoRandom.INSTANCE.nextBytes(aad);
        CryptoRandom.INSTANCE.nextBytes(text);
        SymmetricKey key = new SymmetricKey(keyBytes);

        for (int tagSize = 8; tagSize <= 16; tagSize++) {
            Mgm enc = start(true, tagSize, key, icn, aad);
            byte[] cipherText = new byte[TEXT_LENGTH];
            enc.processBytes(text, 0, TEXT_LENGTH, cipherText, 0);
            byte[] tag = new byte[tagSize];
            enc.finishEncryption(tag, 0);

            // Хвост после тега произволен: проверка не должна его читать
            byte[] padded = Arrays.copyOf(tag, tagSize + 4);
            Arrays.fill(padded, tagSize, padded.length, (byte) 0xA5);
            Mgm ok = start(false, tagSize, key, icn, aad);
            ok.processBytes(cipherText, 0, TEXT_LENGTH, new byte[TEXT_LENGTH], 0);
            assertDoesNotThrow(
                    () -> ok.finishDecryption(padded, 0), "верный тег, tagSize " + tagSize);

            for (int i = 0; i < tagSize; i++) {
                byte[] broken = Arrays.copyOf(padded, padded.length);
                broken[i] ^= 0x01;
                Mgm bad = start(false, tagSize, key, icn, aad);
                bad.processBytes(cipherText, 0, TEXT_LENGTH, new byte[TEXT_LENGTH], 0);
                assertThrows(
                        AuthenticationException.class,
                        () -> bad.finishDecryption(broken, 0),
                        "изменён байт " + i + " тега, tagSize " + tagSize);
            }
        }
    }
}
