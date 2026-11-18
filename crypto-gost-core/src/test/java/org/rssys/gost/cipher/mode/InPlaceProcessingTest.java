package org.rssys.gost.cipher.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.StreamCipher;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.CryptoRandom;

/**
 * Обработка на месте (входной и выходной массив совпадают) в потоковых режимах: расшифрование
 * потока в буфере вызывающего опирается на то, что режим читает вход раньше, чем пишет выход на
 * то же место. В CFB это особенно важно: шифртекст нужен для обратной связи.
 */
@DisplayName("Потоковые режимы: обработка на месте совпадает с обработкой в отдельный буфер")
class InPlaceProcessingTest {

    private static final int[] LENGTHS = {1, 7, 15, 16, 17, 31, 32, 33, 100, 4097};

    private enum Kind {
        CTR(8),
        CFB(16),
        OFB(16);

        final int ivLength;

        Kind(int ivLength) {
            this.ivLength = ivLength;
        }

        StreamCipher create() {
            Kuznyechik kuznyechik = new Kuznyechik();
            return switch (this) {
                case CTR -> new Ctr(kuznyechik);
                case CFB -> new Cfb(kuznyechik);
                case OFB -> new Ofb(kuznyechik);
            };
        }
    }

    private static StreamCipher init(Kind kind, boolean encrypt, SymmetricKey key, byte[] iv) {
        StreamCipher cipher = kind.create();
        cipher.init(encrypt, new ParametersWithIV(key, iv));
        return cipher;
    }

    @Test
    @DisplayName("Расшифрование на месте на длинах, не кратных блоку, и с нулевым смещением")
    void decryptionInPlaceMatchesSeparateBuffer() {
        byte[] keyBytes = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(keyBytes);
        SymmetricKey key = new SymmetricKey(keyBytes);
        for (Kind kind : Kind.values()) {
            byte[] iv = new byte[kind.ivLength];
            CryptoRandom.INSTANCE.nextBytes(iv);
            for (int length : LENGTHS) {
                byte[] plain = new byte[length];
                CryptoRandom.INSTANCE.nextBytes(plain);
                byte[] cipherText = new byte[length];
                init(kind, true, key, iv).processBytes(plain, 0, length, cipherText, 0);

                byte[] separate = new byte[length];
                init(kind, false, key, iv).processBytes(cipherText, 0, length, separate, 0);

                byte[] inPlace = cipherText.clone();
                init(kind, false, key, iv).processBytes(inPlace, 0, length, inPlace, 0);

                String where = kind + ", длина " + length;
                assertArrayEquals(plain, separate, "расшифрование в отдельный буфер, " + where);
                assertArrayEquals(separate, inPlace, "расшифрование на месте, " + where);
            }
        }
    }

    @Test
    @DisplayName("Расшифрование на месте по частям с произвольным смещением внутри массива")
    void decryptionInPlaceInPiecesAtOffset() {
        byte[] keyBytes = new byte[32];
        CryptoRandom.INSTANCE.nextBytes(keyBytes);
        SymmetricKey key = new SymmetricKey(keyBytes);
        int[] pieces = {5, 11, 16, 1, 40, 27};
        int total = Arrays.stream(pieces).sum();
        for (Kind kind : Kind.values()) {
            byte[] iv = new byte[kind.ivLength];
            CryptoRandom.INSTANCE.nextBytes(iv);
            byte[] plain = new byte[total];
            CryptoRandom.INSTANCE.nextBytes(plain);
            byte[] cipherText = new byte[total];
            init(kind, true, key, iv).processBytes(plain, 0, total, cipherText, 0);

            int offset = 3;
            byte[] buffer = new byte[offset + total + 2];
            System.arraycopy(cipherText, 0, buffer, offset, total);
            StreamCipher decrypting = init(kind, false, key, iv);
            int position = offset;
            for (int piece : pieces) {
                decrypting.processBytes(buffer, position, piece, buffer, position);
                position += piece;
            }
            assertArrayEquals(
                    plain,
                    Arrays.copyOfRange(buffer, offset, offset + total),
                    "частями на месте, режим " + kind);
        }
    }
}
