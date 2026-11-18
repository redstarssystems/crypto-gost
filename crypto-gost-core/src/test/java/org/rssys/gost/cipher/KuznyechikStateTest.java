package org.rssys.gost.cipher;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Кузнечик: состояние ключа и zero-allocation вход encryptToFields")
class KuznyechikStateTest {

    private static final byte[] KEY = new byte[Kuznyechik.KEY_SIZE];

    @Test
    @DisplayName("encryptToFields без ключа отвергается, а не считает на нулевых раундовых ключах")
    void encryptToFieldsRequiresKey() {
        Kuznyechik cipher = new Kuznyechik();
        assertThrows(
                IllegalStateException.class,
                () -> cipher.encryptToFields(1L, 2L),
                "шифр без ключа не должен выдавать «шифртекст»");
    }

    @Test
    @DisplayName("encryptToFields после destroy отвергается")
    void encryptToFieldsAfterDestroyIsRejected() {
        Kuznyechik cipher = new Kuznyechik();
        cipher.init(true, new SymmetricKey(KEY));
        cipher.encryptToFields(1L, 2L);
        cipher.destroy();
        assertThrows(
                IllegalStateException.class,
                () -> cipher.encryptToFields(1L, 2L),
                "уничтоженный шифр не должен считать");
    }

    @Test
    @DisplayName("encryptToFields совпадает с processBlock на том же блоке")
    void encryptToFieldsMatchesProcessBlock() {
        Kuznyechik cipher = new Kuznyechik();
        cipher.init(true, new SymmetricKey(KEY));
        byte[] in = new byte[Kuznyechik.BLOCK_SIZE];
        in[15] = 1;
        byte[] out = new byte[Kuznyechik.BLOCK_SIZE];
        cipher.processBlock(in, 0, out, 0);
        cipher.encryptToFields(0L, 1L);
        java.nio.ByteBuffer expected = java.nio.ByteBuffer.wrap(out);
        assertEquals(expected.getLong(0), cipher.getEncBufHi(), "старшие 8 байт");
        assertEquals(expected.getLong(8), cipher.getEncBufLo(), "младшие 8 байт");
    }
}
