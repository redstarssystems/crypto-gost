package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;

@DisplayName("Cipher Tests")
class CipherTest {

    private SymmetricKey key;
    private byte[] data16; // кратные 16 байт
    private byte[] data20; // не кратные 16 байт
    private byte[] dataLong; // 1024 байта

    @BeforeEach
    void setUp() {
        key = KeyGenerator.generateSymmetricKey();
        data16 = "1234567890ABCDEF".getBytes(StandardCharsets.UTF_8); // 16 байт
        data20 = "1234567890ABCDEFGHIJ".getBytes(StandardCharsets.UTF_8); // 20 байт
        dataLong = new byte[1024];
        for (int i = 0; i < dataLong.length; i++) dataLong[i] = (byte) i;
    }

    // -----------------------------------------------------------------------
    // CTR — roundtrip
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CTR: roundtrip 20 байт (не кратно блоку)")
    void testCtrRoundtrip20() {
        byte[] enc = Cipher.encrypt(data20, key, Cipher.Mode.CTR);
        byte[] dec = Cipher.decrypt(enc, key, Cipher.Mode.CTR);
        assertArrayEquals(data20, dec);
    }

    @Test
    @DisplayName("CTR: roundtrip 1024 байта")
    void testCtrRoundtripLong() {
        byte[] enc = Cipher.encrypt(dataLong, key, Cipher.Mode.CTR);
        byte[] dec = Cipher.decrypt(enc, key, Cipher.Mode.CTR);
        assertArrayEquals(dataLong, dec);
    }

    @Test
    @DisplayName("CTR: IV prepend-ится (первые 8 байт)")
    void testCtrIvPrepended() {
        byte[] enc = Cipher.encrypt(data16, key, Cipher.Mode.CTR);
        // IV = 8 байт для CTR
        assertEquals(8 + data16.length, enc.length);
    }

    @Test
    @DisplayName("CTR: два шифрования с разными IV дают разный шифртекст")
    void testCtrDifferentIV() {
        byte[] enc1 = Cipher.encrypt(data16, key, Cipher.Mode.CTR);
        byte[] enc2 = Cipher.encrypt(data16, key, Cipher.Mode.CTR);
        // IV случайный — шифртексты (включая IV) должны отличаться
        assertFalse(Arrays.equals(enc1, enc2));
    }

    @Test
    @DisplayName("CTR: явный IV — encrypt без prepend, decrypt с явным IV")
    void testCtrExplicitIV() {
        byte[] iv = new byte[8];
        Arrays.fill(iv, (byte) 0x42);
        byte[] enc = Cipher.encrypt(data20, key, iv, Cipher.Mode.CTR);
        // Без prepend — длина равна длине данных
        assertEquals(data20.length, enc.length);
        byte[] dec = Cipher.decrypt(enc, key, iv, Cipher.Mode.CTR);
        assertArrayEquals(data20, dec);
    }

    // -----------------------------------------------------------------------
    // CFB — roundtrip
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CFB: roundtrip 20 байт")
    void testCfbRoundtrip() {
        byte[] enc = Cipher.encrypt(data20, key, Cipher.Mode.CFB);
        byte[] dec = Cipher.decrypt(enc, key, Cipher.Mode.CFB);
        assertArrayEquals(data20, dec);
    }

    @Test
    @DisplayName("CFB: IV prepend-ится (первые 16 байт)")
    void testCfbIvPrepended() {
        byte[] enc = Cipher.encrypt(data20, key, Cipher.Mode.CFB);
        assertEquals(16 + data20.length, enc.length);
    }

    // -----------------------------------------------------------------------
    // OFB — roundtrip
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("OFB: roundtrip 20 байт")
    void testOfbRoundtrip() {
        byte[] enc = Cipher.encrypt(data20, key, Cipher.Mode.OFB);
        byte[] dec = Cipher.decrypt(enc, key, Cipher.Mode.OFB);
        assertArrayEquals(data20, dec);
    }

    // -----------------------------------------------------------------------
    // CBC — roundtrip с padding
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CBC + PKCS7: roundtrip 20 байт (не кратно блоку)")
    void testCbcPkcs7Roundtrip20() {
        byte[] enc = Cipher.encrypt(data20, key, Cipher.Mode.CBC, Cipher.Padding.PKCS7);
        byte[] dec = Cipher.decrypt(enc, key, Cipher.Mode.CBC, Cipher.Padding.PKCS7);
        assertArrayEquals(data20, dec);
    }

    @Test
    @DisplayName("CBC + PKCS7: roundtrip 16 байт (кратно блоку — padding = целый блок)")
    void testCbcPkcs7Roundtrip16() {
        byte[] enc = Cipher.encrypt(data16, key, Cipher.Mode.CBC);
        byte[] dec = Cipher.decrypt(enc, key, Cipher.Mode.CBC);
        assertArrayEquals(data16, dec);
    }

    @Test
    @DisplayName("CBC + ISO7816_4: roundtrip 20 байт")
    void testCbcIso7816Roundtrip() {
        byte[] enc = Cipher.encrypt(data20, key, Cipher.Mode.CBC, Cipher.Padding.ISO7816_4);
        byte[] dec = Cipher.decrypt(enc, key, Cipher.Mode.CBC, Cipher.Padding.ISO7816_4);
        assertArrayEquals(data20, dec);
    }

    @Test
    @DisplayName("CBC + NONE: roundtrip 16 байт")
    void testCbcNonePaddingRoundtrip() {
        byte[] enc = Cipher.encrypt(data16, key, Cipher.Mode.CBC, Cipher.Padding.NONE);
        byte[] dec = Cipher.decrypt(enc, key, Cipher.Mode.CBC, Cipher.Padding.NONE);
        assertArrayEquals(data16, dec);
    }

    @Test
    @DisplayName("CBC + NONE: не кратные данные -> IllegalArgumentException")
    void testCbcNonePaddingRejectsUnaligned() {
        assertThrows(
                IllegalArgumentException.class,
                () -> Cipher.encrypt(data20, key, Cipher.Mode.CBC, Cipher.Padding.NONE));
    }

    @Test
    @DisplayName("CBC: IV prepend-ится (первые 16 байт)")
    void testCbcIvPrepended() {
        byte[] enc = Cipher.encrypt(data16, key, Cipher.Mode.CBC);
        // IV(16) + padded_data(32: 16 данных + 16 padding для полного блока)
        assertEquals(16 + 32, enc.length);
    }

    // -----------------------------------------------------------------------
    // Потоковое шифрование (CTR, CFB, OFB)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CTR потоковый: encryptingStream / decryptingStream roundtrip")
    void testCtrStreamRoundtrip() throws Exception {
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream enc = Cipher.encryptingStream(encBuf, key, Cipher.Mode.CTR)) {
            enc.write(dataLong, 0, 512);
            enc.write(dataLong, 512, 512);
        }

        byte[] encBytes = encBuf.toByteArray();
        // IV(8) + данные
        assertEquals(8 + dataLong.length, encBytes.length);

        ByteArrayInputStream decIn = new ByteArrayInputStream(encBytes);
        ByteArrayOutputStream decBuf = new ByteArrayOutputStream();
        try (InputStream dec = Cipher.decryptingStream(decIn, key, Cipher.Mode.CTR)) {
            byte[] buf = new byte[256];
            int n;
            while ((n = dec.read(buf)) > 0) decBuf.write(buf, 0, n);
        }
        assertArrayEquals(dataLong, decBuf.toByteArray());
    }

    @Test
    @DisplayName("CFB потоковый: roundtrip")
    void testCfbStreamRoundtrip() throws Exception {
        ByteArrayOutputStream encBuf = new ByteArrayOutputStream();
        try (OutputStream enc = Cipher.encryptingStream(encBuf, key, Cipher.Mode.CFB)) {
            enc.write(data20);
        }

        ByteArrayInputStream decIn = new ByteArrayInputStream(encBuf.toByteArray());
        ByteArrayOutputStream decBuf = new ByteArrayOutputStream();
        try (InputStream dec = Cipher.decryptingStream(decIn, key, Cipher.Mode.CFB)) {
            byte[] buf = new byte[64];
            int n;
            while ((n = dec.read(buf)) > 0) decBuf.write(buf, 0, n);
        }
        assertArrayEquals(data20, decBuf.toByteArray());
    }

    @Test
    @DisplayName("CBC потоковый: UnsupportedOperationException")
    void testCbcStreamUnsupported() {
        assertThrows(
                Exception.class,
                () -> {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    try (OutputStream enc = Cipher.encryptingStream(out, key, Cipher.Mode.CBC)) {
                        enc.write(data16);
                    }
                });
    }

    // -----------------------------------------------------------------------
    // Неверный ключ — расшифрование даёт другой результат
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CTR: неверный ключ -> неверный plaintext")
    void testWrongKeyGivesWrongPlaintext() {
        byte[] enc = Cipher.encrypt(data20, key, Cipher.Mode.CTR);
        SymmetricKey wrongKey = KeyGenerator.generateSymmetricKey();
        byte[] dec = Cipher.decrypt(enc, wrongKey, Cipher.Mode.CTR);
        assertFalse(Arrays.equals(data20, dec), "Неверный ключ должен давать неверный plaintext");
    }

    // -----------------------------------------------------------------------
    // Пустые данные
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("CTR: пустые данные")
    void testCtrEmptyData() {
        byte[] enc = Cipher.encrypt(new byte[0], key, Cipher.Mode.CTR);
        byte[] dec = Cipher.decrypt(enc, key, Cipher.Mode.CTR);
        assertArrayEquals(new byte[0], dec);
    }
}
