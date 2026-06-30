package org.rssys.gost.api;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.cipher.SymmetricKey;
import org.rssys.gost.util.AuthenticationException;

@DisplayName("KeyExport: KExp15/KImp15 (RFC 9189 §8.2.1)")
class KeyExportTest {

    // -----------------------------------------------------------------------
    // KAT: RFC 9189 Appendix A.1.3.2 — TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC
    // -----------------------------------------------------------------------

    private static final byte[] KAT_SECRET =
            hex(
                    "A5 57 6C E7 92 4A 24 F5 81 13 80 8D BD 9E F8 56"
                            + "F5 BD C3 B1 83 CE 5D AD CA 36 A5 3A A0 77 65 1D");

    private static final byte[] KAT_K_EXP_MAC =
            hex(
                    "7D AC 56 E4 8A 4D C1 70 FA A8 FC BA E2 0D B8 45"
                            + "45 0C CC C4 C6 32 8B DC 8D 01 15 7C EF A2 A5 F1");

    private static final byte[] KAT_K_EXP_ENC =
            hex(
                    "1F 1C BA D8 86 61 66 F0 1F FA AB 01 52 E2 4B F4"
                            + "60 9D 5F 46 A5 C8 99 C7 87 90 0D 08 B9 FC AD 24");

    private static final byte[] KAT_IV = hex("21 4A 6A 29 8E 99 E3 25");

    /** PMSEXP = KExp15(PMS, K_MAC, K_ENC, IV) — RFC 9189 Appendix A.1.3.2. */
    private static final byte[] KAT_PMSEXP =
            hex(
                    "25 0D 1B 67 A2 70 AB 04 D3 F6 54 18 E1 D3 80 B4"
                            + "CB 94 5F 0A 3D CA 51 50 0C F3 A1 BE F3 7F 76 C0"
                            + "73 41 A9 83 9C CF 6C BA 71 89 DA 61 EB 67 17 6C");

    private static final SymmetricKey KAT_ENC_KEY = new SymmetricKey(KAT_K_EXP_ENC);
    private static final SymmetricKey KAT_MAC_KEY = new SymmetricKey(KAT_K_EXP_MAC);

    @Test
    @DisplayName("KAT: kExp15 даёт эталонный PMSEXP из RFC 9189 Appendix A.1.3.2")
    void testKatKExp15() {
        byte[] result = KeyExport.kExp15(KAT_SECRET, KAT_MAC_KEY, KAT_ENC_KEY, KAT_IV);
        assertArrayEquals(KAT_PMSEXP, result);
    }

    @Test
    @DisplayName("KAT: kImp15 восстанавливает PMS из PMSEXP")
    void testKatKImp15() throws AuthenticationException {
        byte[] result = KeyExport.kImp15(KAT_PMSEXP, KAT_MAC_KEY, KAT_ENC_KEY, KAT_IV);
        assertArrayEquals(KAT_SECRET, result);
    }

    // -----------------------------------------------------------------------
    // Round-trip: разные длины секрета
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("round-trip: секрет 1 байт")
    void testRoundTrip1Byte() throws AuthenticationException {
        roundTrip(new byte[] {0x42});
    }

    @Test
    @DisplayName("round-trip: секрет 16 байт (ровно блок)")
    void testRoundTrip16Bytes() throws AuthenticationException {
        roundTrip(hex("01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10"));
    }

    @Test
    @DisplayName("round-trip: секрет 32 байта (2 блока)")
    void testRoundTrip32Bytes() throws AuthenticationException {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte) 0xAB);
        roundTrip(secret);
    }

    @Test
    @DisplayName("обратимость: секрет 256 байт")
    void testRoundTrip256Bytes() throws AuthenticationException {
        byte[] secret = new byte[256];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) i;
        }
        roundTrip(secret);
    }

    private void roundTrip(byte[] secret) throws AuthenticationException {
        byte[] iv = new byte[KeyExport.IV_LENGTH];
        Arrays.fill(iv, (byte) 0x55);
        byte[] encKeyBytes = new byte[KeyExport.KEY_LENGTH];
        byte[] macKeyBytes = new byte[KeyExport.KEY_LENGTH];
        Arrays.fill(encKeyBytes, (byte) 0x11);
        Arrays.fill(macKeyBytes, (byte) 0x22);
        SymmetricKey encKey = new SymmetricKey(encKeyBytes);
        SymmetricKey macKey = new SymmetricKey(macKeyBytes);

        byte[] wrapped = KeyExport.kExp15(secret, macKey, encKey, iv);
        assertEquals(secret.length + KeyExport.BLOCK_SIZE, wrapped.length);

        byte[] restored = KeyExport.kImp15(wrapped, macKey, encKey, iv);
        assertArrayEquals(secret, restored);
    }

    // -----------------------------------------------------------------------
    // Негативные тесты: повреждённые данные
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("kImp15: повреждён шифртекст (1 бит) -> AuthenticationException")
    void testTamperedCiphertext() {
        byte[] wrapped = KeyExport.kExp15(KAT_SECRET, KAT_MAC_KEY, KAT_ENC_KEY, KAT_IV);
        wrapped[0] ^= 0x01; // флип бита
        assertThrows(
                AuthenticationException.class,
                () -> KeyExport.kImp15(wrapped, KAT_MAC_KEY, KAT_ENC_KEY, KAT_IV));
    }

    @Test
    @DisplayName("kImp15: повреждён MAC-блок -> AuthenticationException")
    void testTamperedMacBlock() {
        byte[] wrapped = KeyExport.kExp15(KAT_SECRET, KAT_MAC_KEY, KAT_ENC_KEY, KAT_IV);
        wrapped[wrapped.length - 1] ^= 0x01; // флип бита в последнем байте (MAC)
        assertThrows(
                AuthenticationException.class,
                () -> KeyExport.kImp15(wrapped, KAT_MAC_KEY, KAT_ENC_KEY, KAT_IV));
    }

    @Test
    @DisplayName("kImp15: неверный K_MAC -> AuthenticationException")
    void testWrongMacKey() {
        byte[] badKeyBytes = new byte[KeyExport.KEY_LENGTH];
        Arrays.fill(badKeyBytes, (byte) 0xFF);
        SymmetricKey badKey = new SymmetricKey(badKeyBytes);
        assertThrows(
                AuthenticationException.class,
                () -> KeyExport.kImp15(KAT_PMSEXP, badKey, KAT_ENC_KEY, KAT_IV));
    }

    @Test
    @DisplayName("kImp15: неверный K_ENC -> AuthenticationException")
    void testWrongEncKey() {
        byte[] badKeyBytes = new byte[KeyExport.KEY_LENGTH];
        Arrays.fill(badKeyBytes, (byte) 0xFF);
        SymmetricKey badKey = new SymmetricKey(badKeyBytes);
        assertThrows(
                AuthenticationException.class,
                () -> KeyExport.kImp15(KAT_PMSEXP, KAT_MAC_KEY, badKey, KAT_IV));
    }

    @Test
    @DisplayName("kImp15: неверный IV -> AuthenticationException")
    void testWrongIv() {
        byte[] badIv = new byte[KeyExport.IV_LENGTH];
        Arrays.fill(badIv, (byte) 0xFF);
        assertThrows(
                AuthenticationException.class,
                () -> KeyExport.kImp15(KAT_PMSEXP, KAT_MAC_KEY, KAT_ENC_KEY, badIv));
    }

    // -----------------------------------------------------------------------
    // Guard tests: невалидные аргументы
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("kExp15: null secret -> IllegalArgumentException")
    void testNullSecret() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kExp15(null, KAT_MAC_KEY, KAT_ENC_KEY, KAT_IV));
    }

    @Test
    @DisplayName("kExp15: пустой secret -> IllegalArgumentException")
    void testEmptySecret() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kExp15(new byte[0], KAT_MAC_KEY, KAT_ENC_KEY, KAT_IV));
    }

    @Test
    @DisplayName("kExp15: null K_MAC -> IllegalArgumentException")
    void testNullMacKey() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kExp15(KAT_SECRET, null, KAT_ENC_KEY, KAT_IV));
    }

    @Test
    @DisplayName("kExp15: null K_ENC -> IllegalArgumentException")
    void testNullEncKey() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kExp15(KAT_SECRET, KAT_MAC_KEY, null, KAT_IV));
    }

    @Test
    @DisplayName("kExp15: null IV -> IllegalArgumentException")
    void testNullIv() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kExp15(KAT_SECRET, KAT_MAC_KEY, KAT_ENC_KEY, null));
    }

    @Test
    @DisplayName("kExp15: IV неверной длины -> IllegalArgumentException")
    void testInvalidIvLength() {
        byte[] badIv = new byte[7];
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kExp15(KAT_SECRET, KAT_MAC_KEY, KAT_ENC_KEY, badIv));
    }

    @Test
    @DisplayName("kImp15: null sExp -> IllegalArgumentException")
    void testNullSExp() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kImp15(null, KAT_MAC_KEY, KAT_ENC_KEY, KAT_IV));
    }

    @Test
    @DisplayName("kImp15: sExp короче 17 байт -> IllegalArgumentException")
    void testShortSExp() {
        byte[] tooShort = new byte[KeyExport.BLOCK_SIZE]; // 16 байт (только MAC, нет данных)
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kImp15(tooShort, KAT_MAC_KEY, KAT_ENC_KEY, KAT_IV));
    }

    @Test
    @DisplayName("kImp15: null K_MAC -> IllegalArgumentException")
    void testImpNullMacKey() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kImp15(KAT_PMSEXP, null, KAT_ENC_KEY, KAT_IV));
    }

    @Test
    @DisplayName("kImp15: null K_ENC -> IllegalArgumentException")
    void testImpNullEncKey() {
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kImp15(KAT_PMSEXP, KAT_MAC_KEY, null, KAT_IV));
    }

    @Test
    @DisplayName("kImp15: IV неверной длины -> IllegalArgumentException")
    void testImpInvalidIvLength() {
        byte[] badIv = new byte[9];
        assertThrows(
                IllegalArgumentException.class,
                () -> KeyExport.kImp15(KAT_PMSEXP, KAT_MAC_KEY, KAT_ENC_KEY, badIv));
    }

    // -----------------------------------------------------------------------
    // Хелпер: hex string -> byte[]
    // -----------------------------------------------------------------------

    private static byte[] hex(String s) {
        String cleaned = s.replaceAll("\\s+", "");
        int len = cleaned.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] =
                    (byte)
                            ((Character.digit(cleaned.charAt(i), 16) << 4)
                                    + Character.digit(cleaned.charAt(i + 1), 16));
        }
        return data;
    }
}
