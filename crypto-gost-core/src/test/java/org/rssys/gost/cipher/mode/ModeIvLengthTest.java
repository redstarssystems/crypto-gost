package org.rssys.gost.cipher.mode;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.cipher.CipherParameters;
import org.rssys.gost.cipher.Kuznyechik;
import org.rssys.gost.cipher.ParametersWithIV;
import org.rssys.gost.cipher.SymmetricKey;

@DisplayName("Длина IV режимов CBC, CFB, OFB: регистр m = n·z (ГОСТ Р 34.13-2015)")
class ModeIvLengthTest {

    private static final HexFormat HEX = HexFormat.of();

    private static final byte[] KEY =
            HEX.parseHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");

    /** Синхропосылка 32 байта (m = 2n): приложение А стандарта, контрольные примеры CBC, OFB, CFB. */
    private static final byte[] IV32 =
            HEX.parseHex("1234567890abcef0a1b2c3d4e5f001122334455667788990" + "1213141516171819");

    private static final byte[] PLAIN =
            HEX.parseHex(
                    "1122334455667700ffeeddccbbaa9988"
                            + "00112233445566778899aabbcceeff0a"
                            + "112233445566778899aabbcceeff0a00"
                            + "2233445566778899aabbcceeff0a0011");

    /** Шифртекст CBC для IV из 32 байт: контрольный пример ГОСТ Р 34.13-2015, А.1.4. */
    private static final byte[] CBC_CIPHER_IV32 =
            HEX.parseHex(
                    "689972d4a085fa4d90e52e3d6d7dcc27"
                            + "2826e661b478eca6af1e8e448d5ea5ac"
                            + "fe7babf1e91999e85640e8b0f49d90d0"
                            + "167688065a895c631a2d9a1560b63970");

    private static CipherParameters params(byte[] iv) {
        return new ParametersWithIV(new SymmetricKey(KEY), iv);
    }

    private static byte[] cbcEncrypt(byte[] iv) {
        Cbc cbc = new Cbc(new Kuznyechik());
        cbc.init(true, params(iv));
        byte[] out = new byte[PLAIN.length];
        for (int off = 0; off < PLAIN.length; off += 16) {
            cbc.processBlock(PLAIN, off, out, off);
        }
        return out;
    }

    @Test
    @DisplayName("CBC с IV из 32 байт (m = 2n) даёт контрольный пример А.1.4 стандарта")
    void cbcWithTwoBlockRegisterMatchesStandard() {
        assertArrayEquals(
                CBC_CIPHER_IV32,
                cbcEncrypt(IV32),
                "шифртекст CBC при m = 2n должен совпасть с контрольным примером стандарта");
    }

    @Test
    @DisplayName("CBC с IV из 32 байт расшифровывается обратно в исходный текст")
    void cbcWithTwoBlockRegisterRoundTrips() {
        Cbc cbc = new Cbc(new Kuznyechik());
        cbc.init(false, params(IV32));
        byte[] plain = new byte[PLAIN.length];
        for (int off = 0; off < PLAIN.length; off += 16) {
            cbc.processBlock(CBC_CIPHER_IV32, off, plain, off);
        }
        assertArrayEquals(PLAIN, plain, "расшифрование при m = 2n должно вернуть открытый текст");
    }

    @Test
    @DisplayName("IV из 32 байт и его первые 16 байт дают разные режимы, а не один")
    void longIvIsNotTruncatedIv() {
        byte[] withShort = cbcEncrypt(Arrays.copyOf(IV32, 16));
        assertArrayEquals(
                Arrays.copyOf(CBC_CIPHER_IV32, 16),
                Arrays.copyOf(withShort, 16),
                "первый блок зависит только от первых n байт регистра");
        assertFalse(
                Arrays.equals(CBC_CIPHER_IV32, withShort),
                "со второго блока регистр m = 2n и m = n расходятся");
    }

    @ParameterizedTest(name = "длина IV {0}")
    @ValueSource(ints = {0, 1, 15, 17, 24, 31, 33, 47})
    @DisplayName("IV, длина которого не кратна размеру блока, отвергается во всех режимах")
    void ivNotMultipleOfBlockIsRejected(int length) {
        CipherParameters invalid = params(new byte[length]);
        assertThrows(
                IllegalArgumentException.class,
                () -> new Cbc(new Kuznyechik()).init(true, invalid),
                "CBC должен отвергать IV длиной " + length);
        assertThrows(
                IllegalArgumentException.class,
                () -> new Cfb(new Kuznyechik()).init(true, invalid),
                "CFB должен отвергать IV длиной " + length);
        assertThrows(
                IllegalArgumentException.class,
                () -> new Ofb(new Kuznyechik()).init(true, invalid),
                "OFB должен отвергать IV длиной " + length);
    }

    @ParameterizedTest(name = "длина IV {0}")
    @ValueSource(ints = {16, 32, 48})
    @DisplayName("IV, кратный размеру блока, принимается во всех режимах")
    void ivMultipleOfBlockIsAccepted(int length) {
        CipherParameters valid = params(new byte[length]);
        assertDoesNotThrow(() -> new Cbc(new Kuznyechik()).init(true, valid));
        assertDoesNotThrow(() -> new Cfb(new Kuznyechik()).init(true, valid));
        assertDoesNotThrow(() -> new Ofb(new Kuznyechik()).init(true, valid));
    }

    @ParameterizedTest(name = "длина IV {0}")
    @ValueSource(ints = {0, 7, 9, 16, 32})
    @DisplayName("CTR принимает IV ровно в 8 байт")
    void ctrAcceptsOnlyEightBytes(int length) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new Ctr(new Kuznyechik()).init(true, params(new byte[length])),
                "CTR должен отвергать IV длиной " + length);
    }
}
