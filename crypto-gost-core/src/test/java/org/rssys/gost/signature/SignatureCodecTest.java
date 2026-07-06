package org.rssys.gost.signature;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Тесты кодирования подписи {@link SignatureCodec#encode}.
 */
@DisplayName("SignatureCodec.encode")
class SignatureCodecTest {

    private static final ECParameters PARAMS_256 = ECParameters.cryptoProA();

    @Test
    @DisplayName("encode/decode roundtrip для валидных компонент")
    void encodeDecodeRoundtrip() {
        BigInteger r = BigInteger.valueOf(0x0102_0304L);
        BigInteger s = BigInteger.valueOf(0x0A0B_0C0DL);
        byte[] enc = SignatureCodec.encode(r, s, PARAMS_256);
        int rolen = (PARAMS_256.n.bitLength() + 7) / 8;
        assertEquals(2 * rolen, enc.length, "длина кодировки должна быть 2*rolen");
        BigInteger[] rs = SignatureCodec.decode(enc, PARAMS_256);
        assertEquals(r, rs[0], "r должен восстановиться");
        assertEquals(s, rs[1], "s должен восстановиться");
    }

    @Test
    @DisplayName("fail-closed: компонента шире поля -> IllegalArgumentException вместо усечения")
    void encodeThrowsOnOversizedComponent() {
        int rolen = (PARAMS_256.n.bitLength() + 7) / 8;
        // Значение 2^(8*(rolen+1)): toByteArray() даёт rolen+2 значащих байт,
        // что превышает допустимое поле (даже с учётом знакового байта) и раньше
        // молча усекалось. Порог reject — строго больше rolen+1.
        BigInteger oversized = BigInteger.ONE.shiftLeft(8 * (rolen + 1));
        assertTrue(oversized.toByteArray().length > rolen + 1, "предусловие теста");
        BigInteger ok = BigInteger.ONE;
        assertThrows(
                IllegalArgumentException.class,
                () -> SignatureCodec.encode(oversized, ok, PARAMS_256),
                "слишком большой r должен отклоняться, а не усекаться");
        assertThrows(
                IllegalArgumentException.class,
                () -> SignatureCodec.encode(ok, oversized, PARAMS_256),
                "слишком большой s должен отклоняться, а не усекаться");
    }

    @Test
    @DisplayName("значение с ведущим знаковым байтом (rolen+1) кодируется корректно")
    void encodeAcceptsSignByte() {
        int rolen = (PARAMS_256.n.bitLength() + 7) / 8;
        // 2^(8*rolen-1): старший бит установлен -> toByteArray() добавляет знаковый нуль,
        // итого rolen+1 байт — это легитимный случай, отклонять нельзя.
        BigInteger withSignByte = BigInteger.ONE.shiftLeft(8 * rolen - 1);
        assertEquals(rolen + 1, withSignByte.toByteArray().length, "ожидается знаковый байт");
        byte[] enc = SignatureCodec.encode(withSignByte, BigInteger.ONE, PARAMS_256);
        assertEquals(2 * rolen, enc.length, "кодировка должна пройти без исключения");
    }
}
