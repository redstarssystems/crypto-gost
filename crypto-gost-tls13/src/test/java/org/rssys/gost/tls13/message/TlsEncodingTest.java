package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.tls13.*;

@DisplayName("TlsEncoding: encode/decode, ECDHE, утилиты")
class TlsEncodingTest {

    @Test
    @DisplayName("encodeUint16: корректная упаковка short")
    void testEncodeUint16() {
        assertArrayEquals(new byte[] {0x00, 0x00}, encode16(0));
        assertArrayEquals(new byte[] {0x00, 0x01}, encode16(1));
        assertArrayEquals(new byte[] {0x00, (byte) 0xFF}, encode16(255));
        assertArrayEquals(new byte[] {0x01, 0x00}, encode16(256));
        assertArrayEquals(new byte[] {(byte) 0xFF, (byte) 0xFF}, encode16(65535));
    }

    @Test
    @DisplayName("encodeUint24: корректная упаковка 24-битного значения")
    void testEncodeUint24() {
        assertArrayEquals(new byte[] {0x00, 0x00, 0x00}, encode24(0));
        assertArrayEquals(new byte[] {0x00, 0x00, 0x01}, encode24(1));
        assertArrayEquals(new byte[] {0x00, 0x00, (byte) 0xFF}, encode24(255));
        assertArrayEquals(new byte[] {0x00, 0x01, 0x00}, encode24(256));
        assertArrayEquals(new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF}, encode24(0xFFFFFF));
    }

    @Test
    @DisplayName("encodeExtension: формат type(2) + length(2) + data")
    void testEncodeExtension() {
        byte[] data = new byte[] {0x01, 0x02, 0x03};
        byte[] encoded = encodeExt(TlsConstants.EXT_KEY_SHARE, data);
        assertEquals(7, encoded.length);
        assertEquals(TlsConstants.EXT_KEY_SHARE, ((encoded[0] & 0xFF) << 8) | (encoded[1] & 0xFF));
        assertEquals(0x00, encoded[2] & 0xFF);
        assertEquals(0x03, encoded[3] & 0xFF);
    }

    @Test
    @DisplayName("toFixedLengthBytes: точное совпадение длины")
    void testToFixedLengthBytesExact() {
        BigInteger v = new BigInteger("1234567890abcdef1234567890abcdef", 16);
        byte[] result = TlsEncoding.toFixedLengthBytes(v, 16);
        assertEquals(16, result.length);
        assertEquals(v, new BigInteger(1, result));
    }

    @Test
    @DisplayName("toFixedLengthBytes: дополнение нулями слева")
    void testToFixedLengthBytesPadLeft() {
        assertArrayEquals(
                new byte[] {0x00, 0x00, 0x00, (byte) 0xFF},
                TlsEncoding.toFixedLengthBytes(BigInteger.valueOf(255), 4));
    }

    @Test
    @DisplayName("toFixedLengthBytes: обрезка знакового байта BigInteger")
    void testToFixedLengthBytesTrimLeadingZero() {
        BigInteger v = new BigInteger("80000000000000000000000000000000", 16);
        byte[] result = TlsEncoding.toFixedLengthBytes(v, 16);
        assertEquals(16, result.length);
        assertEquals(0x80, result[0] & 0xFF);
    }

    @Test
    @DisplayName("toFixedLengthBytes: отрицательное значение — дополнение нулями")
    void testToFixedLengthBytesNegative() {
        byte[] result = TlsEncoding.toFixedLengthBytes(BigInteger.valueOf(-1), 4);
        assertEquals(4, result.length);
        assertEquals(0x00, result[0] & 0xFF);
        assertEquals(0x00, result[1] & 0xFF);
        assertEquals(0x00, result[2] & 0xFF);
        assertEquals(0xFF, result[3] & 0xFF);
    }

    @Test
    @DisplayName("encodePoint/decodePoint: обратимость 256")
    void testEncodeDecodePoint256() throws TlsException {
        testPointRoundtrip(ECParameters.tc26a256());
    }

    @Test
    @DisplayName("encodePoint/decodePoint: обратимость 512")
    void testEncodeDecodePoint512() throws TlsException {
        testPointRoundtrip(ECParameters.tc26a512());
    }

    private void testPointRoundtrip(ECParameters params) throws TlsException {
        var kp = KeyGenerator.generateKeyPair(params);
        PublicKeyParameters pub = kp.getPublic();

        byte[] encoded = TlsEncoding.encodePoint(pub);
        assertEquals(params.hlen * 2, encoded.length);

        PublicKeyParameters decoded = TlsEncoding.decodePoint(encoded, params);
        assertEquals(pub.getQ().getX(), decoded.getQ().getX());
        assertEquals(pub.getQ().getY(), decoded.getQ().getY());
    }

    @Test
    @DisplayName("decodePoint: точка не на кривой -> handshake_failure")
    void testDecodePointNotOnCurveThrows() {
        ECParameters params = ECParameters.tc26a256();
        byte[] raw = new byte[64];
        TlsException e =
                assertThrows(TlsException.class, () -> TlsEncoding.decodePoint(raw, params));
        assertEquals(TlsConstants.ALERT_HANDSHAKE_FAILURE, e.getAlertCode());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static byte[] encode16(int value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsEncoding.encodeUint16(out, value);
        return out.toByteArray();
    }

    private static byte[] encode24(int value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsEncoding.encodeUint24(out, value);
        return out.toByteArray();
    }

    private static byte[] encodeExt(int type, byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        TlsEncoding.encodeExtension(out, type, data);
        return out.toByteArray();
    }
}
