package org.rssys.gost.jca.spec;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;
import org.rssys.gost.util.Pack;

/**
 * Проверка длины содержимого закрытого ключа в {@link GostDerCodec#decodePrivateKey}:
 * маскированные ключи RFC 9548 §5.1 и неканонические длины не должны превращаться
 * в неверный скаляр.
 * <p>
 * Маскированный ключ собирается синтетически по §5.1: K_M = K · M⁻¹ mod q,
 * I = LE(K_M) ‖ LE(M₁) ‖ ... . Эталонная проверка на gost-engine вынесена в кросс-валидацию.
 */
@DisplayName("GostDerCodec: длина закрытого ключа и маскированные ключи RFC 9548")
class GostDerCodecPrivateKeyLengthTest {

    private static final ECParameters[] CURVES = {
        ECParameters.cryptoProA(), ECParameters.tc26a256(), ECParameters.tc26c512()
    };

    private static final BigInteger SAMPLE_KEY =
            new BigInteger("5a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef", 16);

    /** Собирает PKCS#8 с заданным содержимым I (little-endian), сохраняя AlgorithmIdentifier кривой. */
    private static byte[] pkcs8WithContent(ECParameters params, byte[] contentLittleEndian) {
        byte[] template =
                GostDerCodec.encodePrivateKey(new PrivateKeyParameters(SAMPLE_KEY, params));
        byte[][] outer = DerCodec.parseSequenceContents(template, 0);
        return DerCodec.encodeSequence(
                outer[0], outer[1], DerCodec.encodeOctetString(contentLittleEndian));
    }

    private static int scalarLength(ECParameters params) {
        return (params.n.bitLength() + 7) / 8;
    }

    private static byte[] littleEndian(BigInteger value, int length) {
        byte[] be = new byte[length];
        byte[] raw = value.toByteArray();
        int copy = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - copy, be, length - copy, copy);
        return Pack.reverseBytes(be);
    }

    /** I = LE(K_M) ‖ LE(M₁) ‖ ... для заданного K и масок (K = K_M · M₁ · ... mod q). */
    private static byte[] maskedContent(ECParameters params, BigInteger key, BigInteger... masks) {
        int n = scalarLength(params);
        BigInteger maskProduct = BigInteger.ONE;
        for (BigInteger mask : masks) {
            maskProduct = maskProduct.multiply(mask).mod(params.n);
        }
        BigInteger maskedKey = key.multiply(maskProduct.modInverse(params.n)).mod(params.n);
        byte[] content = littleEndian(maskedKey, n);
        for (BigInteger mask : masks) {
            byte[] maskBytes = littleEndian(mask, n);
            byte[] joined = Arrays.copyOf(content, content.length + n);
            System.arraycopy(maskBytes, 0, joined, content.length, n);
            content = joined;
        }
        return content;
    }

    @Test
    @DisplayName("Ключ длины n принимается и возвращает тот же d")
    void exactLengthIsAccepted() {
        for (ECParameters p : CURVES) {
            byte[] der = GostDerCodec.encodePrivateKey(new PrivateKeyParameters(SAMPLE_KEY, p));
            PrivateKeyParameters decoded = GostDerCodec.decodePrivateKey(der);
            assertEquals(SAMPLE_KEY, decoded.getD(), "d после круга encode/decode: " + p.n);
            decoded.destroy();
        }
    }

    @Test
    @DisplayName("Ключ короче n (обрезанные нулевые старшие байты) принимается")
    void shortLengthIsAccepted() {
        for (ECParameters p : CURVES) {
            byte[] der = pkcs8WithContent(p, new byte[] {5});
            PrivateKeyParameters decoded = GostDerCodec.decodePrivateKey(der);
            assertEquals(BigInteger.valueOf(5), decoded.getD(), "d = 5 при |I| = 1: " + p.n);
            decoded.destroy();
        }
    }

    @Test
    @DisplayName("Маскированный ключ k=1 -> UnsupportedOperationException, а не неверный скаляр")
    void maskedKeyK1IsRejected() {
        for (ECParameters p : CURVES) {
            BigInteger mask = new BigInteger("1234567890abcdef1234567890abcdef", 16);
            byte[] der = pkcs8WithContent(p, maskedContent(p, SAMPLE_KEY, mask));
            assertThrows(
                    UnsupportedOperationException.class,
                    () -> GostDerCodec.decodePrivateKey(der),
                    "маскированный I = K_M || M должен быть отвергнут: " + p.n);
        }
    }

    @Test
    @DisplayName("Маскированный ключ k=2 (|I| = 3n) -> UnsupportedOperationException")
    void maskedKeyK2IsRejected() {
        for (ECParameters p : CURVES) {
            BigInteger mask1 = new BigInteger("1234567890abcdef1234567890abcdef", 16);
            BigInteger mask2 = new BigInteger("fedcba0987654321fedcba0987654321", 16);
            byte[] der = pkcs8WithContent(p, maskedContent(p, SAMPLE_KEY, mask1, mask2));
            assertThrows(
                    UnsupportedOperationException.class,
                    () -> GostDerCodec.decodePrivateKey(der),
                    "маскированный I = K_M || M1 || M2 должен быть отвергнут: " + p.n);
        }
    }

    @Test
    @DisplayName("checkNotMasked отвергает тот же маскированный ключ")
    void checkNotMaskedRejectsMasked() {
        for (ECParameters p : CURVES) {
            byte[] der =
                    pkcs8WithContent(
                            p, maskedContent(p, SAMPLE_KEY, BigInteger.valueOf(0xABCDEFL)));
            assertThrows(
                    UnsupportedOperationException.class,
                    () -> GostDerCodec.checkNotMasked(der),
                    "checkNotMasked должен отвергать маскированный ключ: " + p.n);
        }
    }

    @Test
    @DisplayName("Нулевая маска (|I| = 2n, хвост из нулей) -> IllegalArgumentException")
    void zeroMaskIsRejectedAsNonCanonical() {
        for (ECParameters p : CURVES) {
            int n = scalarLength(p);
            byte[] content = Arrays.copyOf(littleEndian(SAMPLE_KEY, n), 2 * n);
            byte[] der = pkcs8WithContent(p, content);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> GostDerCodec.decodePrivateKey(der),
                    "нулевая маска не должна давать d = K_M: " + p.n);
        }
    }

    @Test
    @DisplayName("|I| = n+1 с нулевым последним байтом -> IllegalArgumentException")
    void oneExtraZeroByteIsRejectedAsNonCanonical() {
        for (ECParameters p : CURVES) {
            int n = scalarLength(p);
            byte[] content = Arrays.copyOf(littleEndian(SAMPLE_KEY, n), n + 1);
            byte[] der = pkcs8WithContent(p, content);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> GostDerCodec.decodePrivateKey(der),
                    "неканоническая длина n+1 должна быть отвергнута: " + p.n);
        }
    }

    @Test
    @DisplayName("|I| = n+1 с ненулевым последним байтом -> UnsupportedOperationException")
    void oneExtraNonZeroByteIsRejectedAsMasked() {
        for (ECParameters p : CURVES) {
            int n = scalarLength(p);
            byte[] content = Arrays.copyOf(littleEndian(SAMPLE_KEY, n), n + 1);
            content[n] = 1;
            byte[] der = pkcs8WithContent(p, content);
            assertThrows(
                    UnsupportedOperationException.class,
                    () -> GostDerCodec.decodePrivateKey(der),
                    "ненулевой байт за n означает маскированный ключ: " + p.n);
        }
    }

    @Test
    @DisplayName("KeyFactory.generatePrivate на маскированном PKCS#8 -> InvalidKeySpecException")
    void keyFactoryRejectsMaskedKey() throws Exception {
        JcaTestSupport.ensureProvider();
        KeyFactory keyFactory = KeyFactory.getInstance("ECGOST3410-2012");
        for (ECParameters p : CURVES) {
            byte[] der =
                    pkcs8WithContent(
                            p, maskedContent(p, SAMPLE_KEY, BigInteger.valueOf(0xABCDEFL)));
            assertThrows(
                    InvalidKeySpecException.class,
                    () -> keyFactory.generatePrivate(new PKCS8EncodedKeySpec(der)),
                    "KeyFactory не должен молча принимать маскированный ключ: " + p.n);
        }
    }
}
