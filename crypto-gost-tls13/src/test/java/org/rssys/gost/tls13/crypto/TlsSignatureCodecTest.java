package org.rssys.gost.tls13.crypto;
import org.rssys.gost.tls13.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.signature.ECDSASigner;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.api.Digest;
import org.rssys.gost.digest.Streebog256;

import java.math.BigInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("TlsSignatureCodec — LE fixed-length signature encode/decode/sign/verify (RFC 9367 §3.2)")
class TlsSignatureCodecTest {

    private static final int ROLEN_256 = 32;
    private static final int ROLEN_512 = 64;

    // ========================================================================
    // encode/decode roundtrip
    // ========================================================================

    @Test
    @DisplayName("encode/decode roundtrip для 256-бит")
    void testEncodeDecodeRoundtrip256() {
        BigInteger r = new BigInteger("1234567890ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 16);
        BigInteger s = new BigInteger("FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321", 16);
        byte[] encoded = TlsSignatureCodec.encode(r, s, ROLEN_256);
        assertEquals(64, encoded.length);
        BigInteger[] decoded = TlsSignatureCodec.decode(encoded, ROLEN_256);
        assertEquals(r, decoded[0]);
        assertEquals(s, decoded[1]);
    }

    @Test
    @DisplayName("encode/decode roundtrip для 512-бит")
    void testEncodeDecodeRoundtrip512() {
        BigInteger r = new BigInteger("A".repeat(128), 16);
        BigInteger s = new BigInteger("B".repeat(128), 16);
        byte[] encoded = TlsSignatureCodec.encode(r, s, ROLEN_512);
        assertEquals(128, encoded.length);
        BigInteger[] decoded = TlsSignatureCodec.decode(encoded, ROLEN_512);
        assertEquals(r, decoded[0]);
        assertEquals(s, decoded[1]);
    }

    @Test
    @DisplayName("encode: little-endian формат (младший байт в начале)")
    void testEncodeLittleEndian() {
        // r = 0x01020304..., s = 0x05060708...
        byte[] rBytes = new byte[32];
        byte[] sBytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            rBytes[i] = (byte) (i + 1);
            sBytes[i] = (byte) (i + 33);
        }
        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        byte[] encoded = TlsSignatureCodec.encode(r, s, ROLEN_256);

        // first byte of r should be the least significant byte of r
        assertEquals(32, encoded[0]); // r = 0x0102...20, LS byte is 0x20
        assertEquals(31, encoded[1]);
        // first byte of s should be LS byte of s
        assertEquals(64, encoded[32]); // s = 0x21...40, LS byte is 0x40
        assertEquals(63, encoded[33]);
    }

    @Test
    @DisplayName("decode: нулевые компоненты")
    void testDecodeZero() {
        byte[] sig = new byte[64];
        BigInteger[] decoded = TlsSignatureCodec.decode(sig, ROLEN_256);
        assertEquals(BigInteger.ZERO, decoded[0]);
        assertEquals(BigInteger.ZERO, decoded[1]);
    }

    @Test
    @DisplayName("decode: длины компонент не совпадают с rolen → ошибка")
    void testDecodeWrongLength() {
        byte[] sig = new byte[32]; // too short for 2*rolen
        assertThrows(IllegalArgumentException.class,
                () -> TlsSignatureCodec.decode(sig, ROLEN_256));
    }

    // ========================================================================
    // sign/verify с реальными ключами
    // ========================================================================

    @Test
    @DisplayName("sign/verify roundtrip для 256-бит tc26-A")
    void testSignVerify256() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] hash = Digest.digest256("test message".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] sig = TlsSignatureCodec.sign(hash, kp.getPrivate(), ROLEN_256);
        assertEquals(64, sig.length);
        assertTrue(TlsSignatureCodec.verify(hash, sig, kp.getPublic(), ROLEN_256));
    }

    @Test
    @DisplayName("sign/verify для CryptoPro-A (другая кривая)")
    void testSignVerifyCryptoProA() throws Exception {
        ECParameters params = ECParameters.cryptoProA();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] hash = Digest.digest256("another message".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] sig = TlsSignatureCodec.sign(hash, kp.getPrivate(), ROLEN_256);
        assertTrue(TlsSignatureCodec.verify(hash, sig, kp.getPublic(), ROLEN_256));
    }

    @Test
    @DisplayName("sign: детерминизм (одинаковые ключи+данные → одинаковая подпись)")
    void testSignDeterminism() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] hash = Digest.digest256("deterministic test".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        Supplier<org.rssys.gost.digest.Digest> factory = Streebog256::new;
        ECDSASigner signer = new ECDSASigner(factory);
        signer.init(true, kp.getPrivate());
        BigInteger[] rs = signer.generateSignature(hash);

        byte[] sig = TlsSignatureCodec.encode(rs[0], rs[1], ROLEN_256);
        assertTrue(TlsSignatureCodec.verify(hash, sig, kp.getPublic(), ROLEN_256));
    }

    @Test
    @DisplayName("verify: подмена подписи → false")
    void testVerifyTamperedSignature() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] hash = Digest.digest256("tamper test".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] sig = TlsSignatureCodec.sign(hash, kp.getPrivate(), ROLEN_256);
        sig[0] ^= 0xFF; // flip a bit in the signature
        assertFalse(TlsSignatureCodec.verify(hash, sig, kp.getPublic(), ROLEN_256));
    }

    @Test
    @DisplayName("verify: другой ключ → false")
    void testVerifyWrongKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp1 = KeyGenerator.generateKeyPair(params);
        org.rssys.gost.api.KeyPair kp2 = KeyGenerator.generateKeyPair(params);
        byte[] hash = Digest.digest256("wrong key test".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] sig = TlsSignatureCodec.sign(hash, kp1.getPrivate(), ROLEN_256);
        assertFalse(TlsSignatureCodec.verify(hash, sig, kp2.getPublic(), ROLEN_256));
    }

    @Test
    @DisplayName("verify: подмена хеша → false")
    void testVerifyTamperedHash() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] hash1 = Digest.digest256("original message".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] hash2 = Digest.digest256("tampered message".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] sig = TlsSignatureCodec.sign(hash1, kp.getPrivate(), ROLEN_256);
        assertFalse(TlsSignatureCodec.verify(hash2, sig, kp.getPublic(), ROLEN_256));
    }

    @Test
    @DisplayName("verify: null public key → NPE")
    void testVerifyNullPubKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        byte[] hash = Digest.digest256("test".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] sig = new byte[64];
        assertThrows(IllegalArgumentException.class,
                () -> TlsSignatureCodec.verify(hash, sig, null, ROLEN_256));
    }

    // ========================================================================
    // 512-бит sign/verify
    // ========================================================================

    @Test
    @DisplayName("sign/verify roundtrip для 512-бит tc26-A")
    void testSignVerify512A() throws Exception {
        ECParameters params = ECParameters.tc26a512();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] hash = Digest.digest512("test 512-a".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] sig = TlsSignatureCodec.sign(hash, kp.getPrivate(), ROLEN_512);
        assertEquals(128, sig.length);
        assertTrue(TlsSignatureCodec.verify(hash, sig, kp.getPublic(), ROLEN_512));
    }

    @Test
    @DisplayName("sign/verify roundtrip для 512-бит tc26-B")
    void testSignVerify512B() throws Exception {
        ECParameters params = ECParameters.tc26b512();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] hash = Digest.digest512("test 512-b".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] sig = TlsSignatureCodec.sign(hash, kp.getPrivate(), ROLEN_512);
        assertTrue(TlsSignatureCodec.verify(hash, sig, kp.getPublic(), ROLEN_512));
    }

    @Test
    @DisplayName("sign/verify roundtrip для 512-бит tc26-C")
    void testSignVerify512C() throws Exception {
        ECParameters params = ECParameters.tc26c512();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] hash = Digest.digest512("test 512-c".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] sig = TlsSignatureCodec.sign(hash, kp.getPrivate(), ROLEN_512);
        assertTrue(TlsSignatureCodec.verify(hash, sig, kp.getPublic(), ROLEN_512));
    }

    @Test
    @DisplayName("verify: 512-бит подмена подписи → false")
    void testVerifyTamperedSignature512() throws Exception {
        ECParameters params = ECParameters.tc26a512();
        org.rssys.gost.api.KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] hash = Digest.digest512("tamper 512".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] sig = TlsSignatureCodec.sign(hash, kp.getPrivate(), ROLEN_512);
        sig[0] ^= 0xFF;
        assertFalse(TlsSignatureCodec.verify(hash, sig, kp.getPublic(), ROLEN_512));
    }

    @Test
    @DisplayName("verify: 512-бит другой ключ → false")
    void testVerifyWrongKey512() throws Exception {
        ECParameters params = ECParameters.tc26a512();
        org.rssys.gost.api.KeyPair kp1 = KeyGenerator.generateKeyPair(params);
        org.rssys.gost.api.KeyPair kp2 = KeyGenerator.generateKeyPair(params);
        byte[] hash = Digest.digest512("wrong key 512".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] sig = TlsSignatureCodec.sign(hash, kp1.getPrivate(), ROLEN_512);
        assertFalse(TlsSignatureCodec.verify(hash, sig, kp2.getPublic(), ROLEN_512));
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================


}
