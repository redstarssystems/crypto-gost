package org.rssys.gost;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.rssys.gost.digest.Digest;
import org.rssys.gost.digest.Streebog256;
import org.rssys.gost.digest.Streebog512;
import org.rssys.gost.signature.*;
import org.rssys.gost.signature.NonceMode;

// -----------------------------------------------------------------------
// RFC 7091 §7: тест-векторы из официального приложения к ГОСТ Р 34.10-2012
//
// Параметры кривой (256-bit, §7.1):
//   p  = 0x8000000000000000000000000000000000000000000000000000000000000431
//   a  = 0x7
//   b  = 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E
//   q  = 0x80000000000000000000000000000001 50FE8A1892976154C59CFC193ACCF5B3
//   Px = 0x2
//   Py = 0x8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8
//
// Ключи (§7.1.6-7):
//   d  = 0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28
//   Qx = 0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B
//   Qy = 0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA
//
// Подпись (§7.2):
//   e  = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
//   k  = 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3
//   r  = 0x41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493
//   s  = 0x1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40
// -----------------------------------------------------------------------

@DisplayName("ГОСТ Р 34.10-2012: подпись и эталонные векторы")
class SignatureTest {

    // -----------------------------------------------------------------------
    // Roundtrip: sign then verify (using pre-hashed values via bare signer)
    // -----------------------------------------------------------------------

    private static byte[] doHash(Digest digest, byte[] msg) {
        digest.update(msg, 0, msg.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    @Test
    @DisplayName("Tc26-256-paramSetA: подпись и проверка")
    void testRoundtrip256() {
        roundtrip(
                ECParameters.tc26a256(),
                Streebog256::new,
                "0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8090A1B2C3D4E5F6A7B8C9D0E1F");
    }

    @Test
    @DisplayName("Tc26-512-paramSetA: подпись и проверка")
    void testRoundtrip512() {
        roundtrip(
                ECParameters.tc26a512(),
                Streebog512::new,
                "1C5B9A9D9C5B7AD29A2D74A4D4A3B9E4D5F6A7B8C9D0E1F2A3B4C5D6E7F8090A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8090A1B2C3D4E5F6A7B8");
    }

    private void roundtrip(ECParameters params, Supplier<Digest> digestFactory, String privKeyHex) {
        BigInteger d = new BigInteger(privKeyHex, 16);
        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint Q = g.multiply(d);
        assertTrue(Q.isOnCurve(), "public key on curve");

        PrivateKeyParameters priv = new PrivateKeyParameters(d, params);
        PublicKeyParameters pub = new PublicKeyParameters(Q, params);

        byte[] msg = "test message for GOST signature".getBytes(StandardCharsets.UTF_8);
        byte[] hash = doHash(digestFactory.get(), msg);

        ECDSASigner signer = new ECDSASigner(digestFactory, NonceMode.DETERMINISTIC, null);
        signer.init(true, priv);
        BigInteger[] sig = signer.generateSignature(hash);

        signer.init(false, pub);
        assertTrue(signer.verifySignature(hash, sig[0], sig[1]), "roundtrip");

        // wrong key should reject
        BigInteger wrongD =
                d.add(BigInteger.ONE).mod(params.n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        ECPoint wrongQ = g.multiply(wrongD);
        signer.init(false, new PublicKeyParameters(wrongQ, params));
        assertFalse(signer.verifySignature(hash, sig[0], sig[1]), "wrong key rejects");
    }

    // -----------------------------------------------------------------------
    // Curve validation
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Все кривые: базовая точка лежит на кривой, n·G равно бесконечности")
    void testBasePointOnCurve() {
        ECParameters[] curves = {
            ECParameters.tc26a256(),
            ECParameters.tc26a512(),
            ECParameters.tc26b512(),
            ECParameters.tc26c512(),
            ECParameters.cryptoProA(),
            ECParameters.cryptoProB(),
            ECParameters.cryptoProC()
        };
        for (ECParameters p : curves) {
            ECPoint g = ECPoint.affine(p.gx, p.gy, p);
            assertTrue(
                    g.isOnCurve(),
                    "base point on curve: " + p.p.toString(16).substring(0, 8) + "...");
            assertTrue(
                    g.multiply(p.n).isInfinity(),
                    "n*G = infinity: " + p.p.toString(16).substring(0, 8) + "...");
        }
    }

    /** Закрытые ключи для прямого прохода {@code DigestSigner}: 256 и 512 бит. */
    private static final String DIGEST_SIGNER_KEY_256_HEX =
            "0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8090A1B2C3D4E5F6A7B8C9D0E1F";

    private static final String DIGEST_SIGNER_KEY_512_HEX =
            "1C5B9A9D9C5B7AD29A2D74A4D4A3B9E4D5F6A7B8C9D0E1F2A3B4C5D6E7F8090A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8090A1B2C3D4E5F6A7B8";

    /**
     * Прямой проход {@code DigestSigner}: он открытый и работает без {@code api.Signature}, поэтому
     * покрытие через высокоуровневый API его самого не заменяет.
     */
    @ParameterizedTest(
            name =
                    "DigestSigner, {0} бит: подпись и проверка, изменённые сообщение и подпись отвергаются")
    @ValueSource(ints = {256, 512})
    void testDigestSignerRoundtrip(int bits) {
        boolean is256 = bits == 256;
        ECParameters params = is256 ? ECParameters.tc26a256() : ECParameters.tc26a512();
        Supplier<Digest> digestFactory = is256 ? Streebog256::new : Streebog512::new;
        BigInteger d =
                new BigInteger(is256 ? DIGEST_SIGNER_KEY_256_HEX : DIGEST_SIGNER_KEY_512_HEX, 16);
        ECPoint q = ECPoint.affine(params.gx, params.gy, params).multiply(d);
        PrivateKeyParameters priv = new PrivateKeyParameters(d, params);
        PublicKeyParameters pub = new PublicKeyParameters(q, params);

        DigestSigner signer =
                new DigestSigner(
                        new ECDSASigner(digestFactory, NonceMode.DETERMINISTIC, null),
                        digestFactory.get());
        byte[] message = "DigestSigner: прямой проход".getBytes(StandardCharsets.UTF_8);

        signer.init(true, priv);
        signer.update(message, 0, message.length);
        byte[] signature = signer.sign();
        assertEquals(bits / 4, signature.length, "длина подписи: две компоненты по bits / 8 байт");

        signer.init(false, pub);
        signer.update(message, 0, message.length);
        assertTrue(signer.verify(signature), "подпись должна проверяться");

        byte[] changedMessage = message.clone();
        changedMessage[0] ^= 0x01;
        signer.init(false, pub);
        signer.update(changedMessage, 0, changedMessage.length);
        assertFalse(signer.verify(signature), "изменённое сообщение должно отвергаться");

        byte[] changedSignature = signature.clone();
        changedSignature[0] ^= 0x01;
        signer.init(false, pub);
        signer.update(message, 0, message.length);
        assertFalse(signer.verify(changedSignature), "изменённая подпись должна отвергаться");
    }

    @Test
    @DisplayName("Точка в бесконечности")
    void testInfinity() {
        ECPoint inf = ECPoint.infinity(ECParameters.tc26a256());
        assertTrue(inf.isInfinity());
        ECPoint norm = inf.normalize();
        assertTrue(norm.isInfinity());
    }

    // -----------------------------------------------------------------------
    // RFC 7091 §7: официальные тест-векторы ГОСТ Р 34.10-2012
    // -----------------------------------------------------------------------

    /**
     * Параметры кривой из RFC 7091 §7.1 (256-bit).
     * Это тестовая кривая, отличная от tc26a256 — используется только для проверки
     * соответствия реализации стандарту.
     */
    private static ECParameters rfc7091Curve() {
        return new ECParameters(
                // p
                "8000000000000000000000000000000000000000000000000000000000000431",
                // a
                "7",
                // b
                "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E",
                // gx
                "2",
                // gy
                "08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8",
                // q (= m для данной кривой, n = 1)
                "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3",
                // hlen
                32,
                // cofactor
                1);
    }

    @Test
    @DisplayName("RFC 7091 §7.1: базовая точка G лежит на кривой и q*G = O")
    void testRfc7091BasePoint() {
        ECParameters params = rfc7091Curve();
        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        assertTrue(g.isOnCurve(), "RFC 7091 base point must be on curve");
        assertTrue(g.multiply(params.n).isInfinity(), "q*G must be the point at infinity");
    }

    @Test
    @DisplayName("RFC 7091 §7.1: Q = d*G совпадает с эталонным открытым ключом")
    void testRfc7091PublicKeyDerivation() {
        ECParameters params = rfc7091Curve();

        BigInteger d =
                new BigInteger(
                        "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28", 16);
        BigInteger expectedQx =
                new BigInteger(
                        "7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B", 16);
        BigInteger expectedQy =
                new BigInteger(
                        "26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA", 16);

        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint Q = g.multiply(d).normalize();

        assertEquals(expectedQx, Q.getX(), "RFC 7091 Qx mismatch");
        assertEquals(expectedQy, Q.getY(), "RFC 7091 Qy mismatch");
    }

    @Test
    @DisplayName("RFC 7091 §7.2: k*G даёт эталонный x_C = r")
    void testRfc7091KTimesG() {
        ECParameters params = rfc7091Curve();

        BigInteger k =
                new BigInteger(
                        "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3", 16);
        BigInteger expectedR =
                new BigInteger(
                        "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493", 16);

        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint C = g.multiply(k).normalize();

        assertEquals(expectedR, C.getX().mod(params.n), "RFC 7091 x_C mod q must equal r");
    }

    @Test
    @DisplayName("RFC 7091 §7.2: s = (r*d + k*e) mod q совпадает с эталоном")
    void testRfc7091SignatureFormula() {
        ECParameters params = rfc7091Curve();

        BigInteger d =
                new BigInteger(
                        "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28", 16);
        BigInteger e =
                new BigInteger(
                        "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5", 16);
        BigInteger k =
                new BigInteger(
                        "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3", 16);
        BigInteger r =
                new BigInteger(
                        "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493", 16);
        BigInteger expectedS =
                new BigInteger(
                        "1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40", 16);

        BigInteger s = r.multiply(d).add(k.multiply(e)).mod(params.n);
        assertEquals(expectedS, s, "RFC 7091 s = (r*d + k*e) mod q mismatch");
    }

    @Test
    @DisplayName("RFC 7091 §7.3: верификация — z1, z2, R = r")
    void testRfc7091Verification() {
        ECParameters params = rfc7091Curve();

        BigInteger e =
                new BigInteger(
                        "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5", 16);
        BigInteger r =
                new BigInteger(
                        "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493", 16);
        BigInteger s =
                new BigInteger(
                        "1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40", 16);

        BigInteger expectedZ1 =
                new BigInteger(
                        "5358F8FFB38F7C09ABC782A2DF2A3927DA4077D07205F763682F3A76C9019B4F", 16);
        BigInteger expectedZ2 =
                new BigInteger(
                        "3221B4FBBF6D101074EC14AFAC2D4F7EFAC4CF9FEC1ED11BAE336D27D527665", 16);
        BigInteger expectedR =
                new BigInteger(
                        "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493", 16);

        BigInteger q = params.n;
        BigInteger v = e.modInverse(q);
        BigInteger z1 = s.multiply(v).mod(q);
        BigInteger z2 = q.subtract(r).multiply(v).mod(q);

        assertEquals(expectedZ1, z1, "RFC 7091 z1 mismatch");
        assertEquals(expectedZ2, z2, "RFC 7091 z2 mismatch");

        BigInteger Qx =
                new BigInteger(
                        "7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B", 16);
        BigInteger Qy =
                new BigInteger(
                        "26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA", 16);

        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint Q = ECPoint.affine(Qx, Qy, params);
        ECPoint C = g.multiply(z1).add(Q.multiply(z2)).normalize();

        assertFalse(C.isInfinity(), "RFC 7091 point C must not be infinity");
        assertEquals(expectedR, C.getX().mod(q), "RFC 7091 R = x_C mod q must equal r");
    }

    @Test
    @DisplayName("RFC 7091 §7: полный цикл verifySignature через ECDSASigner")
    void testRfc7091FullVerify() {
        ECParameters params = rfc7091Curve();

        BigInteger d =
                new BigInteger(
                        "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28", 16);
        // e из RFC 7091 §7.2 — это уже готовое значение e = alpha mod q (не хэш сообщения).
        // Чтобы подать его в verifySignature(byte[] hash, ...) нужен сырой хэш-массив.
        // По RFC 7091 §5.3: alpha читается LSB-first из H, поэтому чтобы получить e из hash-массива
        // нужен hash = reverseBytes(int2bytes(e)).
        BigInteger eVal =
                new BigInteger(
                        "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5", 16);
        BigInteger r =
                new BigInteger(
                        "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493", 16);
        BigInteger s =
                new BigInteger(
                        "1456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40", 16);

        BigInteger Qx =
                new BigInteger(
                        "7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B", 16);
        BigInteger Qy =
                new BigInteger(
                        "26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA", 16);
        ECPoint Q = ECPoint.affine(Qx, Qy, params);

        // Восстанавливаем фиктивный hash-массив: hash = reverseBytes(padded(e, 32))
        byte[] eBytes = toFixedBytes(eVal, 32);
        byte[] hash =
                reverseBytes(eBytes); // ECDSASigner сделает reverseBytes внутри -> вернёт eBytes

        ECDSASigner signer = new ECDSASigner(Streebog256::new, NonceMode.DETERMINISTIC, null);
        signer.init(false, new PublicKeyParameters(Q, params));

        assertTrue(
                signer.verifySignature(hash, r, s),
                "RFC 7091 §7.3: signature must verify correctly");
    }

    // -----------------------------------------------------------------------
    // RFC 6979: детерминированность нонса k (golden value тесты)
    //
    // generateK — private метод, тестируется косвенно через generateSignature.
    // r = (k·G).x mod q — если k одинаков, r одинаков.
    // Затравка HMAC-DRBG - int2octets(e), где e - число из уравнения подписи (ГОСТ читает хэш
    // младшим байтом вперёд). Затравка из байт хэша в прямом порядке позволяла двум разным e
    // получить один k и раскрывала закрытый ключ, см. DeterministicNonceTest.
    //
    // Оба golden r (кривая RFC 7091 и CryptoPro-A, обе 256 бит без сдвига хэша) получены
    // независимо: HMAC-DRBG на HMAC-Стрибог из BouncyCastle, которому подан int2octets(e) и
    // идентификатор кривой (NonceOracle в x-validation-tests/sign). Остальные кривые, в том
    // числе со сдвигом хэша, покрывает DeterministicNonceTest и сверка с эталоном. Если затравка
    // снова станет производной от байт хэша или потеряет привязку к кривой, golden r перестанет
    // совпадать.
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("RFC 6979: k детерминирован — RFC 7091 кривая, known hash")
    void testRfc6979KDeterminism_Rfc7091Curve() {
        // Параметры и ключ из RFC 7091 §7
        ECParameters params = rfc7091Curve();
        BigInteger d =
                new BigInteger(
                        "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28", 16);

        // e = 0x2DFBC1B3... из RFC 7091 §7.2 — это LE-integer (ГОСТ-нотация).
        // raw hash = reverseBytes(e) — big-endian вывод Streebog, как передаётся в
        // generateSignature.
        BigInteger eVal =
                new BigInteger(
                        "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5", 16);
        byte[] hash = reverseBytes(toFixedBytes(eVal, 32));

        PrivateKeyParameters priv = new PrivateKeyParameters(d, params);
        ECPoint Q = ECPoint.affine(params.gx, params.gy, params).multiply(d);
        PublicKeyParameters pub = new PublicKeyParameters(Q, params);

        ECDSASigner signer = new ECDSASigner(Streebog256::new, NonceMode.DETERMINISTIC, null);

        // Подписываем дважды — r обязан совпасть (детерминированность)
        signer.init(true, priv);
        BigInteger[] sig1 = signer.generateSignature(hash);
        signer.init(true, priv);
        BigInteger[] sig2 = signer.generateSignature(hash);

        assertEquals(
                sig1[0],
                sig2[0],
                "RFC 6979: одинаковый (d, hash) должен давать одинаковый k -> одинаковый r");

        // Golden r - от затравки int2octets(e) и идентификатора кривой (независимый эталон).
        // hash (BE): e53e042b67e6ec678e2e02b12a0352ce1fc6eee0529cc088119ad872b3c1fb2d
        BigInteger expectedR =
                new BigInteger(
                        "29a8c74af529d9e9605fa5ba6e54f21d3f9f172a013f9f74e7d6199954e0c70d", 16);
        assertEquals(
                expectedR,
                sig1[0],
                "RFC 6979: golden r не совпал - затравка нонса больше не int2octets(e)");

        // Подпись должна верифицироваться
        signer.init(false, pub);
        assertTrue(
                signer.verifySignature(hash, sig1[0], sig1[1]),
                "RFC 6979: подпись должна верифицироваться");
    }

    @Test
    @DisplayName("RFC 6979: k детерминирован — CryptoPro-A, Streebog-256(\"test\")")
    void testRfc6979KDeterminism_CryptoProA() {
        ECParameters params = ECParameters.cryptoProA();
        BigInteger d =
                new BigInteger(
                        "0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8090A1B2C3D4E5F6A7B8C9D0E1F", 16);

        // hash = Streebog-256("test") — проверяем и само значение хэша
        byte[] hash = doHash(new Streebog256(), "test".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(
                toFixedBytes(
                        new BigInteger(
                                "12a50838191b5504f1e5f2fd078714cf6b592b9d29af99d0b10d8d02881c3857",
                                16),
                        32),
                hash,
                "Streebog-256(\"test\") golden hash не совпал");

        PrivateKeyParameters priv = new PrivateKeyParameters(d, params);
        ECPoint Q = ECPoint.affine(params.gx, params.gy, params).multiply(d);
        PublicKeyParameters pub = new PublicKeyParameters(Q, params);

        ECDSASigner signer = new ECDSASigner(Streebog256::new, NonceMode.DETERMINISTIC, null);

        // Детерминированность
        signer.init(true, priv);
        BigInteger[] sig1 = signer.generateSignature(hash);
        signer.init(true, priv);
        BigInteger[] sig2 = signer.generateSignature(hash);

        assertEquals(
                sig1[0],
                sig2[0],
                "RFC 6979: одинаковый (d, hash) должен давать одинаковый k -> одинаковый r");

        // Golden r - от затравки int2octets(e) и идентификатора кривой (независимый эталон).
        // Кривая CryptoPro-A (RFC 4357 §11.2 = TC26-256-paramSetB).
        BigInteger expectedR =
                new BigInteger(
                        "77ee6e5be024073a8dc0926b84078f82415c9d036a819176d8507f288a63b3cb", 16);
        assertEquals(
                expectedR,
                sig1[0],
                "RFC 6979: golden r для CryptoPro-A не совпал - затравка нонса больше не int2octets(e)");

        // Верификация
        signer.init(false, pub);
        assertTrue(
                signer.verifySignature(hash, sig1[0], sig1[1]),
                "RFC 6979: подпись должна верифицироваться");
    }

    /** Кодирует BigInteger в big-endian byte[] фиксированной длины len байт. */
    private static byte[] toFixedBytes(BigInteger val, int len) {
        byte[] raw = val.toByteArray();
        byte[] out = new byte[len];
        if (raw.length <= len) {
            System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        } else {
            // обрезаем ведущий 0x00 если есть
            System.arraycopy(raw, raw.length - len, out, 0, len);
        }
        return out;
    }

    /** Реверсирует байты массива (big-endian <-> little-endian). */
    private static byte[] reverseBytes(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) out[i] = in[in.length - 1 - i];
        return out;
    }
}
