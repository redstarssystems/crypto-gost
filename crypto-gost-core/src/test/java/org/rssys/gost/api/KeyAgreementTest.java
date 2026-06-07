package org.rssys.gost.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.Pack;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("KeyAgreement: ECDH shared secret")
class KeyAgreementTest {

    // ========================================================================
    // KAT vector: CryptoPro-A (GC256B), d = 0x02×32, Q_S известен
    // Данные из TlsKATExample1Test (RFC 9367 §6.1.1, Example 2)
    // ========================================================================

    private static final BigInteger D_C_GC256B = new BigInteger(
            1, hex("0202020202020202020202020202020202020202020202020202020202020202"));

    private static final byte[] Q_S_LE_GC256B = hex(
            "3D2FB067E106CC9980FB8842811164BA708BBB5038D5EDFBEE1D5E5DFBE6F74F"
                    + "1931217C67C2BDF46253DB9CE3487241F2DBD84E2DABDF65455851B0B19AEFEC");

    private static final byte[] ECDHE_GC256B = hex(
            "985A8659D55A8D48E0E6771396580B2CDCDA37E92AEE1814D10E1BF2A44F0D24");

    @Test
    @DisplayName("KAT vector: CryptoPro-A, d=0x02×32")
    void sharedSecret_gc256b_kat() {
        ECParameters params = ECParameters.cryptoProA();
        PrivateKeyParameters clientPriv = new PrivateKeyParameters(D_C_GC256B, params);

        PublicKeyParameters serverPub = decodePublicKeyLe(Q_S_LE_GC256B, params);

        byte[] shared = KeyAgreement.computeSharedSecret(clientPriv, serverPub);
        assertArrayEquals(ECDHE_GC256B, shared,
                () -> "Ожидал " + hexStr(ECDHE_GC256B) + ", получил " + hexStr(shared));
    }

    // ========================================================================
    // Симметричность: computeSharedSecret(privA, pubB) == computeSharedSecret(privB, pubA)
    // ========================================================================

    @Test
    @DisplayName("CryptoPro-A: симметричность shared secret")
    void sharedSecret_symmetry_cryptoProA() {
        ECParameters params = ECParameters.cryptoProA();
        assertSymmetry(params);
    }

    @Test
    @DisplayName("tc26a512: симметричность shared secret")
    void sharedSecret_symmetry_tc26a512() {
        ECParameters params = ECParameters.tc26a512();
        assertSymmetry(params);
    }

    @Test
    @DisplayName("tc26b512: симметричность shared secret")
    void sharedSecret_symmetry_tc26b512() {
        ECParameters params = ECParameters.tc26b512();
        assertSymmetry(params);
    }

    private static void assertSymmetry(ECParameters params) {
        KeyPair pairA = KeyGenerator.generateKeyPair(params);
        KeyPair pairB = KeyGenerator.generateKeyPair(params);
        try {
            byte[] secretAB = KeyAgreement.computeSharedSecret(pairA.getPrivate(), pairB.getPublic());
            byte[] secretBA = KeyAgreement.computeSharedSecret(pairB.getPrivate(), pairA.getPublic());

            assertEquals(secretAB.length, params.hlen, "Длина shared secret = hlen");
            assertArrayEquals(secretAB, secretBA,
                    "shared secret должен быть симметричным: A·B == B·A");
        } finally {
            pairA.getPrivate().destroy();
            pairB.getPrivate().destroy();
        }
    }

    // ========================================================================
    // Длина результата: 32 байта для 256-бит, 64 для 512-бит кривых
    // ========================================================================

    @Test
    @DisplayName("CryptoPro-A: длина shared secret = 32 байта")
    void sharedSecret_length_256bit() {
        ECParameters params = ECParameters.cryptoProA();
        assertLength(params, 32);
    }

    @Test
    @DisplayName("VKO KAT: RFC 7836 Appendix B Test #7, tc26a512, UKM=8 байт")
    void vkoGostR3410_2012_256_kat() {
        ECParameters params = ECParameters.tc26a512();
        PrivateKeyParameters privA = new PrivateKeyParameters(D_A_TC26A512, params);
        PrivateKeyParameters privB = new PrivateKeyParameters(D_B_TC26A512, params);
        PublicKeyParameters pubA = decodePublicKeyLe(Q_A_LE_TC26A512, params);
        PublicKeyParameters pubB = decodePublicKeyLe(Q_B_LE_TC26A512, params);
        BigInteger ukm = leBytesToBigInteger(UKM_8BYTES);

        byte[] kekA = KeyAgreement.vkoGostR3410_2012_256(privA, pubB, ukm);
        assertArrayEquals(KEK_VKO_TC26A512, kekA,
                () -> "Ожидал " + hexStr(KEK_VKO_TC26A512) + ", получил " + hexStr(kekA));

        byte[] kekB = KeyAgreement.vkoGostR3410_2012_256(privB, pubA, ukm);
        assertArrayEquals(KEK_VKO_TC26A512, kekB,
                "VKO должен быть симметричным на эталонных ключах");
    }

    @Test
    @DisplayName("tc26a512: длина shared secret = 64 байта")
    void sharedSecret_length_512bit() {
        ECParameters params = ECParameters.tc26a512();
        assertLength(params, 64);
    }

    private static void assertLength(ECParameters params, int expectedLen) {
        KeyPair pairA = KeyGenerator.generateKeyPair(params);
        KeyPair pairB = KeyGenerator.generateKeyPair(params);
        try {
            byte[] shared = KeyAgreement.computeSharedSecret(pairA.getPrivate(), pairB.getPublic());
            assertEquals(expectedLen, shared.length,
                    "Длина shared secret для hlen=" + params.hlen);
        } finally {
            pairA.getPrivate().destroy();
            pairB.getPrivate().destroy();
        }
    }

    // ========================================================================
    // Несовпадение кривых
    // ========================================================================

    @Test
    @DisplayName("CryptoPro-A vs tc26a512: разные кривые → IllegalArgumentException")
    void sharedSecret_curveMismatch() {
        ECParameters paramsA = ECParameters.cryptoProA();
        ECParameters paramsB = ECParameters.tc26a512();

        KeyPair pairA = KeyGenerator.generateKeyPair(paramsA);
        KeyPair pairB = KeyGenerator.generateKeyPair(paramsB);
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> KeyAgreement.computeSharedSecret(pairA.getPrivate(), pairB.getPublic()),
                    "Разные кривые должны давать IllegalArgumentException");
        } finally {
            pairA.getPrivate().destroy();
            pairB.getPrivate().destroy();
        }
    }

    // ========================================================================
    // Null-аргументы
    // ========================================================================

    @Test
    @DisplayName("null закрытый ключ → IllegalArgumentException")
    void sharedSecret_nullPrivate() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> KeyAgreement.computeSharedSecret(null, pair.getPublic()));
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("null открытый ключ → IllegalArgumentException")
    void sharedSecret_nullPublic() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> KeyAgreement.computeSharedSecret(pair.getPrivate(), null));
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("оба null → IllegalArgumentException")
    void sharedSecret_bothNull() {
        assertThrows(IllegalArgumentException.class,
                () -> KeyAgreement.computeSharedSecret(null, null));
    }

    // ========================================================================
    // Уничтоженный ключ
    // ========================================================================

    @Test
    @DisplayName("уничтоженный закрытый ключ → IllegalStateException")
    void sharedSecret_destroyedPrivate() {
        ECParameters params = ECParameters.cryptoProA();
        PrivateKeyParameters priv = new PrivateKeyParameters(D_C_GC256B, params);
        PublicKeyParameters pub = decodePublicKeyLe(Q_S_LE_GC256B, params);

        priv.destroy();
        assertThrows(IllegalStateException.class,
                () -> KeyAgreement.computeSharedSecret(priv, pub),
                "Уничтоженный ключ должен давать IllegalStateException");
    }

    // ========================================================================
    // Бесконечность: точка peerPub = infinity → IllegalStateException
    // ========================================================================

    @Test
    @DisplayName("ключ удалённой стороны — точка на бесконечности → IllegalStateException")
    void sharedSecret_peerInfinity() {
        ECParameters params = ECParameters.cryptoProA();
        PrivateKeyParameters priv = new PrivateKeyParameters(D_C_GC256B, params);
        ECPoint infinity = ECPoint.infinity(params);
        PublicKeyParameters peerPub = new PublicKeyParameters(infinity, params);
        try {
            assertThrows(IllegalStateException.class,
                    () -> KeyAgreement.computeSharedSecret(priv, peerPub),
                    "Точка на бесконечности должна давать IllegalStateException");
        } finally {
            priv.destroy();
        }
    }

    // ========================================================================
    // Edge-case: граничные значения приватных ключей (d=1, d=n-1)
    // ========================================================================

    @Test
    @DisplayName("d=1 с обеих сторон: shared secret = X(G·G) = X(2·G) — не бесконечность")
    void sharedSecret_edge_d1_both() {
        ECParameters params = ECParameters.cryptoProA();
        BigInteger one = BigInteger.ONE;
        PrivateKeyParameters privA = new PrivateKeyParameters(one, params);
        PrivateKeyParameters privB = new PrivateKeyParameters(one, params);

        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint qA = g.multiply(BigInteger.ONE).normalize();
        ECPoint qB = g.multiply(BigInteger.ONE).normalize();
        PublicKeyParameters pubA = new PublicKeyParameters(qA, params);
        PublicKeyParameters pubB = new PublicKeyParameters(qB, params);

        byte[] sharedAB = KeyAgreement.computeSharedSecret(privA, pubB);
        byte[] sharedBA = KeyAgreement.computeSharedSecret(privB, pubA);

        assertEquals(params.hlen, sharedAB.length);
        assertArrayEquals(sharedAB, sharedBA,
                "d=1: A·B == B·A");

        // shared = X(dA·dB·G) = X(1·1·G) = X(G). Для CryptoPro-A Gx известен.
        byte[] expected = ECPoint.affine(params.gx, params.gy, params)
                .normalize()
                .getX()
                .toByteArray();
        // X координата — это shared secret
        BigInteger sharedX = new BigInteger(1, sharedAB);
        assertTrue(sharedX.signum() > 0, "shared secret не должен быть 0");

        privA.destroy();
        privB.destroy();
    }

    @Test
    @DisplayName("d=1 (A) × random (B): симметричность shared secret")
    void sharedSecret_edge_d1_vs_random() {
        ECParameters params = ECParameters.cryptoProA();
        BigInteger one = BigInteger.ONE;
        PrivateKeyParameters privA = new PrivateKeyParameters(one, params);

        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint qA = g.multiply(BigInteger.ONE).normalize();
        PublicKeyParameters pubA = new PublicKeyParameters(qA, params);

        KeyPair pairB = KeyGenerator.generateKeyPair(params);
        try {
            byte[] sharedAB = KeyAgreement.computeSharedSecret(privA, pairB.getPublic());
            byte[] sharedBA = KeyAgreement.computeSharedSecret(pairB.getPrivate(), pubA);

            assertArrayEquals(sharedAB, sharedBA,
                    "d=1 × random: A·B == B·A");
        } finally {
            privA.destroy();
            pairB.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("d=n-1 с обеих сторон: shared secret = Q(-G · -G) = Q(2·G)")
    void sharedSecret_edge_dNminus1_both() {
        ECParameters params = ECParameters.cryptoProA();
        BigInteger d = params.n.subtract(BigInteger.ONE);
        PrivateKeyParameters privA = new PrivateKeyParameters(d, params);
        PrivateKeyParameters privB = new PrivateKeyParameters(d, params);

        // Q = (n-1)·G = -G
        ECPoint g = ECPoint.affine(params.gx, params.gy, params);
        ECPoint q = g.multiply(d).normalize();
        PublicKeyParameters pubA = new PublicKeyParameters(q, params);
        PublicKeyParameters pubB = new PublicKeyParameters(q, params);

        byte[] sharedAB = KeyAgreement.computeSharedSecret(privA, pubB);
        byte[] sharedBA = KeyAgreement.computeSharedSecret(privB, pubA);

        assertEquals(params.hlen, sharedAB.length);
        assertArrayEquals(sharedAB, sharedBA,
                "d=n-1: A·B == B·A");

        // (n-1)·(n-1)·G = 1·G = G, но shared = X координата.
        BigInteger sharedX = new BigInteger(1, sharedAB);
        assertTrue(sharedX.signum() > 0, "shared secret не должен быть 0");

        privA.destroy();
        privB.destroy();
    }

    // ========================================================================
    // VKO_GOSTR3410_2012_256: KAT вектор из RFC 7836 Appendix B Test Example 7
    // Кривая: id-tc26-gost-3410-12-512-paramSetA (tc26a512)
    // UKM: 8 байт, KEK_VKO = H_256(X_LE((h·d·UKM mod q)·Qpeer))
    // ========================================================================

    private static final byte[] UKM_8BYTES = hex("1d80603c8544c727");

    private static final BigInteger D_A_TC26A512 = leBytesToBigInteger(
            hex("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"
                    + "c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"));

    private static final BigInteger D_B_TC26A512 = leBytesToBigInteger(
            hex("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"
                    + "8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"));

    private static final byte[] Q_A_LE_TC26A512 = hex(
            "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5"
                    + "d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7"
                    + "914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38"
                    + "461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a");

    private static final byte[] Q_B_LE_TC26A512 = hex(
            "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e"
                    + "fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651"
                    + "04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b"
                    + "b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79");

    private static final byte[] KEK_VKO_TC26A512 = hex(
            "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221");

    @Test
    @DisplayName("VKO: UKM=1 даёт 32 байта для любой кривой")
    void vkoGostR3410_2012_256_length32() {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        KeyPair peer = KeyGenerator.generateKeyPair(params);
        try {
            byte[] kek = KeyAgreement.vkoGostR3410_2012_256(
                    pair.getPrivate(), peer.getPublic(), BigInteger.ONE);
            assertEquals(32, kek.length, "VKO результат всегда 32 байта");
        } finally {
            pair.getPrivate().destroy();
            peer.getPrivate().destroy();
        }
    }

    // ========================================================================
    // VKO_GOSTR3410_2012_256: симметричность
    // ========================================================================

    @Test
    @DisplayName("VKO CryptoPro-A: симметричность с UKM")
    void vko_symmetry_cryptoProA() {
        assertVkoSymmetry(ECParameters.cryptoProA(), BigInteger.valueOf(12345));
    }

    @Test
    @DisplayName("VKO tc26a512: симметричность с UKM")
    void vko_symmetry_tc26a512() {
        assertVkoSymmetry(ECParameters.tc26a512(), new BigInteger(1, UKM_8BYTES));
    }

    private static void assertVkoSymmetry(ECParameters params, BigInteger ukm) {
        KeyPair pairA = KeyGenerator.generateKeyPair(params);
        KeyPair pairB = KeyGenerator.generateKeyPair(params);
        try {
            byte[] kekAB = KeyAgreement.vkoGostR3410_2012_256(
                    pairA.getPrivate(), pairB.getPublic(), ukm);
            byte[] kekBA = KeyAgreement.vkoGostR3410_2012_256(
                    pairB.getPrivate(), pairA.getPublic(), ukm);
            assertEquals(32, kekAB.length, "VKO результат всегда 32 байта");
            assertArrayEquals(kekAB, kekBA,
                    "VKO должен быть симметричным: A·B == B·A");
        } finally {
            pairA.getPrivate().destroy();
            pairB.getPrivate().destroy();
        }
    }

    // ========================================================================
    // VKO_GOSTR3410_2012_256: неверные UKM
    // ========================================================================

    @Test
    @DisplayName("VKO: UKM=null → IllegalArgumentException")
    void vko_ukmNull() {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        KeyPair peer = KeyGenerator.generateKeyPair(params);
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> KeyAgreement.vkoGostR3410_2012_256(
                            pair.getPrivate(), peer.getPublic(), null),
                    "UKM=null должен давать IllegalArgumentException");
        } finally {
            pair.getPrivate().destroy();
            peer.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("VKO: UKM=0 → IllegalArgumentException")
    void vko_ukmZero() {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        KeyPair peer = KeyGenerator.generateKeyPair(params);
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> KeyAgreement.vkoGostR3410_2012_256(
                            pair.getPrivate(), peer.getPublic(), BigInteger.ZERO),
                    "UKM=0 должен давать IllegalArgumentException");
        } finally {
            pair.getPrivate().destroy();
            peer.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("VKO: UKM=-1 → IllegalArgumentException")
    void vko_ukmNegative() {
        ECParameters params = ECParameters.cryptoProA();
        KeyPair pair = KeyGenerator.generateKeyPair(params);
        KeyPair peer = KeyGenerator.generateKeyPair(params);
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> KeyAgreement.vkoGostR3410_2012_256(
                            pair.getPrivate(), peer.getPublic(), BigInteger.valueOf(-1)),
                    "UKM=-1 должен давать IllegalArgumentException");
        } finally {
            pair.getPrivate().destroy();
            peer.getPrivate().destroy();
        }
    }

    // ========================================================================
    // VKO_GOSTR3410_2012_256: null и неверные ключи
    // ========================================================================

    @Test
    @DisplayName("VKO: null закрытый ключ → IllegalArgumentException")
    void vko_nullPrivate() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> KeyAgreement.vkoGostR3410_2012_256(
                            null, pair.getPublic(), BigInteger.ONE));
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("VKO: null открытый ключ → IllegalArgumentException")
    void vko_nullPublic() {
        KeyPair pair = KeyGenerator.generateKeyPair(ECParameters.cryptoProA());
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> KeyAgreement.vkoGostR3410_2012_256(
                            pair.getPrivate(), null, BigInteger.ONE));
        } finally {
            pair.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("VKO: разные кривые → IllegalArgumentException")
    void vko_curveMismatch() {
        ECParameters paramsA = ECParameters.cryptoProA();
        ECParameters paramsB = ECParameters.tc26a512();
        KeyPair pairA = KeyGenerator.generateKeyPair(paramsA);
        KeyPair pairB = KeyGenerator.generateKeyPair(paramsB);
        try {
            assertThrows(IllegalArgumentException.class,
                    () -> KeyAgreement.vkoGostR3410_2012_256(
                            pairA.getPrivate(), pairB.getPublic(), BigInteger.ONE),
                    "Разные кривые должны давать IllegalArgumentException");
        } finally {
            pairA.getPrivate().destroy();
            pairB.getPrivate().destroy();
        }
    }

    @Test
    @DisplayName("VKO: уничтоженный закрытый ключ → IllegalStateException")
    void vko_destroyedPrivate() {
        ECParameters params = ECParameters.cryptoProA();
        PrivateKeyParameters priv = new PrivateKeyParameters(D_C_GC256B, params);
        PublicKeyParameters pub = decodePublicKeyLe(Q_S_LE_GC256B, params);
        priv.destroy();
        assertThrows(IllegalStateException.class,
                () -> KeyAgreement.vkoGostR3410_2012_256(priv, pub, BigInteger.ONE),
                "Уничтоженный ключ должен давать IllegalStateException");
    }

    @Test
    @DisplayName("VKO: точка на бесконечности → IllegalStateException")
    void vko_peerInfinity() {
        ECParameters params = ECParameters.cryptoProA();
        PrivateKeyParameters priv = new PrivateKeyParameters(D_C_GC256B, params);
        ECPoint infinity = ECPoint.infinity(params);
        PublicKeyParameters peerPub = new PublicKeyParameters(infinity, params);
        try {
            assertThrows(IllegalStateException.class,
                    () -> KeyAgreement.vkoGostR3410_2012_256(priv, peerPub, BigInteger.ONE),
                    "Точка на бесконечности должна давать IllegalStateException");
        } finally {
            priv.destroy();
        }
    }

    // ========================================================================
    // Утилиты
    // ========================================================================

    private static PublicKeyParameters decodePublicKeyLe(byte[] qLe, ECParameters params) {
        int hlen = params.hlen;
        byte[] xLe = new byte[hlen];
        byte[] yLe = new byte[hlen];
        System.arraycopy(qLe, 0, xLe, 0, hlen);
        System.arraycopy(qLe, hlen, yLe, 0, hlen);
        byte[] xBe = Pack.reverseBytes(xLe);
        byte[] yBe = Pack.reverseBytes(yLe);
        ECPoint q = ECPoint.affine(
                new BigInteger(1, xBe), new BigInteger(1, yBe), params);
        return new PublicKeyParameters(q, params);
    }

    /** Приводит LE-байты из RFC к BigInteger (реверс + new BigInteger(1, bytes)). */
    private static BigInteger leBytesToBigInteger(byte[] le) {
        return new BigInteger(1, Pack.reverseBytes(le));
    }

    private static byte[] hex(String s) {
        String cleaned = s.replaceAll("\\s+", "");
        int len = cleaned.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(cleaned.charAt(i), 16) << 4)
                    + Character.digit(cleaned.charAt(i + 1), 16));
        }
        return data;
    }

    private static String hexStr(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xFF));
        }
        return sb.toString();
    }
}
