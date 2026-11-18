package org.rssys.gost.jca.spec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Signature;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.ECPoint;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Строгий разбор SubjectPublicKeyInfo: неоднозначные и неканонические кодировки ключа отвергаются,
 * допустимые по RFC 9215 варианты OID набора параметров и {@code digestParamSet} принимаются.
 */
@DisplayName("GostDerCodec.decodePublicKey: строгий SPKI")
class GostDerCodecStrictSpkiTest {

    private static final String DIGEST_256 = "1.2.643.7.1.1.2.2";
    private static final String DIGEST_512 = "1.2.643.7.1.1.2.3";
    private static final String RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
    private static final int MAX_ATTEMPTS = 64;

    // ------------------------------------------------------------------------
    // Построители SPKI
    // ------------------------------------------------------------------------

    private static PublicKeyParameters publicKey(ECParameters params, long d) {
        return Signature.derivePublicKey(new PrivateKeyParameters(BigInteger.valueOf(d), params));
    }

    private static int coordLength(ECParameters params) {
        return (params.p.bitLength() + 7) / 8;
    }

    private static int bitsOf(ECParameters params) {
        return coordLength(params) * 8;
    }

    private static byte[] littleEndian(BigInteger value, int length) {
        byte[] bigEndian = value.toByteArray();
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            int index = bigEndian.length - 1 - i;
            result[i] = index >= 0 ? bigEndian[index] : 0;
        }
        return result;
    }

    private static byte[] pointBytes(ECParameters params, BigInteger x, BigInteger y) {
        int length = coordLength(params);
        return DerCodec.concat(littleEndian(x, length), littleEndian(y, length));
    }

    private static String signOid(ECParameters params) {
        return params.hlen == 32 ? GostCurves.OID_SIGN_256 : GostCurves.OID_SIGN_512;
    }

    private static String digestOid(ECParameters params) {
        return params.hlen == 32 ? DIGEST_256 : DIGEST_512;
    }

    private static byte[] pubKeyParams(String curveOid, String digestOidOrNull) {
        return digestOidOrNull == null
                ? DerCodec.encodeSequence(DerCodec.encodeOid(curveOid))
                : DerCodec.encodeSequence(
                        DerCodec.encodeOid(curveOid), DerCodec.encodeOid(digestOidOrNull));
    }

    private static byte[] algorithm(String signOid, byte[] parameters) {
        return DerCodec.encodeSequence(DerCodec.encodeOid(signOid), parameters);
    }

    private static byte[] bitString(byte[] pointBytes) {
        return DerCodec.encodeBitString(DerCodec.encodeOctetString(pointBytes));
    }

    private static byte[] spki(byte[] algorithm, byte[] bitString) {
        return DerCodec.encodeSequence(algorithm, bitString);
    }

    /** SPKI с правильными OID алгоритма и digest для кривой с OID {@code curveOid}. */
    private static byte[] spki(String curveOid, ECParameters params, byte[] pointBytes) {
        GostCurves.DigestParamSetPolicy policy = GostCurves.digestPolicyOf(curveOid);
        String digest =
                policy == GostCurves.DigestParamSetPolicy.FORBIDDEN ? null : digestOid(params);
        return spki(
                algorithm(signOid(params), pubKeyParams(curveOid, digest)), bitString(pointBytes));
    }

    private static byte[] spki(String curveOid, PublicKeyParameters key) {
        return spki(curveOid, key.getParams(), GostDerCodec.subjectPublicKeyPointBytes(key));
    }

    private static void assertRejected(byte[] encoded, String message) {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerCodec.decodePublicKey(encoded),
                message);
    }

    private static void assertAccepted(byte[] encoded, String message) {
        assertNotNull(GostDerCodec.decodePublicKey(encoded), message);
    }

    // ------------------------------------------------------------------------
    // Исходные кодировки принимаются
    // ------------------------------------------------------------------------

    @Nested
    @DisplayName("Корректные SPKI")
    class ValidEncodings {

        @Test
        @DisplayName("encodePublicKey -> decodePublicKey: ключ сохраняется для всех кривых")
        void roundtripAllCurves() {
            String[] curves = {
                GostCurves.OID_TC26_A_256,
                GostCurves.OID_CRYPTOPRO_A,
                GostCurves.OID_CRYPTOPRO_B,
                GostCurves.OID_CRYPTOPRO_C,
                GostCurves.OID_TC26_A_512,
                GostCurves.OID_TC26_B_512,
                GostCurves.OID_TC26_C_512
            };
            for (String curve : curves) {
                ECParameters params = GostCurves.byName(curve);
                PublicKeyParameters key = publicKey(params, 123456789L);
                PublicKeyParameters decoded =
                        GostDerCodec.decodePublicKey(GostDerCodec.encodePublicKey(key));
                assertEquals(key, decoded, "Ключ должен сохраняться для кривой " + curve);
            }
        }
    }

    // ------------------------------------------------------------------------
    // x+p, y+p, x = p
    // ------------------------------------------------------------------------

    @Nested
    @DisplayName("Координаты не меньше модуля поля")
    class CoordinatesNotReduced {

        private void assertSpkiWithCoordinate(
                String curveOid, PublicKeyParameters key, boolean shiftX, boolean shiftY) {
            ECParameters params = key.getParams();
            ECPoint q = key.getQ();
            BigInteger x = q.getX();
            BigInteger y = q.getY();
            BigInteger shiftedX = shiftX ? x.add(params.p) : x;
            BigInteger shiftedY = shiftY ? y.add(params.p) : y;
            // Предусловие теста: сдвинутая координата действительно помещается в поле байт
            assertTrue(
                    shiftedX.bitLength() <= bitsOf(params)
                            && shiftedY.bitLength() <= bitsOf(params),
                    "Сдвинутая координата должна помещаться в " + bitsOf(params) + " бит");
            assertAccepted(spki(curveOid, key), "Исходная кодировка ключа должна приниматься");
            assertRejected(
                    spki(curveOid, params, pointBytes(params, shiftedX, shiftedY)),
                    "SPKI со сдвинутой на p координатой должен отвергаться");
        }

        // x+p: у генератора CryptoPro-A (gx = 1), CryptoPro-B (gx = 1), TC26-A-512 (gx = 3) и
        // TC26-B-512 (gx = 2) малый x, поэтому подходит d = 1; у остальных d случайные координаты.

        @Test
        @DisplayName("x+p: CryptoPro-A, d = 1")
        void xPlusPCryptoProA() {
            assertSpkiWithCoordinate(
                    GostCurves.OID_CRYPTOPRO_A,
                    publicKey(GostCurves.byName(GostCurves.OID_CRYPTOPRO_A), 1),
                    true,
                    false);
        }

        @Test
        @DisplayName("x+p: CryptoPro-B, d = 1")
        void xPlusPCryptoProB() {
            assertSpkiWithCoordinate(
                    GostCurves.OID_CRYPTOPRO_B,
                    publicKey(GostCurves.byName(GostCurves.OID_CRYPTOPRO_B), 1),
                    true,
                    false);
        }

        @Test
        @DisplayName("x+p: TC26-A-512, d = 1")
        void xPlusPTc26A512() {
            assertSpkiWithCoordinate(
                    GostCurves.OID_TC26_A_512,
                    publicKey(GostCurves.byName(GostCurves.OID_TC26_A_512), 1),
                    true,
                    false);
        }

        @Test
        @DisplayName("x+p: TC26-B-512, d = 1")
        void xPlusPTc26B512() {
            assertSpkiWithCoordinate(
                    GostCurves.OID_TC26_B_512,
                    publicKey(GostCurves.byName(GostCurves.OID_TC26_B_512), 1),
                    true,
                    false);
        }

        @Test
        @DisplayName("x+p: CryptoPro-C, первый d >= 2 с x > 0 и x+p < 2^256 (d = 1 даёт x = 0)")
        void xPlusPCryptoProC() {
            ECParameters params = GostCurves.byName(GostCurves.OID_CRYPTOPRO_C);
            for (long d = 2; d < 2 + MAX_ATTEMPTS; d++) {
                PublicKeyParameters key = publicKey(params, d);
                BigInteger x = key.getQ().getX();
                if (x.signum() > 0 && x.add(params.p).bitLength() <= bitsOf(params)) {
                    assertSpkiWithCoordinate(GostCurves.OID_CRYPTOPRO_C, key, true, false);
                    return;
                }
            }
            fail(
                    "Среди d = 2.."
                            + (MAX_ATTEMPTS + 1)
                            + " не найден ключ CryptoPro-C с x+p < 2^256; ожидается около 65% успехов");
        }

        // y+p: у генератора CryptoPro-B, CryptoPro-C и TC26-B-512 малый y. У CryptoPro-A,
        // TC26-A-512, TC26-A-256 и TC26-C-512 y+p для реального ключа недостижим (y большой,
        // а 2^bits - p равно сотням), поэтому там проверяется только ветка x.

        @Test
        @DisplayName("y+p: CryptoPro-B, d = 1")
        void yPlusPCryptoProB() {
            assertSpkiWithCoordinate(
                    GostCurves.OID_CRYPTOPRO_B,
                    publicKey(GostCurves.byName(GostCurves.OID_CRYPTOPRO_B), 1),
                    false,
                    true);
        }

        @Test
        @DisplayName("y+p: CryptoPro-C, d = 1")
        void yPlusPCryptoProC() {
            assertSpkiWithCoordinate(
                    GostCurves.OID_CRYPTOPRO_C,
                    publicKey(GostCurves.byName(GostCurves.OID_CRYPTOPRO_C), 1),
                    false,
                    true);
        }

        @Test
        @DisplayName("y+p: TC26-B-512, d = 1")
        void yPlusPTc26B512() {
            assertSpkiWithCoordinate(
                    GostCurves.OID_TC26_B_512,
                    publicKey(GostCurves.byName(GostCurves.OID_TC26_B_512), 1),
                    false,
                    true);
        }

        @Test
        @DisplayName("x = p: CryptoPro-C при d = 1 (x = 0 закодирован как p) отвергается")
        void xEqualsPCryptoProC() {
            ECParameters params = GostCurves.byName(GostCurves.OID_CRYPTOPRO_C);
            PublicKeyParameters key = publicKey(params, 1);
            ECPoint q = key.getQ();
            assertEquals(BigInteger.ZERO, q.getX(), "У генератора CryptoPro-C gx должен быть 0");
            assertRejected(
                    spki(
                            GostCurves.OID_CRYPTOPRO_C,
                            params,
                            pointBytes(params, params.p, q.getY())),
                    "SPKI с x = p вместо x = 0 должен отвергаться");
        }

        @Test
        @DisplayName("x+p на TC26-A-256 и TC26-C-512: сконструированная точка с малым x")
        void xPlusPCraftedPoints() {
            for (String curveOid :
                    new String[] {GostCurves.OID_TC26_A_256, GostCurves.OID_TC26_C_512}) {
                ECParameters params = GostCurves.byName(curveOid);
                ECPoint point = findPointWithSmallX(params);
                BigInteger x = point.getX();
                BigInteger y = point.getY();
                assertTrue(
                        x.add(params.p).bitLength() <= bitsOf(params),
                        "x+p должен помещаться в поле байт для кривой " + curveOid);
                assertRejected(
                        spki(curveOid, params, pointBytes(params, x.add(params.p), y)),
                        "SPKI с x+p на кривой " + curveOid + " должен отвергаться");
            }
        }

        /**
         * Ищет точку в подгруппе порядка n с наименьшим x &gt; 0 среди x &lt; 2^bits - p.
         * Закрытый ключ к ней неизвестен и не нужен: проверяется только кодировка.
         * У обеих кривых p = 3 (mod 4), поэтому корень берётся как a^((p+1)/4).
         */
        private ECPoint findPointWithSmallX(ECParameters params) {
            BigInteger p = params.p;
            assertEquals(3, p.mod(BigInteger.valueOf(4)).intValue(), "Ожидается p = 3 (mod 4)");
            BigInteger limit = BigInteger.ONE.shiftLeft(bitsOf(params)).subtract(p);
            BigInteger exponent = p.add(BigInteger.ONE).shiftRight(2);
            for (BigInteger x = BigInteger.ONE; x.compareTo(limit) < 0; x = x.add(BigInteger.ONE)) {
                BigInteger rhs = x.pow(3).add(params.a.multiply(x)).add(params.b).mod(p);
                BigInteger y = rhs.modPow(exponent, p);
                if (!y.multiply(y).mod(p).equals(rhs)) {
                    continue;
                }
                ECPoint candidate = ECPoint.affine(x, y, params);
                if (candidate.isValidPublicKey()) {
                    return candidate.normalize();
                }
            }
            fail(
                    "Точка с x < 2^bits - p, лежащая в подгруппе n, не найдена для кривой с p = "
                            + p.toString(16));
            return null;
        }
    }

    // ------------------------------------------------------------------------
    // Матрица digestParamSet (RFC 9215 §4.2)
    // ------------------------------------------------------------------------

    @Nested
    @DisplayName("digestParamSet по RFC 9215")
    class DigestParamSetMatrix {

        private byte[] withDigest(String curveOid, String digestOidOrNull) {
            ECParameters params = GostCurves.byName(curveOid);
            PublicKeyParameters key = publicKey(params, 7);
            return spki(
                    algorithm(signOid(params), pubKeyParams(curveOid, digestOidOrNull)),
                    bitString(GostDerCodec.subjectPublicKeyPointBytes(key)));
        }

        @Test
        @DisplayName("CryptoPro A/B/C, XchA, XchB: digest обязателен и равен Стрибог-256")
        void required() {
            for (String oid :
                    new String[] {
                        GostCurves.OID_CRYPTOPRO_A,
                        GostCurves.OID_CRYPTOPRO_B,
                        GostCurves.OID_CRYPTOPRO_C,
                        GostCurves.OID_CRYPTOPRO_XCHA,
                        GostCurves.OID_CRYPTOPRO_XCHB
                    }) {
                assertAccepted(
                        withDigest(oid, DIGEST_256),
                        "С digest набор " + oid + " должен приниматься");
                assertRejected(
                        withDigest(oid, null), "Без digest набор " + oid + " должен отвергаться");
                assertRejected(
                        withDigest(oid, DIGEST_512),
                        "Digest Стрибог-512 на 256-битной кривой " + oid + " должен отвергаться");
            }
        }

        @Test
        @DisplayName(
                "SPKI с XchB (1.2.643.2.2.36.1) принимается и даёт параметры CryptoPro-C; 38.0 отвергается")
        void xchbDecodesToCryptoProC() {
            PublicKeyParameters key = publicKey(ECParameters.cryptoProC(), 7);
            byte[] withXchb = spki(GostCurves.OID_CRYPTOPRO_XCHB, key);

            PublicKeyParameters decoded = GostDerCodec.decodePublicKey(withXchb);
            assertSame(
                    ECParameters.cryptoProC(),
                    decoded.getParams(),
                    "XchB — кривая C, точка на ней должна проходить проверку");

            // 38.0 — дуга политик, а не набор параметров: раньше ошибочно считалась XchB
            byte[] withPolicyArc =
                    spki(
                            algorithm(
                                    signOid(ECParameters.cryptoProC()),
                                    pubKeyParams("1.2.643.2.2.38.0", DIGEST_256)),
                            bitString(GostDerCodec.subjectPublicKeyPointBytes(key)));
            assertRejected(withPolicyArc, "OID 1.2.643.2.2.38.0 не набор параметров кривой");
        }

        @Test
        @DisplayName("TC26 B/C/D-256: digest должен отсутствовать")
        void forbidden() {
            for (String oid :
                    new String[] {
                        GostCurves.OID_TC26_B_256,
                        GostCurves.OID_TC26_C_256,
                        GostCurves.OID_TC26_D_256
                    }) {
                assertAccepted(
                        withDigest(oid, null), "Без digest набор " + oid + " должен приниматься");
                assertRejected(
                        withDigest(oid, DIGEST_256),
                        "С digest набор " + oid + " должен отвергаться");
            }
        }

        @Test
        @DisplayName("TC26 A-256 и 512 A/B/C: digest допускается и отсутствует, и присутствует")
        void optional() {
            for (String oid : new String[] {GostCurves.OID_TC26_A_256}) {
                assertAccepted(
                        withDigest(oid, null), "Без digest набор " + oid + " должен приниматься");
                assertAccepted(
                        withDigest(oid, DIGEST_256),
                        "С digest набор " + oid + " должен приниматься");
                assertRejected(
                        withDigest(oid, DIGEST_512), "Digest не того размера должен отвергаться");
            }
            for (String oid :
                    new String[] {
                        GostCurves.OID_TC26_A_512,
                        GostCurves.OID_TC26_B_512,
                        GostCurves.OID_TC26_C_512
                    }) {
                assertAccepted(
                        withDigest(oid, null), "Без digest набор " + oid + " должен приниматься");
                assertAccepted(
                        withDigest(oid, DIGEST_512),
                        "С digest набор " + oid + " должен приниматься");
                assertRejected(
                        withDigest(oid, DIGEST_256), "Digest не того размера должен отвергаться");
            }
        }

        @Test
        @DisplayName(
                "Политика берётся по исходному OID: XchA и TC26-B-256 — одна кривая, правила разные")
        void policyUsesOriginalOid() {
            assertEquals(
                    GostCurves.byName(GostCurves.OID_CRYPTOPRO_XCHA),
                    GostCurves.byName(GostCurves.OID_TC26_B_256),
                    "XchA и TC26-B-256 должны указывать на один объект ECParameters");
            assertAccepted(withDigest(GostCurves.OID_CRYPTOPRO_XCHA, DIGEST_256), "XchA с digest");
            assertRejected(withDigest(GostCurves.OID_CRYPTOPRO_XCHA, null), "XchA без digest");
            assertAccepted(withDigest(GostCurves.OID_TC26_B_256, null), "TC26-B-256 без digest");
            assertRejected(
                    withDigest(GostCurves.OID_TC26_B_256, DIGEST_256), "TC26-B-256 с digest");
        }
    }

    // ------------------------------------------------------------------------
    // Структура
    // ------------------------------------------------------------------------

    @Nested
    @DisplayName("Структура SubjectPublicKeyInfo")
    class Structure {

        private final ECParameters params256 = GostCurves.byName(GostCurves.OID_TC26_A_256);
        private final ECParameters params512 = GostCurves.byName(GostCurves.OID_TC26_A_512);
        private final PublicKeyParameters key256 = publicKey(params256, 11);
        private final PublicKeyParameters key512 = publicKey(params512, 11);
        private final byte[] point256 = GostDerCodec.subjectPublicKeyPointBytes(key256);
        private final byte[] curve256 = DerCodec.encodeOid(GostCurves.OID_TC26_A_256);
        private final byte[] digest256 = DerCodec.encodeOid(DIGEST_256);
        private final byte[] validParams = DerCodec.encodeSequence(curve256, digest256);
        private final byte[] validAlgorithm =
                DerCodec.encodeSequence(DerCodec.encodeOid(GostCurves.OID_SIGN_256), validParams);
        private final byte[] validBitString = bitString(point256);
        private final byte[] valid = spki(validAlgorithm, validBitString);

        @Test
        @DisplayName("Эталонный SPKI принимается")
        void baseline() {
            assertAccepted(valid, "Эталонный SPKI должен приниматься");
        }

        @Test
        @DisplayName("Байты после внешней SEQUENCE отвергаются")
        void trailingBytes() {
            assertRejected(DerCodec.concat(valid, new byte[] {0x00}), "Хвост после SEQUENCE");
            assertRejected(
                    DerCodec.concat(valid, new byte[] {0x05, 0x00}), "Хвост NULL после SEQUENCE");
        }

        @Test
        @DisplayName("BER с indefinite-length отвергается")
        void indefiniteLength() {
            byte[] ber =
                    DerCodec.concat(
                            new byte[] {0x30, (byte) 0x80},
                            validAlgorithm,
                            validBitString,
                            new byte[] {0x00, 0x00});
            assertRejected(ber, "Внешняя SEQUENCE с indefinite-length");
            byte[] berAlgorithm =
                    DerCodec.concat(
                            new byte[] {0x30, (byte) 0x80},
                            DerCodec.encodeOid(GostCurves.OID_SIGN_256),
                            validParams,
                            new byte[] {0x00, 0x00});
            assertRejected(
                    spki(berAlgorithm, validBitString), "AlgorithmIdentifier с indefinite-length");
        }

        @Test
        @DisplayName("Лишний или недостающий элемент внешней SEQUENCE отвергается")
        void outerElementCount() {
            assertRejected(
                    DerCodec.encodeSequence(validAlgorithm, validBitString, DerCodec.encodeNull()),
                    "Третий элемент внешней SEQUENCE");
            assertRejected(
                    DerCodec.encodeSequence(validAlgorithm), "Один элемент внешней SEQUENCE");
        }

        @Test
        @DisplayName("AlgorithmIdentifier из 0, 1 и 3 элементов отвергается")
        void algorithmIdentifierElementCount() {
            assertRejected(
                    spki(DerCodec.encodeSequence(), validBitString),
                    "AlgorithmIdentifier из 0 элементов");
            assertRejected(
                    spki(
                            DerCodec.encodeSequence(DerCodec.encodeOid(GostCurves.OID_SIGN_256)),
                            validBitString),
                    "AlgorithmIdentifier без parameters");
            assertRejected(
                    spki(
                            DerCodec.encodeSequence(
                                    DerCodec.encodeOid(GostCurves.OID_SIGN_256),
                                    validParams,
                                    DerCodec.encodeNull()),
                            validBitString),
                    "AlgorithmIdentifier из 3 элементов");
        }

        @Test
        @DisplayName("GostR3410-2012-PublicKeyParameters из 0 и 3 элементов отвергается")
        void publicKeyParametersElementCount() {
            assertRejected(
                    spki(
                            algorithm(GostCurves.OID_SIGN_256, DerCodec.encodeSequence()),
                            validBitString),
                    "parameters из 0 элементов");
            assertRejected(
                    spki(
                            algorithm(
                                    GostCurves.OID_SIGN_256,
                                    DerCodec.encodeSequence(
                                            curve256, digest256, DerCodec.encodeNull())),
                            validBitString),
                    "parameters из 3 элементов");
        }

        @Test
        @DisplayName("Чужой OID алгоритма и OID, не соответствующий размеру кривой, отвергаются")
        void algorithmOid() {
            assertRejected(
                    spki(algorithm(RSA_ENCRYPTION, validParams), validBitString),
                    "rsaEncryption вместо ГОСТ");
            assertRejected(
                    spki(algorithm(GostCurves.OID_SIGN_512, validParams), validBitString),
                    "OID подписи 512 бит на 256-битной кривой");
            byte[] point512 = GostDerCodec.subjectPublicKeyPointBytes(key512);
            byte[] params = pubKeyParams(GostCurves.OID_TC26_A_512, DIGEST_512);
            assertRejected(
                    spki(algorithm(GostCurves.OID_SIGN_256, params), bitString(point512)),
                    "OID подписи 256 бит на 512-битной кривой");
            assertRejected(
                    spki(algorithm("1.2.643.2.2.19", validParams), validBitString),
                    "Наследный OID ГОСТ Р 34.10-2001 не поддерживается");
        }

        @Test
        @DisplayName("Ненулевое число неиспользуемых бит BIT STRING отвергается")
        void unusedBits() {
            byte[] octets = DerCodec.encodeOctetString(point256);
            byte[] content = DerCodec.concat(new byte[] {0x00}, octets);
            content[0] = 0x01;
            // Младший бит последнего байта обнуляем: иначе BIT STRING отвергнет сам разбор DER
            // (ненулевые неиспользуемые биты), а здесь проверяется правило SPKI unused == 0
            content[content.length - 1] &= (byte) 0xFE;
            assertRejected(
                    spki(validAlgorithm, DerCodec.encodeTlv(DerCodec.TAG_BIT_STRING, content)),
                    "BIT STRING с unused bits = 1");
        }

        @Test
        @DisplayName("Данные после OCTET STRING внутри BIT STRING отвергаются")
        void trailingInsideBitString() {
            byte[] octets = DerCodec.encodeOctetString(point256);
            byte[] content = DerCodec.concat(new byte[] {0x00}, octets, new byte[] {0x00});
            assertRejected(
                    spki(validAlgorithm, DerCodec.encodeTlv(DerCodec.TAG_BIT_STRING, content)),
                    "Хвост после OCTET STRING в BIT STRING");
        }

        @Test
        @DisplayName("Значение OCTET STRING неверной длины отвергается")
        void wrongPointLength() {
            byte[] shortPoint = java.util.Arrays.copyOf(point256, point256.length - 1);
            assertRejected(spki(validAlgorithm, bitString(shortPoint)), "Точка на 1 байт короче");
            byte[] longPoint = java.util.Arrays.copyOf(point256, point256.length + 1);
            assertRejected(spki(validAlgorithm, bitString(longPoint)), "Точка на 1 байт длиннее");
        }

        @Test
        @DisplayName("Точка не на кривой отвергается")
        void pointNotOnCurve() {
            byte[] broken = point256.clone();
            broken[0] ^= 0x01;
            assertRejected(spki(validAlgorithm, bitString(broken)), "Точка не на кривой");
        }
    }
}
