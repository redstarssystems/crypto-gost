package org.rssys.gost.jca.spec;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.JcaTestSupport;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Строгий разбор PrivateKeyInfo / OneAsymmetricKey (RFC 5958) в {@link GostDerCodec}:
 * версия 0 и версия 1 с {@code [1] publicKey}, порядок и состав полей, сверка открытого
 * ключа с вычисленным из d.
 */
@DisplayName("GostDerCodec: PKCS#8 версии 0 и 1, строгий разбор и сверка publicKey")
class GostDerCodecPrivateKeyInfoTest {

    private static final int TAG_ATTRIBUTES = 0xA0;
    private static final int TAG_PUBLIC_KEY = 0x81;

    /** Расшифрованный ключ из RFC 9548, пример A.2.3 (OneAsymmetricKey версии 1, 512 бит). */
    private static final String RFC_9548_A2_KEY_BASE64 =
            "MIHiAgEBMBcGCCqFAwcBAQECMAsGCSqFAwcBAgECAQRAEWkl+eblsHWs86SNgRKq"
                    + "SxMOgGhbvR/uZ5/WWfdNG1axvUwVhpcXIxDZUmzQuNzqJBkseI7f5/JjXyTFRF1a"
                    + "+YGBgQG0i7davCkOGGVcYqFPtS1fUIROzB0fYARIe0tclTRpare/qzRuVRapqzzO"
                    + "+K21LDpYVfDPs2Sqa13ZN+Ts/JUlv59qCFB2cYpFyB/0kh4+K79yvz7r8+4WE0Em"
                    + "Zf8T3ae/J1Jo6xGunecH1/G4hMts9HYLnxbwJDMNVGuIHV6gzg==";

    private static final BigInteger SAMPLE_KEY =
            new BigInteger("5a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef", 16);

    private static final ECParameters[] CURVES = {
        ECParameters.cryptoProA(), ECParameters.tc26c512()
    };

    // ------------------------------------------------------------------
    // Сборка синтетических PKCS#8
    // ------------------------------------------------------------------

    /** Части версии 0 из нашего кодировщика: AlgorithmIdentifier и OCTET STRING с ключом. */
    private record Template(byte[] algorithmIdentifier, byte[] privateKeyOctets, byte[] point) {}

    private static Template template(ECParameters params, BigInteger key) {
        PrivateKeyParameters priv = new PrivateKeyParameters(key, params);
        try {
            byte[][] outer = DerCodec.parseSequenceContents(GostDerCodec.encodePrivateKey(priv), 0);
            return new Template(
                    outer[1],
                    outer[2],
                    GostDerCodec.subjectPublicKeyPointBytes(priv.derivePublicKey()));
        } finally {
            priv.destroy();
        }
    }

    private static byte[] version(int value) {
        return DerCodec.encodeInteger(value);
    }

    private static byte[] publicKeyElement(int leadingOctet, byte[] point) {
        byte[] content = new byte[1 + point.length];
        content[0] = (byte) leadingOctet;
        System.arraycopy(point, 0, content, 1, point.length);
        return DerCodec.encodeTlv(TAG_PUBLIC_KEY, content);
    }

    private static byte[] attributesElement() {
        return DerCodec.encodeTlv(TAG_ATTRIBUTES, new byte[0]);
    }

    private static byte[] pkcs8(int version, Template t, byte[]... optional) {
        byte[][] elements = new byte[3 + optional.length][];
        elements[0] = version(version);
        elements[1] = t.algorithmIdentifier();
        elements[2] = t.privateKeyOctets();
        System.arraycopy(optional, 0, elements, 3, optional.length);
        return DerCodec.encodeSequence(elements);
    }

    private static void assertRejected(byte[] der, String expectedPart, String message) {
        IllegalArgumentException e =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> GostDerCodec.decodePrivateKey(der),
                        message);
        assertTrue(
                e.getMessage().contains(expectedPart),
                message
                        + ": сообщение «"
                        + e.getMessage()
                        + "» не содержит «"
                        + expectedPart
                        + "»");
    }

    // ------------------------------------------------------------------
    // Версия 1: допустимые формы
    // ------------------------------------------------------------------

    @Test
    @DisplayName(
            "Версия 1, первый октет 0x00 и верная точка: принимается на 256- и 512-битной кривой")
    void versionOneWithZeroLeadingOctetIsAccepted() {
        for (ECParameters params : CURVES) {
            Template t = template(params, SAMPLE_KEY);
            PrivateKeyParameters decoded =
                    GostDerCodec.decodePrivateKey(pkcs8(1, t, publicKeyElement(0x00, t.point())));
            assertEquals(SAMPLE_KEY, decoded.getD(), "d должен совпасть: " + params.n.bitLength());
        }
    }

    @Test
    @DisplayName("Версия 1, первый октет 0x01 (как в A.2 RFC 9548): принимается на обеих кривых")
    void versionOneWithOneLeadingOctetIsAccepted() {
        for (ECParameters params : CURVES) {
            Template t = template(params, SAMPLE_KEY);
            PrivateKeyParameters decoded =
                    GostDerCodec.decodePrivateKey(pkcs8(1, t, publicKeyElement(0x01, t.point())));
            assertEquals(SAMPLE_KEY, decoded.getD(), "d должен совпасть: " + params.n.bitLength());
        }
    }

    @Test
    @DisplayName(
            "Первый октет 0x01 и нечётный последний байт точки: принимается (младший бит не проверяется)")
    void oneLeadingOctetWithOddLastPointByteIsAccepted() {
        // В A.2 последний байт точки чётный (0xCE), поэтому пример сам по себе не поймает
        // «ужесточение» до правила DER про нулевой младший бит: этот тест его поймает
        for (ECParameters params : CURVES) {
            BigInteger key = SAMPLE_KEY;
            Template t = template(params, key);
            while ((t.point()[t.point().length - 1] & 1) == 0) {
                key = key.add(BigInteger.ONE);
                t = template(params, key);
            }
            PrivateKeyParameters decoded =
                    GostDerCodec.decodePrivateKey(pkcs8(1, t, publicKeyElement(0x01, t.point())));
            assertEquals(
                    key, decoded.getD(), "ключ с нечётным последним байтом точки должен грузиться");
        }
    }

    @Test
    @DisplayName("Версия 1 с [0] attributes перед [1] publicKey принимается")
    void versionOneWithAttributesIsAccepted() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        PrivateKeyParameters decoded =
                GostDerCodec.decodePrivateKey(
                        pkcs8(1, t, attributesElement(), publicKeyElement(0x00, t.point())));
        assertEquals(SAMPLE_KEY, decoded.getD());
    }

    @Test
    @DisplayName("Версия 0 с [0] attributes принимается")
    void versionZeroWithAttributesIsAccepted() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        PrivateKeyParameters decoded =
                GostDerCodec.decodePrivateKey(pkcs8(0, t, attributesElement()));
        assertEquals(SAMPLE_KEY, decoded.getD());
    }

    @Test
    @DisplayName("Ключ из RFC 9548 A.2.3 (версия 1, 512 бит) загружается целиком")
    void rfc9548ExampleA2Loads() {
        byte[] der = Base64.getDecoder().decode(RFC_9548_A2_KEY_BASE64);
        PrivateKeyParameters decoded = GostDerCodec.decodePrivateKey(der);

        assertEquals(512, decoded.getParams().n.bitLength(), "A.2 использует 512-битную кривую");
        // Открытый ключ из примера (128 байт после первого октета) равен вычисленному из d
        byte[][] outer = DerCodec.parseSequenceContents(der, 0);
        byte[] publicKeyField = outer[3];
        byte[] expectedPoint = GostDerCodec.subjectPublicKeyPointBytes(decoded.derivePublicKey());
        assertArrayEquals(
                expectedPoint,
                Arrays.copyOfRange(
                        publicKeyField, publicKeyField.length - 128, publicKeyField.length),
                "точка из примера должна совпасть с вычисленной из d");
    }

    // ------------------------------------------------------------------
    // Версия 1: отказы по publicKey
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Первый октет 0x02 при верной точке -> отказ")
    void unsupportedLeadingOctetIsRejected() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        assertRejected(
                pkcs8(1, t, publicKeyElement(0x02, t.point())),
                "leading octet",
                "октет, отличный от 0x00 и 0x01, недопустим даже при верной точке");
    }

    @Test
    @DisplayName("Точка с изменённым байтом -> отказ без раскрытия значений")
    void mismatchedPointIsRejected() {
        for (ECParameters params : CURVES) {
            Template t = template(params, SAMPLE_KEY);
            byte[] tampered = t.point().clone();
            tampered[5] ^= 0x01;
            for (int lead : new int[] {0x00, 0x01}) {
                IllegalArgumentException e =
                        assertThrows(
                                IllegalArgumentException.class,
                                () ->
                                        GostDerCodec.decodePrivateKey(
                                                pkcs8(1, t, publicKeyElement(lead, tampered))),
                                "несовпадающая точка должна отвергаться");
                assertTrue(e.getMessage().contains("does not match"), e.getMessage());
                assertFalse(
                        e.getMessage().contains(SAMPLE_KEY.toString(16)),
                        "сообщение не должно содержать значение d");
            }
        }
    }

    @Test
    @DisplayName("Остаток publicKey на 1 байт короче или длиннее -> отказ")
    void wrongPointLengthIsRejected() {
        for (ECParameters params : CURVES) {
            Template t = template(params, SAMPLE_KEY);
            byte[] shorter = Arrays.copyOf(t.point(), t.point().length - 1);
            byte[] longer = Arrays.copyOf(t.point(), t.point().length + 1);
            assertRejected(
                    pkcs8(1, t, publicKeyElement(0x01, shorter)),
                    "invalid length",
                    "укороченная точка: " + params.n.bitLength());
            assertRejected(
                    pkcs8(1, t, publicKeyElement(0x01, longer)),
                    "invalid length",
                    "удлинённая точка: " + params.n.bitLength());
        }
    }

    // ------------------------------------------------------------------
    // Состав, порядок и версия
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Версия 1 без [1] publicKey -> отказ")
    void versionOneWithoutPublicKeyIsRejected() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        assertRejected(pkcs8(1, t), "requires publicKey", "версия 1 обязана содержать publicKey");
        assertRejected(
                pkcs8(1, t, attributesElement()),
                "requires publicKey",
                "версия 1 с одними attributes тоже не годится");
    }

    @Test
    @DisplayName("Версия 0 с [1] publicKey -> отказ")
    void versionZeroWithPublicKeyIsRejected() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        assertRejected(
                pkcs8(0, t, publicKeyElement(0x00, t.point())),
                "only in version 1",
                "publicKey допустим только в версии 1");
    }

    @Test
    @DisplayName("Версия 2 -> отказ")
    void unsupportedVersionIsRejected() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        assertRejected(
                pkcs8(2, t, publicKeyElement(0x00, t.point())),
                "Unsupported PKCS#8 version",
                "версия 2 не поддерживается");
    }

    @Test
    @DisplayName("[1] перед [0], повтор [0] или [1] -> отказ")
    void wrongOrderAndDuplicatesAreRejected() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        byte[] publicKey = publicKeyElement(0x00, t.point());
        assertRejected(
                pkcs8(1, t, publicKey, attributesElement()),
                "Unexpected element",
                "[0] после [1] нарушает порядок");
        assertRejected(pkcs8(1, t, publicKey, publicKey), "Unexpected element", "повтор [1]");
        assertRejected(
                pkcs8(1, t, attributesElement(), attributesElement(), publicKey),
                "Unexpected element",
                "повтор [0]");
    }

    @Test
    @DisplayName("Лишний элемент после privateKey -> отказ")
    void unknownTrailingElementIsRejected() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        assertRejected(
                pkcs8(0, t, DerCodec.encodeNull()),
                "Unexpected element",
                "неизвестный элемент после ключа");
    }

    @Test
    @DisplayName("Байты после структуры и indefinite length -> отказ")
    void trailingBytesAndIndefiniteLengthAreRejected() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        byte[] der = pkcs8(0, t);

        byte[] withTail = Arrays.copyOf(der, der.length + 1);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerCodec.decodePrivateKey(withTail),
                "байт после структуры недопустим");

        byte[][] outer = DerCodec.parseSequenceContents(der, 0);
        byte[] contents = DerCodec.concat(outer[0], outer[1], outer[2]);
        byte[] indefinite = new byte[2 + contents.length + 2];
        indefinite[0] = 0x30;
        indefinite[1] = (byte) 0x80;
        System.arraycopy(contents, 0, indefinite, 2, contents.length);
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerCodec.decodePrivateKey(indefinite),
                "BER с неопределённой длиной недопустим");
    }

    @Test
    @DisplayName(
            "[0] attributes: длина за границей структуры, битый внутренний TLV и не-SEQUENCE -> отказ")
    void brokenAttributesAreRejected() {
        Template t = template(CURVES[0], SAMPLE_KEY);

        // длина [0] заявляет больше байт, чем осталось в структуре
        byte[] outOfBounds = pkcs8(0, t, attributesElement());
        outOfBounds[outOfBounds.length - 1] = 0x20;
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerCodec.decodePrivateKey(outOfBounds),
                "[0] с длиной за границей структуры недопустим");

        // внешняя длина верна, но внутренний INTEGER заявляет 1 байт при 0 оставшихся: A0 02 02 01
        assertRejected(
                pkcs8(0, t, DerCodec.encodeTlv(TAG_ATTRIBUTES, new byte[] {0x02, 0x01})),
                "out of bounds",
                "битый внутренний TLV в [0]");

        // внутри [0] корректный, но не SEQUENCE элемент: A0 02 05 00
        assertRejected(
                pkcs8(0, t, DerCodec.encodeTlv(TAG_ATTRIBUTES, DerCodec.encodeNull())),
                "Invalid attributes",
                "атрибут обязан быть SEQUENCE");
    }

    @Test
    @DisplayName("[0] attributes с корректным атрибутом (SEQUENCE { OID, SET }) принимается")
    void wellFormedAttributeIsAccepted() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        byte[] attribute =
                DerCodec.encodeSequence(
                        DerCodec.encodeOid("1.2.840.113549.1.9.20"), DerCodec.encodeSet());

        PrivateKeyParameters decoded =
                GostDerCodec.decodePrivateKey(
                        pkcs8(0, t, DerCodec.encodeTlv(TAG_ATTRIBUTES, attribute)));

        assertEquals(SAMPLE_KEY, decoded.getD());
    }

    // ------------------------------------------------------------------
    // AlgorithmIdentifier внутри ключа
    // ------------------------------------------------------------------

    private static byte[] pkcs8WithAlgorithmIdentifier(byte[] algorithmIdentifier, Template t) {
        return DerCodec.encodeSequence(version(0), algorithmIdentifier, t.privateKeyOctets());
    }

    @Test
    @DisplayName(
            "AlgorithmIdentifier: лишний элемент, пустые или лишние параметры -> IllegalArgumentException")
    void malformedAlgorithmIdentifierIsRejected() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        byte[][] algId = DerCodec.parseSequenceContents(t.algorithmIdentifier(), 0);

        assertRejected(
                pkcs8WithAlgorithmIdentifier(
                        DerCodec.encodeSequence(algId[0], algId[1], DerCodec.encodeNull()), t),
                "Invalid AlgorithmIdentifier",
                "лишний элемент в AlgorithmIdentifier");
        // пустая последовательность параметров раньше давала ArrayIndexOutOfBoundsException
        assertRejected(
                pkcs8WithAlgorithmIdentifier(
                        DerCodec.encodeSequence(algId[0], DerCodec.encodeSequence()), t),
                "Invalid GostR3410-2012-PublicKeyParameters",
                "пустые параметры ключа");
        byte[][] params = DerCodec.parseSequenceContents(algId[1], 0);
        assertRejected(
                pkcs8WithAlgorithmIdentifier(
                        DerCodec.encodeSequence(
                                algId[0],
                                DerCodec.encodeSequence(
                                        params[0], params[1], DerCodec.encodeNull())),
                        t),
                "Invalid GostR3410-2012-PublicKeyParameters",
                "три элемента в параметрах ключа");
    }

    @Test
    @DisplayName(
            "AlgorithmIdentifier: OID алгоритма подписи не соответствует размеру кривой -> отказ")
    void signatureAlgorithmMustMatchCurveSize() {
        // 512-битная кривая с OID алгоритма подписи для 256 бит
        Template t = template(ECParameters.tc26c512(), SAMPLE_KEY);
        byte[][] algId = DerCodec.parseSequenceContents(t.algorithmIdentifier(), 0);
        byte[] mismatched =
                DerCodec.encodeSequence(DerCodec.encodeOid("1.2.643.7.1.1.1.1"), algId[1]);

        assertRejected(
                pkcs8WithAlgorithmIdentifier(mismatched, t),
                "Unsupported public key algorithm OID",
                "OID подписи 256 бит несовместим с 512-битной кривой");
    }

    // ------------------------------------------------------------------
    // checkNotMasked и запись
    // ------------------------------------------------------------------

    @Test
    @DisplayName("checkNotMasked применяет тот же строгий разбор: версия, состав, порядок")
    void checkNotMaskedSharesStructuralRules() {
        Template t = template(CURVES[0], SAMPLE_KEY);
        assertDoesNotThrow(() -> GostDerCodec.checkNotMasked(pkcs8(0, t)));
        assertDoesNotThrow(
                () -> GostDerCodec.checkNotMasked(pkcs8(1, t, publicKeyElement(0x01, t.point()))));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerCodec.checkNotMasked(pkcs8(2, t)),
                "версия 2");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerCodec.checkNotMasked(pkcs8(1, t)),
                "версия 1 без publicKey");
        assertThrows(
                IllegalArgumentException.class,
                () -> GostDerCodec.checkNotMasked(pkcs8(0, t, DerCodec.encodeNull())),
                "лишний элемент после ключа");
    }

    @Test
    @DisplayName("encodePrivateKey по-прежнему пишет версию 0 без publicKey")
    void encoderStillWritesVersionZeroWithoutPublicKey() {
        byte[] der = GostDerCodec.encodePrivateKey(new PrivateKeyParameters(SAMPLE_KEY, CURVES[0]));
        byte[][] outer = DerCodec.parseSequenceContents(der, 0);

        assertEquals(3, outer.length, "версия, AlgorithmIdentifier и ключ, без [0] и [1]");
        assertEquals(BigInteger.ZERO, DerCodec.parseInteger(outer[0], 0), "версия 0");
    }

    @Test
    @DisplayName("KeyFactory.generatePrivate принимает ключ версии 1 (путь вне PFX)")
    void keyFactoryAcceptsVersionOneKey() throws Exception {
        JcaTestSupport.ensureProvider();
        byte[] der = Base64.getDecoder().decode(RFC_9548_A2_KEY_BASE64);

        PrivateKey key =
                KeyFactory.getInstance("ECGOST3410-2012")
                        .generatePrivate(new PKCS8EncodedKeySpec(der));

        assertNotNull(key, "ключ версии 1 из RFC 9548 должен читаться через KeyFactory");
    }
}
