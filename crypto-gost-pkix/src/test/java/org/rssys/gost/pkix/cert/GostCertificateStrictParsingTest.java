package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Строгий разбор сертификата и PEM: поле version, хвост после сертификата, PEM из одного блока.
 * Сертификат пересобирается с испорченным полем; подпись при разборе не проверяется, поэтому
 * достаточно заменить нужный элемент TBSCertificate.
 */
@DisplayName("GostCertificate и PEM: строгий разбор version, хвоста и числа блоков")
class GostCertificateStrictParsingTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static byte[] validDer;
    private static byte[] validDerWithoutExtensions;
    private static String pem;

    @BeforeAll
    static void setUp() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert =
                GostCertificateBuilder.create(PARAMS, "CN=Strict Parsing,O=Test,C=RU")
                        .publicKey(kp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(30)
                        .basicConstraints(true, null)
                        .sign(kp.getPrivate());
        validDer = cert.getEncoded();
        // v1 и v2 допускают только сертификат без расширений
        validDerWithoutExtensions =
                GostCertificateBuilder.create(PARAMS, "CN=Strict Parsing V1,O=Test,C=RU")
                        .publicKey(kp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(30)
                        .sign(kp.getPrivate())
                        .getEncoded();
        pem = GostPemUtils.toPem(validDer);
    }

    /** Заменяет первый элемент TBSCertificate (version [0]) и пересобирает сертификат. */
    private static byte[] withVersionField(byte[] versionField) {
        return withVersionField(validDer, versionField);
    }

    private static byte[] withVersionField(byte[] baseDer, byte[] versionField) {
        byte[][] top = DerCodec.parseSequenceContents(baseDer, 0);
        byte[][] tbs = DerCodec.parseSequenceContents(top[0], 0);
        tbs[0] = versionField;
        top[0] = DerCodec.encodeSequence(tbs);
        return DerCodec.encodeSequence(top);
    }

    private static byte[] explicitVersion(byte... integerContent) {
        return DerCodec.encodeTlv(
                DerCodec.TAG_CTX_CONSTRUCTED_0, DerCodec.encodeTlv(0x02, integerContent));
    }

    // ------------------------------------------------------------------------
    // version
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Контрольный сертификат: v3, разбирается")
    void validCertificateIsParsed() {
        assertEquals(3, new GostCertificate(validDer).getVersion(), "Ожидалась версия v3");
    }

    @Test
    @DisplayName("version 0, 1, 2 принимаются; явный v1 (значение 0) допускается")
    void versionZeroToTwoAccepted() {
        for (int value = 0; value <= 2; value++) {
            byte[] der = withVersionField(validDerWithoutExtensions, explicitVersion((byte) value));
            GostCertificate cert = assertDoesNotThrow(() -> new GostCertificate(der));
            assertEquals(value + 1, cert.getVersion(), "version=" + value);
        }
    }

    @Test
    @DisplayName("version 3 и выше, отрицательная и неминимальная запись отвергаются")
    void invalidVersionValuesRejected() {
        byte[][] bad = {
            explicitVersion((byte) 0x03),
            explicitVersion((byte) 0x7F),
            explicitVersion((byte) 0xFF),
            explicitVersion((byte) 0x00, (byte) 0x02),
            explicitVersion((byte) 0x02, (byte) 0x00),
            explicitVersion(new byte[0]),
        };
        for (byte[] field : bad) {
            byte[] der = withVersionField(field);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new GostCertificate(der),
                    "Некорректное поле version должно отвергаться: " + Arrays.toString(field));
        }
    }

    @Test
    @DisplayName("Лишние байты после INTEGER внутри [0] отвергаются")
    void trailingBytesInsideVersionFieldRejected() {
        byte[] content =
                DerCodec.concat(DerCodec.encodeTlv(0x02, new byte[] {2}), DerCodec.encodeNull());
        byte[] der = withVersionField(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, content));
        assertThrows(IllegalArgumentException.class, () -> new GostCertificate(der));
    }

    @Test
    @DisplayName("Не INTEGER внутри [0] отвергается")
    void nonIntegerInsideVersionFieldRejected() {
        byte[] der =
                withVersionField(
                        DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, DerCodec.encodeNull()));
        assertThrows(IllegalArgumentException.class, () -> new GostCertificate(der));
    }

    // ------------------------------------------------------------------------
    // Подпись: тег и хвост внутри внешней SEQUENCE
    // ------------------------------------------------------------------------

    @Test
    @DisplayName(
            "Тег подписи 0x23, 0x43 и 0x83 отвергается: сверка тега целиком, а не по маске 0x1F")
    void signatureTagMustBeExactBitString() {
        byte[][] top = DerCodec.parseSequenceContents(validDer, 0);
        for (int tag : new int[] {0x23, 0x43, 0x83}) {
            byte[] signature = top[2].clone();
            signature[0] = (byte) tag;
            byte[] der = DerCodec.encodeSequence(top[0], top[1], signature);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new GostCertificate(der),
                    "Тег подписи 0x" + Integer.toHexString(tag) + " не BIT STRING");
        }
    }

    @Test
    @DisplayName("Элемент после подписи внутри внешней SEQUENCE отвергается")
    void trailingElementAfterSignatureRejected() {
        byte[][] top = DerCodec.parseSequenceContents(validDer, 0);
        byte[] der = DerCodec.encodeSequence(top[0], top[1], top[2], DerCodec.encodeNull());
        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> new GostCertificate(der));
        assertTrue(
                e.getMessage().contains("trailing"),
                "Сообщение должно называть хвост: " + e.getMessage());
    }

    // ------------------------------------------------------------------------
    // Хвост после сертификата
    // ------------------------------------------------------------------------

    @Test
    @DisplayName("Байты после сертификата отвергаются, а не остаются в getEncoded()")
    void trailingBytesAfterCertificateRejected() {
        byte[] withTail = Arrays.copyOf(validDer, validDer.length + 3);
        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> new GostCertificate(withTail));
        assertTrue(
                e.getMessage().contains("trailing"),
                "Сообщение должно называть хвост: " + e.getMessage());
    }

    @Test
    @DisplayName("Два сертификата подряд в одном DER-массиве отвергаются")
    void concatenatedCertificatesRejected() {
        byte[] two = DerCodec.concat(validDer, validDer);
        assertThrows(IllegalArgumentException.class, () -> new GostCertificate(two));
    }

    // ------------------------------------------------------------------------
    // PEM
    // ------------------------------------------------------------------------

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    @Test
    @DisplayName("PEM из одного блока декодируется")
    void singlePemBlockDecoded() {
        assertTrue(Arrays.equals(validDer, GostPemUtils.pemToDer(ascii(pem))), "DER совпадает");
        assertEquals(3, GostCertificate.fromPemOrDer(ascii(pem)).getVersion());
    }

    @Test
    @DisplayName("PEM из двух блоков отвергается с подсказкой про listFromPem")
    void twoPemBlocksRejected() {
        byte[] chain = ascii(pem + pem);
        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> GostPemUtils.pemToDer(chain));
        assertTrue(
                e.getMessage().contains("exactly one PEM block, got 2")
                        && e.getMessage().contains("listFromPem"),
                "Сообщение должно называть число блоков и listFromPem: " + e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> GostCertificate.fromPemOrDer(chain));
        assertThrows(IllegalArgumentException.class, () -> GostCertificate.pemToDer(chain));
    }

    @Test
    @DisplayName("Для файла цепочки служит listFromPem")
    void listFromPemReadsChain() {
        assertEquals(2, GostCertificate.listFromPem(ascii(pem + pem)).size());
    }

    @Test
    @DisplayName("BEGIN без END и END без BEGIN отвергаются")
    void unbalancedHeadersRejected() {
        String begin = "-----BEGIN CERTIFICATE-----\n";
        String end = "-----END CERTIFICATE-----\n";
        String body = pem.substring(begin.length(), pem.length() - end.length());
        assertThrows(
                IllegalArgumentException.class, () -> GostPemUtils.pemToDer(ascii(begin + body)));
        assertThrows(
                IllegalArgumentException.class, () -> GostPemUtils.pemToDer(ascii(body + end)));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostPemUtils.pemToDer(ascii(end + body + begin)),
                "Порядок END, BEGIN недопустим");
    }

    @Test
    @DisplayName("Данные без заголовков читаются как голый Base64")
    void headerlessBase64Accepted() {
        String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        assertTrue(Arrays.equals(validDer, GostPemUtils.pemToDer(ascii(body))));
    }
}
