package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * issuerUniqueID и subjectUniqueID в TBSCertificate (RFC 5280 §4.1.2.8): IMPLICIT BIT STRING,
 * то есть примитивные теги {@code 0x81} и {@code 0x82}. Допустимы только в сертификатах v2 и v3.
 * Сертификаты ИнфоТеКС их содержат, и раньше такой сертификат не читался вовсе.
 */
@DisplayName("GostCertificate: uniqueID в TBSCertificate")
class GostCertificateUniqueIdTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final int TAG_VERSION = 0xA0;
    private static final int TAG_EXTENSIONS = 0xA3;

    private static byte[] baseCertDer;
    private static byte[] serial;

    @BeforeAll
    static void setUp() {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate cert =
                GostCertificateBuilder.sign(
                        GostCertificateBuilder.create(PARAMS, "CN=Unique Id,O=Test,C=RU")
                                .publicKey(kp.getPublic())
                                .randomSerial()
                                .notBefore("260601000000Z")
                                .notAfter("360601000000Z")
                                .additionalExtensions(
                                        GostCertificateBuilder.buildSkiExtension(kp.getPublic()))
                                .buildTbs(),
                        GostSigner.of(kp.getPrivate()));
        baseCertDer = cert.getEncoded();
        serial = cert.getSerialNumber();
    }

    private static byte[] bitString(int tag) {
        // BIT STRING: 0 неиспользуемых бит и один октет данных
        return DerCodec.encodeTlv(tag, new byte[] {0x00, 0x5A});
    }

    /**
     * Пересобирает сертификат: задаёт версию (0 - без поля), расширения и uniqueID.
     * Подпись остаётся от исходного TBS и недействительна, но разбор её не проверяет.
     */
    private static byte[] rebuild(int version, boolean keepExtensions, byte[]... uniqueIds)
            throws Exception {
        byte[][] top = DerCodec.parseSequenceContents(baseCertDer, 0);
        byte[][] tbsChildren = DerCodec.parseSequenceContents(top[0], 0);

        List<byte[]> children = new ArrayList<>();
        for (byte[] child : tbsChildren) {
            int tag = child[0] & 0xFF;
            if (tag == TAG_VERSION || tag == TAG_EXTENSIONS) {
                continue;
            }
            children.add(child);
        }
        if (version > 1) {
            byte[] versionField =
                    DerCodec.encodeTlv(TAG_VERSION, DerCodec.encodeInteger(version - 1));
            children.add(0, versionField);
        }
        for (byte[] uniqueId : uniqueIds) {
            children.add(uniqueId);
        }
        if (keepExtensions) {
            for (byte[] child : tbsChildren) {
                if ((child[0] & 0xFF) == TAG_EXTENSIONS) {
                    children.add(child);
                }
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        children.forEach(out::writeBytes);
        return DerCodec.encodeSequence(DerCodec.encodeSequence(out.toByteArray()), top[1], top[2]);
    }

    @Test
    @DisplayName("v3: канонические примитивные uniqueID 0x81 и 0x82 пропускаются, поля сохранены")
    void v3PrimitiveUniqueIdsAccepted() throws Exception {
        byte[] der = rebuild(3, true, bitString(0x81), bitString(0x82));
        GostCertificate cert = assertDoesNotThrow(() -> GostCertificate.fromDer(der));
        assertEquals(
                new java.math.BigInteger(1, serial),
                cert.getSerialNumberBigInt(),
                "Серийный номер читается после uniqueID");
        assertEquals("CN=Unique Id, O=Test, C=RU", cert.getSubjectDn(), "Subject читается");
    }

    @Test
    @DisplayName("v3: расширения после uniqueID разбираются (SKI на месте)")
    void v3ExtensionsParsedAfterUniqueIds() throws Exception {
        byte[] der = rebuild(3, true, bitString(0x81));
        GostCertificate cert = GostCertificate.fromDer(der);
        assertEquals(
                true, cert.getSubjectKeyIdentifier() != null, "Расширения не потеряны за uniqueID");
    }

    @Test
    @DisplayName("v3: constructed-вариант 0xA1 по-прежнему пропускается")
    void v3ConstructedUniqueIdStillAccepted() throws Exception {
        byte[] der =
                rebuild(3, true, DerCodec.encodeTlv(0xA1, new byte[] {0x03, 0x02, 0x00, 0x5A}));
        assertDoesNotThrow(() -> GostCertificate.fromDer(der));
    }

    @Test
    @DisplayName("v2: uniqueID допустимы (расширений в v2 нет)")
    void v2UniqueIdsAccepted() throws Exception {
        byte[] der = rebuild(2, false, bitString(0x81), bitString(0x82));
        assertDoesNotThrow(() -> GostCertificate.fromDer(der));
    }

    @Test
    @DisplayName("v1: uniqueID недопустимы (RFC 5280 §4.1.2.8) -> отказ")
    void v1UniqueIdsRejected() throws Exception {
        byte[] der = rebuild(1, false, bitString(0x81));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificate.fromDer(der),
                "uniqueID в сертификате v1 — несогласованная структура");
    }

    @Test
    @DisplayName("Лишний неизвестный тег после SPKI по-прежнему отвергается")
    void unknownTagStillRejected() throws Exception {
        byte[] der = rebuild(3, true, DerCodec.encodeTlv(0x83, new byte[] {0x00, 0x01}));
        assertThrows(
                IllegalArgumentException.class,
                () -> GostCertificate.fromDer(der),
                "Неизвестное поле TBSCertificate");
    }
}
