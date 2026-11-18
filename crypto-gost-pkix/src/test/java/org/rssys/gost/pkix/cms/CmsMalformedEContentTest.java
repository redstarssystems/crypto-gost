package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Битый encapContentInfo недоверенного контейнера даёт только {@code PkixException(PARSE_ERROR)}:
 * ни {@code ArrayIndexOutOfBoundsException}, ни {@code IllegalArgumentException} из разбора DER
 * наружу не выходят ни из {@link CmsSignedDataVerifier}, ни из {@link CAdESVerifier}.
 */
@DisplayName("CMS: битый eContent даёт PkixException(PARSE_ERROR), а не исключение парсера")
class CmsMalformedEContentTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();

    private static GostCertificate cert;
    private static byte[] signed;
    private static VerifyOptions options;
    private static TrustAnchors anchors;

    @BeforeAll
    static void setUp() throws Exception {
        KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
        cert =
                GostCertificateBuilder.create(PARAMS, "CN=Malformed EContent,O=Test,C=RU")
                        .publicKey(kp.getPublic())
                        .randomSerial()
                        .notBeforeNow()
                        .validForDays(30)
                        .basicConstraints(true, null)
                        .sign(kp.getPrivate());
        signed =
                CmsSignedDataBuilder.create()
                        .data("payload".getBytes())
                        .addSigner(kp.getPrivate(), cert)
                        .addCertificate(cert)
                        .build();
        anchors = TrustAnchors.ofCertificate(cert);
        options = VerifyOptions.trusting(anchors, SignerSelection.ALL, Revocation.none());
    }

    /** Пересобирает контейнер с заменой полей encapContentInfo после eContentType. */
    private static byte[] withEncapFields(byte[]... fieldsAfterType) throws PkixException {
        CmsContentInfo contentInfo = CmsContentInfo.decode(signed);
        byte[][] signedData = DerCodec.parseSequenceContents(contentInfo.content(), 0);
        byte[][] encap = DerCodec.parseSequenceContents(signedData[2], 0);
        byte[][] rebuilt = new byte[1 + fieldsAfterType.length][];
        rebuilt[0] = encap[0];
        System.arraycopy(fieldsAfterType, 0, rebuilt, 1, fieldsAfterType.length);
        signedData[2] = DerCodec.encodeSequence(rebuilt);
        return CmsContentInfo.encode(GostOids.CMS_SIGNED_DATA, DerCodec.encodeSequence(signedData));
    }

    private static byte[] concat(byte[]... parts) {
        return DerCodec.concat(parts);
    }

    private static byte[] explicit0(byte[] content) {
        return DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_0, content);
    }

    private static void assertParseError(byte[] container, String message) {
        PkixException direct =
                assertThrows(
                        PkixException.class,
                        () -> CmsSignedDataVerifier.verify(container, options),
                        message);
        assertEquals(PkixException.Reason.PARSE_ERROR, direct.reason(), message);
        // CAdES идёт через тот же разбор: наружу только PkixException
        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyBES(container, anchors),
                message + " (CAdES)");
    }

    @Test
    @DisplayName("Контрольный контейнер с исправным eContent принимается")
    void validContainerIsAccepted() {
        assertDoesNotThrow(() -> CmsSignedDataVerifier.verify(signed, options));
    }

    @Test
    @DisplayName("Пустой [0] eContent")
    void emptyExplicitField() throws Exception {
        assertParseError(withEncapFields(explicit0(new byte[0])), "пустой [0]");
    }

    @Test
    @DisplayName("[0] с одним байтом внутри и OCTET STRING с завышенной длиной")
    void truncatedOctetString() throws Exception {
        assertParseError(withEncapFields(explicit0(new byte[] {0x04})), "усечённый OCTET STRING");
        assertParseError(
                withEncapFields(explicit0(new byte[] {0x04, 0x05, 0x01})),
                "длина OCTET STRING больше содержимого");
    }

    @Test
    @DisplayName("Хвост после OCTET STRING внутри [0]")
    void trailingBytesAfterOctetString() throws Exception {
        byte[] octets = DerCodec.encodeOctetString("payload".getBytes());
        assertParseError(
                withEncapFields(explicit0(concat(octets, new byte[] {0x00, 0x00}))),
                "хвост после OCTET STRING");
    }

    @Test
    @DisplayName("Неопределённая длина [0] без маркера конца")
    void indefiniteLengthWithoutEoc() throws Exception {
        assertParseError(
                withEncapFields(new byte[] {(byte) 0xA0, (byte) 0x80}), "A0 80 без маркера конца");
    }

    @Test
    @DisplayName("Constructed OCTET STRING из сегментов и неопределённая длина BER принимаются")
    void berEncodedEContentIsAccepted() throws Exception {
        byte[] first = DerCodec.encodeOctetString("pay".getBytes());
        byte[] second = DerCodec.encodeOctetString("load".getBytes());
        byte[] constructed =
                DerCodec.encodeTlv(DerCodec.TAG_OCTET_STRING_CONSTRUCTED, concat(first, second));
        // Хэш подписанных атрибутов считается по склеенному содержимому "payload"
        assertDoesNotThrow(
                () ->
                        CmsSignedDataVerifier.verify(
                                withEncapFields(explicit0(constructed)), options),
                "сегменты склеиваются");
        byte[] indefinite =
                concat(
                        new byte[] {(byte) 0xA0, (byte) 0x80},
                        DerCodec.encodeOctetString("payload".getBytes()),
                        new byte[] {0x00, 0x00});
        assertDoesNotThrow(
                () -> CmsSignedDataVerifier.verify(withEncapFields(indefinite), options),
                "неопределённая длина [0] с маркером конца");
    }

    @Test
    @DisplayName("Форма КриптоПро: A0 80 { 24 80 { 04 .. 04 .. } } с маркерами конца принимается")
    void cryptoProStreamingFormIsAccepted() throws Exception {
        byte[] cryptoPro =
                concat(
                        new byte[] {(byte) 0xA0, (byte) 0x80, 0x24, (byte) 0x80},
                        DerCodec.encodeOctetString("pay".getBytes()),
                        DerCodec.encodeOctetString("load".getBytes()),
                        new byte[] {0x00, 0x00, 0x00, 0x00});
        assertDoesNotThrow(
                () -> CmsSignedDataVerifier.verify(withEncapFields(cryptoPro), options),
                "потоковая BER-форма КриптоПро с несколькими сегментами");
    }

    @Test
    @DisplayName("Усечение потоковой формы и хвост после неё отвергаются")
    void truncatedOrTrailingStreamingFormRejected() throws Exception {
        byte[] segments = DerCodec.encodeOctetString("payload".getBytes());
        byte[] noOuterEoc =
                concat(
                        new byte[] {(byte) 0xA0, (byte) 0x80, 0x24, (byte) 0x80},
                        segments,
                        new byte[] {0x00, 0x00});
        assertParseError(withEncapFields(noOuterEoc), "нет внешнего маркера конца");
        byte[] emptyIndefinite = new byte[] {(byte) 0xA0, (byte) 0x80, 0x00, 0x00};
        assertParseError(withEncapFields(emptyIndefinite), "A0 80 00 00 - пустое значение");
    }

    @Test
    @DisplayName("Чужой тег вместо [0] EXPLICIT")
    void wrongExplicitTag() throws Exception {
        byte[] octets = DerCodec.encodeOctetString("payload".getBytes());
        assertParseError(
                withEncapFields(DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, octets)),
                "тег [1] вместо [0]");
    }
}
