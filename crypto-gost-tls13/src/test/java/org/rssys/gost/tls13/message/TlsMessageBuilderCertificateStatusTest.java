package org.rssys.gost.tls13.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixCertTestHelper;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsConstants;

/**
 * Формат CertificateStatus в Certificate: {@code status_type(1) || uint24(len) || OCSPResponse}
 * (RFC 6066 §8, RFC 8446 §4.4.2.1).
 */
@DisplayName("TlsMessageBuilder/Parser: CertificateStatus (OCSP staple) по RFC 6066 §8")
class TlsMessageBuilderCertificateStatusTest {

    private static final int HASH_LEN = 32;

    /** Минимальный OCSPResponse DER: successful, без responseBytes. */
    private static final byte[] OCSP = {0x30, 0x03, 0x0A, 0x01, 0x00};

    private static PkixCertTestHelper.CertBundle serverCert;

    @BeforeAll
    static void setUp() throws Exception {
        serverCert = PkixCertTestHelper.createCertWithKey(ECParameters.tc26a256());
    }

    private static TlsMessageBuilder builder() {
        TlsCiphersuite cs = TlsCiphersuite.TLS_GOST_2012_KUZNYECHIK_MGM_STREEBOG_256_L;
        return new TlsMessageBuilder(
                cs,
                List.of(cs.getId()),
                TlsConstants.GRP_GC256A,
                TlsConstants.SIG_GOST_TC26_A_256,
                serverCert.priv,
                List.of(serverCert.cert),
                HASH_LEN);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    @Test
    @DisplayName("Wire-вектор: 01 00 00 05 30 03 0A 01 00")
    void wireVector() {
        byte[] body = builder().buildCertificateBody(OCSP);
        byte[] expected = {
            0x00, 0x05, 0x00, 0x09, 0x01, 0x00, 0x00, 0x05, 0x30, 0x03, 0x0A, 0x01, 0x00
        };
        int at = indexOf(body, expected);
        assertEquals(
                body.length - expected.length,
                at,
                "status_request должно быть последним полем записи и содержать uint24-длину");
        // Расширение единственное в блоке extensions записи: блок = 2 + 2 + 9 = 13 байт, его
        // длина стоит сразу перед типом расширения
        assertEquals(0x00, body[at - 2], "старший байт длины блока extensions");
        assertEquals(0x0D, body[at - 1], "длина блока extensions = 13");
    }

    @Test
    @DisplayName("Круговой проход: парсер возвращает чистый OCSPResponse DER")
    void roundTrip() throws Exception {
        List<GostCertificate> chain =
                TlsMessageParser.parseCertificate(
                        builder().buildCertificateBody(OCSP),
                        Set.of(TlsConstants.EXT_STATUS_REQUEST));
        assertArrayEquals(OCSP, chain.get(0).getOcspResponse(), "OCSP-ответ должен совпасть");
    }

    @Test
    @DisplayName("Максимальный ответ (поле extensions - uint16): кодируется без переполнения")
    void maxResponseRoundTrip() throws Exception {
        byte[] big = new byte[TlsConstants.MAX_OCSP_STAPLE_SIZE];
        big[0] = 0x30;
        List<GostCertificate> chain =
                TlsMessageParser.parseCertificate(
                        builder().buildCertificateBody(big),
                        Set.of(TlsConstants.EXT_STATUS_REQUEST));
        assertArrayEquals(big, chain.get(0).getOcspResponse(), "предельный ответ должен пройти");
    }

    @Test
    @DisplayName("Неизвестный status_type игнорируется: сертификат разобран, staple не сохранён")
    // RFC 8446 §4.2: неизвестное значение не повод рвать соединение.
    void unknownStatusTypeIgnored() throws Exception {
        byte[] body = builder().buildCertificateBody(OCSP);
        // Хвост записи: status_type(1) || uint24(1) || OCSP(5).
        int statusTypeOffset = body.length - (1 + 3 + OCSP.length);
        body[statusTypeOffset] = 0x7F;
        List<GostCertificate> chain =
                TlsMessageParser.parseCertificate(body, Set.of(TlsConstants.EXT_STATUS_REQUEST));
        assertEquals(null, chain.get(0).getOcspResponse(), "неизвестный тип не даёт staple");
    }

    @Test
    @DisplayName("null отключает staple, расширение не пишется")
    void nullDisablesStaple() throws Exception {
        List<GostCertificate> chain =
                TlsMessageParser.parseCertificate(
                        builder().buildCertificateBody(null),
                        Set.of(TlsConstants.EXT_STATUS_REQUEST));
        assertEquals(null, chain.get(0).getOcspResponse(), "staple не должен быть передан");
    }

    @Test
    @DisplayName("Пустой не-null ответ -> IllegalArgumentException")
    void emptyResponseRejected() {
        TlsMessageBuilder b = builder();
        assertThrows(
                IllegalArgumentException.class,
                () -> b.buildCertificateBody(new byte[0]),
                "пустой ответ нарушает OCSPResponse<1..2^24-1>");
    }

    @Test
    @DisplayName("Ответ больше предела блока extensions -> IllegalArgumentException")
    // Иначе uint16-длина расширения переполнилась бы и испортила сообщение.
    void oversizedResponseRejected() {
        TlsMessageBuilder b = builder();
        byte[] tooBig = new byte[TlsConstants.MAX_OCSP_STAPLE_SIZE + 1];
        assertThrows(
                IllegalArgumentException.class,
                () -> b.buildCertificateBody(tooBig),
                "ответ не помещается в uint16 блока extensions");
    }
}
