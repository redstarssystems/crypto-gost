package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostCrlBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.GostSignatureHelper;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

@DisplayName("CAdESXLongData: кодирование/декодирование CertificateValues и RevocationValues")
class CAdESXLongDataTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static KeyPair caKp;
    private static GostCertificate caCert;
    private static KeyPair signerKp;
    private static GostCertificate signerCert;
    private static KeyPair otherKp;
    private static GostCertificate otherCert;
    private static GostCrl crl;
    private static GostOcspResponse ocspResponse;

    @BeforeAll
    static void setUp() throws Exception {
        caKp = KeyGenerator.generateKeyPair(PARAMS);
        caCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        caKp.getPrivate(), caKp.getPublic(), BigInteger.valueOf(1), "CA");

        signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        signerKp.getPrivate(),
                        signerKp.getPublic(),
                        BigInteger.valueOf(2),
                        "Signer");

        otherKp = KeyGenerator.generateKeyPair(PARAMS);
        otherCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        otherKp.getPrivate(), otherKp.getPublic(), BigInteger.valueOf(3), "Other");

        byte[] crlDer =
                GostCrlBuilder.create(caCert.getSubjectDnBytes())
                        .thisUpdateNow()
                        .nextUpdateDays(30)
                        .withCrlNumber(1)
                        .sign(caKp.getPrivate());
        crl = new GostCrl(crlDer);

        byte[] ocspDer =
                GostOcspResponseBuilder.create(signerCert.getSerialNumber())
                        .issuerDn(caCert.getSubjectDnBytes())
                        .sign(caKp.getPrivate());
        ocspResponse = new GostOcspResponse(ocspDer);
    }

    @Test
    @DisplayName("Кодирование/декодирование CertificateValues с одним сертификатом")
    void encodeDecodeCertificateValuesSingleCert() throws Exception {
        byte[] der = CAdESXLongData.encodeCertificateValues(List.of(signerCert));
        assertNotNull(der);

        List<GostCertificate> decoded = CAdESXLongData.decodeCertificateValues(der);
        assertEquals(1, decoded.size());
        assertEquals(signerCert.getSerialNumberBigInt(), decoded.get(0).getSerialNumberBigInt());
    }

    @Test
    @DisplayName("Кодирование/декодирование CertificateValues с цепочкой из трёх сертификатов")
    void encodeDecodeCertificateValuesMultiCert() throws Exception {
        List<GostCertificate> chain = List.of(signerCert, caCert, otherCert);
        byte[] der = CAdESXLongData.encodeCertificateValues(chain);
        assertNotNull(der);

        List<GostCertificate> decoded = CAdESXLongData.decodeCertificateValues(der);
        assertEquals(3, decoded.size());
        assertEquals(signerCert.getSerialNumberBigInt(), decoded.get(0).getSerialNumberBigInt());
        assertEquals(caCert.getSerialNumberBigInt(), decoded.get(1).getSerialNumberBigInt());
        assertEquals(otherCert.getSerialNumberBigInt(), decoded.get(2).getSerialNumberBigInt());
    }

    @Test
    @DisplayName("Кодирование/декодирование RevocationValues только с CRL")
    void encodeDecodeRevocationValuesCrlOnly() throws Exception {
        List<GostCrl> crls = List.of(crl);
        List<GostOcspResponse> ocspResponses = List.of();

        byte[] der = CAdESXLongData.encodeRevocationValues(crls, ocspResponses);
        assertNotNull(der);

        CAdESXLongData.RevocationValuesDecoded decoded = CAdESXLongData.decodeRevocationValues(der);
        assertEquals(1, decoded.crls().size());
        assertEquals(crl.getCrlNumber(), decoded.crls().get(0).getCrlNumber());
        assertTrue(decoded.ocspResponses().isEmpty());
    }

    @Test
    @DisplayName("Кодирование/декодирование RevocationValues только с OCSP-ответами")
    void encodeDecodeRevocationValuesOcspOnly() throws Exception {
        List<GostCrl> crls = List.of();
        List<GostOcspResponse> ocspResponses = List.of(ocspResponse);

        byte[] der = CAdESXLongData.encodeRevocationValues(crls, ocspResponses);
        assertNotNull(der);

        CAdESXLongData.RevocationValuesDecoded decoded = CAdESXLongData.decodeRevocationValues(der);
        assertTrue(decoded.crls().isEmpty());
        assertEquals(1, decoded.ocspResponses().size());
        assertNotNull(decoded.ocspResponses().get(0).getProducedAt());
    }

    @Test
    @DisplayName("Кодирование/декодирование RevocationValues с CRL и OCSP одновременно")
    void encodeDecodeRevocationValuesBothCrlAndOcsp() throws Exception {
        List<GostCrl> crls = List.of(crl);
        List<GostOcspResponse> ocspResponses = List.of(ocspResponse);

        byte[] der = CAdESXLongData.encodeRevocationValues(crls, ocspResponses);
        assertNotNull(der);

        CAdESXLongData.RevocationValuesDecoded decoded = CAdESXLongData.decodeRevocationValues(der);
        assertEquals(1, decoded.crls().size());
        assertEquals(1, decoded.ocspResponses().size());
    }

    @Test
    @DisplayName("Декодирование невалидного DER вызывает PkixException")
    void decodeInvalidDerThrowsPkixException() {
        // Усечённый DER — последний байт отрезан
        byte[] truncated = DerCodec.encodeSequence(DerCodec.encodeInteger(BigInteger.ONE));
        byte[] bad = Arrays.copyOf(truncated, truncated.length - 1);
        assertThrows(
                Exception.class,
                () -> CAdESXLongData.decodeCertificateValues(bad),
                "Усечённый DER должен вызывать исключение");

        // Неправильный тег: OCTET STRING вместо SEQUENCE
        byte[] wrongTag = DerCodec.encodeOctetString(new byte[] {0x00});
        assertThrows(
                Exception.class,
                () -> CAdESXLongData.decodeCertificateValues(wrongTag),
                "Неправильный тег DER должен вызывать исключение");
    }

    private static void assertParseError(
            org.junit.jupiter.api.function.Executable action, String message) {
        PkixException e = assertThrows(PkixException.class, action, message);
        assertEquals(
                PkixException.Reason.PARSE_ERROR,
                e.reason(),
                "Структурная ошибка недоверенного атрибута — PARSE_ERROR");
    }

    @Test
    @DisplayName(
            "certificate-values: битый сертификат и усечённый DER дают PkixException, не unchecked")
    void decodeCertificateValuesMalformedIsPkixException() {
        // certificate-values — неподписанный атрибут: ввод враждебный
        byte[] garbageCert =
                DerCodec.encodeSequence(DerCodec.encodeSequence(DerCodec.encodeNull()));
        assertParseError(
                () -> CAdESXLongData.decodeCertificateValues(garbageCert),
                "Битый сертификат внутри certificate-values");

        byte[] truncated = DerCodec.encodeSequence(DerCodec.encodeInteger(BigInteger.ONE));
        byte[] bad = Arrays.copyOf(truncated, truncated.length - 1);
        assertParseError(
                () -> CAdESXLongData.decodeCertificateValues(bad),
                "Усечённый DER certificate-values");
    }

    @Test
    @DisplayName("revocation-values: битый CRL, CRL с хвостом и усечённый DER дают PkixException")
    void decodeRevocationValuesMalformedIsPkixException() throws Exception {
        byte[] garbageCrl = DerCodec.encodeSequence(DerCodec.encodeNull());
        byte[] withGarbage =
                DerCodec.encodeSequence(
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeSequence(garbageCrl)));
        assertParseError(
                () -> CAdESXLongData.decodeRevocationValues(withGarbage), "Битый CRL в crlVals");

        // CRL с хвостом: хвост не принадлежит подписанной структуре
        byte[] crlDer = crl.getEncoded();
        byte[] crlWithTrailer = Arrays.copyOf(crlDer, crlDer.length + 2);
        crlWithTrailer[crlDer.length] = 0x05;
        byte[] withTrailer =
                DerCodec.encodeSequence(
                        DerCodec.encodeContextConstructed(
                                0, DerCodec.encodeSequence(crlWithTrailer)));
        assertParseError(
                () -> CAdESXLongData.decodeRevocationValues(withTrailer),
                "CRL с хвостом в crlVals");

        byte[] valid = CAdESXLongData.encodeRevocationValues(List.of(crl), List.of());
        byte[] truncated = Arrays.copyOf(valid, valid.length - 1);
        assertParseError(
                () -> CAdESXLongData.decodeRevocationValues(truncated),
                "Усечённый DER revocation-values");
    }

    @Test
    @DisplayName("Кодирование пустого списка сертификатов даёт пустую SEQUENCE")
    void encodeEmptyCertListProducesEmptySequence() throws Exception {
        byte[] der = CAdESXLongData.encodeCertificateValues(List.of());
        assertNotNull(der);
        // Пустая SEQUENCE: 0x30 0x00
        assertEquals(0x30, der[0] & 0xFF);
        assertEquals(0, der[1]);

        List<GostCertificate> decoded = CAdESXLongData.decodeCertificateValues(der);
        assertTrue(decoded.isEmpty());
    }

    @Test
    @DisplayName("RevocationValues: пустые списки дают пустую SEQUENCE — decode возвращает EMPTY")
    void emptyRevocationValuesRoundtrip() throws Exception {
        byte[] der = CAdESXLongData.encodeRevocationValues(List.of(), List.of());
        assertNotNull(der);

        CAdESXLongData.RevocationValuesDecoded decoded = CAdESXLongData.decodeRevocationValues(der);
        assertTrue(decoded.crls().isEmpty());
        assertTrue(decoded.ocspResponses().isEmpty());
    }

    @Test
    @DisplayName("decodeRevocationValues(null) возвращает EMPTY")
    void decodeRevocationValuesNullReturnsEmpty() throws Exception {
        CAdESXLongData.RevocationValuesDecoded decoded =
                CAdESXLongData.decodeRevocationValues(null);
        assertTrue(decoded.crls().isEmpty());
        assertTrue(decoded.ocspResponses().isEmpty());

        decoded = CAdESXLongData.decodeRevocationValues(new byte[0]);
        assertTrue(decoded.crls().isEmpty());
        assertTrue(decoded.ocspResponses().isEmpty());
    }

    @Test
    @DisplayName("encodeRevocationValues: null в середине списка — не попадает в закодированные")
    void nullCrlInMiddleNotEncoded() throws Exception {
        List<GostCrl> crls = Arrays.asList(null, crl, null);
        List<GostOcspResponse> ocsp = Arrays.asList(null, null, null);

        byte[] der = CAdESXLongData.encodeRevocationValues(crls, ocsp);
        CAdESXLongData.RevocationValuesDecoded decoded = CAdESXLongData.decodeRevocationValues(der);

        assertEquals(1, decoded.crls().size(), "только один CRL не-null — в середине списка");
        assertTrue(decoded.ocspResponses().isEmpty(), "все OCSP null → не закодированы");

        byte[] actualHash = GostSignatureHelper.digestByOid(GostOids.DIGEST_256, crl.getEncoded());
        byte[] expectedHash =
                GostSignatureHelper.digestByOid(
                        GostOids.DIGEST_256, decoded.crls().getFirst().getEncoded());
        assertArrayEquals(
                expectedHash, actualHash, "закодированный CRL — из середины, не сдвинутый");
    }

    @Test
    @DisplayName("encodeRevocationValues: null в середине OCSP списка — не ломает null-фильтрацию")
    void nullOcspInMiddleNotEncoded() throws Exception {
        byte[] ocspDer =
                GostOcspResponseBuilder.create(signerCert.getSerialNumber())
                        .issuerDn(signerCert.getSubjectDnBytes())
                        .sign(signerKp.getPrivate());
        GostOcspResponse ocspResp = new GostOcspResponse(ocspDer);

        List<GostCrl> crls = Arrays.asList(null, null, null);
        List<GostOcspResponse> ocsp = Arrays.asList(null, ocspResp, null);

        byte[] der = CAdESXLongData.encodeRevocationValues(crls, ocsp);
        CAdESXLongData.RevocationValuesDecoded decoded = CAdESXLongData.decodeRevocationValues(der);

        assertTrue(decoded.crls().isEmpty(), "все CRL null → не закодированы");
        assertEquals(
                1, decoded.ocspResponses().size(), "только один OCSP не-null — в середине списка");
    }
}
