package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Модульные тесты {@link GostOcspRequest}: разбор OCSP-запроса.
 */
@DisplayName("GostOcspRequest: парсинг OCSP-запроса")
class GostOcspRequestTest {

    private static ECParameters params256 = ECParameters.tc26a256();
    private static ECParameters params512 = ECParameters.tc26a512();

    private static record CertPair(GostCertificate ca, GostCertificate leaf) {}

    private static CertPair createCaAndLeaf(ECParameters params, String caDn, String leafDn) {
        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        KeyPair leafKp = KeyGenerator.generateKeyPair(params);

        GostCertificate ca =
                GostCertificateBuilder.create(params, caDn)
                        .publicKey(caKp.getPublic())
                        .notBefore("20250101000000Z")
                        .notAfter("20351231235959Z")
                        .basicConstraints(true, null)
                        .keyUsage(GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN)
                        .randomSerial()
                        .sign(caKp.getPrivate());

        GostCertificate leaf =
                GostCertificateBuilder.create(params, leafDn)
                        .publicKey(leafKp.getPublic())
                        .issuerDn(ca.getSubjectDnBytes())
                        .notBefore("20250101000000Z")
                        .notAfter("20261231235959Z")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .randomSerial()
                        .sign(caKp.getPrivate());

        return new CertPair(ca, leaf);
    }

    private static CertPair certs256;
    private static CertPair certs512;

    @BeforeAll
    static void setUp() {
        certs256 = createCaAndLeaf(params256, "CN=Test CA,O=Test", "CN=leaf,O=Test");
        certs512 = createCaAndLeaf(params512, "CN=Test CA 512,O=Test", "CN=leaf512,O=Test");
    }

    @Test
    @DisplayName("Round-trip: builder -> парсер -> сравниваем CertId")
    void testRoundTrip() throws Exception {
        GostOcspRequestBuilder builder =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded());
        byte[] der = builder.build();
        byte[] expectedNonce = builder.getNonce().clone();

        GostOcspRequest parsed = GostOcspRequest.fromDer(der);

        assertEquals(1, parsed.getCertIds().size());
        CertId certId = parsed.getCertIds().get(0);

        assertArrayEquals(certs256.leaf.getSerialNumber(), certId.serialNumber());
        assertEquals(
                GostOids.DIGEST_256,
                certId.hashAlgOid(),
                "hashAlgOid должен быть Streebog-256 OID");
        assertEquals(32, certId.issuerNameHash().length);
        assertEquals(32, certId.issuerKeyHash().length);

        assertArrayEquals(expectedNonce, parsed.getNonce());
    }

    @Test
    @DisplayName("Round-trip: 512-битный запрос")
    void testRoundTrip512() throws Exception {
        GostOcspRequestBuilder builder =
                GostOcspRequestBuilder.create()
                        .targetCert(certs512.leaf.getEncoded())
                        .issuerCert(certs512.ca.getEncoded())
                        .hashLen(64);
        byte[] der = builder.build();
        byte[] expectedNonce = builder.getNonce().clone();

        GostOcspRequest parsed = GostOcspRequest.fromDer(der);

        assertEquals(1, parsed.getCertIds().size());
        CertId certId = parsed.getCertIds().get(0);

        assertEquals(
                GostOids.DIGEST_512,
                certId.hashAlgOid(),
                "hashAlgOid должен быть Streebog-512 OID");
        assertEquals(64, certId.issuerNameHash().length);
        assertEquals(64, certId.issuerKeyHash().length);

        assertArrayEquals(certs512.leaf.getSerialNumber(), certId.serialNumber());
        assertArrayEquals(expectedNonce, parsed.getNonce());
    }

    @Test
    @DisplayName("Round-trip: signed request -> isSigned() + verifySignature()")
    void testSignedRoundTrip() throws Exception {
        KeyPair signKp = KeyGenerator.generateKeyPair(params256);
        GostOcspRequestBuilder builder =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .signKey(signKp.getPrivate())
                        .params(params256);
        byte[] der = builder.build();

        GostOcspRequest parsed = GostOcspRequest.fromDer(der);

        assertTrue(parsed.isSigned(), "Подписанный запрос: isSigned() должен вернуть true");
        parsed.verifySignature(signKp.getPublic());
        assertTrue(
                parsed.isSignatureVerified(),
                "verifySignature() должен установить флаг isSignatureVerified()");
    }

    @Test
    @DisplayName("Пустой запрос -> PkixException")
    void testNullRequest() {
        assertThrows(PkixException.class, () -> GostOcspRequest.fromDer(null));
        assertThrows(PkixException.class, () -> GostOcspRequest.fromDer(new byte[0]));
    }

    @Test
    @DisplayName("Битый DER -> PkixException")
    void testBrokenDer() {
        assertThrows(
                PkixException.class, () -> GostOcspRequest.fromDer(new byte[] {0x00, 0x01, 0x02}));
    }

    @Test
    @DisplayName("Не подписанный запрос -> isSigned() = false, verifySignature бросает")
    void testUnsignedRequest() throws Exception {
        byte[] der =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .build();

        GostOcspRequest parsed = GostOcspRequest.fromDer(der);

        assertFalse(parsed.isSigned());
        KeyPair anyKp = KeyGenerator.generateKeyPair(params256);
        assertThrows(
                PkixException.class,
                () -> parsed.verifySignature(anyKp.getPublic()),
                "verifySignature() на неподписанном запросе должен бросать");
    }

    @Test
    @DisplayName("Чужой ключ для verifySignature -> PkixException")
    void testWrongKeySignature() throws Exception {
        KeyPair signKp = KeyGenerator.generateKeyPair(params256);
        KeyPair wrongKp = KeyGenerator.generateKeyPair(params256);
        byte[] der =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .signKey(signKp.getPrivate())
                        .params(params256)
                        .build();

        GostOcspRequest parsed = GostOcspRequest.fromDer(der);
        assertThrows(
                PkixException.class,
                () -> parsed.verifySignature(wrongKp.getPublic()),
                "Чужой ключ должен вызывать PkixException");
    }

    @Test
    @DisplayName("fromDer: статический фабричный метод эквивалентен конструктору")
    void testFromDerFactory() throws Exception {
        byte[] der =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .build();

        GostOcspRequest fromConstructor = new GostOcspRequest(der);
        GostOcspRequest fromFactory = GostOcspRequest.fromDer(der);

        assertEquals(fromConstructor.getCertIds().size(), fromFactory.getCertIds().size());
        assertArrayEquals(
                fromConstructor.getCertIds().get(0).serialNumber(),
                fromFactory.getCertIds().get(0).serialNumber());
        assertArrayEquals(fromConstructor.getNonce(), fromFactory.getNonce());
    }

    @Test
    @DisplayName("GostOcspRequest(byte[]): массив > MAX_OCSP_REQUEST_SIZE -> PkixException")
    void testOcspRequestOversizedRejected() {
        byte[] oversizedDer = new byte[65_537]; // на 1 больше MAX_OCSP_REQUEST_SIZE = 65_536
        assertThrows(PkixException.class, () -> GostOcspRequest.fromDer(oversizedDer));
    }

    // ========================================================================
    // PEM round-trip
    // ========================================================================

    @Test
    @DisplayName("PEM round-trip: toPem() -> fromPemOrDer() -> идентичность полей")
    void testPemRoundTrip() throws Exception {
        byte[] der =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .build();

        GostOcspRequest req = GostOcspRequest.fromDer(der);
        String pem = req.toPem();
        assertTrue(
                pem.contains("-----BEGIN OCSP REQUEST-----"),
                "PEM должен содержать BEGIN OCSP REQUEST");
        assertTrue(
                pem.contains("-----END OCSP REQUEST-----"),
                "PEM должен содержать END OCSP REQUEST");

        GostOcspRequest reparsed =
                GostOcspRequest.fromPemOrDer(
                        pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        assertEquals(req.getCertIds().size(), reparsed.getCertIds().size());
        assertArrayEquals(
                req.getCertIds().get(0).serialNumber(),
                reparsed.getCertIds().get(0).serialNumber());
        assertArrayEquals(req.getNonce(), reparsed.getNonce());
        assertEquals(req.isSigned(), reparsed.isSigned());
    }

    @Test
    @DisplayName("PEM fromPemOrDer: автоопределение DER")
    void testPemFromPemOrDerAutoDetectsDer() throws Exception {
        byte[] der =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .build();

        GostOcspRequest parsed = GostOcspRequest.fromPemOrDer(der);
        assertEquals(1, parsed.getCertIds().size(), "fromPemOrDer должен парсить DER без ошибок");
    }

    @Test
    @DisplayName("PEM fromPemOrDer: мусорные данные -> PkixException")
    void testPemFromPemOrDerGarbage() {
        assertThrows(
                PkixException.class,
                () -> GostOcspRequest.fromPemOrDer(new byte[] {0x00, 0x01, 0x02}));
    }

    @Test
    @DisplayName("getEncoded: возвращает защитную копию исходного DER")
    void testGetEncodedDefensiveCopy() throws Exception {
        byte[] der =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .build();

        GostOcspRequest req = GostOcspRequest.fromDer(der);
        byte[] encoded = req.getEncoded();
        assertArrayEquals(der, encoded, "getEncoded должен вернуть точную копию исходного DER");

        // Модификация копии не должна влиять на объект
        encoded[0] = 0;
        assertArrayEquals(
                der, req.getEncoded(), "мутация возвращённого массива не должна менять состояние");
    }

    @Test
    @DisplayName("Подпись запроса неверной длины -> PkixException(SIGNATURE_INVALID), не IAE")
    void testTruncatedSignatureGivesPkixException() throws Exception {
        KeyPair signKp = KeyGenerator.generateKeyPair(params256);
        byte[] der =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .signKey(signKp.getPrivate())
                        .params(params256)
                        .build();

        // OCSPRequest ::= SEQUENCE { tbsRequest, optionalSignature [0] EXPLICIT Signature },
        // Signature ::= SEQUENCE { signatureAlgorithm, signature BIT STRING, certs [0] OPTIONAL }
        byte[][] request = DerCodec.parseSequenceContents(der, 0);
        int[] explicitLen = DerCodec.decodeLength(request[1], 1);
        byte[][] signature = DerCodec.parseSequenceContents(request[1], 1 + explicitLen[1]);
        byte[] signatureBits = DerCodec.parseBitString(signature[1], 0);
        signature[1] =
                DerCodec.encodeBitString(Arrays.copyOf(signatureBits, signatureBits.length - 1));
        byte[] tampered =
                DerCodec.encodeSequence(
                        request[0],
                        DerCodec.encodeContextConstructed(0, DerCodec.encodeSequence(signature)));

        GostOcspRequest parsed = GostOcspRequest.fromDer(tampered);
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> parsed.verifySignature(signKp.getPublic()),
                        "подпись неверной длины должна давать PkixException");
        assertEquals(PkixException.Reason.SIGNATURE_INVALID, e.reason(), "причина - подпись");
    }
}
