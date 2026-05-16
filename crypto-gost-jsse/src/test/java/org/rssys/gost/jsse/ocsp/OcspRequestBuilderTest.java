package org.rssys.gost.jsse.ocsp;
import org.rssys.gost.jsse.RssysGostJsseProvider;


import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsCiphersuite;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.tls13.cert.TlsCertificate;
import org.rssys.gost.tls13.cert.TlsDerParser;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Структурная и семантическая проверка OcspRequestBuilder.
 */
class OcspRequestBuilderTest {

    private static TlsTestHelper.CertBundle root;
    private static TlsTestHelper.CertBundle server;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params = ECParameters.tc26a256();
        root = TlsTestHelper.createRootCA(params);
        server = TlsTestHelper.createCertSignedBy(params, root.priv,
                root.cert.getPublicKey(), root.subjectDn,
                "240501120000Z", "290501120000Z",
                new String[]{"localhost"}, null, null,
                false, null);
    }

    @Test
    @DisplayName("OCSPRequest: структурная целостность DER-кодировки")
    void testOcspRequestStructure() throws Exception {
        byte[] request = OcspRequestBuilder.build(
                server.cert.getEncoded(), root.cert.getEncoded());

        // Проверяем, что корневая структура — SEQUENCE, как требует RFC 6960 §4.1
        int[] outer = TlsDerParser.readTlv(request, 0);
        assertEquals(0x30, request[0] & 0xFF, "Корневой элемент должен быть SEQUENCE");

        // TBSRequest — SEQUENCE, внутри requestList
        int[] tbsReq = TlsDerParser.readTlv(request, outer[0]);
        assertEquals(0x30, request[outer[0]] & 0xFF, "TBSRequest должен быть SEQUENCE");

        // requestList содержит Request с CertID
        int[] reqList = TlsDerParser.readTlv(request, tbsReq[0]);
        assertEquals(0x30, request[tbsReq[0]] & 0xFF, "Список запросов должен быть SEQUENCE");
        int[] req = TlsDerParser.readTlv(request, reqList[0]);
        assertEquals(0x30, request[reqList[0]] & 0xFF, "Запрос должен быть SEQUENCE");

        // CertID — SEQUENCE из хешей и серийного номера
        int[] certId = TlsDerParser.readTlv(request, req[0]);
        assertEquals(0x30, request[req[0]] & 0xFF, "CertID должен быть SEQUENCE");

        // AlgorithmIdentifier — первый элемент CertID
        int[] algId = TlsDerParser.readTlv(request, certId[0]);
        assertEquals(0x30, request[certId[0]] & 0xFF);

        // issuerNameHash — OCTET STRING, 32 байта (Streebog-256)
        int[] nameHash = TlsDerParser.readTlv(request, algId[1]);
        assertEquals(0x04, request[algId[1]] & 0xFF, "issuerNameHash должен быть OCTET STRING");
        assertEquals(32, nameHash[1] - nameHash[0], "issuerNameHash должен быть 32 байта");

        // issuerKeyHash — OCTET STRING, 32 байта
        int[] keyHash = TlsDerParser.readTlv(request, nameHash[1]);
        assertEquals(0x04, request[nameHash[1]] & 0xFF, "issuerKeyHash должен быть OCTET STRING");
        assertEquals(32, keyHash[1] - keyHash[0], "issuerKeyHash должен быть 32 байта");

        // serialNumber — последнее поле CertID (INTEGER)
        int[] serial = TlsDerParser.readTlv(request, keyHash[1]);
        assertEquals(0x02, request[keyHash[1]] & 0xFF, "serialNumber должен быть INTEGER");
        assertTrue(serial[1] > serial[0], "serialNumber должен содержать данные");
    }

    @Test
    @DisplayName("OCSPRequest: семантическая корректность хешей")
    void testOcspRequestSemantics() throws Exception {
        byte[] request = OcspRequestBuilder.build(
                server.cert.getEncoded(), root.cert.getEncoded());

        // Извлекаем issuerNameHash и issuerKeyHash из DER
        int[] outer = TlsDerParser.readTlv(request, 0);
        int[] tbsReq = TlsDerParser.readTlv(request, outer[0]);
        int[] reqList = TlsDerParser.readTlv(request, tbsReq[0]);
        int[] req = TlsDerParser.readTlv(request, reqList[0]);
        int[] certId = TlsDerParser.readTlv(request, req[0]);
        int[] algId = TlsDerParser.readTlv(request, certId[0]);
        int[] nameHash = TlsDerParser.readTlv(request, algId[1]);
        int[] keyHash = TlsDerParser.readTlv(request, nameHash[1]);

        // issuerNameHash = Streebog256(issuer.subjectDN) — RFC 6960 §4.1.1 требует хеш от полного DER subject
        byte[] expectedNameHash = Digest.digest256(extractSubjectBytes(root.cert.getEncoded()));
        byte[] actualNameHash = java.util.Arrays.copyOfRange(request, nameHash[0], nameHash[1]);
        assertArrayEquals(expectedNameHash, actualNameHash,
                "issuerNameHash должен совпадать с хешем subject DN издателя");

        // issuerKeyHash = Streebog256(full SPKI DER) — полный SubjectPublicKeyInfo, а не только BIT STRING
        byte[] rawPubKey = extractRawPublicKey(root.cert.getEncoded());
        byte[] expectedKeyHash = Digest.digest256(rawPubKey);
        byte[] actualKeyHash = java.util.Arrays.copyOfRange(request, keyHash[0], keyHash[1]);
        assertArrayEquals(expectedKeyHash, actualKeyHash,
                "issuerKeyHash должен совпадать с хешем публичного ключа издателя");
    }

    @Test
    @DisplayName("OCSPRequest: serialNumber скопирован бит-в-бит")
    void testOcspRequestSerial() throws Exception {
        byte[] request = OcspRequestBuilder.build(
                server.cert.getEncoded(), root.cert.getEncoded());

        // serial — последний элемент CertID (INTEGER TLV)
        int[] outer = TlsDerParser.readTlv(request, 0);
        int[] tbsReq = TlsDerParser.readTlv(request, outer[0]);
        int[] reqList = TlsDerParser.readTlv(request, tbsReq[0]);
        int[] req = TlsDerParser.readTlv(request, reqList[0]);
        int[] certId = TlsDerParser.readTlv(request, req[0]);
        int[] algId = TlsDerParser.readTlv(request, certId[0]);
        int[] nameHash = TlsDerParser.readTlv(request, algId[1]);
        int[] keyHash = TlsDerParser.readTlv(request, nameHash[1]);

        int[] serialTlv_out = TlsDerParser.readTlv(request, keyHash[1]);
        byte[] requestSerialBytes = java.util.Arrays.copyOfRange(
                request, keyHash[1], serialTlv_out[1]);

        // Должен совпадать с serialNumber из исходного сертификата
        byte[] certSerialTlv = extractSerialTlv(server.cert.getEncoded());
        assertArrayEquals(certSerialTlv, requestSerialBytes,
                "serialNumber должен быть точной битовой копией");
    }

    @Test
    @DisplayName("OCSPRequest: OID алгоритма хеширования в CertID = Streebog-256")
    void testCertIdHashAlgorithmOid() throws Exception {
        // T-6: OID в CertID должен совпадать с STREEBOG256_OID_BYTES из TlsOcspVerifier,
        // иначе OCSP-верификатор отклонит ответ
        byte[] request = OcspRequestBuilder.build(
                server.cert.getEncoded(), root.cert.getEncoded());
        int[] outer = TlsDerParser.readTlv(request, 0);
        int[] tbsReq = TlsDerParser.readTlv(request, outer[0]);
        int[] reqList = TlsDerParser.readTlv(request, tbsReq[0]);
        int[] req = TlsDerParser.readTlv(request, reqList[0]);
        int[] certId = TlsDerParser.readTlv(request, req[0]);

        // AlgorithmIdentifier внутри CertID
        int[] hashAlgSeq = TlsDerParser.parseSequence(request, certId[0]);
        int haPos = hashAlgSeq[0];
        int[] oidTlv = TlsDerParser.readTlv(request, haPos);

        assertTrue(TlsDerParser.matchesOid(request, oidTlv[0], oidTlv[1] - oidTlv[0],
                org.rssys.gost.tls13.cert.TlsOcspVerifier.STREEBOG256_OID_BYTES),
                "OID алгоритма хеширования CertID должен быть Streebog-256");
    }

    /** Извлекает BIT STRING value SubjectPublicKeyInfo — для проверки issuerKeyHash (RFC 6960 §4.1.1). */
    private static byte[] extractRawPublicKey(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = TlsDerParser.readTlv(der, pos)[1];
        pos = TlsDerParser.readTlv(der, pos)[1]; // serial
        pos = TlsDerParser.readTlv(der, pos)[1]; // signature alg
        pos = TlsDerParser.readTlv(der, pos)[1]; // issuer
        pos = TlsDerParser.readTlv(der, pos)[1]; // validity
        pos = TlsDerParser.readTlv(der, pos)[1]; // subject
        int[] spkiTlv = TlsDerParser.readTlv(der, pos);
        int spkiPos = spkiTlv[0];
        int[] algTlv = TlsDerParser.readTlv(der, spkiPos);
        spkiPos = algTlv[1];
        int[] bsTlv = TlsDerParser.readTlv(der, spkiPos);
        return java.util.Arrays.copyOfRange(der, bsTlv[0], bsTlv[1]);
    }

    /** Извлекает subject DN (полный TLV) — для проверки issuerNameHash, как в OcspRequestBuilder. */
    private static byte[] extractSubjectBytes(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = TlsDerParser.readTlv(der, pos)[1];
        pos = TlsDerParser.readTlv(der, pos)[1]; // serial
        pos = TlsDerParser.readTlv(der, pos)[1]; // signature
        int[] issuerTlv = TlsDerParser.readTlv(der, pos);
        pos = issuerTlv[1];
        int[] validityTlv = TlsDerParser.readTlv(der, pos);
        pos = validityTlv[1];
        int[] subjectTlv = TlsDerParser.readTlv(der, pos);
        return java.util.Arrays.copyOfRange(der, pos, subjectTlv[1]);
    }

    private static int findTbsOffset(byte[] der) {
        int[] certSeq = TlsDerParser.readTlv(der, 0);
        int[] tbsTlv = TlsDerParser.readTlv(der, certSeq[0]);
        return tbsTlv[0];
    }

    /**
     * Проверяет, что serialNumber скопирован bit-exact (TLV INTEGER как есть).
     * OcspRequestBuilder должен сохранять исходную DER-кодировку serialNumber.
     */
    private static byte[] extractSerialTlv(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = TlsDerParser.readTlv(der, pos)[1];
        int tlvStart = pos;
        int[] serialTlv = TlsDerParser.readTlv(der, pos);
        return java.util.Arrays.copyOfRange(der, tlvStart, serialTlv[1]);
    }
}
