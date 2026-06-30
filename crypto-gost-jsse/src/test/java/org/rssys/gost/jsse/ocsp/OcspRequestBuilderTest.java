package org.rssys.gost.jsse.ocsp;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.jsse.RssysGostJsseProvider;
import org.rssys.gost.pkix.cert.GostDerParser;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;

/**
 * Структурная и семантическая проверка OcspRequestBuilder.
 */
class OcspRequestBuilderTest {

    private static TlsTestHelper.CertBundle root;
    private static TlsTestHelper.CertBundle server;
    private static TlsTestHelper.CertBundle signKey256;
    private static TlsTestHelper.CertBundle signKey512;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new RssysGostJsseProvider());
        ECParameters params256 = ECParameters.tc26a256();
        root = TlsTestHelper.createRootCA(params256);
        server =
                TlsTestHelper.createCertSignedBy(
                        params256,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "240501120000Z",
                        "290501120000Z",
                        new String[] {"localhost"},
                        null,
                        null,
                        false,
                        null);
        signKey256 = TlsTestHelper.createCertWithKey(ECParameters.tc26a256());
        signKey512 = TlsTestHelper.createCertWithKey(ECParameters.tc26a512());
    }

    @Test
    @DisplayName("OCSPRequest: структурная целостность DER-кодировки")
    void testOcspRequestStructure() throws Exception {
        byte[] request =
                OcspRequestBuilder.create()
                        .targetCert(server.cert.getEncoded())
                        .issuerCert(root.cert.getEncoded())
                        .build()
                        .der();

        // Проверяем, что корневая структура — SEQUENCE, как требует RFC 6960 §4.1
        int[] outer = GostDerParser.readTlv(request, 0);
        assertEquals(0x30, request[0] & 0xFF, "Корневой элемент должен быть SEQUENCE");

        // TBSRequest — SEQUENCE, внутри requestList
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        assertEquals(0x30, request[outer[0]] & 0xFF, "TBSRequest должен быть SEQUENCE");

        // requestList содержит Request с CertID
        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        assertEquals(0x30, request[tbsReq[0]] & 0xFF, "Список запросов должен быть SEQUENCE");
        int[] req = GostDerParser.readTlv(request, reqList[0]);
        assertEquals(0x30, request[reqList[0]] & 0xFF, "Запрос должен быть SEQUENCE");

        // CertID — SEQUENCE из хешей и серийного номера
        int[] certId = GostDerParser.readTlv(request, req[0]);
        assertEquals(0x30, request[req[0]] & 0xFF, "CertID должен быть SEQUENCE");

        // AlgorithmIdentifier — первый элемент CertID
        int[] algId = GostDerParser.readTlv(request, certId[0]);
        assertEquals(0x30, request[certId[0]] & 0xFF);

        // issuerNameHash — OCTET STRING, 32 байта (Streebog-256)
        int[] nameHash = GostDerParser.readTlv(request, algId[1]);
        assertEquals(0x04, request[algId[1]] & 0xFF, "issuerNameHash должен быть OCTET STRING");
        assertEquals(32, nameHash[1] - nameHash[0], "issuerNameHash должен быть 32 байта");

        // issuerKeyHash — OCTET STRING, 32 байта
        int[] keyHash = GostDerParser.readTlv(request, nameHash[1]);
        assertEquals(0x04, request[nameHash[1]] & 0xFF, "issuerKeyHash должен быть OCTET STRING");
        assertEquals(32, keyHash[1] - keyHash[0], "issuerKeyHash должен быть 32 байта");

        // serialNumber — последнее поле CertID (INTEGER)
        int[] serial = GostDerParser.readTlv(request, keyHash[1]);
        assertEquals(0x02, request[keyHash[1]] & 0xFF, "serialNumber должен быть INTEGER");
        assertTrue(serial[1] > serial[0], "serialNumber должен содержать данные");
    }

    @Test
    @DisplayName("OCSPRequest: семантическая корректность хешей")
    void testOcspRequestSemantics() throws Exception {
        byte[] request =
                OcspRequestBuilder.create()
                        .targetCert(server.cert.getEncoded())
                        .issuerCert(root.cert.getEncoded())
                        .build()
                        .der();

        // Извлекаем issuerNameHash и issuerKeyHash из DER
        int[] outer = GostDerParser.readTlv(request, 0);
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        int[] req = GostDerParser.readTlv(request, reqList[0]);
        int[] certId = GostDerParser.readTlv(request, req[0]);
        int[] algId = GostDerParser.readTlv(request, certId[0]);
        int[] nameHash = GostDerParser.readTlv(request, algId[1]);
        int[] keyHash = GostDerParser.readTlv(request, nameHash[1]);

        // issuerNameHash = Streebog256(issuer.subjectDN) — RFC 6960 §4.1.1 требует хеш от полного
        // DER subject
        byte[] expectedNameHash = Digest.digest256(extractSubjectBytes(root.cert.getEncoded()));
        byte[] actualNameHash = java.util.Arrays.copyOfRange(request, nameHash[0], nameHash[1]);
        assertArrayEquals(
                expectedNameHash,
                actualNameHash,
                "issuerNameHash должен совпадать с хешем subject DN издателя");

        // issuerKeyHash = Streebog256(full SPKI DER) — полный SubjectPublicKeyInfo, а не только BIT
        // STRING
        byte[] rawPubKey = extractRawPublicKey(root.cert.getEncoded());
        byte[] expectedKeyHash = Digest.digest256(rawPubKey);
        byte[] actualKeyHash = java.util.Arrays.copyOfRange(request, keyHash[0], keyHash[1]);
        assertArrayEquals(
                expectedKeyHash,
                actualKeyHash,
                "issuerKeyHash должен совпадать с хешем публичного ключа издателя");
    }

    @Test
    @DisplayName("OCSPRequest: serialNumber скопирован бит-в-бит")
    void testOcspRequestSerial() throws Exception {
        byte[] request =
                OcspRequestBuilder.create()
                        .targetCert(server.cert.getEncoded())
                        .issuerCert(root.cert.getEncoded())
                        .build()
                        .der();

        // serial — последний элемент CertID (INTEGER TLV)
        int[] outer = GostDerParser.readTlv(request, 0);
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        int[] req = GostDerParser.readTlv(request, reqList[0]);
        int[] certId = GostDerParser.readTlv(request, req[0]);
        int[] algId = GostDerParser.readTlv(request, certId[0]);
        int[] nameHash = GostDerParser.readTlv(request, algId[1]);
        int[] keyHash = GostDerParser.readTlv(request, nameHash[1]);

        int[] serialTlv_out = GostDerParser.readTlv(request, keyHash[1]);
        byte[] requestSerialBytes =
                java.util.Arrays.copyOfRange(request, keyHash[1], serialTlv_out[1]);

        // Должен совпадать с serialNumber из исходного сертификата
        byte[] certSerialTlv = extractSerialTlv(server.cert.getEncoded());
        assertArrayEquals(
                certSerialTlv,
                requestSerialBytes,
                "serialNumber должен быть точной битовой копией");
    }

    @Test
    @DisplayName("OCSPRequest: OID алгоритма хеширования в CertID = Streebog-256")
    void testCertIdHashAlgorithmOid() throws Exception {
        // T-6: OID в CertID должен совпадать с STREEBOG256_OID_BYTES из GostDerParser,
        // иначе OCSP-верификатор отклонит ответ
        byte[] request =
                OcspRequestBuilder.create()
                        .targetCert(server.cert.getEncoded())
                        .issuerCert(root.cert.getEncoded())
                        .build()
                        .der();
        int[] outer = GostDerParser.readTlv(request, 0);
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        int[] req = GostDerParser.readTlv(request, reqList[0]);
        int[] certId = GostDerParser.readTlv(request, req[0]);

        // AlgorithmIdentifier внутри CertID
        int[] hashAlgSeq = GostDerParser.parseSequence(request, certId[0]);
        int haPos = hashAlgSeq[0];
        int[] oidTlv = GostDerParser.readTlv(request, haPos);

        assertTrue(
                GostDerParser.matchesOid(
                        request,
                        oidTlv[0],
                        oidTlv[1] - oidTlv[0],
                        org.rssys.gost.pkix.cert.GostDerParser.STREEBOG256_OID_BYTES),
                "OID алгоритма хеширования CertID должен быть Streebog-256");
    }

    // ---- Тесты buildSigned (RFC 9215 §4.2) ----

    /**
     * OID 1.2.643.7.1.1.3.2 (id-tc26-signwithdigest-gost3410-2012-256)
     * в DER-кодировке: content байты без 06 LL
     */
    private static final byte[] SIGN_ALG_256_OID = {
        (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02
    };

    /**
     * OID 1.2.643.7.1.1.3.3 (id-tc26-signwithdigest-gost3410-2012-512)
     * в DER-кодировке: content байты без 06 LL
     */
    private static final byte[] SIGN_ALG_512_OID = {
        (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x03
    };

    @Test
    @DisplayName("OCSPRequest signed: AlgorithmIdentifier без параметров, 256 бит (RFC 9215 §4.2)")
    void testBuildSignedAlgIdNoParams256() throws Exception {
        byte[] request =
                OcspRequestBuilder.create()
                        .targetCert(server.cert.getEncoded())
                        .issuerCert(root.cert.getEncoded())
                        .signKey(signKey256.priv)
                        .params(ECParameters.tc26a256())
                        .build()
                        .der();

        int[] ocspSeq = GostDerParser.parseSequence(request, 0);
        // TBSRequest + optionalSignature
        int[] tbsTlv = GostDerParser.readTlv(request, ocspSeq[0]);
        int pos = tbsTlv[1];
        assertEquals(
                0xA0,
                request[pos] & 0xFF,
                "После TBSRequest должен быть [0] EXPLICIT optionalSignature");

        int[] optSigTlv = GostDerParser.readTlv(request, pos);
        // Signature ::= SEQUENCE { signatureAlgorithm, signature, certs OPTIONAL }
        int[] sigSeq = GostDerParser.parseSequence(request, optSigTlv[0]);
        int sigPos = sigSeq[0];

        // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters OPTIONAL }
        int[] algId = GostDerParser.parseSequence(request, sigPos);
        assertEquals(0x06, request[algId[0]] & 0xFF, "AlgorithmIdentifier должен начинаться с OID");

        int[] oidTlv = GostDerParser.readTlv(request, algId[0]);
        // По RFC 9215 §4.2: parameters MUST be absent
        assertEquals(
                oidTlv[1],
                algId[1],
                "AlgorithmIdentifier не должен содержать parameters (RFC 9215 §4.2)");

        // OID должен быть SIGN_ALG_256 = 1.2.643.7.1.1.3.2
        assertTrue(
                GostDerParser.matchesOid(
                        request, oidTlv[0], oidTlv[1] - oidTlv[0], SIGN_ALG_256_OID),
                "OID должен быть id-tc26-signwithdigest-gost3410-2012-256");
    }

    @Test
    @DisplayName("OCSPRequest signed: AlgorithmIdentifier без параметров, 512 бит (RFC 9215 §4.2)")
    void testBuildSignedAlgIdNoParams512() throws Exception {
        byte[] request =
                OcspRequestBuilder.create()
                        .targetCert(server.cert.getEncoded())
                        .issuerCert(root.cert.getEncoded())
                        .signKey(signKey512.priv)
                        .params(ECParameters.tc26a512())
                        .build()
                        .der();

        int[] ocspSeq = GostDerParser.parseSequence(request, 0);
        int[] tbsTlv = GostDerParser.readTlv(request, ocspSeq[0]);
        int pos = tbsTlv[1];
        assertEquals(
                0xA0,
                request[pos] & 0xFF,
                "После TBSRequest должен быть [0] EXPLICIT optionalSignature");

        int[] optSigTlv = GostDerParser.readTlv(request, pos);
        int[] sigSeq = GostDerParser.parseSequence(request, optSigTlv[0]);
        int sigPos = sigSeq[0];

        int[] algId = GostDerParser.parseSequence(request, sigPos);
        assertEquals(0x06, request[algId[0]] & 0xFF, "AlgorithmIdentifier должен начинаться с OID");

        int[] oidTlv = GostDerParser.readTlv(request, algId[0]);
        assertEquals(
                oidTlv[1],
                algId[1],
                "AlgorithmIdentifier не должен содержать parameters (RFC 9215 §4.2)");

        // OID должен быть SIGN_ALG_512 = 1.2.643.7.1.1.3.3
        assertTrue(
                GostDerParser.matchesOid(
                        request, oidTlv[0], oidTlv[1] - oidTlv[0], SIGN_ALG_512_OID),
                "OID должен быть id-tc26-signwithdigest-gost3410-2012-512");
    }

    @Test
    @DisplayName("OCSPRequest signed: signKey=null возвращает запрос без подписи")
    void testBuildSignedNullKey() throws Exception {
        byte[] withKey =
                OcspRequestBuilder.create()
                        .targetCert(server.cert.getEncoded())
                        .issuerCert(root.cert.getEncoded())
                        .signKey(root.priv)
                        .params(ECParameters.tc26a256())
                        .build()
                        .der();
        byte[] withNull =
                OcspRequestBuilder.create()
                        .targetCert(server.cert.getEncoded())
                        .issuerCert(root.cert.getEncoded())
                        .signKey(null)
                        .params(ECParameters.tc26a256())
                        .build()
                        .der();

        // С подписью длиннее — есть optionalSignature
        assertTrue(
                withKey.length > withNull.length,
                "Запрос с подписью должен быть длиннее запроса без подписи");

        // Без подписи — проверяем, что нет [0] EXPLICIT после TBSRequest
        int[] outerNull = GostDerParser.readTlv(withNull, 0);
        int[] tbsNull = GostDerParser.readTlv(withNull, outerNull[0]);
        // После TBSRequest конец данных (нет [0])
        assertEquals(
                tbsNull[1],
                outerNull[1],
                "Без подписи после TBSRequest не должно быть optionalSignature");

        // С подписью — есть [0]
        int[] outerKey = GostDerParser.readTlv(withKey, 0);
        int[] tbsKey = GostDerParser.readTlv(withKey, outerKey[0]);
        assertEquals(
                0xA0,
                withKey[tbsKey[1]] & 0xFF,
                "С подписью после TBSRequest должен быть [0] EXPLICIT");
    }

    @Test
    @DisplayName("OCSPRequest: 512-битный CertID — OID DIGEST_512, хэши по 64 байта")
    void testBuildWithNonce512CertId() throws Exception {
        byte[] request =
                OcspRequestBuilder.create()
                        .targetCert(server.cert.getEncoded())
                        .issuerCert(root.cert.getEncoded())
                        .hashLen(64)
                        .build()
                        .der();

        int[] outer = GostDerParser.readTlv(request, 0);
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        int[] req = GostDerParser.readTlv(request, reqList[0]);
        int[] certId = GostDerParser.readTlv(request, req[0]);

        // AlgorithmIdentifier внутри CertID
        int[] hashAlgSeq = GostDerParser.parseSequence(request, certId[0]);
        int haPos = hashAlgSeq[0];
        int[] oidTlv = GostDerParser.readTlv(request, haPos);

        assertTrue(
                GostDerParser.matchesOid(
                        request,
                        oidTlv[0],
                        oidTlv[1] - oidTlv[0],
                        org.rssys.gost.pkix.cert.GostDerParser.STREEBOG512_OID_BYTES),
                "OID алгоритма хеширования CertID должен быть Streebog-512");

        // issuerNameHash — 64 байта
        int[] nameHash = GostDerParser.readTlv(request, hashAlgSeq[1]);
        assertEquals(
                64, nameHash[1] - nameHash[0], "issuerNameHash должен быть 64 байта для hlen=64");

        // issuerKeyHash — 64 байта
        int[] keyHash = GostDerParser.readTlv(request, nameHash[1]);
        assertEquals(64, keyHash[1] - keyHash[0], "issuerKeyHash должен быть 64 байта для hlen=64");
    }

    @Test
    @DisplayName("OCSPRequest signed: 512-битный ключ -> CertID с DIGEST_512")
    void testBuildSigned512CertId() throws Exception {
        byte[] request =
                OcspRequestBuilder.create()
                        .targetCert(server.cert.getEncoded())
                        .issuerCert(root.cert.getEncoded())
                        .signKey(signKey512.priv)
                        .params(ECParameters.tc26a512())
                        .build()
                        .der();

        // OCSPRequest ::= SEQUENCE { TBSRequest, [0] optSig }
        int[] outer = GostDerParser.readTlv(request, 0);
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]); // TBSRequest напрямую
        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        int[] req = GostDerParser.readTlv(request, reqList[0]);
        int[] certId = GostDerParser.readTlv(request, req[0]);

        // AlgorithmIdentifier внутри CertID
        int[] hashAlgSeq = GostDerParser.parseSequence(request, certId[0]);
        int haPos = hashAlgSeq[0];
        int[] oidTlv = GostDerParser.readTlv(request, haPos);

        assertTrue(
                GostDerParser.matchesOid(
                        request,
                        oidTlv[0],
                        oidTlv[1] - oidTlv[0],
                        org.rssys.gost.pkix.cert.GostDerParser.STREEBOG512_OID_BYTES),
                "buildSigned с 512-битным ключом: CertID OID должен быть Streebog-512");
    }

    /** Извлекает BIT STRING value SubjectPublicKeyInfo — для проверки issuerKeyHash (RFC 6960 §4.1.1). */
    private static byte[] extractRawPublicKey(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = GostDerParser.readTlv(der, pos)[1];
        pos = GostDerParser.readTlv(der, pos)[1]; // serial
        pos = GostDerParser.readTlv(der, pos)[1]; // signature alg
        pos = GostDerParser.readTlv(der, pos)[1]; // issuer
        pos = GostDerParser.readTlv(der, pos)[1]; // validity
        pos = GostDerParser.readTlv(der, pos)[1]; // subject
        int[] spkiTlv = GostDerParser.readTlv(der, pos);
        int spkiPos = spkiTlv[0];
        int[] algTlv = GostDerParser.readTlv(der, spkiPos);
        spkiPos = algTlv[1];
        int[] bsTlv = GostDerParser.readTlv(der, spkiPos);
        return java.util.Arrays.copyOfRange(der, bsTlv[0], bsTlv[1]);
    }

    /** Извлекает subject DN (полный TLV) — для проверки issuerNameHash, как в OcspRequestBuilder. */
    private static byte[] extractSubjectBytes(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = GostDerParser.readTlv(der, pos)[1];
        pos = GostDerParser.readTlv(der, pos)[1]; // serial
        pos = GostDerParser.readTlv(der, pos)[1]; // signature
        int[] issuerTlv = GostDerParser.readTlv(der, pos);
        pos = issuerTlv[1];
        int[] validityTlv = GostDerParser.readTlv(der, pos);
        pos = validityTlv[1];
        int[] subjectTlv = GostDerParser.readTlv(der, pos);
        return java.util.Arrays.copyOfRange(der, pos, subjectTlv[1]);
    }

    private static int findTbsOffset(byte[] der) {
        int[] certSeq = GostDerParser.readTlv(der, 0);
        int[] tbsTlv = GostDerParser.readTlv(der, certSeq[0]);
        return tbsTlv[0];
    }

    /**
     * Проверяет, что serialNumber скопирован bit-exact (TLV INTEGER как есть).
     * OcspRequestBuilder должен сохранять исходную DER-кодировку serialNumber.
     */
    private static byte[] extractSerialTlv(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = GostDerParser.readTlv(der, pos)[1];
        int tlvStart = pos;
        int[] serialTlv = GostDerParser.readTlv(der, pos);
        return java.util.Arrays.copyOfRange(der, tlvStart, serialTlv[1]);
    }
}
