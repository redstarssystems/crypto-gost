package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.Digest;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Структурная и семантическая проверка {@link GostOcspRequestBuilder}.
 */
@DisplayName("GostOcspRequestBuilder: построение OCSP-запроса")
class GostOcspRequestBuilderTest {

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
                        .assembleCert(caKp.getPrivate());

        GostCertificate leaf =
                GostCertificateBuilder.create(params, leafDn)
                        .publicKey(leafKp.getPublic())
                        .issuerDn(ca.getSubjectDnBytes())
                        .notBefore("20250101000000Z")
                        .notAfter("20261231235959Z")
                        .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                        .assembleCert(caKp.getPrivate());

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
    @DisplayName("OCSPRequest: структурная целостность DER-кодировки")
    void testOcspRequestStructure() {
        GostOcspRequestBuilder builder =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded());
        byte[] request = builder.build();

        int[] outer = GostDerParser.readTlv(request, 0);
        assertEquals(0x30, request[0] & 0xFF, "Корневой элемент должен быть SEQUENCE");

        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        assertEquals(0x30, request[outer[0]] & 0xFF, "TBSRequest должен быть SEQUENCE");

        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        assertEquals(0x30, request[tbsReq[0]] & 0xFF, "Список запросов должен быть SEQUENCE");

        int[] req = GostDerParser.readTlv(request, reqList[0]);
        assertEquals(0x30, request[reqList[0]] & 0xFF, "Запрос должен быть SEQUENCE");

        int[] certId = GostDerParser.readTlv(request, req[0]);
        assertEquals(0x30, request[req[0]] & 0xFF, "CertID должен быть SEQUENCE");

        int[] algId = GostDerParser.readTlv(request, certId[0]);
        assertEquals(0x30, request[certId[0]] & 0xFF);

        int[] nameHash = GostDerParser.readTlv(request, algId[1]);
        assertEquals(0x04, request[algId[1]] & 0xFF, "issuerNameHash должен быть OCTET STRING");
        assertEquals(32, nameHash[1] - nameHash[0], "issuerNameHash должен быть 32 байта");

        int[] keyHash = GostDerParser.readTlv(request, nameHash[1]);
        assertEquals(0x04, request[nameHash[1]] & 0xFF, "issuerKeyHash должен быть OCTET STRING");
        assertEquals(32, keyHash[1] - keyHash[0], "issuerKeyHash должен быть 32 байта");

        int[] serial = GostDerParser.readTlv(request, keyHash[1]);
        assertEquals(0x02, request[keyHash[1]] & 0xFF, "serialNumber должен быть INTEGER");
        assertTrue(serial[1] > serial[0], "serialNumber должен содержать данные");
    }

    @Test
    @DisplayName("OCSPRequest: семантическая корректность хешей")
    void testOcspRequestSemantics() {
        byte[] request =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .build();

        int[] outer = GostDerParser.readTlv(request, 0);
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        int[] req = GostDerParser.readTlv(request, reqList[0]);
        int[] certId = GostDerParser.readTlv(request, req[0]);
        int[] algId = GostDerParser.readTlv(request, certId[0]);
        int[] nameHash = GostDerParser.readTlv(request, algId[1]);
        int[] keyHash = GostDerParser.readTlv(request, nameHash[1]);

        byte[] expectedNameHash = Digest.digest256(certs256.ca.getSubjectDnBytes());
        byte[] actualNameHash = Arrays.copyOfRange(request, nameHash[0], nameHash[1]);
        assertArrayEquals(
                expectedNameHash,
                actualNameHash,
                "issuerNameHash должен совпадать с хешем subject DN издателя");

        byte[] expectedKeyHash = CertIdHasher.hashIssuerPublicKey(certs256.ca, 32);
        byte[] actualKeyHash = Arrays.copyOfRange(request, keyHash[0], keyHash[1]);
        assertArrayEquals(
                expectedKeyHash,
                actualKeyHash,
                "issuerKeyHash должен совпадать с хешем публичного ключа издателя");
    }

    @Test
    @DisplayName("OCSPRequest: serialNumber скопирован бит-в-бит")
    void testOcspRequestSerial() {
        byte[] request =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .build();

        int[] outer = GostDerParser.readTlv(request, 0);
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        int[] req = GostDerParser.readTlv(request, reqList[0]);
        int[] certId = GostDerParser.readTlv(request, req[0]);
        int[] algId = GostDerParser.readTlv(request, certId[0]);
        int[] nameHash = GostDerParser.readTlv(request, algId[1]);
        int[] keyHash = GostDerParser.readTlv(request, nameHash[1]);

        int[] serialTlvOut = GostDerParser.readTlv(request, keyHash[1]);
        byte[] requestSerialBytes = Arrays.copyOfRange(request, keyHash[1], serialTlvOut[1]);

        assertArrayEquals(
                extractSerialTlv(certs256.leaf.getEncoded()),
                requestSerialBytes,
                "serialNumber должен быть точной битовой копией");
    }

    @Test
    @DisplayName("OCSPRequest: OID алгоритма хеширования в CertID = Streebog-256")
    void testCertIdHashAlgorithmOid() {
        byte[] request =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .build();

        int[] outer = GostDerParser.readTlv(request, 0);
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        int[] req = GostDerParser.readTlv(request, reqList[0]);
        int[] certId = GostDerParser.readTlv(request, req[0]);

        int[] hashAlgSeq = GostDerParser.parseSequence(request, certId[0]);
        int haPos = hashAlgSeq[0];
        int[] oidTlv = GostDerParser.readTlv(request, haPos);

        assertTrue(
                GostDerParser.matchesOid(
                        request,
                        oidTlv[0],
                        oidTlv[1] - oidTlv[0],
                        GostDerParser.STREEBOG256_OID_BYTES),
                "OID алгоритма хеширования CertID должен быть Streebog-256");
    }

    @Test
    @DisplayName("OCSPRequest: nonce присутствует и возвращается через getNonce()")
    void testNoncePresent() {
        GostOcspRequestBuilder builder =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded());
        byte[] request = builder.build();
        byte[] nonce = builder.getNonce();

        assertNotNull(nonce, "Nonce должен быть сгенерирован");
        assertEquals(16, nonce.length, "Nonce должен быть 16 байт");

        // Проверяем наличие nonce в requestExtensions [2]
        int[] outer = GostDerParser.readTlv(request, 0);
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        int afterReqList = findAfterRequestList(request, tbsReq[0]);
        if (afterReqList < tbsReq[1]) {
            int tag = request[afterReqList] & 0xFF;
            assertEquals(
                    DerCodec.TAG_CTX_BASE | 2,
                    tag,
                    "После requestList должен быть requestExtensions [2]");
        }
    }

    @Test
    @DisplayName("OCSPRequest: getNonce() до build() бросает IllegalStateException")
    void testGetNonceBeforeBuild() {
        GostOcspRequestBuilder builder =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded());
        assertThrows(
                IllegalStateException.class,
                builder::getNonce,
                "getNonce() до build() должен бросать исключение");
    }

    @Test
    @DisplayName("OCSPRequest: 512-битный CertID — OID DIGEST_512, хэши по 64 байта")
    void testBuild512CertId() {
        byte[] request =
                GostOcspRequestBuilder.create()
                        .targetCert(certs512.leaf.getEncoded())
                        .issuerCert(certs512.ca.getEncoded())
                        .hashLen(64)
                        .build();

        int[] outer = GostDerParser.readTlv(request, 0);
        int[] tbsReq = GostDerParser.readTlv(request, outer[0]);
        int[] reqList = GostDerParser.readTlv(request, tbsReq[0]);
        int[] req = GostDerParser.readTlv(request, reqList[0]);
        int[] certId = GostDerParser.readTlv(request, req[0]);

        int[] hashAlgSeq = GostDerParser.parseSequence(request, certId[0]);
        int haPos = hashAlgSeq[0];
        int[] oidTlv = GostDerParser.readTlv(request, haPos);

        assertTrue(
                GostDerParser.matchesOid(
                        request,
                        oidTlv[0],
                        oidTlv[1] - oidTlv[0],
                        GostDerParser.STREEBOG512_OID_BYTES),
                "OID алгоритма хеширования CertID должен быть Streebog-512");

        int[] nameHash = GostDerParser.readTlv(request, hashAlgSeq[1]);
        assertEquals(
                64, nameHash[1] - nameHash[0], "issuerNameHash должен быть 64 байта для hlen=64");

        int[] keyHash = GostDerParser.readTlv(request, nameHash[1]);
        assertEquals(64, keyHash[1] - keyHash[0], "issuerKeyHash должен быть 64 байта для hlen=64");
    }

    @Test
    @DisplayName("OCSPRequest signed: AlgorithmIdentifier без параметров, 256 бит (RFC 9215 §4.2)")
    void testBuildSignedAlgIdNoParams256() {
        KeyPair signKp = KeyGenerator.generateKeyPair(params256);
        byte[] request =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .signKey(signKp.getPrivate())
                        .params(params256)
                        .build();

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

        assertTrue(
                GostDerParser.matchesOid(
                        request, oidTlv[0], oidTlv[1] - oidTlv[0], SIGN_ALG_256_OID),
                "OID должен быть id-tc26-signwithdigest-gost3410-2012-256");
    }

    @Test
    @DisplayName("OCSPRequest signed: AlgorithmIdentifier без параметров, 512 бит (RFC 9215 §4.2)")
    void testBuildSignedAlgIdNoParams512() {
        KeyPair signKp = KeyGenerator.generateKeyPair(params512);
        byte[] request =
                GostOcspRequestBuilder.create()
                        .targetCert(certs512.leaf.getEncoded())
                        .issuerCert(certs512.ca.getEncoded())
                        .signKey(signKp.getPrivate())
                        .params(params512)
                        .hashLen(64)
                        .build();

        int[] ocspSeq = GostDerParser.parseSequence(request, 0);
        int[] tbsTlv = GostDerParser.readTlv(request, ocspSeq[0]);
        int pos = tbsTlv[1];
        assertEquals(0xA0, request[pos] & 0xFF);

        int[] optSigTlv = GostDerParser.readTlv(request, pos);
        int[] sigSeq = GostDerParser.parseSequence(request, optSigTlv[0]);
        int sigPos = sigSeq[0];

        int[] algId = GostDerParser.parseSequence(request, sigPos);
        assertEquals(0x06, request[algId[0]] & 0xFF);

        int[] oidTlv = GostDerParser.readTlv(request, algId[0]);
        assertEquals(oidTlv[1], algId[1]);

        assertTrue(
                GostDerParser.matchesOid(
                        request, oidTlv[0], oidTlv[1] - oidTlv[0], SIGN_ALG_512_OID),
                "OID должен быть id-tc26-signwithdigest-gost3410-2012-512");
    }

    @Test
    @DisplayName("OCSPRequest signed: signKey=null возвращает запрос без подписи")
    void testBuildSignedNullKey() {
        KeyPair signKp = KeyGenerator.generateKeyPair(params256);
        byte[] withKey =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .signKey(signKp.getPrivate())
                        .params(params256)
                        .build();
        byte[] withoutKey =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .build();

        assertTrue(
                withKey.length > withoutKey.length,
                "Запрос с подписью должен быть длиннее запроса без подписи");

        int[] outerNull = GostDerParser.readTlv(withoutKey, 0);
        int[] tbsNull = GostDerParser.readTlv(withoutKey, outerNull[0]);
        assertEquals(
                tbsNull[1],
                outerNull[1],
                "Без подписи после TBSRequest не должно быть optionalSignature");
    }

    @Test
    @DisplayName("OCSPRequest signed: signKey без params бросает исключение")
    void testSignKeyRequiresParams() {
        KeyPair signKp = KeyGenerator.generateKeyPair(params256);
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostOcspRequestBuilder.create()
                                .targetCert(certs256.leaf.getEncoded())
                                .issuerCert(certs256.ca.getEncoded())
                                .signKey(signKp.getPrivate())
                                .build(),
                "signKey без params должен бросать исключение");
    }

    @Test
    @DisplayName("OCSPRequest signed: hashLen несовместим с params.hlen бросает исключение")
    void testHashLenMismatchFails() {
        KeyPair signKp = KeyGenerator.generateKeyPair(params256);
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostOcspRequestBuilder.create()
                                .targetCert(certs256.leaf.getEncoded())
                                .issuerCert(certs256.ca.getEncoded())
                                .signKey(signKp.getPrivate())
                                .params(params256)
                                .hashLen(64)
                                .build(),
                "hashLen=64 с params.hlen=32 должен бросать исключение");
    }

    @Test
    @DisplayName("Multi-cert: round-trip с двумя парами — оба CertID в ответе")
    void testMultiCertRoundtrip() throws Exception {
        byte[] der =
                GostOcspRequestBuilder.create()
                        .addRequest(certs256.leaf.getEncoded(), certs256.ca.getEncoded())
                        .targetCert(certs512.leaf.getEncoded())
                        .issuerCert(certs512.ca.getEncoded())
                        .hashLen(32)
                        .build();

        GostOcspRequest parsed = GostOcspRequest.fromDer(der);
        assertEquals(2, parsed.getCertIds().size(), "Должно быть два CertID");

        assertArrayEquals(
                certs256.leaf.getSerialNumber(),
                parsed.getCertIds().get(0).serialNumber(),
                "Первый CertID — serial должен совпадать с certs256.leaf");

        assertArrayEquals(
                certs512.leaf.getSerialNumber(),
                parsed.getCertIds().get(1).serialNumber(),
                "Второй CertID — serial должен совпадать с certs512.leaf");

        byte[] der2 =
                GostOcspRequestBuilder.create()
                        .addRequest(certs256.leaf.getEncoded(), certs256.ca.getEncoded())
                        .addRequest(certs512.leaf.getEncoded(), certs512.ca.getEncoded())
                        .hashLen(32)
                        .build();
        GostOcspRequest parsed2 = GostOcspRequest.fromDer(der2);
        assertEquals(2, parsed2.getCertIds().size());
        assertNotNull(parsed2.getNonce(), "Multi-cert запрос должен содержать nonce");
    }

    @Test
    @DisplayName("Multi-cert: build() без пар бросает IllegalStateException")
    void testMultiCertNoPairs() {
        assertThrows(
                IllegalStateException.class,
                () -> GostOcspRequestBuilder.create().build(),
                "build() без пар должен бросать исключение");
    }

    @Test
    @DisplayName("Multi-cert: targetCert без issuerCert бросает до build()")
    void testUnpairedTargetCertFails() {
        assertThrows(
                IllegalStateException.class,
                () ->
                        GostOcspRequestBuilder.create()
                                .targetCert(certs256.leaf.getEncoded())
                                .addRequest(certs512.leaf.getEncoded(), certs512.ca.getEncoded())
                                .build(),
                "targetCert без issuerCert должен бросать исключение");
    }

    @Test
    @DisplayName("Multi-cert: чередующиеся targetCert/issuerCert — три пары")
    void testInterleavedCertCalls() {
        byte[] der =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .targetCert(certs512.leaf.getEncoded())
                        .issuerCert(certs512.ca.getEncoded())
                        .targetCert(certs256.ca.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .hashLen(32)
                        .build();

        int[] outer = GostDerParser.readTlv(der, 0);
        int[] tbsReq = GostDerParser.readTlv(der, outer[0]);
        int pos = tbsReq[0];
        if ((der[pos] & 0xFF) == 0xA0) pos = GostDerParser.readTlv(der, pos)[1];
        if ((der[pos] & 0xFF) == 0xA1) pos = GostDerParser.readTlv(der, pos)[1];
        int[] reqList = GostDerParser.readTlv(der, pos);
        int rlPos = reqList[0];
        int rlEnd = reqList[1];
        int count = 0;
        while (rlPos < rlEnd) {
            rlPos = GostDerParser.readTlv(der, rlPos)[1];
            count++;
        }
        assertEquals(3, count, "Чередующиеся вызовы должны дать три Request");
    }

    @Test
    @DisplayName("Multi-cert: повторные targetCert — последний побеждает")
    void testRepeatedTargetCertLastWins() throws Exception {
        byte[] der =
                GostOcspRequestBuilder.create()
                        .targetCert(certs256.leaf.getEncoded())
                        .targetCert(certs512.leaf.getEncoded())
                        .targetCert(certs256.ca.getEncoded())
                        .issuerCert(certs256.ca.getEncoded())
                        .hashLen(32)
                        .build();

        GostOcspRequest parsed = GostOcspRequest.fromDer(der);
        assertEquals(1, parsed.getCertIds().size(), "Должна быть одна пара");
        assertArrayEquals(
                certs256.ca.getSerialNumber(),
                parsed.getCertIds().get(0).serialNumber(),
                "Последний targetCert (ca) должен быть в запросе");
    }

    // -------------------------------------------------------------------------
    // Вспомогательные методы
    // -------------------------------------------------------------------------

    private static final byte[] SIGN_ALG_256_OID = {
        (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02
    };

    private static final byte[] SIGN_ALG_512_OID = {
        (byte) 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x03
    };

    private static byte[] extractSerialTlv(byte[] der) {
        int pos = findTbsOffset(der);
        if ((der[pos] & 0xFF) == 0xA0) pos = GostDerParser.readTlv(der, pos)[1];
        int tlvStart = pos;
        int[] serialTlv = GostDerParser.readTlv(der, pos);
        return Arrays.copyOfRange(der, tlvStart, serialTlv[1]);
    }

    private static int findTbsOffset(byte[] der) {
        int[] certSeq = GostDerParser.readTlv(der, 0);
        int[] tbsTlv = GostDerParser.readTlv(der, certSeq[0]);
        return tbsTlv[0];
    }

    /** Находит позицию после requestList в TBSRequest для проверки requestExtensions. */
    private static int findAfterRequestList(byte[] der, int tbsPos) {
        int pos = tbsPos;
        if (pos < der.length && (der[pos] & 0xFF) == 0xA0) {
            pos = GostDerParser.readTlv(der, pos)[1]; // version
        }
        if (pos < der.length && (der[pos] & 0xFF) == 0xA1) {
            pos = GostDerParser.readTlv(der, pos)[1]; // requestorName
        }
        // requestList
        int[] reqList = GostDerParser.readTlv(der, pos);
        return reqList[1];
    }
}
