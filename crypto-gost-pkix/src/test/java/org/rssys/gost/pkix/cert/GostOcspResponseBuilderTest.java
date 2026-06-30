package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.*;
import static org.rssys.gost.pkix.cert.GostDerParser.*;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Модульные тесты {@link GostOcspResponseBuilder}: построение и проверка OCSP-ответов.
 */
@DisplayName("GostOcspResponseBuilder: построение и верификация OCSP")
class GostOcspResponseBuilderTest {

    @Test
    @DisplayName("buildOcspResponse: обратимость — строим ответ, верифицируем через OcspVerifier")
    void testBuildOcspResponseRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serialNumber = new byte[] {0x01};

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .signer(kp.getPrivate(), kp.getPublic())
                        .issuerDn(caDn)
                        .build();

        assertNotNull(ocspDer);
        assertTrue(ocspDer.length > 100);

        OcspVerifier.verify(ocspDer, serialNumber, kp.getPublic());
    }

    @Test
    @DisplayName("buildOcspResponse: чужой ключ -> PkixException")
    void testBuildOcspResponseWrongKey() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        KeyPair wrongKp = KeyGenerator.generateKeyPair(params);
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serialNumber = new byte[] {0x01};

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .signer(kp.getPrivate(), kp.getPublic())
                        .issuerDn(caDn)
                        .build();

        assertThrows(
                PkixException.class,
                () -> OcspVerifier.verify(ocspDer, serialNumber, wrongKp.getPublic()));
    }

    @Test
    @DisplayName("buildOcspResponse: 512-битная кривая — CertID с DIGEST_512 и хэшами 64 байта")
    void testBuildOcspResponse512() throws Exception {
        ECParameters params = ECParameters.tc26a512();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA 512");
        byte[] serialNumber = new byte[] {0x01};

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .signer(kp.getPrivate(), kp.getPublic())
                        .issuerDn(caDn)
                        .build();

        assertNotNull(ocspDer);
        OcspVerifier.verify(ocspDer, serialNumber, kp.getPublic());

        // Проверяем на DER-уровне: CertID.hashAlgorithm = DIGEST_512, хэши по 64 байта
        int[] ocspSeq = GostDerParser.parseSequence(ocspDer, 0);
        int pos = ocspSeq[0];
        pos = GostDerParser.readTlv(ocspDer, pos)[1]; // status
        if ((ocspDer[pos] & 0xFF) == 0xA0)
            pos = GostDerParser.readTlv(ocspDer, pos)[0]; // responseBytes [0]
        int[] rbSeq = GostDerParser.parseSequence(ocspDer, pos);
        pos = rbSeq[0];
        pos = GostDerParser.readTlv(ocspDer, pos)[1]; // OID
        int[] octTlv = GostDerParser.readTlv(ocspDer, pos);
        int[] basicSeq = GostDerParser.parseSequence(ocspDer, octTlv[0]);
        int[] tbsSeq = GostDerParser.parseSequence(ocspDer, basicSeq[0]);
        int tbsPos = tbsSeq[0];
        if ((ocspDer[tbsPos] & 0xFF) == 0xA0)
            tbsPos = GostDerParser.readTlv(ocspDer, tbsPos)[1]; // version
        tbsPos = GostDerParser.readTlv(ocspDer, tbsPos)[1]; // responderID
        tbsPos = GostDerParser.readTlv(ocspDer, tbsPos)[1]; // producedAt
        int[] respSeq = GostDerParser.parseSequence(ocspDer, tbsPos);
        int[] srSeq = GostDerParser.parseSequence(ocspDer, respSeq[0]);
        int[] certIdSeq = GostDerParser.parseSequence(ocspDer, srSeq[0]);

        // CertID.hashAlgorithm должен быть DIGEST_512
        int[] hashAlgSeq = GostDerParser.parseSequence(ocspDer, certIdSeq[0]);
        int[] haOid = GostDerParser.readTlv(ocspDer, hashAlgSeq[0]);
        assertTrue(
                GostDerParser.matchesOid(
                        ocspDer,
                        haOid[0],
                        haOid[1] - haOid[0],
                        GostDerParser.STREEBOG512_OID_BYTES),
                "CertID.hashAlgorithm должен быть Streebog-512 для 512-битного ключа");

        // issuerNameHash должен быть 64 байта
        int[] nameHashTlv = GostDerParser.readTlv(ocspDer, hashAlgSeq[1]);
        assertEquals(
                64,
                nameHashTlv[1] - nameHashTlv[0],
                "issuerNameHash должен быть 64 байта для 512-битного ключа");

        // issuerKeyHash должен быть 64 байта
        int[] keyHashTlv = GostDerParser.readTlv(ocspDer, nameHashTlv[1]);
        assertEquals(
                64,
                keyHashTlv[1] - keyHashTlv[0],
                "issuerKeyHash должен быть 64 байта для 512-битного ключа");
    }

    @Test
    @DisplayName("buildDummyOcspResponse: строит ненулевой ответ")
    void testBuildDummyOcspResponse() throws Exception {
        byte[] ocspDer = buildDummyOcspResponse();
        assertNotNull(ocspDer);
        assertTrue(ocspDer.length > 50);
    }

    private static byte[] buildDummyOcspResponse() throws Exception {
        byte[] tbs = new byte[] {0x30, 0x03, 0x02, 0x01, 0x00};
        byte[] sigAlg = DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.SIGN_ALG_256));
        byte[] sig = DerCodec.encodeBitString(new byte[64]);
        byte[] basicOcsp = DerCodec.encodeSequence(tbs, sigAlg, sig);
        byte[] basicOctet = DerCodec.encodeOctetString(basicOcsp);
        byte[] responseBytesContent =
                DerCodec.encodeSequence(DerCodec.encodeOid(GostOids.OCSP_BASIC), basicOctet);
        byte[] responseBytes = DerCodec.encodeTlv(0xA0, responseBytesContent);
        byte[] status = new byte[] {0x0A, 0x01, 0x00};
        return DerCodec.encodeSequence(status, responseBytes);
    }

    @Test
    @DisplayName("buildOcspResponseWithDelegatedCerts: обратимость")
    void testBuildOcspResponseWithDelegatedCerts() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair caKp = KeyGenerator.generateKeyPair(params);
        KeyPair delKp = KeyGenerator.generateKeyPair(params);
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serialNumber = new byte[] {0x01};

        byte[] delDn = GostDnParser.encodeDn("CN=Test Delegated Cert");
        byte[] delTbs =
                GostCertificateBuilder.create(params, delDn)
                        .publicKey(delKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(caDn)
                        .buildTbs();
        GostCertificate delCert =
                GostCertificateBuilder.assembleCert(delTbs, caKp.getPrivate(), params);
        byte[][] delegatedCerts = new byte[][] {delCert.getEncoded()};

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .signer(delKp.getPrivate(), delKp.getPublic())
                        .caPublicKey(caKp.getPublic())
                        .issuerDn(caDn)
                        .nextUpdate("21010101000000Z")
                        .withDelegatedCerts(delegatedCerts)
                        .build();

        assertNotNull(ocspDer);

        java.util.List<byte[]> extracted = new GostOcspResponse(ocspDer).getDelegatedCertificates();
        assertEquals(1, extracted.size());
    }

    // ========================================================================
    // Nonce (RFC 8954)
    // ========================================================================

    @Test
    @DisplayName("nonce: DER содержит responseExtensions [1] с nonce OID")
    void testNonceStructureInDer() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serialNumber = new byte[] {0x01};
        byte[] nonce =
                new byte[] {
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
                };

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .signer(kp.getPrivate(), kp.getPublic())
                        .issuerDn(caDn)
                        .nonce(nonce)
                        .build();

        // Навигация DER: OCSPResponse -> responseBytes [0] -> OID -> OCTET STRING
        // -> BasicOCSPResponse -> tbsResponseData -> ... -> responses -> responseExtensions [1]
        int[] ocspSeq = parseSequence(ocspDer, 0);
        int pos = ocspSeq[0];
        pos = readTlv(ocspDer, pos)[1]; // status
        if ((ocspDer[pos] & 0xFF) == 0xA0) pos = readTlv(ocspDer, pos)[0]; // responseBytes [0]
        int[] rbSeq = parseSequence(ocspDer, pos);
        pos = rbSeq[0];
        pos = readTlv(ocspDer, pos)[1]; // OID
        int[] octTlv = readTlv(ocspDer, pos);
        int[] basicSeq = parseSequence(ocspDer, octTlv[0]);
        int[] tbsSeq = parseSequence(ocspDer, basicSeq[0]);
        int tbsPos = tbsSeq[0];
        if ((ocspDer[tbsPos] & 0xFF) == 0xA0) tbsPos = readTlv(ocspDer, tbsPos)[1]; // version
        tbsPos = readTlv(ocspDer, tbsPos)[1]; // responderID
        tbsPos = readTlv(ocspDer, tbsPos)[1]; // producedAt
        int[] respSeq = parseSequence(ocspDer, tbsPos); // responses
        tbsPos = respSeq[1];

        // После responses должен быть responseExtensions [1] EXPLICIT
        assertTrue(tbsPos < tbsSeq[1], "После responses должен быть responseExtensions");
        assertEquals(
                0xA1,
                ocspDer[tbsPos] & 0xFF,
                "Тег responseExtensions должен быть [1] EXPLICIT = 0xA1");
        int[] reExplTlv = readTlv(ocspDer, tbsPos);
        int[] reSeq = parseSequence(ocspDer, reExplTlv[0]);
        int[] extSeq = parseSequence(ocspDer, reSeq[0]);
        int extPos = extSeq[0];
        // OID nonce внутри Extension
        int[] oidTlv = readTlv(ocspDer, extPos);
        assertArrayEquals(
                GostDerParser.OCSP_NONCE_OID_BYTES,
                java.util.Arrays.copyOfRange(ocspDer, oidTlv[0], oidTlv[1]),
                "OID расширения должен быть id-pkix-ocsp-nonce");
        extPos = oidTlv[1];
        // OCTET STRING — значение nonce
        int[] valueTlv = readTlv(ocspDer, extPos);
        assertEquals(
                0x04, ocspDer[valueTlv[0] - 2] & 0xFF, "Значение nonce должно быть OCTET STRING");
        assertArrayEquals(
                nonce,
                java.util.Arrays.copyOfRange(ocspDer, valueTlv[0], valueTlv[1]),
                "Значение nonce должно совпадать");
    }

    @Test
    @DisplayName("nonce: round-trip через OcspVerifier.verify со strict-проверкой")
    void testNonceRoundtrip() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serialNumber = new byte[] {0x01};
        byte[] nonce =
                new byte[] {
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
                };

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .signer(kp.getPrivate(), kp.getPublic())
                        .issuerDn(caDn)
                        .nonce(nonce)
                        .build();

        // strict=true — nonce должен совпадать
        OcspVerifier.verify(ocspDer, serialNumber, kp.getPublic(), caDn, null, nonce, true);

        // Чужой nonce с strict=true -> ошибка (mismatch всегда бросается)
        byte[] wrongNonce = new byte[16];
        wrongNonce[0] = (byte) 0xFF;
        assertThrows(
                PkixException.class,
                () ->
                        OcspVerifier.verify(
                                ocspDer,
                                serialNumber,
                                kp.getPublic(),
                                caDn,
                                null,
                                wrongNonce,
                                true),
                "Чужой nonce при strict=true должен вызывать ошибку");
    }

    @Test
    @DisplayName("OCSP с certStatus=revoked + неверный ключ -> SIGNATURE_INVALID, не REVOKED")
    void testOcspVerify_tamperedRevoked_failsOnSignature() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        KeyPair wrongKp = KeyGenerator.generateKeyPair(params);
        byte[] caDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serialNumber = new byte[] {0x01};

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .signer(kp.getPrivate(), kp.getPublic())
                        .issuerDn(caDn)
                        .revoked("20260101000000Z")
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(ocspDer, serialNumber, wrongKp.getPublic()),
                        "OCSP-ответ с certStatus=revoked и неверной подписью"
                                + " должен падать на проверке подписи, а не на статусе");

        assertNotEquals(
                PkixException.Reason.REVOKED,
                ex.reason(),
                "Причина ошибки не должна быть REVOKED — подпись проверяется до certStatus");
    }

    @Test
    @DisplayName("Instant-перегрузки producedAt/thisUpdate/nextUpdate: валидный OCSP-ответ")
    void testInstantProducedAtThisUpdateNextUpdate() throws Exception {
        ECParameters params = ECParameters.tc26a256();
        KeyPair kp = KeyGenerator.generateKeyPair(params);
        byte[] issuerDn = GostDnParser.encodeDn("CN=Test CA");
        byte[] serialNumber = new byte[] {0x01};
        Instant now = Instant.now();
        Instant future = now.plusSeconds(3600L * 24 * 365);

        byte[] ocspDer =
                GostOcspResponseBuilder.create(serialNumber)
                        .signer(kp.getPrivate(), kp.getPublic())
                        .issuerDn(issuerDn)
                        .caPublicKey(kp.getPublic())
                        .producedAt(now)
                        .thisUpdate(now)
                        .nextUpdate(future)
                        .build();

        assertNotNull(ocspDer, "OCSP-ответ должен быть не null");

        GostOcspResponse resp = new GostOcspResponse(ocspDer);
        resp.verify(kp.getPublic());
        assertTrue(resp.isSignatureVerified(), "Подпись должна быть верифицирована");

        Instant producedAt = resp.getProducedAt();
        assertNotNull(producedAt, "producedAt должен быть не null");
        assertTrue(
                producedAt.toEpochMilli() >= now.toEpochMilli() - 1000,
                "producedAt должен быть >= now - 1с");
    }
}
