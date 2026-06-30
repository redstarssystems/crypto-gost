package org.rssys.gost.tls13.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.GostOcspResponseBuilder;
import org.rssys.gost.pkix.cert.OcspVerifier;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.tls13.TlsTestHelper;
import org.rssys.gost.util.DerCodec;

/**
 * Unit-тесты для OcspVerifier.verify() — CertID matching negative paths.
 */
class TlsOcspVerifierTest {

    private static ECParameters params;
    private static TlsTestHelper.CertBundle root;
    private static TlsTestHelper.CertBundle leaf;

    @BeforeAll
    static void setUp() throws Exception {
        params = ECParameters.tc26a256();
        root = TlsTestHelper.createRootCA(params);
        leaf =
                TlsTestHelper.createCertSignedBy(
                        params,
                        root.priv,
                        root.cert.getPublicKey(),
                        root.subjectDn,
                        "20240501120000Z",
                        "21060101120000Z",
                        new String[] {"gost.example.com"},
                        (byte[]) null,
                        (String[]) null,
                        false,
                        null);
    }

    @Test
    @DisplayName("CertID: неверный issuer DN -> issuerNameHash mismatch")
    void testCertIdNameHashMismatch() throws Exception {
        byte[] ocsp =
                TlsTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                OcspVerifier.verify(
                                        ocsp,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey(),
                                        new byte[] {0x30, 0x00},
                                        root.cert.getEncoded()));
        assertTrue(ex.getMessage().contains("issuerNameHash mismatch"));
    }

    @Test
    @DisplayName("CertID: чужой issuer с другим ключом -> issuerKeyHash mismatch")
    void testCertIdKeyHashMismatch() throws Exception {
        TlsTestHelper.CertBundle otherRoot = TlsTestHelper.createRootCA(params);
        byte[] ocsp =
                TlsTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                OcspVerifier.verify(
                                        ocsp,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey(),
                                        root.subjectDn,
                                        otherRoot.cert.getEncoded()));
        assertTrue(ex.getMessage().contains("issuerKeyHash mismatch"));
    }

    @Test
    @DisplayName("CertID: OID алгоритма хеширования не Streebog-256 -> отказ")
    void testCertIdHashAlgorithmMismatch() throws Exception {
        byte[] ocsp =
                TlsTestHelper.buildOcspResponse(
                        leaf.cert.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);
        // Мутируем OID с Streebog-256 (0x06,0x08,0x2A,0x85,...) на SHA-1
        // (0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A)
        byte[] mutated = ocsp.clone();
        byte[] streebogOid = {0x06, 0x08, 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02};
        byte[] sha1Oid = {0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A};
        int idx = indexOf(mutated, streebogOid);
        assertTrue(idx >= 0, "OID Streebog-256 должен быть найден в OCSP-ответе");
        System.arraycopy(sha1Oid, 0, mutated, idx, sha1Oid.length);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                OcspVerifier.verify(
                                        mutated,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey(),
                                        root.subjectDn,
                                        root.cert.getEncoded()));
        assertTrue(
                ex.getMessage().contains("must be Streebog-256 or Streebog-512"),
                "Ожидалась ошибка hashAlgorithm, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("thisUpdate в будущем -> отказ (RFC 6960 §3.2)")
    void testThisUpdateInFuture() throws Exception {
        // Строим OCSP-ответ с thisUpdate в далёком будущем напрямую через builder API —
        // без byte-hacking'а готового DER, который подвержен ложным совпадениям тега 0x18
        // в случайных данных хэшей (issuerNameHash/issuerKeyHash).
        byte[] ocsp =
                GostOcspResponseBuilder.create(leaf.cert.getSerialNumber())
                        .signer(root.priv, root.cert.getPublicKey())
                        .issuerDn(root.subjectDn)
                        .nextUpdate("21010101000000Z")
                        .producedAt("20250101000000Z")
                        .thisUpdate("21010101000000Z")
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                OcspVerifier.verify(
                                        ocsp,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey()));
        assertTrue(
                ex.getMessage().contains("future"),
                "Ожидалось thisUpdate future, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("Multi-SingleResponse: находит искомый сертификат во втором SingleResponse")
    void testMultiSingleResponseSecondIsRevoked() throws Exception {
        // OCSP-ответ для ДРУГОГО сертификата (good) — будет первым
        // Серийный номер должен отличаться от leaf, иначе цикл найдёт otherCert первым
        var otherKp = KeyGenerator.generateKeyPair(params);
        byte[] otherSubjectDn = TlsTestHelper.buildDN("Test Cert Other");
        byte[] otherTbs =
                GostCertificateBuilder.create(params, otherSubjectDn)
                        .publicKey(otherKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(root.subjectDn)
                        .serial(BigInteger.TWO)
                        .buildTbs();
        GostCertificate otherGost =
                GostCertificateBuilder.assembleCert(otherTbs, root.priv, params);
        byte[] ocspOther =
                TlsTestHelper.buildOcspResponse(
                        otherGost.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);

        // OCSP-ответ для искомого сертификата (good, потом запятчим до revoked)
        byte[] ocspTargetGood = ocspTargetGood();

        // Извлекаем SingleResponse из каждого
        byte[] srOther = extractFirstSingleResponse(ocspOther);
        byte[] srTargetGood = extractFirstSingleResponse(ocspTargetGood);

        // Патчим второй SingleResponse: good(0x80)→revoked(0xA1), без сдвига длин
        // Заменяем только тег certStatus (0x80→0xA1), оставляя тело как есть
        byte[] srTargetRevoked = srTargetGood.clone();
        int certStatusPos = findCertStatusInSingleResponse(srTargetRevoked);
        assertTrue(certStatusPos >= 0, "certStatus должен быть найден");
        assertEquals((byte) 0x80, srTargetRevoked[certStatusPos]);
        srTargetRevoked[certStatusPos] = (byte) 0xA1; // good → revoked

        // Строим OCSP-ответ с двумя SingleResponses (other первым, target вторым)
        // с валидной подписью — TlsTestHelper переподписывает новый TBS
        byte[] multiOcsp =
                TlsTestHelper.buildMultiResponseOcsp(
                        ocspOther, srOther, srTargetRevoked, root.priv);

        // Верификация: находит leaf во втором SingleResponse → получает REVOKED
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                OcspVerifier.verify(
                                        multiOcsp,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey()));
        assertEquals(
                PkixException.Reason.REVOKED,
                ex.reason(),
                "Должен быть REVOKED для второго (revoked) SingleResponse");
    }

    @Test
    @DisplayName("Multi-SingleResponse: находит искомый первым (good) — happy path")
    void testMultiSingleResponseFirstIsGood() throws Exception {
        // Создаём сертификат с уникальным серийным, чтобы не пересечься с leaf
        var otherKp = KeyGenerator.generateKeyPair(params);
        byte[] otherSubjectDn = TlsTestHelper.buildDN("Test Cert First");
        byte[] otherTbs =
                GostCertificateBuilder.create(params, otherSubjectDn)
                        .publicKey(otherKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(root.subjectDn)
                        .serial(BigInteger.valueOf(42))
                        .buildTbs();
        GostCertificate otherGost =
                GostCertificateBuilder.assembleCert(otherTbs, root.priv, params);
        byte[] ocspOther =
                TlsTestHelper.buildOcspResponse(
                        otherGost.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);

        byte[] srTarget = extractFirstSingleResponse(ocspTargetGood());
        byte[] srOther = extractFirstSingleResponse(ocspOther);

        // target первым → verifier находит его в первом же SR, сертификат good:
        // проходит certStatus-проверку, но подпись нового TBS недействительна
        byte[] multiOcsp = buildMultiResponseOcsp(ocspTargetGood(), srTarget, srOther);
        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                OcspVerifier.verify(
                                        multiOcsp,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey()));
        assertTrue(
                ex.getMessage().contains("signature verification failed"),
                "Должен пройти certStatus (good), но упасть на подписи: " + ex.getMessage());
    }

    @Test
    @DisplayName("Multi-SingleResponse: искомый серийный номер не найден ни в одном")
    void testMultiSingleResponseSerialNotFound() throws Exception {
        // OCSP только для другого сертификата — leaf'а там нет
        var otherKp = KeyGenerator.generateKeyPair(params);
        byte[] otherSubjectDn = TlsTestHelper.buildDN("Test Cert Nf");
        byte[] otherTbs =
                GostCertificateBuilder.create(params, otherSubjectDn)
                        .publicKey(otherKp.getPublic())
                        .notBefore("20240501120000Z")
                        .notAfter("21060101120000Z")
                        .issuerDn(root.subjectDn)
                        .serial(BigInteger.valueOf(99))
                        .buildTbs();
        GostCertificate otherGost =
                GostCertificateBuilder.assembleCert(otherTbs, root.priv, params);
        byte[] ocspOther =
                TlsTestHelper.buildOcspResponse(
                        otherGost.getSerialNumber(), root.priv,
                        root.cert.getPublicKey(), root.subjectDn);

        // Два SingleResponse — оба для other, leaf'а нет
        byte[] srOther = extractFirstSingleResponse(ocspOther);
        byte[] multiOcsp = buildMultiResponseOcsp(ocspOther, srOther, srOther);

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                OcspVerifier.verify(
                                        multiOcsp,
                                        leaf.cert.getSerialNumber(),
                                        root.cert.getPublicKey()));
        assertTrue(
                ex.getMessage().contains("not found"),
                "Ожидалась ошибка 'not found', получено: " + ex.getMessage());
    }

    // ========================================================================
    // Вспомогательные методы
    // ========================================================================

    /** Строит OCSP-ответ (good-статус) для leaf-сертификата. */
    private static byte[] ocspTargetGood() {
        try {
            return TlsTestHelper.buildOcspResponse(
                    leaf.cert.getSerialNumber(), root.priv,
                    root.cert.getPublicKey(), root.subjectDn);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Ищет позицию тега certStatus (0x80, 0xA0, 0xA1) в SingleResponse DER.
     * certStatus следует после CertID внутри SingleResponse SEQUENCE.
     */
    private static int findCertStatusInSingleResponse(byte[] srDer) {
        // SingleResponse: SEQUENCE { CertID, certStatus, thisUpdate, [nextUpdate] }
        // Парсим SR SEQUENCE через его длину, затем длину CertID — certStatus сразу за ним
        int[] srLen = DerCodec.decodeLength(srDer, 1);
        int contentOff = 1 + srLen[1]; // позиция первого элемента SEQUENCE = CertID
        int[] certIdLen = DerCodec.decodeLength(srDer, contentOff + 1);
        int afterCertId = contentOff + 1 + certIdLen[1] + certIdLen[0];
        if (srDer[afterCertId] == (byte) 0x80
                || srDer[afterCertId] == (byte) 0xA0
                || srDer[afterCertId] == (byte) 0xA1) {
            return afterCertId;
        }
        return -1;
    }

    /** Извлекает первый SingleResponse как сырые DER-байты из OCSP-ответа. */
    private static byte[] extractFirstSingleResponse(byte[] ocspDer) {
        byte[][] outer = DerCodec.parseSequenceContents(ocspDer, 0);
        byte[] rb = outer[1]; // responseBytes [A0]
        int[] rbLen = DerCodec.decodeLength(rb, 1);
        byte[][] rbContent = DerCodec.parseSequenceContents(rb, 1 + rbLen[1]);
        byte[] basicDer = DerCodec.parseOctetString(rbContent[1], 0);
        byte[][] basicParts = DerCodec.parseSequenceContents(basicDer, 0);
        byte[] tbs = basicParts[0];
        byte[][] tbsParts = DerCodec.parseSequenceContents(tbs, 0);
        byte[] responsesField = tbsParts[3];
        int[] respLen = DerCodec.decodeLength(responsesField, 1);
        int contentOff = 1 + respLen[1];
        // Первый SingleResponse TLV внутри SEQUENCE
        int[] srTlv = DerCodec.decodeLength(responsesField, contentOff + 1);
        return Arrays.copyOfRange(responsesField, contentOff, contentOff + 1 + srTlv[1] + srTlv[0]);
    }

    /** Строит OCSP-ответ с двумя SingleResponse внутри. */
    private static byte[] buildMultiResponseOcsp(byte[] baseOcsp, byte[] sr1, byte[] sr2) {
        byte[][] outer = DerCodec.parseSequenceContents(baseOcsp, 0);
        byte[] rb = outer[1];
        int[] rbLen = DerCodec.decodeLength(rb, 1);
        byte[][] rbContent = DerCodec.parseSequenceContents(rb, 1 + rbLen[1]);
        byte[] basicDer = DerCodec.parseOctetString(rbContent[1], 0);
        byte[][] basicParts = DerCodec.parseSequenceContents(basicDer, 0);
        byte[] tbs = basicParts[0];
        byte[][] tbsParts = DerCodec.parseSequenceContents(tbs, 0);

        byte[] newResponses = DerCodec.encodeSequence(sr1, sr2);

        // Пересобираем TBSResponseData через encodeSequence — гарантирует корректную длину SEQUENCE
        byte[][] newTbsParts = new byte[tbsParts.length][];
        System.arraycopy(tbsParts, 0, newTbsParts, 0, tbsParts.length);
        newTbsParts[3] = newResponses;
        byte[] newTbs = DerCodec.encodeSequence(newTbsParts);
        // Пересобираем BasicOCSPResponse
        byte[] newBasic = DerCodec.encodeSequence(newTbs, basicParts[1], basicParts[2]);
        byte[] newBasicOctet = DerCodec.encodeOctetString(newBasic);
        // Пересобираем responseBytes
        byte[] newRbContent = DerCodec.encodeSequence(rbContent[0], newBasicOctet);
        byte[] newRb = DerCodec.encodeContextConstructed(0, newRbContent);
        return DerCodec.encodeSequence(outer[0], newRb);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}
