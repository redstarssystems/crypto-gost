package org.rssys.gost.pkix.cert;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.GostSigner;
import org.rssys.gost.jca.spec.GostDerCodec;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;
import org.rssys.gost.util.DerCodec;

/**
 * Алгоритм CertID берётся из ответа, а запись выбирается по полному CertID
 * (серийный номер уникален только в пределах одного УЦ).
 */
@DisplayName("OcspVerifier: выбор записи по полному CertID и алгоритм хэша CertID")
class OcspVerifierCertIdSelectionTest {

    private static final byte[] STATUS_GOOD = DerCodec.encodeTlv(0x80, new byte[0]);
    private static final byte[] STATUS_REVOKED =
            DerCodec.encodeTlv(0xA1, DerCodec.encodeGeneralizedTime("20250101000000Z"));
    private static final byte[] LEAF_SERIAL = {0x01, 0x23, 0x45};

    private static PkixCertTestHelper.CertBundle ca256;
    private static PkixCertTestHelper.CertBundle ca512;
    private static PkixCertTestHelper.CertBundle foreignCa;

    @BeforeAll
    static void setUp() throws Exception {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);
        ca256 = PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
        ca512 = PkixCertTestHelper.createRootCA(ECParameters.tc26a512());
        foreignCa = PkixCertTestHelper.createRootCA(ECParameters.tc26a256());
    }

    // ------------------------------------------------------------------
    // Алгоритм хэша CertID берётся из ответа
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Матрица: ключ УЦ 256/512 x CertID Стрибог-256/512 — ответ принимается")
    void certIdHashLengthMatrix() {
        for (PkixCertTestHelper.CertBundle ca :
                new PkixCertTestHelper.CertBundle[] {ca256, ca512}) {
            for (int certIdLen :
                    new int[] {GostOids.STREEBOG_256_HASH_LEN, GostOids.STREEBOG_512_HASH_LEN}) {
                byte[] ocsp =
                        GostOcspResponseBuilder.create(LEAF_SERIAL)
                                .issuerDn(ca.subjectDn)
                                .certIdHashLen(certIdLen)
                                .sign(ca.priv);
                assertDoesNotThrow(
                        () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca.cert),
                        "Ответ с CertID длиной "
                                + certIdLen
                                + " для УЦ с ключом "
                                + ca.cert.getPublicKey().getParams().hlen * 8
                                + " бит должен приниматься");
            }
        }
    }

    @Test
    @DisplayName("УЦ-512 с CertID на Стрибоге-256 — верный ответ принимается (путь verifyEvidence)")
    void ca512WithStreebog256CertId_evidence() throws Exception {
        byte[] ocsp =
                GostOcspResponseBuilder.create(LEAF_SERIAL)
                        .issuerDn(ca512.subjectDn)
                        .certIdHashLen(GostOids.STREEBOG_256_HASH_LEN)
                        .sign(ca512.priv);
        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                OcspVerifier.verifyEvidence(
                        ocsp,
                        LEAF_SERIAL,
                        ca512.cert,
                        nowWindow(),
                        RevocationFreshnessPolicy.ETSI_DEFAULT),
                "Верный ответ УЦ-512 с CertID Стрибог-256 должен приниматься");
    }

    @Test
    @DisplayName("Построитель отвергает длину хэша CertID, не равную 32 и 64")
    void builderRejectsBadCertIdHashLength() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GostOcspResponseBuilder.create(LEAF_SERIAL).certIdHashLen(20),
                "Длина 20 недопустима для CertID");
    }

    // ------------------------------------------------------------------
    // verify: выбор записи
    // ------------------------------------------------------------------

    @Test
    @DisplayName(
            "verify: чужая отозванная запись идёт первой — наш сертификат определяется по CertID")
    void verify_foreignFirst() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(foreignCa, LEAF_SERIAL, STATUS_REVOKED),
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD));
        assertDoesNotThrow(
                () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca256.cert),
                "Чужая запись с тем же серийным номером не должна давать ложный REVOKED");
    }

    @Test
    @DisplayName("verify: чужая отозванная запись идёт второй — наша запись выбирается")
    void verify_foreignSecond() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD),
                        entry(foreignCa, LEAF_SERIAL, STATUS_REVOKED));
        assertDoesNotThrow(
                () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca256.cert),
                "Наша запись good должна быть выбрана независимо от порядка");
    }

    @Test
    @DisplayName("verify: наша запись revoked остаётся revoked при чужой good")
    void verify_ourRevokedStillRevoked() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(foreignCa, LEAF_SERIAL, STATUS_GOOD),
                        entry(ca256, LEAF_SERIAL, STATUS_REVOKED));
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca256.cert),
                        "Чужая запись good не должна скрывать наш отзыв");
        assertEquals(PkixException.Reason.REVOKED, e.reason(), "Причина — REVOKED");
    }

    @Test
    @DisplayName("verify: только чужие записи, первая отозвана — отказ по CertID, не REVOKED")
    void verify_onlyForeign_notRevoked() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(foreignCa, LEAF_SERIAL, STATUS_REVOKED),
                        entry(foreignCa, LEAF_SERIAL, STATUS_GOOD));
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca256.cert),
                        "Ответ без нашей записи должен отвергаться");
        assertNotEquals(
                PkixException.Reason.REVOKED, e.reason(), "Чужой отзыв не должен давать REVOKED");
        assertTrue(
                e.getMessage().contains("issuerNameHash mismatch"),
                "Причина отказа — несовпадение CertID, получено: " + e.getMessage());
    }

    @Test
    @DisplayName("verify: дубликат полного CertID с разным статусом — отказ")
    void verify_duplicateDifferentStatus() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD),
                        entry(ca256, LEAF_SERIAL, STATUS_REVOKED));
        assertThrows(
                PkixException.class,
                () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca256.cert),
                "Противоречивые записи с одинаковым CertID должны отвергаться");
    }

    @Test
    @DisplayName("verify: дубликат полного CertID с одинаковым статусом — принимается")
    void verify_duplicateSameStatus() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD),
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD));
        assertDoesNotThrow(
                () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca256.cert),
                "Одинаковые записи принимались раньше и должны приниматься");
    }

    @Test
    @DisplayName("verify: нет записи с нашим серийным номером — отказ")
    void verify_serialNotFound() throws Exception {
        byte[] ocsp = signMulti(ca256, entry(ca256, new byte[] {0x7F}, STATUS_GOOD));
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca256.cert),
                        "Без записи с нужным серийным номером ответ отвергается");
        assertTrue(
                e.getMessage().contains("not found"),
                "Причина отказа - нет записи с нашим серийным номером, получено: "
                        + e.getMessage());
    }

    // ------------------------------------------------------------------
    // verifyEvidence: выбор записи
    // ------------------------------------------------------------------

    @Test
    @DisplayName("verifyEvidence: чужая запись с тем же серийным номером идёт первой — принимается")
    void evidence_foreignFirst() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(foreignCa, LEAF_SERIAL, STATUS_REVOKED),
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD));
        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                evidence(ocsp),
                "Долговременное доказательство не должно отвергаться из-за чужой записи");
    }

    @Test
    @DisplayName("verifyEvidence: чужая запись идёт второй — принимается")
    void evidence_foreignSecond() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD),
                        entry(foreignCa, LEAF_SERIAL, STATUS_REVOKED));
        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                evidence(ocsp),
                "Наша запись должна выбираться независимо от порядка");
    }

    @Test
    @DisplayName("verifyEvidence: только чужие записи — отказ")
    void evidence_onlyForeign() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(foreignCa, LEAF_SERIAL, STATUS_REVOKED),
                        entry(foreignCa, LEAF_SERIAL, STATUS_GOOD));
        PkixException e =
                assertThrows(
                        PkixException.class,
                        () -> evidence(ocsp),
                        "Ответ без нашей записи должен отвергаться, а не приниматься откатом");
        assertTrue(
                e.getMessage().contains("mismatch"),
                "Причина отказа — несовпадение CertID, получено: " + e.getMessage());
    }

    @Test
    @DisplayName("verifyEvidence: любой дубликат полного CertID — отказ")
    void evidence_anyDuplicate() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD),
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD));
        assertThrows(
                PkixException.class,
                () -> evidence(ocsp),
                "Для долговременного доказательства дубликат полного CertID недопустим");
    }

    @Test
    @DisplayName("verifyEvidence: нет записи с нашим серийным номером — отказ")
    void evidence_serialNotFound() throws Exception {
        byte[] ocsp = signMulti(ca256, entry(ca256, new byte[] {0x7F}, STATUS_GOOD));
        assertThrows(
                PkixException.class,
                () -> evidence(ocsp),
                "Без записи с нужным серийным номером ответ отвергается");
    }

    // ------------------------------------------------------------------
    // Одинаковое имя у разных УЦ; длина хэша при выборе записи
    // ------------------------------------------------------------------

    @Test
    @DisplayName(
            "Одинаковое имя, разные ключи: чужая отозванная запись первой — выбирается наша (verify)")
    void verify_sameNameOtherKey_foreignFirst() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        sameNameOtherKey(foreignCa, ca256, STATUS_REVOKED),
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD));
        assertDoesNotThrow(
                () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca256.cert),
                "Запись с тем же именем, но чужим ключом, не должна заслонять нашу");
    }

    @Test
    @DisplayName(
            "Одинаковое имя, разные ключи: чужая запись второй — выбирается наша (verifyEvidence)")
    void evidence_sameNameOtherKey_foreignSecond() throws Exception {
        byte[] ocsp =
                signMulti(
                        ca256,
                        entry(ca256, LEAF_SERIAL, STATUS_GOOD),
                        sameNameOtherKey(foreignCa, ca256, STATUS_REVOKED));
        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                evidence(ocsp),
                "Запись с тем же именем, но чужим ключом, не должна заслонять нашу");
    }

    @Test
    @DisplayName("Одинаковое имя, разные ключи: только чужая запись — отказ по issuerKeyHash")
    void sameNameOtherKey_onlyForeign_keyHashMismatch() throws Exception {
        byte[] ocsp = signMulti(ca256, sameNameOtherKey(foreignCa, ca256, STATUS_REVOKED));
        PkixException verifyError =
                assertThrows(
                        PkixException.class,
                        () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca256.cert),
                        "Чужой ключ при совпадающем имени должен отвергаться");
        assertTrue(
                verifyError.getMessage().contains("issuerKeyHash mismatch"),
                "Имя совпало, ключ нет: " + verifyError.getMessage());
        assertNotEquals(
                PkixException.Reason.REVOKED, verifyError.reason(), "Чужой отзыв не даёт REVOKED");

        PkixException evidenceError =
                assertThrows(
                        PkixException.class,
                        () -> evidence(ocsp),
                        "Долговременное доказательство тоже отвергает чужой ключ");
        assertTrue(
                evidenceError.getMessage().contains("issuerKeyHash mismatch"),
                "Имя совпало, ключ нет: " + evidenceError.getMessage());
    }

    @Test
    @DisplayName("УЦ-512 с CertID Стрибог-256: чужая отозванная запись первой — выбирается наша")
    void ca512Streebog256CertId_foreignFirst() throws Exception {
        // Длина хэша при выборе записи берётся из записи (32), а не из ключа УЦ (64):
        // иначе наша запись не опознаётся, а откат «первая» подсунул бы чужую
        byte[] ocsp =
                signMulti(
                        ca512,
                        withHashLen(foreignCa, STATUS_REVOKED, GostOids.STREEBOG_256_HASH_LEN),
                        withHashLen(ca512, STATUS_GOOD, GostOids.STREEBOG_256_HASH_LEN));
        assertDoesNotThrow(
                () -> OcspVerifier.verify(ocsp, LEAF_SERIAL, ca512.cert),
                "Наша запись УЦ-512 с CertID Стрибог-256 должна опознаваться в verify");
        assertEquals(
                EvidenceFreshness.IN_WINDOW,
                evidence(ocsp, ca512),
                "Наша запись УЦ-512 с CertID Стрибог-256 должна опознаваться в verifyEvidence");
    }

    // ------------------------------------------------------------------
    // Вспомогательные методы
    // ------------------------------------------------------------------

    private static EvidenceFreshness evidence(byte[] ocsp) throws PkixException {
        return evidence(ocsp, ca256);
    }

    private static EvidenceFreshness evidence(byte[] ocsp, PkixCertTestHelper.CertBundle issuer)
            throws PkixException {
        return OcspVerifier.verifyEvidence(
                ocsp,
                LEAF_SERIAL,
                issuer.cert,
                nowWindow(),
                RevocationFreshnessPolicy.ETSI_DEFAULT);
    }

    private static RevocationEvidenceWindow nowWindow() {
        Instant now = Instant.now();
        return new RevocationEvidenceWindow(now, now);
    }

    /**
     * Запись ответа: УЦ, чей ключ идёт в issuerKeyHash, серийный номер и статус. Имя для
     * issuerNameHash и длина хэша CertID по умолчанию берутся от этого же УЦ; задаются явно,
     * чтобы получить УЦ с чужим ключом и тем же именем либо CertID не по размеру ключа УЦ.
     */
    private record Entry(
            PkixCertTestHelper.CertBundle issuer,
            byte[] serial,
            byte[] status,
            byte[] subjectDn,
            int hashLen) {}

    private static Entry entry(PkixCertTestHelper.CertBundle issuer, byte[] serial, byte[] status) {
        return new Entry(
                issuer,
                serial,
                status,
                issuer.subjectDn,
                issuer.cert.getPublicKey().getParams().hlen);
    }

    /** Запись с чужим ключом, но именем нашего УЦ: норма объясняет хэш ключа именно этим случаем. */
    private static Entry sameNameOtherKey(
            PkixCertTestHelper.CertBundle otherKeyOwner,
            PkixCertTestHelper.CertBundle nameOwner,
            byte[] status) {
        return new Entry(
                otherKeyOwner,
                LEAF_SERIAL,
                status,
                nameOwner.subjectDn,
                otherKeyOwner.cert.getPublicKey().getParams().hlen);
    }

    /** Запись с заданной длиной хэша CertID. */
    private static Entry withHashLen(
            PkixCertTestHelper.CertBundle issuer, byte[] status, int hashLen) {
        return new Entry(issuer, LEAF_SERIAL, status, issuer.subjectDn, hashLen);
    }

    /**
     * Собирает и подписывает ответ с несколькими SingleResponse: построитель
     * библиотеки выпускает ровно одну запись, а для выбора по CertID нужно несколько.
     */
    private static byte[] signMulti(PkixCertTestHelper.CertBundle signer, Entry... entries) {
        String now = GostSignatureHelper.nowGeneralizedTime();
        String nextUpdate = GostSignatureHelper.nowPlusYears(3);
        ByteArrayOutputStream responses = new ByteArrayOutputStream();
        for (Entry entry : entries) {
            byte[] singleResponse = singleResponse(entry, now, nextUpdate);
            responses.write(singleResponse, 0, singleResponse.length);
        }
        byte[] responderId = DerCodec.encodeTlv(DerCodec.TAG_CTX_CONSTRUCTED_1, signer.subjectDn);
        byte[] producedAt = DerCodec.encodeTlv(0x18, now.getBytes(StandardCharsets.US_ASCII));
        byte[] tbs =
                DerCodec.encodeSequence(
                        DerCodec.concat(
                                responderId,
                                producedAt,
                                DerCodec.encodeSequence(responses.toByteArray())));

        PrivateKeyParameters priv = signer.priv;
        PublicKeyParameters pub = signer.cert.getPublicKey();
        int signerHlen = pub.getParams().hlen;
        byte[] hash = GostSignatureHelper.doHash(tbs, signerHlen);
        byte[] signature = GostSignatureHelper.signHashChecked(hash, GostSigner.of(priv));
        byte[] basicOcsp =
                DerCodec.encodeSequence(
                        tbs,
                        GostSignatureHelper.buildAlgId(pub.getParams()),
                        DerCodec.encodeBitString(signature));

        byte[] responseBytes =
                DerCodec.encodeTlv(
                        0xA0,
                        DerCodec.encodeSequence(
                                DerCodec.encodeOid(GostOids.OCSP_BASIC),
                                DerCodec.encodeOctetString(basicOcsp)));
        return DerCodec.encodeSequence(new byte[] {0x0A, 0x01, 0x00}, responseBytes);
    }

    private static byte[] singleResponse(Entry entry, String thisUpdate, String nextUpdate) {
        PublicKeyParameters issuerPub = entry.issuer().cert.getPublicKey();
        int hlen = entry.hashLen();
        String digestOid =
                hlen == GostOids.STREEBOG_512_HASH_LEN ? GostOids.DIGEST_512 : GostOids.DIGEST_256;
        byte[] certId =
                DerCodec.encodeSequence(
                        DerCodec.encodeSequence(DerCodec.encodeOid(digestOid)),
                        DerCodec.encodeOctetString(
                                GostSignatureHelper.doHash(entry.subjectDn(), hlen)),
                        DerCodec.encodeOctetString(
                                GostSignatureHelper.doHash(
                                        GostDerCodec.encodeSpkiKeyBits(issuerPub), hlen)),
                        DerCodec.encodeTlv(0x02, entry.serial()));
        byte[] nextUpdateField =
                DerCodec.encodeTlv(
                        0xA0,
                        DerCodec.encodeTlv(0x18, nextUpdate.getBytes(StandardCharsets.US_ASCII)));
        return DerCodec.encodeSequence(
                certId,
                entry.status(),
                DerCodec.encodeGeneralizedTime(thisUpdate),
                nextUpdateField);
    }
}
