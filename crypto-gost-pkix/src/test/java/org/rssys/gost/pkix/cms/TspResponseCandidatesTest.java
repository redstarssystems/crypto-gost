package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCertificateBuilder;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.tsp.TspRequestBuilder;
import org.rssys.gost.pkix.tsp.TspResponse;
import org.rssys.gost.pkix.tsp.TspResponseBuilder;
import org.rssys.gost.signature.ECParameters;

/**
 * Проверка TSA-токена с недоверенными кандидатами: промежуточный УЦ и сам сертификат
 * TSA берутся из соседних структур, а не из токена. Доверие кандидаты не создают.
 */
@DisplayName("TspResponse.verify: недоверенные кандидаты сертификатов TSA")
class TspResponseCandidatesTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static final byte[] IMPRINT = new byte[32];

    private static KeyPair rootKp;
    private static GostCertificate root;
    private static KeyPair intKp;
    private static GostCertificate tsaInt;
    private static KeyPair tsaKp;
    private static GostCertificate tsa;

    /** Тот же издатель, serial и ключ, но другой DER (перевыпуск с иным сроком). */
    private static GostCertificate tsaReissued;

    private static GostCertificate foreignRoot;

    @BeforeAll
    static void setUp() throws Exception {
        rootKp = KeyGenerator.generateKeyPair(PARAMS);
        root = caCert(rootKp, rootKp, "Cand Root", null, 11);
        intKp = KeyGenerator.generateKeyPair(PARAMS);
        tsaInt = caCert(intKp, rootKp, "Cand Intermediate", root, 12);
        tsaKp = KeyGenerator.generateKeyPair(PARAMS);
        tsa = tsaCert(tsaKp, intKp, tsaInt, 365);
        tsaReissued = tsaCert(tsaKp, intKp, tsaInt, 366);
        KeyPair foreignKp = KeyGenerator.generateKeyPair(PARAMS);
        foreignRoot = caCert(foreignKp, foreignKp, "Cand Foreign Root", null, 99);
    }

    private static GostCertificate caCert(
            KeyPair subject, KeyPair issuerKp, String name, GostCertificate issuer, long serial)
            throws Exception {
        byte[] dn = testDn(name);
        return GostCertificateBuilder.create(PARAMS, dn)
                .issuerDn(issuer == null ? dn : issuer.getSubjectDnBytes())
                .publicKey(subject.getPublic())
                .serial(BigInteger.valueOf(serial))
                .notBeforeNow()
                .validForDays(365)
                .basicConstraints(true, null)
                .keyUsage(
                        GostCertificateBuilder.KeyUsage.KEY_CERT_SIGN,
                        GostCertificateBuilder.KeyUsage.CRL_SIGN)
                .sign(issuerKp.getPrivate());
    }

    private static GostCertificate tsaCert(
            KeyPair subject, KeyPair issuerKp, GostCertificate issuer, int days) throws Exception {
        return GostCertificateBuilder.create(PARAMS, testDn("Cand TSA"))
                .issuerDn(issuer.getSubjectDnBytes())
                .publicKey(subject.getPublic())
                .serial(BigInteger.valueOf(500))
                .notBeforeNow()
                .validForDays(days)
                .keyUsage(GostCertificateBuilder.KeyUsage.DIGITAL_SIGNATURE)
                .extendedKeyUsage(true, GostOids.EXT_TIME_STAMPING)
                .sign(issuerKp.getPrivate());
    }

    private static byte[] testDn(String cn) {
        return CmsTestUtils.buildDn(cn);
    }

    /**
     * Токен, подписанный TSA. Если {@code embedCert} ложно, поле certificates токена
     * удаляется (как у КриптоПро): оно не входит в подписанные данные.
     */
    private static TspResponse token(boolean embedCert, boolean withEssCertId) throws Exception {
        byte[] request =
                TspRequestBuilder.create()
                        .messageImprint(IMPRINT, GostOids.DIGEST_256)
                        .certReq(true)
                        .build();
        TspResponseBuilder builder =
                TspResponseBuilder.create(request)
                        .signer(tsaKp.getPrivate(), tsa)
                        .policyOid("1.2.3.4.5")
                        .serialNumber(BigInteger.ONE);
        if (withEssCertId) {
            builder.withCAdES();
        }
        TspResponse response = TspResponse.fromDer(builder.buildGranted());
        if (embedCert) {
            return response;
        }
        SignedDataParts sd =
                SignedDataParts.parse(
                        CmsContentInfo.decode(response.timeStampTokenDer()).content());
        byte[] stripped =
                CmsContentInfo.encode(
                        GostOids.CMS_SIGNED_DATA, sd.rebuild(null, sd.signerInfosField()));
        return TspResponse.parseTimeStampToken(stripped);
    }

    private static void verify(
            TspResponse response, List<GostCertificate> candidates, GostCertificate trusted)
            throws PkixException {
        response.verify(IMPRINT, GostOids.DIGEST_256, null, candidates, trusted);
    }

    @Test
    @DisplayName("Промежуточный УЦ только среди кандидатов: цепочка до переданного корня строится")
    void intermediateFromCandidatesBuildsChain() throws Exception {
        TspResponse response = token(true, true);

        assertDoesNotThrow(() -> verify(response, List.of(tsaInt), root));
    }

    @Test
    @DisplayName("Без кандидатов тот же токен отвергается: промежуточного УЦ нет")
    void withoutCandidatesRejected() throws Exception {
        TspResponse response = token(true, true);

        assertThrows(
                PkixException.class,
                () -> response.verify(IMPRINT, GostOids.DIGEST_256, null, root));
    }

    @Test
    @DisplayName("Чужой корень не даёт доверия, даже если кандидаты содержат полную цепочку")
    void foreignRootRejected() throws Exception {
        TspResponse response = token(true, true);

        assertThrows(
                PkixException.class, () -> verify(response, List.of(tsaInt, root), foreignRoot));
    }

    @Test
    @DisplayName("Промежуточный УЦ из кандидатов не становится якорем")
    void candidateIntermediateIsNotAnchor() throws Exception {
        TspResponse response = token(true, true);

        // корня нет ни среди якорей, ни в токене: промежуточного УЦ-кандидата недостаточно
        assertThrows(PkixException.class, () -> verify(response, List.of(tsaInt), foreignRoot));
    }

    @Test
    @DisplayName("Сертификат TSA только среди кандидатов, signingCertificateV2 совпал: принимается")
    void tsaFromCandidatesWithMatchingEssCertId() throws Exception {
        TspResponse response = token(false, true);

        assertDoesNotThrow(() -> verify(response, List.of(tsa, tsaInt), root));
    }

    @Test
    @DisplayName("Сертификат TSA из кандидатов без signingCertificateV2: отказ")
    void tsaFromCandidatesWithoutEssCertIdRejected() throws Exception {
        TspResponse response = token(false, false);

        assertThrows(PkixException.class, () -> verify(response, List.of(tsa, tsaInt), root));
    }

    @Test
    @DisplayName(
            "Сертификат TSA из собственного certificates токена без signingCertificateV2: как раньше")
    void tsaFromOwnCertificatesWithoutEssCertIdAccepted() throws Exception {
        TspResponse response = token(true, false);

        assertDoesNotThrow(() -> verify(response, List.of(tsaInt), root));
    }

    @Test
    @DisplayName("Перевыпуск с тем же sid, но другим DER: не совпал с certHash, отказ")
    void reissuedCandidateWithOtherDerRejected() throws Exception {
        TspResponse response = token(false, true);

        assertThrows(
                PkixException.class, () -> verify(response, List.of(tsaReissued, tsaInt), root));
    }

    @Test
    @DisplayName("Два кандидата с одним sid: выбирается названный в signingCertificateV2")
    void candidateNamedByEssCertIdIsChosen() throws Exception {
        TspResponse response = token(false, true);

        assertDoesNotThrow(() -> verify(response, List.of(tsaReissued, tsa, tsaInt), root));
    }

    @Test
    @DisplayName("Одинаковые DER среди кандидатов схлопываются без отказа")
    void duplicateDerCollapses() throws Exception {
        TspResponse response = token(false, true);

        assertDoesNotThrow(() -> verify(response, List.of(tsa, tsa, tsaInt), root));
    }

    @Test
    @DisplayName("Самоподписанный чужой кандидат доверия не даёт")
    void selfSignedForeignCandidateGivesNoTrust() throws Exception {
        TspResponse response = token(false, true);

        assertThrows(
                PkixException.class,
                () -> verify(response, List.of(tsa, foreignRoot), foreignRoot));
    }

    @Test
    @DisplayName("Кандидатов больше MAX_EMBEDDED_CERTS: отказ")
    void tooManyCandidatesRejected() throws Exception {
        TspResponse response = token(true, true);
        List<GostCertificate> many = new ArrayList<>();
        for (int i = 0; i <= CmsConstants.MAX_EMBEDDED_CERTS; i++) {
            KeyPair kp = KeyGenerator.generateKeyPair(PARAMS);
            many.add(caCert(kp, kp, "Many " + i, null, 1000 + i));
        }

        assertThrows(PkixException.class, () -> verify(response, many, root));
    }

    @Test
    @DisplayName("null в списке кандидатов: IllegalArgumentException")
    void nullCandidateRejected() throws Exception {
        TspResponse response = token(true, true);
        List<GostCertificate> withNull = new ArrayList<>();
        withNull.add(null);

        assertThrows(IllegalArgumentException.class, () -> verify(response, withNull, root));
    }
}
