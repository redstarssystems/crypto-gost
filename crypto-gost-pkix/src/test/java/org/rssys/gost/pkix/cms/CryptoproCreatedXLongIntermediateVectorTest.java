package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.GostCrl;
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.RevocationFreshnessPolicy;
import org.rssys.gost.pkix.cert.TrustAnchors;

/**
 * Готовый вектор: CAdES-X Long Type 1 с промежуточными УЦ, созданный КриптоПро
 * ({@code cryptcp -enhance -xlongtype1 -enhall -cadestsa}) поверх CAdES-BES crypto-gost.
 *
 * <p>Цепочка подписанта: подписант -> промежуточный УЦ подписанта -> корень. Служба штампов
 * выпущена другим промежуточным УЦ. У подписанта источник отзыва только OCSP, у промежуточных
 * УЦ только CRL корня, выпущенный до штампа подписи. Это форма настоящих файлов КриптоПро с
 * несколькими УЦ, которой нет в векторе с одним УЦ. Подпись подписанта сделана crypto-gost, всё
 * остальное - КриптоПро; закрытых ключей КриптоПро и персональных данных в файлах нет.
 * Сообщение attached: {@code -enhance} не принимает detached.
 */
@DisplayName("CAdES-X Long с промежуточными УЦ, созданный КриптоПро (готовый вектор)")
class CryptoproCreatedXLongIntermediateVectorTest {

    private static final String DIR = "/cryptopro_xlong_intermediate/";
    private static final String CONTENT = "intermediate vector\n";

    private static byte[] signature;
    private static GostCertificate root;
    private static GostCertificate signerCa;
    private static GostCertificate tsaCa;

    @BeforeAll
    static void load() throws IOException {
        signature = CryptoproVectorSupport.resource(DIR, "xlong.p7s");
        root = new GostCertificate(CryptoproVectorSupport.resource(DIR, "root.cer"));
        signerCa = new GostCertificate(CryptoproVectorSupport.resource(DIR, "signer-ca.cer"));
        tsaCa = new GostCertificate(CryptoproVectorSupport.resource(DIR, "tsa-ca.cer"));
    }

    private static VerifiedCAdESData verify(
            RevocationFreshnessPolicy policy, GostCertificate... anchors) throws PkixException {
        return CAdESVerifier.verifyXLong(signature, policy, TrustAnchors.ofCertificates(anchors));
    }

    @Test
    @DisplayName("ETSI_DEFAULT: принимается, данные совпадают с исходными")
    void etsiDefaultAccepts() throws Exception {
        VerifiedCAdESData result = verify(RevocationFreshnessPolicy.ETSI_DEFAULT, root);

        assertEquals(1, result.signers().size(), "ровно один подписант");
        assertTrue(
                result.signerCertificate().getSubjectDn().contains("Crossval Intermediate Signer"),
                "подписант - сертификат, выпущенный промежуточным УЦ");
        assertArrayEquals(
                CONTENT.getBytes(StandardCharsets.UTF_8), result.data(), "данные не изменились");
    }

    @Test
    @DisplayName("STRICT: отвергается - CRL промежуточного УЦ выпущен раньше штампа подписи")
    void strictRejectsOldCrl() {
        PkixException error =
                assertThrows(
                        PkixException.class,
                        () -> verify(RevocationFreshnessPolicy.STRICT, root),
                        "STRICT не должен принять CRL, выпущенный до штампа подписи");

        assertEquals(
                PkixException.Reason.REVOCATION_EVIDENCE_OUT_OF_WINDOW,
                error.reason(),
                "причина - доказательство отзыва вне окна свежести");
        assertTrue(
                error.getMessage().contains("chain[1]"),
                "отказ относится к промежуточному УЦ подписанта: " + error.getMessage());
    }

    @Test
    @DisplayName("Форма: три звена цепочки, CRL корня для промежуточного УЦ, OCSP для подписанта")
    void vectorHasIntermediateForm() throws Exception {
        CAdESSignerResult signer =
                verify(RevocationFreshnessPolicy.ETSI_DEFAULT, root).signers().get(0);

        List<GostCertificate> chain = signer.certificateValues();
        assertEquals(3, chain.size(), "подписант, промежуточный УЦ, корень");
        assertArrayEquals(
                signerCa.getEncoded(),
                chain.get(1).getEncoded(),
                "второе звено - промежуточный УЦ подписанта");
        assertArrayEquals(root.getEncoded(), chain.get(2).getEncoded(), "третье звено - корень");

        assertEquals(3, signer.completeCertRefs().size(), "ссылка на каждое звено цепочки");
        GostCrl crl = signer.revocationValues().crls().get(0);
        assertEquals(1, signer.revocationValues().crls().size(), "один CRL");
        assertArrayEquals(
                root.getSubjectDnBytes(),
                crl.getIssuerDnBytes(),
                "CRL выпущен корнем: так проверяется промежуточный УЦ");
        assertEquals(1, signer.revocationValues().ocspResponses().size(), "один OCSP-ответ");
    }

    @Test
    @DisplayName(
            "OCSP без встроенного ответчика: сертификат ответчика в certificate-values и в C-ссылках")
    void responderIsInCertificateValues() throws Exception {
        CAdESSignerResult signer =
                verify(RevocationFreshnessPolicy.ETSI_DEFAULT, root).signers().get(0);
        GostOcspResponse ocsp = signer.revocationValues().ocspResponses().get(0);

        assertTrue(
                ocsp.getDelegatedCertificates().isEmpty(),
                "КриптоПро хранит OCSP без сертификата ответчика");

        // certificateValues() результата - первичная цепочка, поэтому ответчика ищем в сыром
        // атрибуте
        List<GostCertificate> rawValues = CryptoproVectorSupport.rawCertificateValues(signature);
        assertFalse(rawValues.isEmpty(), "certificate-values не пуст");
        List<GostCertificate> candidates =
                CAdESVerifier.selectOcspResponderCandidates(
                        rawValues,
                        signer.completeCertRefs(),
                        signer.certificateValues(),
                        new GostCertificate[] {root});

        assertEquals(1, candidates.size(), "ответчик - единственный кандидат с C-ссылкой");
        assertTrue(
                candidates.get(0).getSubjectDn().contains("Crossval Signer CA OCSP"),
                "ответчик выпущен промежуточным УЦ подписанта");
        assertDoesNotThrow(
                () -> ocsp.verify(candidates.get(0).getPublicKey()),
                "подпись OCSP проверяется ключом ответчика из certificate-values");
    }

    @Test
    @DisplayName("Промежуточный УЦ службы штампов есть в файле, но не в цепочке подписанта")
    void tsaIntermediateIsInFileOnly() throws Exception {
        // Размещение не проверяется: сервер вектора кладёт промежуточный УЦ в каждый токен, поэтому
        // он есть и в escTimeStamp. Форму «только в соседнем токене» покрывает
        // CAdESXLongTsaIntermediateFromOtherTokenTest.
        assertTrue(
                CryptoproVectorSupport.indexOf(signature, tsaCa.getEncoded()) >= 0,
                "сертификат промежуточного УЦ службы штампов лежит в файле");

        List<GostCertificate> chain =
                verify(RevocationFreshnessPolicy.ETSI_DEFAULT, root)
                        .signers()
                        .get(0)
                        .certificateValues();
        assertTrue(
                chain.stream().noneMatch(c -> Arrays.equals(c.getEncoded(), tsaCa.getEncoded())),
                "промежуточный УЦ службы штампов не входит в цепочку подписанта");
    }

    @Test
    @DisplayName("Промежуточный УЦ не заменяет якорь: с ним вместо корня файл отвергается")
    void intermediateIsNotAnAnchor() {
        assertThrows(
                PkixException.class,
                () -> verify(RevocationFreshnessPolicy.ETSI_DEFAULT, tsaCa),
                "чужой промежуточный УЦ не должен быть доверенным якорем");
    }

    @Test
    @DisplayName("Подмена байта подписанных данных отвергается как PkixException")
    void tamperedContentRejected() {
        byte[] content = CONTENT.getBytes(StandardCharsets.UTF_8);
        int offset = CryptoproVectorSupport.indexOf(signature, content);
        assertTrue(offset >= 0, "содержимое должно находиться в исходных байтах файла");

        byte[] broken = Arrays.copyOf(signature, signature.length);
        broken[offset] ^= 0x01;

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                broken,
                                RevocationFreshnessPolicy.ETSI_DEFAULT,
                                TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("Подмена байта внутри signatureValue отвергается как PkixException")
    void tamperedSignatureValueRejected() throws Exception {
        VerifiedSignedData parsed =
                CmsSignedDataVerifier.verify(
                        signature,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(root),
                                SignerSelection.ALL,
                                Revocation.none()));
        byte[] signatureValue = parsed.signers().get(0).signatureValue();
        int offset = CryptoproVectorSupport.indexOf(signature, signatureValue);
        assertTrue(offset >= 0, "signatureValue должен находиться в исходных байтах файла");

        // Правим один байт на месте: длины и структура остаются исходными
        byte[] broken = Arrays.copyOf(signature, signature.length);
        broken[offset + signatureValue.length / 2] ^= 0x01;

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLong(
                                broken,
                                RevocationFreshnessPolicy.ETSI_DEFAULT,
                                TrustAnchors.ofCertificates(root)));
    }
}
