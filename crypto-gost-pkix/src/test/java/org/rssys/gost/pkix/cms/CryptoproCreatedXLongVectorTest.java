package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
import org.rssys.gost.pkix.cert.GostOcspResponse;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.RevocationFreshnessPolicy;
import org.rssys.gost.pkix.cert.TrustAnchors;

/**
 * Готовый вектор: CAdES-X Long Type 1 (detached), созданный КриптоПро
 * ({@code cryptcp -sign -xlongtype1 -cadestsa}) ключом из контейнера КриптоПро.
 * Сертификат подписанта выпущен тестовым УЦ с фиксированным ключом, срок до 2045 года;
 * TSA, OCSP-ответчик и УЦ - те же тестовые. Закрытых ключей и персональных данных нет.
 * Тест воспроизводит проверку КриптоПро -> crypto-gost без КриптоПро и без человека.
 */
@DisplayName("CAdES-X Long, созданный КриптоПро: проверка crypto-gost (готовый вектор)")
class CryptoproCreatedXLongVectorTest {

    private static final String DIR = "/cryptopro_xlong/";

    private static byte[] signature;
    private static byte[] content;
    private static GostCertificate root;

    @BeforeAll
    static void load() throws IOException {
        signature = resource("xlong.p7s");
        content = resource("data.txt");
        root = new GostCertificate(resource("root.cer"));
    }

    private static byte[] resource(String name) throws IOException {
        return CryptoproVectorSupport.resource(DIR, name);
    }

    @Test
    @DisplayName("STRICT: принимается (OCSP листа выпущен после штампа подписи)")
    void strictAccepts() throws Exception {
        VerifiedCAdESData result =
                CAdESVerifier.verifyXLongDetached(
                        signature,
                        content,
                        RevocationFreshnessPolicy.STRICT,
                        TrustAnchors.ofCertificates(root));

        assertEquals(1, result.signers().size(), "ровно один подписант");
        assertTrue(
                result.signerCertificate().getSubjectDn().contains("Crossval CryptoPro Signer"),
                "подписант - сертификат из контейнера КриптоПро");
    }

    @Test
    @DisplayName("ETSI_DEFAULT: принимается")
    void etsiDefaultAccepts() throws Exception {
        assertEquals(
                1,
                CAdESVerifier.verifyXLongDetached(
                                signature,
                                content,
                                RevocationFreshnessPolicy.ETSI_DEFAULT,
                                TrustAnchors.ofCertificates(root))
                        .signers()
                        .size());
    }

    @Test
    @DisplayName("Изменённые данные отвергаются")
    void tamperedContentRejected() {
        byte[] other = "tampered".getBytes(StandardCharsets.UTF_8);

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLongDetached(
                                signature,
                                other,
                                RevocationFreshnessPolicy.ETSI_DEFAULT,
                                TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("Форма вектора: OCSP без встроенного ответчика, ответчик в certificate-values")
    void vectorHasCryptoProForm() throws Exception {
        VerifiedCAdESData result =
                CAdESVerifier.verifyXLongDetached(
                        signature,
                        content,
                        RevocationFreshnessPolicy.ETSI_DEFAULT,
                        TrustAnchors.ofCertificates(root));
        CAdESSignerResult signer = result.signers().get(0);
        GostOcspResponse ocsp = signer.revocationValues().ocspResponses().get(0);

        assertTrue(
                ocsp.getDelegatedCertificates().isEmpty(),
                "КриптоПро хранит OCSP без сертификата ответчика");

        // certificateValues() результата - первичная цепочка, а не сырой атрибут,
        // поэтому ответчика ищем в сыром certificate-values файла
        List<GostCertificate> rawValues = CryptoproVectorSupport.rawCertificateValues(signature);
        List<GostCertificate> candidates =
                CAdESVerifier.selectOcspResponderCandidates(
                        rawValues,
                        signer.completeCertRefs(),
                        signer.certificateValues(),
                        new GostCertificate[] {root});

        assertEquals(1, candidates.size(), "ответчик - единственный кандидат с C-ссылкой");
        assertDoesNotThrow(
                () -> ocsp.verify(candidates.get(0).getPublicKey()),
                "подпись OCSP проверяется ключом ответчика из certificate-values");
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
                                        Revocation.none())
                                .detached(content));
        byte[] signatureValue = parsed.signers().get(0).signatureValue();
        int offset = CryptoproVectorSupport.indexOf(signature, signatureValue);
        assertTrue(offset >= 0, "signatureValue должен находиться в исходных байтах файла");

        // Правим один байт на месте: длины и структура остаются исходными
        byte[] broken = Arrays.copyOf(signature, signature.length);
        broken[offset + signatureValue.length / 2] ^= 0x01;

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyXLongDetached(
                                broken,
                                content,
                                RevocationFreshnessPolicy.ETSI_DEFAULT,
                                TrustAnchors.ofCertificates(root)));
    }
}
