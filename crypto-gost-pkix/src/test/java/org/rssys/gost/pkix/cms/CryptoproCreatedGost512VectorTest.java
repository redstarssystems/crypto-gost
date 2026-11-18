package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;

/**
 * Готовый вектор CAdES-BES на 512 бит, созданный КриптоПро
 * ({@code cryptcp -sign -cadesbes -hashalg 1.2.643.7.1.1.2.3}, контейнер типа 81).
 * Сертификат подписанта (ключ 512 бит) выпущен 256-битным тестовым УЦ по запросу контейнера.
 *
 * <p>Покрывает только BES: CAdES-T и X Long на 512 бит остаются непокрытыми (нужны 512-битная
 * TSA и хэши Стрибог-512 в запросах и ответах OCSP).
 */
@DisplayName("CAdES-BES 512 бит, созданный КриптоПро: проверка crypto-gost (готовый вектор)")
class CryptoproCreatedGost512VectorTest {

    private static final String DIR = "/cryptopro_bes512/";
    private static final String SIGNER_NAME = "Crossval CryptoPro BES Signer 512";

    private static byte[] signature;
    private static byte[] content;
    private static GostCertificate root;

    @BeforeAll
    static void load() throws IOException {
        signature = CryptoproVectorSupport.resource(DIR, "bes512.p7s");
        content = CryptoproVectorSupport.resource(DIR, "data.txt");
        root = new GostCertificate(CryptoproVectorSupport.resource(DIR, "root.cer"));
    }

    @Test
    @DisplayName("Принимается: подписант с 512-битным ключом, данные совпадают")
    void accepted() throws Exception {
        VerifiedCAdESData result =
                CAdESVerifier.verifyBES(signature, TrustAnchors.ofCertificates(root));

        assertEquals(1, result.signers().size(), "ровно один подписант");
        assertArrayEquals(content, result.data(), "данные из подписи совпадают с исходными");
        GostCertificate signer = result.signerCertificate();
        assertTrue(
                signer.getSubjectDn().contains(SIGNER_NAME),
                "подписант - сертификат из 512-битного контейнера КриптоПро");
        assertEquals(
                64,
                signer.getPublicKey().getParams().hlen,
                "ключ подписанта должен быть 512-битным (hlen = 64 байта)");
        assertEquals(
                128,
                CmsSignedDataVerifier.verify(
                                signature,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(root),
                                        SignerSelection.ALL,
                                        Revocation.none()))
                        .signers()
                        .get(0)
                        .signatureValue()
                        .length,
                "сырая подпись ГОСТ Р 34.10-2012 на 512 бит занимает 128 байт");
    }

    @Test
    @DisplayName("Подмена байта подписанных данных отвергается как PkixException")
    void tamperedContentRejected() {
        int offset = CryptoproVectorSupport.indexOf(signature, content);
        assertTrue(offset >= 0, "содержимое должно находиться в исходных байтах файла");
        byte[] broken = Arrays.copyOf(signature, signature.length);
        broken[offset] ^= 0x01;

        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyBES(broken, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("Подмена байта внутри signatureValue отвергается как PkixException")
    void tamperedSignatureValueRejected() throws Exception {
        byte[] signatureValue =
                CmsSignedDataVerifier.verify(
                                signature,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(root),
                                        SignerSelection.ALL,
                                        Revocation.none()))
                        .signers()
                        .get(0)
                        .signatureValue();
        int offset = CryptoproVectorSupport.indexOf(signature, signatureValue);
        assertTrue(offset >= 0, "signatureValue должен находиться в исходных байтах файла");
        byte[] broken = Arrays.copyOf(signature, signature.length);
        broken[offset + signatureValue.length / 2] ^= 0x01;

        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyBES(broken, TrustAnchors.ofCertificates(root)));
    }
}
