package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;

/**
 * Готовые векторы CAdES-BES с двумя подписантами, созданные КриптоПро: первая подпись -
 * {@code cryptcp -sign -cadesbes}, вторая - {@code cryptcp -addsign} из другого контейнера
 * (для attached и detached). Подписанты выпущены тестовым УЦ по запросам контейнеров.
 *
 * <p>Покрывает только BES: CAdES-T для нескольких подписантов не получен.
 */
@DisplayName("CAdES-BES с двумя подписантами, созданный КриптоПро (готовые векторы)")
class CryptoproCreatedMultiSignerVectorTest {

    private static final String DIR = "/cryptopro_multisigner/";
    private static final String FIRST_SIGNER = "Crossval CryptoPro BES Signer,";
    private static final String SECOND_SIGNER = "Crossval CryptoPro BES Signer 2";

    private static byte[] attached;
    private static byte[] detached;
    private static byte[] content;
    private static GostCertificate root;

    @BeforeAll
    static void load() throws IOException {
        attached = CryptoproVectorSupport.resource(DIR, "multi-attached.p7s");
        detached = CryptoproVectorSupport.resource(DIR, "multi-detached.p7s");
        content = CryptoproVectorSupport.resource(DIR, "data.txt");
        root = new GostCertificate(CryptoproVectorSupport.resource(DIR, "root.cer"));
    }

    @Test
    @DisplayName("attached: оба подписанта проверены")
    void attachedBothSignersAccepted() throws Exception {
        assertBothSigners(CAdESVerifier.verifyBES(attached, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("detached: оба подписанта проверены для исходного документа")
    void detachedBothSignersAccepted() throws Exception {
        assertBothSigners(
                CAdESVerifier.verifyBESDetached(
                        detached, content, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("detached: другой документ отвергается")
    void detachedOtherContentRejected() {
        byte[] other = Arrays.copyOf(content, content.length);
        other[0] ^= 0x01;

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyBESDetached(
                                detached, other, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("attached: порча подписи второго подписанта отвергает весь файл")
    void corruptedSecondSignatureRejected() throws Exception {
        corruptSignerAndAssertRejected(1);
    }

    @Test
    @DisplayName("attached: порча подписи первого подписанта отвергает весь файл")
    void corruptedFirstSignatureRejected() throws Exception {
        corruptSignerAndAssertRejected(0);
    }

    private static void corruptSignerAndAssertRejected(int signerIndex) throws Exception {
        byte[] signatureValue =
                CmsSignedDataVerifier.verify(
                                attached,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(root),
                                        SignerSelection.ALL,
                                        Revocation.none()))
                        .signers()
                        .get(signerIndex)
                        .signatureValue();
        int offset = CryptoproVectorSupport.indexOf(attached, signatureValue);
        assertTrue(offset >= 0, "signatureValue должен находиться в исходных байтах файла");
        byte[] broken = Arrays.copyOf(attached, attached.length);
        broken[offset + signatureValue.length / 2] ^= 0x01;

        // все подписанты обязаны пройти: одна испорченная подпись не должна проходить молча
        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyBES(broken, TrustAnchors.ofCertificates(root)));
    }

    private static void assertBothSigners(VerifiedCAdESData result) {
        List<CAdESSignerResult> signers = result.signers();
        assertEquals(2, signers.size(), "в файле должно быть два подписанта");
        List<String> names =
                signers.stream().map(signer -> signer.signerCertificate().getSubjectDn()).toList();
        assertTrue(
                names.stream().anyMatch(name -> name.contains(FIRST_SIGNER)),
                "среди подписантов должен быть первый: " + names);
        assertTrue(
                names.stream().anyMatch(name -> name.contains(SECOND_SIGNER)),
                "среди подписантов должен быть второй: " + names);
    }
}
