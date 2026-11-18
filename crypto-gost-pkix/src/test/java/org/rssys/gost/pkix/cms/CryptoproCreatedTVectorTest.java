package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
 * Готовые векторы CAdES-T (256 бит), созданные КриптоПро
 * ({@code cryptcp -sign -cadest -cadestsa}, attached и detached). Штамп выдал локальный тестовый
 * TSA, подчинённый промежуточному УЦ ({@code Crossval TSA CA}) под тем же корнем; сертификат
 * промежуточного УЦ едет внутри токена. Подписант выпущен корнем по запросу контейнера.
 */
@DisplayName("CAdES-T, созданный КриптоПро: проверка crypto-gost (готовые векторы)")
class CryptoproCreatedTVectorTest {

    private static final String DIR = "/cryptopro_t/";

    private static byte[] attached;
    private static byte[] detached;
    private static byte[] content;
    private static GostCertificate root;
    private static GostCertificate tsaCa;

    @BeforeAll
    static void load() throws IOException {
        attached = CryptoproVectorSupport.resource(DIR, "t-attached.p7s");
        detached = CryptoproVectorSupport.resource(DIR, "t-detached.p7s");
        content = CryptoproVectorSupport.resource(DIR, "data.txt");
        root = new GostCertificate(CryptoproVectorSupport.resource(DIR, "root.cer"));
        tsaCa = new GostCertificate(CryptoproVectorSupport.resource(DIR, "tsa-ca.cer"));
    }

    @Test
    @DisplayName("attached: принимается, метка времени проверена, данные совпадают")
    void attachedAccepted() throws Exception {
        VerifiedCAdESData result =
                CAdESVerifier.verifyT(attached, TrustAnchors.ofCertificates(root));

        assertEquals(1, result.signers().size(), "ровно один подписант");
        assertArrayEquals(content, result.data(), "данные из подписи совпадают с исходными");
        assertFalse(
                result.signers().get(0).timestamps().isEmpty(),
                "метка времени signature-time-stamp должна быть проверена");
    }

    @Test
    @DisplayName("detached: принимается для исходного документа")
    void detachedAccepted() throws Exception {
        VerifiedCAdESData result =
                CAdESVerifier.verifyTDetached(detached, content, TrustAnchors.ofCertificates(root));

        assertEquals(1, result.signers().size(), "ровно один подписант");
        assertFalse(
                result.signers().get(0).timestamps().isEmpty(),
                "метка времени signature-time-stamp должна быть проверена");
    }

    @Test
    @DisplayName("detached: другой документ отвергается")
    void detachedOtherContentRejected() {
        byte[] other = Arrays.copyOf(content, content.length);
        other[0] ^= 0x01;

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyTDetached(
                                detached, other, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("Промежуточный УЦ службы штампов не заменяет якорь")
    void intermediateIsNotAnAnchor() {
        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyT(attached, TrustAnchors.ofCertificates(tsaCa)),
                "промежуточный УЦ TSA не должен быть доверенным якорем подписанта");
    }

    @Test
    @DisplayName("attached: подмена байта подписанных данных отвергается")
    void tamperedContentRejected() {
        int offset = CryptoproVectorSupport.indexOf(attached, content);
        assertTrue(offset >= 0, "содержимое должно находиться в исходных байтах файла");
        byte[] broken = Arrays.copyOf(attached, attached.length);
        broken[offset] ^= 0x01;

        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyT(broken, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("attached: подмена байта подписи отвергается (метка привязана к подписи)")
    void tamperedSignatureValueRejected() throws Exception {
        byte[] signatureValue =
                CmsSignedDataVerifier.verify(
                                attached,
                                VerifyOptions.trusting(
                                        TrustAnchors.ofCertificates(root),
                                        SignerSelection.ALL,
                                        Revocation.none()))
                        .signers()
                        .get(0)
                        .signatureValue();
        int offset = CryptoproVectorSupport.indexOf(attached, signatureValue);
        assertTrue(offset >= 0, "signatureValue должен находиться в исходных байтах файла");
        byte[] broken = Arrays.copyOf(attached, attached.length);
        broken[offset + signatureValue.length / 2] ^= 0x01;

        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyT(broken, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("attached: подмена байта messageImprint в токене отвергается")
    void tamperedMessageImprintRejected() throws Exception {
        // messageImprint штампа - хэш подписи; байт внутри подписанного TSTInfo токена правится
        // на месте, поэтому проверка обязана упасть на подписи TSA, а не на разборе структуры
        VerifiedCAdESData parsed =
                CAdESVerifier.verifyT(attached, TrustAnchors.ofCertificates(root));
        byte[] imprint = parsed.signers().get(0).timestamps().get(0).messageImprintHash();
        int offset = CryptoproVectorSupport.indexOf(attached, imprint);
        assertTrue(offset >= 0, "messageImprint должен находиться в байтах токена");
        byte[] broken = Arrays.copyOf(attached, attached.length);
        broken[offset] ^= 0x01;

        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyT(broken, TrustAnchors.ofCertificates(root)));
    }
}
