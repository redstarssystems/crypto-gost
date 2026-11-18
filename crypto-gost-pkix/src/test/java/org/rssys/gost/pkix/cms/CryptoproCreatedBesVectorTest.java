package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.api.KeyPair;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;

/**
 * Готовые векторы CAdES-BES (256 бит), созданные КриптоПро
 * ({@code cryptcp -sign -cadesbes}, attached и detached) ключом из контейнера КриптоПро.
 * Сертификат подписанта выпущен тестовым УЦ по запросу контейнера, срок до 2045 года, закрытых
 * ключей и персональных данных в файлах нет. Тест проверяет направление КриптоПро -> crypto-gost
 * без КриптоПро и без человека.
 */
@DisplayName("CAdES-BES, созданный КриптоПро: проверка crypto-gost (готовые векторы)")
class CryptoproCreatedBesVectorTest {

    private static final String DIR = "/cryptopro_bes/";
    private static final String SIGNER_NAME = "Crossval CryptoPro BES Signer";

    private static byte[] attached;
    private static byte[] detached;
    private static byte[] content;
    private static GostCertificate root;

    @BeforeAll
    static void load() throws IOException {
        attached = resource("bes-attached.p7s");
        detached = resource("bes-detached.p7s");
        content = resource("data.txt");
        root = new GostCertificate(resource("root.cer"));
    }

    private static byte[] resource(String name) throws IOException {
        return CryptoproVectorSupport.resource(DIR, name);
    }

    @Test
    @DisplayName("attached: принимается, данные и подписант совпадают с ожидаемыми")
    void attachedAccepted() throws Exception {
        VerifiedCAdESData result =
                CAdESVerifier.verifyBES(attached, TrustAnchors.ofCertificates(root));

        assertEquals(1, result.signers().size(), "ровно один подписант");
        assertArrayEquals(content, result.data(), "данные из подписи совпадают с исходными");
        assertTrue(
                result.signerCertificate().getSubjectDn().contains(SIGNER_NAME),
                "подписант - сертификат из контейнера КриптоПро");
    }

    @Test
    @DisplayName("detached: принимается для исходного документа")
    void detachedAccepted() throws Exception {
        VerifiedCAdESData result =
                CAdESVerifier.verifyBESDetached(
                        detached, content, TrustAnchors.ofCertificates(root));

        assertEquals(1, result.signers().size(), "ровно один подписант");
        assertTrue(
                result.signerCertificate().getSubjectDn().contains(SIGNER_NAME),
                "подписант - сертификат из контейнера КриптоПро");
    }

    @Test
    @DisplayName("detached: другой документ отвергается")
    void detachedOtherContentRejected() {
        byte[] other = "tampered".getBytes(StandardCharsets.UTF_8);

        assertThrows(
                PkixException.class,
                () ->
                        CAdESVerifier.verifyBESDetached(
                                detached, other, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("attached: подмена байта подписанных данных отвергается как PkixException")
    void attachedTamperedContentRejected() {
        int offset = CryptoproVectorSupport.indexOf(attached, content);
        assertTrue(offset >= 0, "содержимое должно находиться в исходных байтах файла");

        byte[] broken = Arrays.copyOf(attached, attached.length);
        broken[offset] ^= 0x01;

        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyBES(broken, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("attached: подмена байта внутри signatureValue отвергается как PkixException")
    void attachedTamperedSignatureValueRejected() throws Exception {
        VerifiedSignedData parsed =
                CmsSignedDataVerifier.verify(
                        attached,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(root),
                                SignerSelection.ALL,
                                Revocation.none()));
        byte[] signatureValue = parsed.signers().get(0).signatureValue();
        int offset = CryptoproVectorSupport.indexOf(attached, signatureValue);
        assertTrue(offset >= 0, "signatureValue должен находиться в исходных байтах файла");

        byte[] broken = Arrays.copyOf(attached, attached.length);
        broken[offset + signatureValue.length / 2] ^= 0x01;

        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyBES(broken, TrustAnchors.ofCertificates(root)));
    }

    @Test
    @DisplayName("Чужой якорь: подписант, выпущенный другим УЦ, отвергается")
    void foreignAnchorRejected() throws Exception {
        // самоподписанный сертификат вместо корня фикстур: цепочка подписанта к нему не строится
        // одна пара ключей: сертификат должен быть внутренне согласован, иначе отказ объяснялся бы
        // его порчей, а не чужим якорем
        KeyPair foreignKeys = KeyGenerator.generateKeyPair(ECParameters.tc26a256());
        GostCertificate foreign =
                CmsTestUtils.createSelfSignedCert(
                        foreignKeys.getPrivate(), foreignKeys.getPublic());

        assertThrows(
                PkixException.class,
                () -> CAdESVerifier.verifyBES(attached, TrustAnchors.ofCertificates(foreign)));
    }
}
