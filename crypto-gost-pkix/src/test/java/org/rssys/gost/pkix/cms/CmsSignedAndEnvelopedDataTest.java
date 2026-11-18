package org.rssys.gost.pkix.cms;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.rssys.gost.api.KeyGenerator;
import org.rssys.gost.pkix.GostOids;
import org.rssys.gost.pkix.cert.GostCertificate;
import org.rssys.gost.pkix.cert.PkixException;
import org.rssys.gost.pkix.cert.TrustAnchors;
import org.rssys.gost.signature.ECParameters;
import org.rssys.gost.signature.PrivateKeyParameters;
import org.rssys.gost.signature.PublicKeyParameters;

@DisplayName("CMS Sign+Encrypt: совмещённая подпись и шифрование")
class CmsSignedAndEnvelopedDataTest {

    private static final ECParameters PARAMS = ECParameters.tc26a256();
    private static PrivateKeyParameters signerKey;
    private static PublicKeyParameters signerPubKey;
    private static GostCertificate signerCert;
    private static PrivateKeyParameters recipientKey;
    private static PublicKeyParameters recipientPubKey;
    private static GostCertificate recipientCert;

    @BeforeAll
    static void setUp() {
        java.security.Security.insertProviderAt(new org.rssys.gost.jca.RssysGostProvider(), 1);

        var signerKp = KeyGenerator.generateKeyPair(PARAMS);
        signerKey = signerKp.getPrivate();
        signerPubKey = signerKp.getPublic();
        signerCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        signerKey, signerPubKey, BigInteger.valueOf(100), "Signer");

        var recipKp = KeyGenerator.generateKeyPair(PARAMS);
        recipientKey = recipKp.getPrivate();
        recipientPubKey = recipKp.getPublic();
        recipientCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        recipientKey, recipientPubKey, BigInteger.valueOf(200), "Recipient");
    }

    @Test
    @DisplayName("decryptAndVerify без якорей отклоняется до расшифрования")
    void decryptAndVerifyWithoutTrustAnchorsRejected() throws PkixException {
        byte[] combined =
                CmsSignedAndEnvelopedData.signThenEncrypt(
                        "payload".getBytes(), signerKey, signerCert, recipientCert);

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        CmsSignedAndEnvelopedData.decryptAndVerify(
                                combined, recipientKey, recipientCert),
                "пустой список доверенных сертификатов должен отклоняться");
    }

    @Test
    @DisplayName("sign-then-encrypt: подпись -> шифрование -> расшифрование -> проверка")
    void signThenEncryptRoundTrip() throws PkixException {
        byte[] data = "Конфиденциальный подписанный документ".getBytes();

        byte[] combined =
                CmsSignedAndEnvelopedData.signThenEncrypt(
                        data, signerKey, signerCert, recipientCert);

        assertNotNull(combined);

        VerifiedSignedData result =
                CmsSignedAndEnvelopedData.decryptAndVerify(
                        combined, recipientKey, recipientCert, signerCert);

        assertArrayEquals(data, result.data());
        assertNotNull(result.signerCertificate());
    }

    @Test
    @DisplayName("decryptAndVerify: detached SignedData внутри EnvelopedData отклоняется")
    void decryptAndVerifyRejectsDetachedSignedData() throws PkixException {
        byte[] detachedSigned =
                CmsSignedDataBuilder.create()
                        .data("detached inside enveloped".getBytes())
                        .addSigner(signerKey, signerCert)
                        .detached(true)
                        .build();
        byte[] enveloped =
                CmsEnvelopedDataBuilder.create()
                        .data(detachedSigned)
                        .addRecipient(recipientCert)
                        .build();

        PkixException ex =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedAndEnvelopedData.decryptAndVerify(
                                        enveloped, recipientKey, recipientCert, signerCert),
                        "detached SignedData без внешнего документа недопустим");
        assertTrue(
                ex.getMessage() != null && ex.getMessage().contains("Detached"),
                "ожидалась причина detached, получено: " + ex.getMessage());
    }

    @Test
    @DisplayName("sign-then-encrypt: неверный ключ расшифрования возвращает ошибку")
    void signThenEncryptWrongRecipientKey() {
        byte[] data = "Secret document".getBytes();

        byte[] combined =
                CmsSignedAndEnvelopedData.signThenEncrypt(
                        data, signerKey, signerCert, recipientCert);

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate wrongCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        wrongKp.getPrivate(),
                        wrongKp.getPublic(),
                        BigInteger.valueOf(300),
                        "Wrong");

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedAndEnvelopedData.decryptAndVerify(
                                combined, wrongKp.getPrivate(), wrongCert, signerCert),
                "Неверный ключ расшифрования должен бросить PkixException");
    }

    @Test
    @DisplayName("sign-then-encrypt: подмена данных — верификация не проходит")
    void signThenEncryptTamper() {
        byte[] data = "Original data".getBytes();

        byte[] combined =
                CmsSignedAndEnvelopedData.signThenEncrypt(
                        data, signerKey, signerCert, recipientCert);

        byte[] tampered = new byte[combined.length];
        System.arraycopy(combined, 0, tampered, 0, combined.length);
        // Портим последний байт зашифрованного содержимого. Середина сообщения
        // зависит от длины DER и после перехода на UTCTime/PrintableString может
        // попасть в незащищённую часть EnvelopedData, из-за чего подмена не
        // обнаруживается. Последний байт всегда принадлежит ciphertext.
        int tamperIndex = combined.length - 1;
        tampered[tamperIndex] ^= 0xFF;

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedAndEnvelopedData.decryptAndVerify(
                                tampered, recipientKey, recipientCert, signerCert),
                "Подмена данных должна бросить PkixException");
    }

    @Test
    @DisplayName("sign-then-encrypt: несколько получателей")
    void signThenEncryptMultipleRecipients() throws PkixException {
        byte[] data = "Multi-recipient data".getBytes();

        var recip2Kp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate recip2Cert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        recip2Kp.getPrivate(),
                        recip2Kp.getPublic(),
                        BigInteger.valueOf(400),
                        "Recipient2");

        byte[] combined =
                CmsSignedAndEnvelopedData.signThenEncrypt(
                        data, signerKey, signerCert, recipientCert, recip2Cert);

        VerifiedSignedData result1 =
                CmsSignedAndEnvelopedData.decryptAndVerify(
                        combined, recipientKey, recipientCert, signerCert);
        assertArrayEquals(data, result1.data());

        VerifiedSignedData result2 =
                CmsSignedAndEnvelopedData.decryptAndVerify(
                        combined, recip2Kp.getPrivate(), recip2Cert, signerCert);
        assertArrayEquals(data, result2.data());
    }

    @Test
    @DisplayName("encrypt-then-sign: шифрование -> подпись -> проверка -> расшифрование")
    void encryptThenSignRoundTrip() throws PkixException {
        byte[] data = "Аудируемый зашифрованный документ".getBytes();

        byte[] combined =
                CmsSignedAndEnvelopedData.encryptThenSign(
                        data, signerKey, signerCert, recipientCert);

        assertNotNull(combined);

        VerifiedSignedData result =
                CmsSignedAndEnvelopedData.verifyAndDecrypt(
                        combined, recipientKey, recipientCert, signerCert);

        assertArrayEquals(data, result.data());
        assertNotNull(result.signerCertificate());
    }

    @Test
    @DisplayName("encrypt-then-sign: неверный сертификат подписанта — верификация не проходит")
    void encryptThenSignWrongSigner() {
        byte[] data = "Data for wrong signer test".getBytes();

        byte[] combined =
                CmsSignedAndEnvelopedData.encryptThenSign(
                        data, signerKey, signerCert, recipientCert);

        var wrongKp = KeyGenerator.generateKeyPair(PARAMS);
        GostCertificate wrongCert =
                CmsTestUtils.createSelfSignedCertWithDn(
                        wrongKp.getPrivate(),
                        wrongKp.getPublic(),
                        BigInteger.valueOf(500),
                        "WrongSigner");

        assertThrows(
                PkixException.class,
                () ->
                        CmsSignedAndEnvelopedData.verifyAndDecrypt(
                                combined, recipientKey, recipientCert, wrongCert),
                "Неверный сертификат подписанта должен бросить PkixException");
    }

    @Test
    @DisplayName("encrypt-then-sign: eContentType в SignedData = id-envelopedData")
    void encryptThenSignContentTypeIsEnvelopedData() throws PkixException {
        byte[] data = "Content type check".getBytes();

        byte[] combined =
                CmsSignedAndEnvelopedData.encryptThenSign(
                        data, signerKey, signerCert, recipientCert);

        VerifiedSignedData result =
                CmsSignedAndEnvelopedData.verifyAndDecrypt(
                        combined, recipientKey, recipientCert, signerCert);

        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName("encrypt-then-sign: round-trip не нарушен при eContentType != id-data")
    void signedDataWithCustomContentTypeRoundTrip() throws PkixException {
        byte[] data = "Standard signed data".getBytes();

        byte[] signedData =
                CmsSignedDataBuilder.create().data(data).addSigner(signerKey, signerCert).build();

        VerifiedSignedData result =
                CmsSignedDataVerifier.verify(
                        signedData,
                        VerifyOptions.trusting(
                                TrustAnchors.ofCertificates(signerCert),
                                SignerSelection.ANY,
                                Revocation.none()));

        assertArrayEquals(data, result.data());
    }

    @Test
    @DisplayName(
            "sign-then-encrypt: контейнер без имитовставки принимается, целостность даёт подпись")
    void signThenEncryptWithoutIntegrityAccepted() throws PkixException {
        byte[] data = "Подписанный документ в контейнере без OMAC".getBytes();
        byte[] signed =
                CmsSignedDataBuilder.create().data(data).addSigner(signerKey, signerCert).build();
        byte[] combined =
                CmsEnvelopedDataBuilder.create()
                        .data(signed)
                        .encryptedContentType(GostOids.CMS_SIGNED_DATA)
                        .addRecipient(recipientCert)
                        .withoutIntegrity()
                        .build();

        VerifiedSignedData result =
                CmsSignedAndEnvelopedData.decryptAndVerify(
                        combined, recipientKey, recipientCert, signerCert);

        assertArrayEquals(
                data, result.data(), "контейнер без OMAC от внешнего узла должен читаться");
    }

    @Test
    @DisplayName("sign-then-encrypt: подмена режима шифра не проходит разбор или проверку подписи")
    void signThenEncryptModeSubstitutionFails() throws PkixException {
        byte[] combined =
                CmsSignedAndEnvelopedData.signThenEncrypt(
                        "Документ".getBytes(), signerKey, signerCert, recipientCert);
        // Понижение OMAC -> обычный CTR с удалением атрибута: строгий decrypt его бы отверг, но
        // здесь целостность обеспечивает подпись, и мусор вместо SignedData не должен пройти.
        byte[] forged =
                CmsEnvelopedRewriter.withoutUnprotectedAttrs(
                        CmsEnvelopedRewriter.withContentOid(combined, GostOids.KUZ_CTR_ACPKM));

        PkixException refusal =
                assertThrows(
                        PkixException.class,
                        () ->
                                CmsSignedAndEnvelopedData.decryptAndVerify(
                                        forged, recipientKey, recipientCert, signerCert),
                        "подмена режима должна давать PkixException, а не непроверяемое исключение");
        // Метод допускает режим без имитовставки, поэтому отказ обязан прийти из разбора
        // SignedData или проверки подписи, а не из политики целостности
        assertNotEquals(
                PkixException.Reason.INTEGRITY_REQUIRED,
                refusal.reason(),
                "отказ не должен происходить из политики целостности");
    }
}
